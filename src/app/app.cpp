#include "app.h"
#include <nlohmann/json.hpp>
#include <saucer/embedded/all.hpp>
#include <saucer/icon.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace maple {

static std::string formatOpcode(uint16_t opcode) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << opcode;
    return oss.str();
}

App::App(Capture& capture) : capture_(capture) {
    // Set scripts base path to exe directory / scripts
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    scriptsBasePath_ = fs::path(exePath).parent_path() / "scripts";
}

void App::setup(saucer::application* app) {
    window_ = saucer::window::create(app).value();
    webview_.emplace(saucer::smartview::create({.window = window_}).value());

    window_->set_title("MapleSniffer");
    window_->set_size({1280, 1024});

    // Set window icon from embedded resource (app.rc: IDI_ICON1)
    {
        HMODULE hModule = GetModuleHandleW(nullptr);
        HRSRC hRes = FindResourceW(hModule, MAKEINTRESOURCEW(1), RT_GROUP_ICON);
        if (!hRes) hRes = FindResourceW(hModule, L"IDI_ICON1", RT_GROUP_ICON);

        // Fallback: load icon.ico from disk next to exe
        auto tryFile = [&]() {
            wchar_t exeBuf[MAX_PATH];
            GetModuleFileNameW(nullptr, exeBuf, MAX_PATH);
            auto icoPath = fs::path(exeBuf).parent_path() / "icon.ico";
            auto ico = saucer::icon::from(icoPath);
            if (ico.has_value()) window_->set_icon(ico.value());
        };

        if (hRes) {
            HGLOBAL hData = LoadResource(hModule, hRes);
            if (hData) {
                auto* grp = static_cast<const uint8_t*>(LockResource(hData));
                DWORD grpSize = SizeofResource(hModule, hRes);
                // Find the best icon entry in the group and load the RT_ICON resource
                // Group header: reserved(2) + type(2) + count(2), then entries of 14 bytes each
                if (grpSize >= 6) {
                    uint16_t count = *reinterpret_cast<const uint16_t*>(grp + 4);
                    // Use the last entry (largest icon, typically 256x256)
                    if (count > 0 && grpSize >= 6u + count * 14u) {
                        uint16_t iconId = *reinterpret_cast<const uint16_t*>(grp + 6 + (count - 1) * 14 + 12);
                        HRSRC hIcon = FindResourceW(hModule, MAKEINTRESOURCEW(iconId), RT_ICON);
                        if (hIcon) {
                            HGLOBAL hIconData = LoadResource(hModule, hIcon);
                            DWORD iconSize = SizeofResource(hModule, hIcon);
                            if (hIconData && iconSize > 0) {
                                auto* iconBytes = static_cast<const uint8_t*>(LockResource(hIconData));
                                // Build a single-entry ICO file in memory
                                std::vector<uint8_t> ico(6 + 16 + iconSize);
                                // Header: reserved=0, type=1, count=1
                                ico[2] = 1; // type
                                ico[4] = 1; // count
                                // Copy the GRPICONDIRENTRY (first 12 bytes of the group entry)
                                std::memcpy(ico.data() + 6, grp + 6 + (count - 1) * 14, 12);
                                // Fix size field (offset 8 in entry = bytes 6+8)
                                *reinterpret_cast<uint32_t*>(ico.data() + 6 + 8) = iconSize;
                                // Offset to image data (6 header + 16 entry)
                                *reinterpret_cast<uint32_t*>(ico.data() + 6 + 12) = 6 + 16;
                                // Append raw icon image
                                std::memcpy(ico.data() + 6 + 16, iconBytes, iconSize);

                                auto stash = saucer::stash::from(std::move(ico));
                                auto icon = saucer::icon::from(stash);
                                if (icon.has_value()) {
                                    window_->set_icon(icon.value());
                                } else {
                                    tryFile();
                                }
                            } else { tryFile(); }
                        } else { tryFile(); }
                    } else { tryFile(); }
                } else { tryFile(); }
            } else { tryFile(); }
        } else {
            tryFile();
        }
    }

    // Expose C++ functions to JavaScript
    webview_->expose("getStatus", [this]() { return getStatus(); });
    webview_->expose("getInterfaces", [this]() { return getInterfaces(); });
    webview_->expose("getPackets", [this](int since) { return getPackets(since); });
    webview_->expose("startCapture", [this](const std::string& iface, const std::string& filter) {
        return startCapture(iface, filter);
    });
    webview_->expose("stopCapture", [this]() { return stopCapture(); });

    // Script I/O (parameterized by locale/version)
    webview_->expose("getScript", [this](const std::string& direction, int opcode, int locale, int version) {
        return getScript(direction, opcode, locale, version);
    });
    webview_->expose("saveScript", [this](const std::string& direction, int opcode, const std::string& code, int locale, int version) {
        return saveScript(direction, opcode, code, locale, version);
    });
    webview_->expose("listScripts", [this](int locale, int version) { return listScripts(locale, version); });
    webview_->expose("getSessions", [this]() { return getSessions(); });

    // Opcode names I/O
    webview_->expose("getOpcodeNames", [this](int locale, int version) {
        return getOpcodeNames(locale, version);
    });
    webview_->expose("saveOpcodeNames", [this](int locale, int version, const std::string& namesJson) {
        return saveOpcodeNames(locale, version, namesJson);
    });

    // Opcode encryption
    webview_->expose("decryptOpcodes", [this](const std::string& hexPayload, const std::string& desKey) {
        return decryptOpcodes(hexPayload, desKey);
    });

    // Embed frontend and serve
    webview_->embed(saucer::embedded::all());
    webview_->serve("/index.html");

    window_->show();
}

void App::addPackets(const std::vector<Packet>& pkts) {
    std::lock_guard<std::mutex> lock(packetsMutex_);
    for (const auto& pkt : pkts) {
        // Track session info from handshake packets
        if (pkt.isHandshake && pkt.version > 0) {
            // Check if this session already exists
            bool found = false;
            for (const auto& s : sessions_) {
                if (s.id == pkt.sessionId) { found = true; break; }
            }
            if (!found) {
                sessions_.push_back({
                    pkt.sessionId,
                    pkt.locale,
                    pkt.version,
                    pkt.subVersionStr,
                    pkt.serverPort,
                    pkt.timestamp
                });
            }
        }

        // Mark session dead on stream desync notification
        if (pkt.isDeadNotification) {
            for (auto& s : sessions_) {
                if (s.id == pkt.sessionId) { s.dead = true; break; }
            }
        }

        packets_.push_back(pkt);
        nextPacketSeq_++;
        if (packets_.size() > MAX_PACKETS) {
            packets_.pop_front();
            baseSeq_++;
        }
    }
}

std::string App::getStatus() {
    json j;
    j["capturing"] = capture_.isRunning();
    j["interface"] = capture_.currentInterface();
    j["filter"] = capture_.currentFilter();
    {
        std::lock_guard<std::mutex> lock(packetsMutex_);
        j["packetCount"] = packets_.size();
    }
    return j.dump();
}

std::string App::getInterfaces() {
    auto ifaces = capture_.listInterfaces();
    json j = json::array();
    for (const auto& iface : ifaces) {
        j.push_back({
            {"name", iface.name},
            {"friendlyName", iface.friendlyName},
            {"description", iface.description}
        });
    }
    return j.dump();
}

std::string App::getPackets(int since) {
    std::lock_guard<std::mutex> lock(packetsMutex_);
    json j = json::array();

    // since is a monotonic sequence number; convert to deque offset
    uint64_t sinceSeq = static_cast<uint64_t>(since);
    size_t startOffset = 0;
    if (sinceSeq > baseSeq_) {
        startOffset = static_cast<size_t>(sinceSeq - baseSeq_);
    }

    for (size_t i = startOffset; i < packets_.size(); i++) {
        const auto& pkt = packets_[i];
        json pktJson;
        pktJson["index"] = static_cast<uint64_t>(baseSeq_ + i);
        pktJson["timestamp"] = pkt.timestamp;
        pktJson["length"] = pkt.length;
        pktJson["hexDump"] = pkt.hexDump;
        pktJson["outbound"] = pkt.outbound;
        pktJson["isHandshake"] = pkt.isHandshake;
        pktJson["sessionId"] = pkt.sessionId;

        if (pkt.isHandshake) {
            pktJson["opcode"] = "Handshake";
            pktJson["opcodeRaw"] = 0;
            pktJson["version"] = pkt.version;
            pktJson["subVersion"] = pkt.subVersionStr;
            pktJson["locale"] = pkt.locale;
        } else {
            pktJson["opcode"] = formatOpcode(pkt.opcode);
            pktJson["opcodeRaw"] = pkt.opcode;
        }

        pktJson["decrypted"] = !pkt.isHandshake;
        j.push_back(pktJson);
    }
    return j.dump();
}

bool App::startCapture(const std::string& iface, const std::string& filter) {
    if (iface.empty()) return false;

    if (capture_.isRunning()) {
        capture_.stop();
    }

    {
        std::lock_guard<std::mutex> lock(packetsMutex_);
        packets_.clear();
        sessions_.clear();
        nextPacketSeq_ = 0;
        baseSeq_ = 0;
    }

    return capture_.start(iface, filter);
}

bool App::stopCapture() {
    capture_.stop();
    return true;
}

std::string App::getScript(const std::string& direction, int opcode, int locale, int version) {
    if (version == 0) return "";

    auto dir = scriptsBasePath_ / (std::to_string(locale) + "_" + std::to_string(version));
    std::ostringstream fname;
    fname << direction << "_0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << opcode << ".js";
    auto path = dir / fname.str();

    std::ifstream ifs(path);
    if (!ifs.is_open()) return "";
    return std::string(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
}

bool App::saveScript(const std::string& direction, int opcode, const std::string& code, int locale, int version) {
    if (version == 0) return false;

    auto dir = scriptsBasePath_ / (std::to_string(locale) + "_" + std::to_string(version));
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) return false;

    std::ostringstream fname;
    fname << direction << "_0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << opcode << ".js";
    auto path = dir / fname.str();

    std::ofstream ofs(path, std::ios::trunc);
    if (!ofs.is_open()) return false;
    ofs << code;
    return ofs.good();
}

std::string App::listScripts(int locale, int version) {
    json j = json::array();
    if (version == 0) return j.dump();

    auto dir = scriptsBasePath_ / (std::to_string(locale) + "_" + std::to_string(version));
    std::error_code ec;
    if (!fs::exists(dir, ec)) return j.dump();

    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) continue;
        auto filename = entry.path().filename().string();
        if (filename.size() < 4 || filename.substr(filename.size() - 3) != ".js") continue;

        // Parse direction and opcode from filename: recv_0x00B5.js
        auto underscore = filename.find('_');
        if (underscore == std::string::npos) continue;

        std::string scriptDir = filename.substr(0, underscore);
        // Extract opcode hex after "0x"
        auto hexStart = filename.find("0x", underscore);
        if (hexStart == std::string::npos) continue;
        std::string hexStr = filename.substr(hexStart + 2, filename.size() - hexStart - 5); // remove ".js"

        int op = 0;
        std::istringstream iss(hexStr);
        iss >> std::hex >> op;

        j.push_back({
            {"direction", scriptDir},
            {"opcode", op},
            {"filename", filename}
        });
    }
    return j.dump();
}

std::string App::getSessions() {
    std::lock_guard<std::mutex> lock(packetsMutex_);
    json j = json::array();
    for (const auto& s : sessions_) {
        j.push_back({
            {"id", s.id},
            {"locale", s.locale},
            {"version", s.version},
            {"subVersion", s.subVersion},
            {"serverPort", s.serverPort},
            {"timestamp", s.timestamp},
            {"dead", s.dead}
        });
    }
    return j.dump();
}

std::string App::getOpcodeNames(int locale, int version) {
    auto path = scriptsBasePath_ / (std::to_string(locale) + "_" + std::to_string(version)) / "opcodes.json";
    std::ifstream ifs(path);
    if (!ifs.is_open()) return "{\"send\":{},\"recv\":{}}";
    return std::string(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
}

bool App::saveOpcodeNames(int locale, int version, const std::string& namesJson) {
    auto dir = scriptsBasePath_ / (std::to_string(locale) + "_" + std::to_string(version));
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) return false;

    auto path = dir / "opcodes.json";
    std::ofstream ofs(path, std::ios::trunc);
    if (!ofs.is_open()) return false;
    ofs << namesJson;
    return ofs.good();
}

std::string App::decryptOpcodes(const std::string& hexPayload, const std::string& desKey) {
    // Parse space-separated hex string to bytes
    std::vector<uint8_t> bytes;
    std::istringstream iss(hexPayload);
    std::string hexByte;
    while (iss >> hexByte) {
        if (hexByte.size() == 2) {
            try {
                bytes.push_back(static_cast<uint8_t>(std::stoi(hexByte, nullptr, 16)));
            } catch (...) {
                return "{}";
            }
        }
    }

    if (bytes.size() < 4) return "{}";

    int32_t bufferSize = static_cast<int32_t>(
        bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));

    if (bufferSize <= 0 || static_cast<int>(bytes.size()) < 4 + bufferSize) return "{}";

    auto mapping = MapleStream::parseOpcodeEncryption(
        bytes.data() + 4, static_cast<int>(bytes.size()) - 4, bufferSize, desKey);

    if (mapping.empty()) return "{}";

    json j;
    for (const auto& [enc, real] : mapping) {
        j[std::to_string(enc)] = real;
    }
    return j.dump();
}

} // namespace maple
