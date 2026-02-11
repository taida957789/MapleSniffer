#include "app.h"
#include <nlohmann/json.hpp>
#include <saucer/embedded/all.hpp>
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
    window_->set_size({1024, 900});

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
                    pkt.serverPort
                });
            }
        }
        packets_.push_back(pkt);
        if (packets_.size() > MAX_PACKETS) {
            packets_.pop_front();
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
    int idx = 0;
    for (const auto& pkt : packets_) {
        if (idx >= since) {
            json pktJson;
            pktJson["index"] = idx;
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
        idx++;
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
            {"serverPort", s.serverPort}
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

} // namespace maple
