#pragma once

#include "../capture/capture.h"
#include "../protocol/protocol.h"
#include <saucer/smartview.hpp>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <filesystem>

namespace maple {

class App {
public:
    explicit App(Capture& capture);

    void setup(saucer::application* app);

    void addPackets(const std::vector<Packet>& pkts);

private:
    std::string getStatus();
    std::string getInterfaces();
    std::string getPackets(int since);
    bool startCapture(const std::string& iface, const std::string& filter);
    bool stopCapture();

    // Script I/O (parameterized by locale/version from frontend)
    std::string getScript(const std::string& direction, int opcode, int locale, int version);
    bool saveScript(const std::string& direction, int opcode, const std::string& code, int locale, int version);
    std::string listScripts(int locale, int version);
    std::string getSessions();

    // Opcode names I/O
    std::string getOpcodeNames(int locale, int version);
    bool saveOpcodeNames(int locale, int version, const std::string& namesJson);

    // Opcode encryption
    std::string decryptOpcodes(const std::string& hexPayload, const std::string& desKey);

    Capture& capture_;
    std::shared_ptr<saucer::window> window_;
    std::optional<saucer::smartview> webview_;

    std::deque<Packet> packets_;
    std::mutex packetsMutex_;
    static constexpr size_t MAX_PACKETS = 500;

    // Script system
    std::filesystem::path scriptsBasePath_;

    // Multi-session tracking
    struct SessionMeta {
        uint32_t id;
        uint8_t locale;
        uint16_t version;
        std::string subVersion;
        uint16_t serverPort;
        double timestamp;
    };
    std::vector<SessionMeta> sessions_;
};

} // namespace maple
