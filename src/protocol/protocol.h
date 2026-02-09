#pragma once

#include "../capture/capture.h"
#include "maple_stream.h"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <tuple>
#include <mutex>

namespace maple {

// Re-export DecryptedPacket as the packet type used by the rest of the system
using Packet = DecryptedPacket;

// TCP connection key: (srcIP, dstIP, srcPort, dstPort)
struct ConnectionKey {
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;

    bool operator<(const ConnectionKey& o) const {
        return std::tie(srcIP, dstIP, srcPort, dstPort) <
               std::tie(o.srcIP, o.dstIP, o.srcPort, o.dstPort);
    }

    // Return the reverse direction key
    ConnectionKey reverse() const {
        return { dstIP, srcIP, dstPort, srcPort };
    }
};

// Parsed TCP segment info
struct TcpSegment {
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    const uint8_t* payload;
    int payloadLen;
    bool syn;
    bool fin;
    bool rst;
};

// Session tracks a MapleStory connection (bidirectional)
class Session {
public:
    // Try to detect handshake from first server->client packet
    // Returns true if handshake was successfully parsed
    bool tryHandshake(const TcpSegment& seg, double timestamp);

    // Feed data into the appropriate direction stream
    // Returns decoded packets (may be 0 or more)
    std::vector<DecryptedPacket> feedData(const TcpSegment& seg, double timestamp);

    bool isInitialized() const { return initialized_; }

    // Accessors for handshake info
    uint16_t version() const { return version_; }
    const std::string& subVersionStr() const { return subVersionStr_; }
    uint8_t localeVal() const { return locale_; }

    // The server endpoint (as seen in handshake)
    uint32_t serverIP = 0;
    uint16_t serverPort = 0;

private:
    static constexpr uint16_t LOGIN_PORT = 8484;

    bool initialized_ = false;
    bool handshakePending_ = true;
    bool isLoginServer_ = false;

    uint16_t version_ = 0;
    std::string subVersionStr_;
    uint8_t locale_ = 0;
    uint8_t sendIV_[4]{};
    uint8_t recvIV_[4]{};

    // outbound = client->server, inbound = server->client
    std::unique_ptr<MapleStream> outboundStream_;  // client -> server
    std::unique_ptr<MapleStream> inboundStream_;    // server -> client
};

// Stateful protocol analyzer
class Protocol {
public:
    Protocol() = default;

    // Process a raw captured Ethernet frame
    // Returns 0 or more decoded packets
    std::vector<Packet> process(const RawPacket& raw);

    // Generate hex dump string from binary data
    static std::string toHexDump(const uint8_t* data, size_t len, size_t maxBytes = 128);

private:
    // Parse TCP segment from Ethernet frame
    static bool parseTcp(const uint8_t* data, int len, TcpSegment& seg);

    std::map<ConnectionKey, std::shared_ptr<Session>> sessions_;
    std::mutex mutex_;
};

} // namespace maple
