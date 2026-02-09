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
    uint32_t seq;
    bool syn;
    bool ack;
    bool fin;
    bool rst;
};

// TCP reassembly buffer (per direction)
// Handles retransmit, out-of-order, and segment replacement.
// Uses one-segment hold: the newest segment stays pending until the next arrives,
// allowing a replacement (same seq, longer data) to overwrite before delivery.
struct TcpReasm {
    uint32_t nextSeq = 0;
    bool initialized = false;
    std::map<uint32_t, std::vector<uint8_t>> staged;

    void init(uint32_t seq) { nextSeq = seq; initialized = true; }

    // Add a TCP segment to staging (replace if same seq and longer)
    void addSegment(uint32_t seq, const uint8_t* data, int len);

    // Drain in-order bytes from staging.
    // If holdLast=true, keep the newest segment pending (for replacement protection).
    std::vector<uint8_t> drain(bool holdLast);
};

// Session tracks a MapleStory connection (bidirectional)
class Session {
public:
    // Process a TCP segment through reassembly → protocol parsing → decrypt
    // Returns decoded packets (may be 0 or more)
    std::vector<DecryptedPacket> processSegment(const TcpSegment& seg, double timestamp);

    bool isInitialized() const { return initialized_; }
    bool isTerminated() const { return terminated_; }
    void terminate() { terminated_ = true; }

    // Pre-initialize sequence numbers from SYN/SYN-ACK
    void initClientSeq(uint32_t seq) { clientReasm_.init(seq); }
    void initServerSeq(uint32_t seq) { serverReasm_.init(seq); }

    // Accessors for handshake info
    uint16_t version() const { return version_; }
    const std::string& subVersionStr() const { return subVersionStr_; }
    uint8_t localeVal() const { return locale_; }

    // The server endpoint (as seen in handshake)
    uint32_t serverIP = 0;
    uint16_t serverPort = 0;
    uint16_t clientPort = 0;

private:
    static constexpr uint16_t LOGIN_PORT = 8484;

    bool initialized_ = false;
    bool terminated_ = false;
    bool isLoginServer_ = false;

    uint16_t version_ = 0;
    std::string subVersionStr_;
    uint8_t locale_ = 0;
    uint8_t sendIV_[4]{};
    uint8_t recvIV_[4]{};

    // TCP reassembly (per direction)
    TcpReasm serverReasm_;  // server → client (inbound)
    TcpReasm clientReasm_;  // client → server (outbound)

    // Pending bytes before handshake is detected
    std::vector<uint8_t> pendingInbound_;   // inbound: for handshake detection
    std::vector<uint8_t> pendingOutbound_;  // outbound: buffered until handshake completes

    // MapleStory protocol streams (created after handshake)
    std::unique_ptr<MapleStream> outboundStream_;
    std::unique_ptr<MapleStream> inboundStream_;

    // Try to detect handshake from accumulated inbound bytes
    // Returns handshake packet if detected, or nullopt
    std::optional<DecryptedPacket> tryDetectHandshake(double timestamp);

    // Feed reassembled bytes to MapleStream and read decoded packets
    std::vector<DecryptedPacket> feedStream(MapleStream* stream, const uint8_t* data, int len, double timestamp);
};

// Stateful protocol analyzer
class Protocol {
public:
    Protocol() = default;

    std::vector<Packet> process(const RawPacket& raw);

    static std::string toHexDump(const uint8_t* data, size_t len, size_t maxBytes = 128);

private:
    static bool parseTcp(const uint8_t* data, int len, TcpSegment& seg);

    std::map<ConnectionKey, std::shared_ptr<Session>> sessions_;
    std::mutex mutex_;
};

} // namespace maple
