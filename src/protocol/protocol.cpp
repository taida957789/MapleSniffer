#include "protocol.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace maple {

// --- Protocol ---

bool Protocol::parseTcp(const uint8_t* data, int len, TcpSegment& seg) {
    // Ethernet header: 14 bytes
    if (len < 14) return false;

    uint16_t etherType = static_cast<uint16_t>((data[12] << 8) | data[13]);
    if (etherType != 0x0800) return false; // Not IPv4

    const uint8_t* ip = data + 14;
    int ipLen = len - 14;

    if (ipLen < 20) return false;

    uint8_t ipVersion = (ip[0] >> 4) & 0x0F;
    if (ipVersion != 4) return false;

    int ipHeaderLen = (ip[0] & 0x0F) * 4;
    if (ipLen < ipHeaderLen) return false;

    uint8_t protocol = ip[9];
    if (protocol != 6) return false; // Not TCP

    seg.srcIP = static_cast<uint32_t>(ip[12]) << 24 |
                static_cast<uint32_t>(ip[13]) << 16 |
                static_cast<uint32_t>(ip[14]) << 8 |
                static_cast<uint32_t>(ip[15]);
    seg.dstIP = static_cast<uint32_t>(ip[16]) << 24 |
                static_cast<uint32_t>(ip[17]) << 16 |
                static_cast<uint32_t>(ip[18]) << 8 |
                static_cast<uint32_t>(ip[19]);

    const uint8_t* tcp = ip + ipHeaderLen;
    int tcpLen = ipLen - ipHeaderLen;
    if (tcpLen < 20) return false;

    seg.srcPort = static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
    seg.dstPort = static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);

    int tcpHeaderLen = ((tcp[12] >> 4) & 0x0F) * 4;
    if (tcpLen < tcpHeaderLen) return false;

    uint8_t flags = tcp[13];
    seg.syn = (flags & 0x02) != 0;
    seg.fin = (flags & 0x01) != 0;
    seg.rst = (flags & 0x04) != 0;

    seg.payload = tcp + tcpHeaderLen;
    seg.payloadLen = tcpLen - tcpHeaderLen;

    return true;
}

std::vector<Packet> Protocol::process(const RawPacket& raw) {
    std::vector<Packet> results;

    TcpSegment seg;
    if (!parseTcp(raw.data.data(), static_cast<int>(raw.data.size()), seg)) {
        return results;
    }

    // Skip empty segments (ACK only, etc.)
    if (seg.payloadLen <= 0) return results;

    std::lock_guard<std::mutex> lock(mutex_);

    // Build connection key (canonical: lower IP/port first to map both directions)
    ConnectionKey fwdKey = { seg.srcIP, seg.dstIP, seg.srcPort, seg.dstPort };
    ConnectionKey revKey = fwdKey.reverse();

    // Find existing session (check both directions)
    std::shared_ptr<Session> session;
    auto it = sessions_.find(fwdKey);
    if (it != sessions_.end()) {
        session = it->second;
    } else {
        auto it2 = sessions_.find(revKey);
        if (it2 != sessions_.end()) {
            session = it2->second;
        }
    }

    // SYN or RST: start fresh session
    if (seg.syn || seg.rst) {
        if (seg.rst && session) {
            sessions_.erase(fwdKey);
            sessions_.erase(revKey);
        }
        if (seg.syn && !session) {
            // SYN packet — just note it, handshake comes from server later
        }
        return results;
    }

    // No existing session: try to detect handshake
    if (!session) {
        session = std::make_shared<Session>();
        if (session->tryHandshake(seg, raw.timestamp)) {
            // Store session keyed by server->client direction
            // The server sent the handshake, so srcIP is server
            ConnectionKey serverKey = { seg.srcIP, seg.dstIP, seg.srcPort, seg.dstPort };
            sessions_[serverKey] = session;

            // Build a handshake packet for display (ref: opcode 0xFFFF)
            Packet hsPkt;
            hsPkt.timestamp = raw.timestamp;
            hsPkt.outbound = false; // server -> client
            hsPkt.opcode = 0xFFFF;
            hsPkt.isHandshake = true;
            hsPkt.length = static_cast<uint32_t>(seg.payloadLen);
            hsPkt.hexDump = toHexDump(seg.payload, seg.payloadLen);

            // Read parsed fields from session
            hsPkt.version = session->version();
            hsPkt.subVersionStr = session->subVersionStr();
            hsPkt.locale = session->localeVal();

            results.push_back(std::move(hsPkt));
            return results;
        }
        // Not a handshake, ignore
        return results;
    }

    // Feed data to existing session
    auto pkts = session->feedData(seg, raw.timestamp);
    for (auto& p : pkts) {
        results.push_back(std::move(p));
    }

    return results;
}

std::string Protocol::toHexDump(const uint8_t* data, size_t len, size_t maxBytes) {
    std::ostringstream oss;
    size_t printLen = std::min(len, maxBytes);
    for (size_t i = 0; i < printLen; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        if (i + 1 < printLen) oss << ' ';
        if ((i + 1) % 16 == 0 && i + 1 < printLen) oss << '\n';
    }
    if (printLen < len) {
        oss << "\n... (" << (len - printLen) << " more bytes)";
    }
    return oss.str();
}

// --- Session ---

bool Session::tryHandshake(const TcpSegment& seg, double timestamp) {
    // MapleStory handshake (server -> client, cleartext):
    // Ref: SessionForm.cs L140-L268
    // First 2 bytes = size field
    if (seg.payloadLen < 4) return false;

    const uint8_t* p = seg.payload;
    int pos = 0;

    uint16_t size = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8));
    pos += 2;

    uint16_t version = 0;
    std::string patchLocation;
    uint8_t localIV[4]{};
    uint8_t remoteIV[4]{};
    uint8_t serverLocale = 0;

    if (size > 0x10) {
        // Standard handshake format:
        // [2B version][MapleString: 2B len + data][4B localIV][4B remoteIV][1B locale]
        int minRequired = 2 + 2 + 0 + 4 + 4 + 1; // version + strLen + IV + IV + locale
        if (seg.payloadLen < pos + minRequired) return false;

        version = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8));
        pos += 2;

        // MapleString: [2B length][NB data]
        uint16_t strLen = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8));
        pos += 2;
        if (strLen > 100 || seg.payloadLen < pos + strLen + 4 + 4 + 1) return false;

        patchLocation.assign(reinterpret_cast<const char*>(p + pos), strLen);
        pos += strLen;

        std::memcpy(localIV, p + pos, 4); pos += 4;
        std::memcpy(remoteIV, p + pos, 4); pos += 4;
        serverLocale = p[pos]; pos += 1;
    } else {
        // Old/short handshake format:
        // [2B version][skip 2B][(ReadUShort+1).ToString()][4B localIV][4B remoteIV][1B locale][skip 1B]
        int minRequired = 2 + 2 + 2 + 4 + 4 + 1 + 1;
        if (seg.payloadLen < pos + minRequired) return false;

        version = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8));
        pos += 2;
        pos += 2; // skip 2 bytes

        uint16_t patchVal = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8));
        pos += 2;
        patchLocation = std::to_string(patchVal + 1);

        std::memcpy(localIV, p + pos, 4); pos += 4;
        std::memcpy(remoteIV, p + pos, 4); pos += 4;
        serverLocale = p[pos]; pos += 1;
        // skip 1 more byte (old format)
    }

    // Validate locale (ref: serverLocale > 0x12 → reject)
    if (serverLocale > 0x12 || serverLocale == 0) return false;

    version_ = version;
    locale_ = serverLocale;

    // Parse subVersion from patchLocation if all digits
    uint8_t subVersion = 1;
    bool allDigits = !patchLocation.empty();
    for (char c : patchLocation) {
        if (c < '0' || c > '9') { allDigits = false; break; }
    }
    if (allDigits) {
        try { subVersion = static_cast<uint8_t>(std::stoi(patchLocation)); } catch (...) {}
    }
    subVersionStr_ = patchLocation;

    // Determine ExtraCipher (ref: SessionForm.cs L195-L198)
    // For TWMS (locale 6): extraCipher = !patchLocation.Contains(":")
    // patchLocation with ":" → login server, no extra cipher
    // patchLocation without ":" (plain number) → game server, extra cipher
    bool extraCipher = false;
    if (serverLocale == 6) { // TAIWAN
        extraCipher = (patchLocation.find(':') == std::string::npos);
    }

    // isLoginSv based on port (ref: SessionForm.cs L205-L215)
    serverIP = seg.srcIP;
    serverPort = seg.srcPort;
    isLoginServer_ = (serverPort == LOGIN_PORT);

    // IVs: localIV → outbound (client→server), remoteIV → inbound (server→client)
    std::memcpy(sendIV_, localIV, 4);
    std::memcpy(recvIV_, remoteIV, 4);

    // Initialize streams
    outboundStream_ = std::make_unique<MapleStream>(true, version_, locale_, sendIV_, subVersion, extraCipher);
    inboundStream_ = std::make_unique<MapleStream>(false, version_, locale_, recvIV_, subVersion, extraCipher);

    initialized_ = true;
    handshakePending_ = false;

    std::cout << "[Session] Handshake: ver=" << version_
              << " patch=" << patchLocation
              << " locale=" << static_cast<int>(locale_)
              << " port=" << serverPort
              << (isLoginServer_ ? " (login)" : " (game)")
              << (extraCipher ? " ExtraCipher" : "")
              << " localIV=" << std::hex
              << static_cast<int>(sendIV_[0]) << static_cast<int>(sendIV_[1])
              << static_cast<int>(sendIV_[2]) << static_cast<int>(sendIV_[3])
              << " remoteIV="
              << static_cast<int>(recvIV_[0]) << static_cast<int>(recvIV_[1])
              << static_cast<int>(recvIV_[2]) << static_cast<int>(recvIV_[3])
              << std::dec << std::endl;

    return true;
}

std::vector<DecryptedPacket> Session::feedData(const TcpSegment& seg, double timestamp) {
    std::vector<DecryptedPacket> results;
    if (!initialized_) return results;

    // Determine direction
    bool isFromServer = (seg.srcIP == serverIP && seg.srcPort == serverPort);
    MapleStream* stream = isFromServer ? inboundStream_.get() : outboundStream_.get();

    if (!stream) return results;

    // Append TCP payload
    stream->append(seg.payload, seg.payloadLen);

    // Try to read all available packets
    while (true) {
        auto pkt = stream->tryRead(timestamp);
        if (!pkt.has_value()) break;

        // Propagate opcode encryption from inbound to outbound
        if (isFromServer && !pkt->outbound && pkt->opcode == 0x46) {
            // The inbound stream parsed the opcode encryption
            // Share it with the outbound stream
            if (outboundStream_) {
                outboundStream_->setOpcodeEncrypted(true);
                // We need to re-parse from inbound's state... but actually
                // MapleStream already internally handles this for itself.
                // For outbound we need to forward the mapping.
                // The inbound stream detected it, but we need to get the map
                // and set it on outbound. Since MapleStream stores it internally
                // and applies it only if outbound_, we need the inbound stream
                // to share its mapping.
                // Let's get the encrypted opcodes from the payload directly.
                if (pkt->payload.size() >= 4) {
                    int32_t bufferSize = static_cast<int32_t>(
                        pkt->payload[0] | (pkt->payload[1] << 8) |
                        (pkt->payload[2] << 16) | (pkt->payload[3] << 24)
                    );
                    if (bufferSize > 0 && static_cast<int>(pkt->payload.size()) >= 4 + bufferSize) {
                        auto mapping = MapleStream::parseOpcodeEncryption(
                            pkt->payload.data() + 4,
                            static_cast<int>(pkt->payload.size()) - 4,
                            bufferSize);
                        outboundStream_->setOpcodeEncrypted(true);
                        outboundStream_->setEncryptedOpcodes(mapping);
                    }
                }
            }
        }

        results.push_back(std::move(*pkt));
    }

    return results;
}

} // namespace maple
