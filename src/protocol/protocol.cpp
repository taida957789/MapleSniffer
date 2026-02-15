#include "protocol.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace maple {

// --- Protocol ---

bool Protocol::parseTcp(const uint8_t* data, int len, TcpSegment& seg) {
    if (len < 14) return false;

    uint16_t etherType = static_cast<uint16_t>((data[12] << 8) | data[13]);
    if (etherType != 0x0800) return false;

    const uint8_t* ip = data + 14;
    int ipLen = len - 14;
    if (ipLen < 20) return false;

    if (((ip[0] >> 4) & 0x0F) != 4) return false;
    int ipHeaderLen = (ip[0] & 0x0F) * 4;
    if (ipLen < ipHeaderLen) return false;
    if (ip[9] != 6) return false; // Not TCP

    seg.srcIP = static_cast<uint32_t>(ip[12]) << 24 | static_cast<uint32_t>(ip[13]) << 16 |
                static_cast<uint32_t>(ip[14]) << 8  | static_cast<uint32_t>(ip[15]);
    seg.dstIP = static_cast<uint32_t>(ip[16]) << 24 | static_cast<uint32_t>(ip[17]) << 16 |
                static_cast<uint32_t>(ip[18]) << 8  | static_cast<uint32_t>(ip[19]);

    const uint8_t* tcp = ip + ipHeaderLen;
    int tcpLen = ipLen - ipHeaderLen;
    if (tcpLen < 20) return false;

    seg.srcPort = static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
    seg.dstPort = static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);
    seg.seq = static_cast<uint32_t>(tcp[4]) << 24 | static_cast<uint32_t>(tcp[5]) << 16 |
              static_cast<uint32_t>(tcp[6]) << 8  | static_cast<uint32_t>(tcp[7]);

    int tcpHeaderLen = ((tcp[12] >> 4) & 0x0F) * 4;
    if (tcpLen < tcpHeaderLen) return false;

    uint8_t flags = tcp[13];
    seg.syn = (flags & 0x02) != 0;
    seg.ack = (flags & 0x10) != 0;
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

    std::lock_guard<std::mutex> lock(mutex_);

    ConnectionKey fwdKey = { seg.srcIP, seg.dstIP, seg.srcPort, seg.dstPort };
    ConnectionKey revKey = fwdKey.reverse();

    // Find existing session
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

    // FIN/RST: remove all keys pointing to this session
    if ((seg.fin || seg.rst) && session) {
        for (auto it = sessions_.begin(); it != sessions_.end(); ) {
            if (it->second == session)
                it = sessions_.erase(it);
            else
                ++it;
        }
        return results;
    }

    // SYN handling: initialize seq tracking
    if (seg.syn) {
        if (!seg.ack) {
            // SYN (client → server)
            // Always create a fresh session — handles reconnection on same port pair
            // where the old FIN/RST was missed by pcap
            if (session) {
                for (auto it = sessions_.begin(); it != sessions_.end(); ) {
                    if (it->second == session)
                        it = sessions_.erase(it);
                    else
                        ++it;
                }
            }
            session = std::make_shared<Session>();
            session->sessionId_ = nextSessionId_++;
            session->clientPort = seg.srcPort;
            sessions_[fwdKey] = session;
            session->initClientSeq(seg.seq + 1);
        } else {
            // SYN-ACK (server → client)
            if (session) {
                session->initServerSeq(seg.seq + 1);
            }
        }
        return results;
    }

    // Skip empty segments
    if (seg.payloadLen <= 0) return results;

    // Skip terminated sessions
    if (session && session->isTerminated()) return results;

    // No session yet: create one (will detect handshake from reassembled stream)
    if (!session) {
        session = std::make_shared<Session>();
        session->sessionId_ = nextSessionId_++;
        sessions_[fwdKey] = session;
    }

    // Route segment to session. Session handles:
    // TCP reassembly → handshake detection → MapleStream decryption
    auto pkts = session->processSegment(seg, raw.timestamp);

    // If session just got initialized (handshake detected), store server key too
    if (session->isInitialized() && session->serverIP != 0) {
        ConnectionKey serverKey = { session->serverIP, seg.dstIP, session->serverPort, seg.dstPort };
        if (sessions_.find(serverKey) == sessions_.end()) {
            sessions_[serverKey] = session;
        }
        ConnectionKey clientKey = serverKey.reverse();
        if (sessions_.find(clientKey) == sessions_.end()) {
            sessions_[clientKey] = session;
        }
    }

    for (auto& p : pkts) {
        results.push_back(std::move(p));
    }
    return results;
}

std::string Protocol::toHexDump(const uint8_t* data, size_t len, size_t /*maxBytes*/) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        if (i + 1 < len) oss << ' ';
        if ((i + 1) % 16 == 0 && i + 1 < len) oss << '\n';
    }
    return oss.str();
}

// --- Session ---

std::vector<DecryptedPacket> Session::processSegment(const TcpSegment& seg, double timestamp) {
    std::vector<DecryptedPacket> results;
    if (terminated_ || seg.payloadLen <= 0) return results;

    // Determine direction
    bool isFromServer = false;
    if (initialized_) {
        isFromServer = (seg.srcIP == serverIP && seg.srcPort == serverPort);
    } else {
        isFromServer = true; // First data should be server handshake
        if (clientPort != 0 && seg.srcPort == clientPort) {
            isFromServer = false;
        }
    }

    // === Before handshake: raw segment payloads, NO reassembly ===
    // The handshake is small (fits in one segment). Using TcpReasm here
    // causes issues with probe/replacement segments and holdLast delays.
    if (!initialized_) {
        if (isFromServer) {
            if (serverIP == 0) {
                serverIP = seg.srcIP;
                serverPort = seg.srcPort;
            }
            pendingInbound_.insert(pendingInbound_.end(),
                seg.payload, seg.payload + seg.payloadLen);
            lastServerSeqEnd_ = seg.seq + static_cast<uint32_t>(seg.payloadLen);

            auto hsPkt = tryDetectHandshake(timestamp);
            if (hsPkt.has_value()) {
                results.push_back(std::move(*hsPkt));

                // Initialize TcpReasm for post-handshake traffic
                serverReasm_.init(lastServerSeqEnd_);
                if (lastClientSeqEnd_ != 0) {
                    clientReasm_.init(lastClientSeqEnd_);
                }

                // Feed remaining inbound bytes after handshake
                if (!pendingInbound_.empty() && inboundStream_) {
                    auto inPkts = feedStream(inboundStream_.get(),
                        pendingInbound_.data(), static_cast<int>(pendingInbound_.size()), timestamp);
                    for (auto& p : inPkts) results.push_back(std::move(p));
                    pendingInbound_.clear();
                }

                // Feed buffered outbound data
                if (!pendingOutbound_.empty() && outboundStream_) {
                    auto outPkts = feedStream(outboundStream_.get(),
                        pendingOutbound_.data(), static_cast<int>(pendingOutbound_.size()), timestamp);
                    for (auto& p : outPkts) results.push_back(std::move(p));
                    pendingOutbound_.clear();
                }
            }
        } else {
            pendingOutbound_.insert(pendingOutbound_.end(),
                seg.payload, seg.payload + seg.payloadLen);
            lastClientSeqEnd_ = seg.seq + static_cast<uint32_t>(seg.payloadLen);
        }
        return results;
    }

    // === After handshake: TcpReasm-based flow ===
    TcpReasm& reasm = isFromServer ? serverReasm_ : clientReasm_;
    reasm.addSegment(seg.seq, seg.payload, seg.payloadLen);

    // holdLast=true for inbound (probe/replacement protection)
    auto bytes = reasm.drain(isFromServer);
    if (bytes.empty()) return results;

    MapleStream* stream = isFromServer ? inboundStream_.get() : outboundStream_.get();
    if (!stream) return results;

    return feedStream(stream, bytes.data(), static_cast<int>(bytes.size()), timestamp);
}

std::optional<DecryptedPacket> Session::tryDetectHandshake(double timestamp) {
    if (pendingInbound_.size() < 4) return std::nullopt;

    const uint8_t* p = pendingInbound_.data();
    int totalLen = static_cast<int>(pendingInbound_.size());

    uint16_t size = static_cast<uint16_t>(p[0] | (p[1] << 8));
    int hsTotal = 2 + static_cast<int>(size);

    // Wait until we have enough bytes
    if (totalLen < hsTotal) return std::nullopt;

    int pos = 2;
    uint16_t version = 0;
    std::string patchLocation;
    uint8_t localIV[4]{};
    uint8_t remoteIV[4]{};
    uint8_t serverLocale = 0;

    if (size > 0x10) {
        // Standard handshake
        int minRequired = 2 + 2 + 0 + 4 + 4 + 1;
        if (totalLen < pos + minRequired) return std::nullopt;

        version = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8)); pos += 2;

        uint16_t strLen = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8)); pos += 2;
        if (strLen > 100 || totalLen < pos + strLen + 4 + 4 + 1) return std::nullopt;

        patchLocation.assign(reinterpret_cast<const char*>(p + pos), strLen); pos += strLen;
        std::memcpy(localIV, p + pos, 4); pos += 4;
        std::memcpy(remoteIV, p + pos, 4); pos += 4;
        serverLocale = p[pos]; pos += 1;
    } else {
        // Old/short handshake
        int minRequired = 2 + 2 + 2 + 4 + 4 + 1 + 1;
        if (totalLen < pos + minRequired) return std::nullopt;

        version = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8)); pos += 2;
        pos += 2; // skip
        uint16_t patchVal = static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8)); pos += 2;
        patchLocation = std::to_string(patchVal + 1);
        std::memcpy(localIV, p + pos, 4); pos += 4;
        std::memcpy(remoteIV, p + pos, 4); pos += 4;
        serverLocale = p[pos]; pos += 1;
    }

    if (serverLocale > 0x12 || serverLocale == 0) return std::nullopt;

    // Handshake parsed successfully
    version_ = version;
    locale_ = serverLocale;

    uint8_t subVersion = 1;
    bool allDigits = !patchLocation.empty();
    for (char c : patchLocation) {
        if (c < '0' || c > '9') { allDigits = false; break; }
    }
    if (allDigits) {
        try { subVersion = static_cast<uint8_t>(std::stoi(patchLocation)); } catch (...) {}
    }
    subVersionStr_ = patchLocation;

    bool extraCipher = false;
    if (serverLocale == 6) {
        extraCipher = (patchLocation.find(':') == std::string::npos);
    }

    isLoginServer_ = (serverPort == LOGIN_PORT);
    std::memcpy(sendIV_, localIV, 4);
    std::memcpy(recvIV_, remoteIV, 4);

    outboundStream_ = std::make_unique<MapleStream>(true, version_, locale_, sendIV_, subVersion, extraCipher);
    inboundStream_ = std::make_unique<MapleStream>(false, version_, locale_, recvIV_, subVersion, extraCipher);
    initialized_ = true;

    // Build handshake display packet
    DecryptedPacket hsPkt;
    hsPkt.timestamp = timestamp;
    hsPkt.outbound = false;
    hsPkt.opcode = 0xFFFF;
    hsPkt.isHandshake = true;
    hsPkt.length = static_cast<uint32_t>(hsTotal);
    hsPkt.hexDump = Protocol::toHexDump(p, hsTotal);
    hsPkt.version = version_;
    hsPkt.subVersionStr = subVersionStr_;
    hsPkt.locale = locale_;
    hsPkt.sessionId = sessionId_;
    hsPkt.serverPort = serverPort;

    // Remove handshake bytes from pending buffer, keep remainder
    pendingInbound_.erase(pendingInbound_.begin(), pendingInbound_.begin() + hsTotal);

    return hsPkt;
}

std::vector<DecryptedPacket> Session::feedStream(MapleStream* stream, const uint8_t* data, int len, double timestamp) {
    std::vector<DecryptedPacket> results;
    if (!stream || len <= 0) return results;

    stream->append(data, len);

    while (true) {
        auto pkt = stream->tryRead(timestamp);
        if (!pkt.has_value()) break;

        // Propagate opcode encryption from inbound to outbound
        if (!pkt->outbound && pkt->opcode == 0x46) {
            if (outboundStream_ && pkt->payload.size() >= 4) {
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

        pkt->sessionId = sessionId_;
        pkt->serverPort = serverPort;
        results.push_back(std::move(*pkt));
    }

    // Emit dead notification if stream just desynchronized
    if (stream->isDead() && !deadNotified_) {
        deadNotified_ = true;
        DecryptedPacket deadPkt;
        deadPkt.timestamp = timestamp;
        deadPkt.outbound = stream == outboundStream_.get();
        deadPkt.opcode = 0;
        deadPkt.length = 0;
        deadPkt.isDeadNotification = true;
        deadPkt.sessionId = sessionId_;
        deadPkt.serverPort = serverPort;
        results.push_back(std::move(deadPkt));
    }

    return results;
}

} // namespace maple
