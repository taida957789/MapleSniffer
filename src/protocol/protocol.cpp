#include "protocol.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

namespace maple {

// --- TcpReasm ---

void TcpReasm::addSegment(uint32_t seq, const uint8_t* data, int len) {
    if (len <= 0) return;
    if (!initialized) { initialized = true; nextSeq = seq; }

    // Insert or replace (keep the longer segment at the same seq)
    auto it = staged.find(seq);
    if (it == staged.end() || static_cast<int>(it->second.size()) < len) {
        staged[seq].assign(data, data + len);
    }
}

std::vector<uint8_t> TcpReasm::drain(bool holdLast) {
    std::vector<uint8_t> result;
    size_t minSize = holdLast ? 1u : 0u;

    while (staged.size() > minSize) {
        auto it = staged.begin();
        uint32_t segSeq = it->first;

        // Gap: segment starts after nextSeq
        if (static_cast<int32_t>(segSeq - nextSeq) > 0) break;

        uint32_t segEnd = segSeq + static_cast<uint32_t>(it->second.size());

        // Fully before nextSeq: already delivered, discard
        if (static_cast<int32_t>(segEnd - nextSeq) <= 0) {
            staged.erase(it);
            continue;
        }

        // Deliver new bytes (skip any overlap at the beginning)
        uint32_t offset = nextSeq - segSeq;  // 0 if in-order, >0 if partial overlap
        result.insert(result.end(), it->second.begin() + offset, it->second.end());
        nextSeq = segEnd;
        staged.erase(it);
    }

    return result;
}

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

    // FIN/RST: terminate or remove session
    if (seg.fin && session) {
        session->terminate();
        return results;
    }
    if (seg.rst && session) {
        sessions_.erase(fwdKey);
        sessions_.erase(revKey);
        return results;
    }

    // SYN handling: initialize seq tracking
    if (seg.syn) {
        if (!seg.ack) {
            // SYN (client → server)
            if (!session) {
                session = std::make_shared<Session>();
                session->clientPort = seg.srcPort;
                sessions_[fwdKey] = session;
            }
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
    if (terminated_) return results;
    if (seg.payloadLen <= 0) return results;

    // Step 1: Determine direction and add to TCP reassembly
    bool isFromServer = false;
    if (initialized_) {
        isFromServer = (seg.srcIP == serverIP && seg.srcPort == serverPort);
    } else {
        // Before handshake: assume server is the first sender we see
        // (or use port heuristic: server port is in the game port range)
        // For now, try both directions; handshake detection will determine
        isFromServer = true; // First data should be server handshake
        if (clientPort != 0 && seg.srcPort == clientPort) {
            isFromServer = false;
        }
    }

    TcpReasm& reasm = isFromServer ? serverReasm_ : clientReasm_;
    reasm.addSegment(seg.seq, seg.payload, seg.payloadLen);

    // Step 2: Drain reassembled bytes
    // Inbound (server): holdLast=true to handle segment replacement (zero-byte prefix)
    // Outbound (client): holdLast=false for immediate delivery
    auto bytes = reasm.drain(isFromServer);

    if (bytes.empty()) return results;

    // Step 3: Protocol parsing
    if (!initialized_ && isFromServer) {
        // Record server endpoint for session matching
        if (serverIP == 0) {
            serverIP = seg.srcIP;
            serverPort = seg.srcPort;
        }

        // Accumulate inbound bytes for handshake detection
        pendingInbound_.insert(pendingInbound_.end(), bytes.begin(), bytes.end());

        auto hsPkt = tryDetectHandshake(timestamp);
        if (hsPkt.has_value()) {
            results.push_back(std::move(*hsPkt));

            // Feed any remaining bytes after handshake to inbound stream
            if (!pendingInbound_.empty() && inboundStream_) {
                auto inPkts = feedStream(inboundStream_.get(),
                    pendingInbound_.data(), static_cast<int>(pendingInbound_.size()), timestamp);
                for (auto& p : inPkts) results.push_back(std::move(p));
                pendingInbound_.clear();
            }

            // Replay buffered outbound data now that we have the encryption keys
            if (!pendingOutbound_.empty() && outboundStream_) {
                auto outPkts = feedStream(outboundStream_.get(),
                    pendingOutbound_.data(), static_cast<int>(pendingOutbound_.size()), timestamp);
                for (auto& p : outPkts) results.push_back(std::move(p));
                pendingOutbound_.clear();
            }
        }
        return results;
    }

    if (!initialized_ && !isFromServer) {
        // Buffer outbound data until handshake is detected
        // (outbound may arrive before inbound handshake due to holdLast delay)
        pendingOutbound_.insert(pendingOutbound_.end(), bytes.begin(), bytes.end());
        return results;
    }

    // Step 4: Feed to MapleStream for decryption
    MapleStream* stream = isFromServer ? inboundStream_.get() : outboundStream_.get();
    if (!stream) return results;

    auto pkts = feedStream(stream, bytes.data(), static_cast<int>(bytes.size()), timestamp);
    for (auto& p : pkts) results.push_back(std::move(p));

    return results;
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

        results.push_back(std::move(*pkt));
    }

    return results;
}

} // namespace maple
