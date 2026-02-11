#pragma once

#include "maple_aes.h"
#include <cstdint>
#include <vector>
#include <optional>
#include <memory>
#include <unordered_map>
#include <string>

namespace maple {

struct DecryptedPacket {
    double timestamp;
    bool outbound;
    uint16_t opcode;
    std::vector<uint8_t> payload;  // after opcode
    std::string hexDump;
    uint32_t length;               // total decrypted size (opcode + payload)
    bool isHandshake = false;

    // Session tracking
    uint32_t sessionId = 0;
    uint16_t serverPort = 0;

    // Handshake fields
    uint16_t version = 0;
    std::string subVersionStr;
    uint8_t locale = 0;
};

class MapleStream {
public:
    MapleStream(bool outbound, uint16_t build, uint8_t locale,
                const uint8_t iv[4], uint8_t subVersion, bool extraCipher);

    // Append TCP payload data to internal buffer
    void append(const uint8_t* data, int len);

    // Try to read one complete decrypted packet
    std::optional<DecryptedPacket> tryRead(double timestamp);

    // Opcode encryption support
    void setOpcodeEncrypted(bool v) { opcodeEncrypted_ = v; }
    void setEncryptedOpcodes(const std::unordered_map<int, uint16_t>& map) { encryptedOpcodes_ = map; }

    // Parse opcode encryption packet (inbound opcode 0x46)
    // Returns mapping: encrypted_opcode -> real_opcode
    // key: 16-byte 3DES key string (empty = use default)
    static std::unordered_map<int, uint16_t> parseOpcodeEncryption(
        const uint8_t* data, int dataLen, int bufferSize,
        const std::string& key = "");

private:
    bool outbound_;
    bool useNewDataShift_ = false;  // inbound on game server (non-8484)
    std::unique_ptr<MapleAES> aes_;
    std::vector<uint8_t> buffer_;
    int cursor_ = 0;
    int expectedDataSize_ = 4;

    bool opcodeEncrypted_ = false;
    std::unordered_map<int, uint16_t> encryptedOpcodes_;

    static constexpr uint16_t DYNAMIC_OPCODE_BASE = 0xCC;
};

} // namespace maple
