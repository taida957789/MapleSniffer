#include "maple_stream.h"
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>

namespace maple {

MapleStream::MapleStream(bool outbound, uint16_t build, uint8_t locale,
                         const uint8_t iv[4], uint8_t subVersion, bool extraCipher)
    : outbound_(outbound)
{
    // TWMS: outbound uses version directly, inbound uses 0xFFFF - version
    uint16_t aesVersion = outbound ? build : static_cast<uint16_t>(0xFFFF - build);
    aes_ = std::make_unique<MapleAES>(aesVersion, locale, iv, subVersion);

    // ExtraCipher = true for game server (non-8484 port)
    // Inbound on game server uses NEW_DATA_SHIFT instead of AES
    if (extraCipher && !outbound) {
        useNewDataShift_ = true;
    }

    buffer_.resize(4096);
    cursor_ = 0;
    expectedDataSize_ = 4;
}

void MapleStream::append(const uint8_t* data, int len) {
    if (len <= 0) return;

    // Grow buffer if needed
    while (static_cast<int>(buffer_.size()) - cursor_ < len) {
        buffer_.resize(buffer_.size() * 2);
    }
    std::memcpy(buffer_.data() + cursor_, data, len);
    cursor_ += len;
}

static std::string toHexDump(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        if (i + 1 < len) oss << ' ';
        if ((i + 1) % 16 == 0 && i + 1 < len) oss << '\n';
    }
    return oss.str();
}

std::optional<DecryptedPacket> MapleStream::tryRead(double timestamp) {
    if (cursor_ < expectedDataSize_) return std::nullopt;

    // Validate header
    if (!aes_->confirmHeader(buffer_.data())) {
        return std::nullopt;
    }

    // Get header length
    int headerLength = MapleAES::getHeaderLength(buffer_.data());
    expectedDataSize_ = headerLength;
    if (cursor_ < headerLength) return std::nullopt;

    // Get packet payload length
    int packetSize = MapleAES::getPacketLength(buffer_.data(), cursor_);
    expectedDataSize_ = packetSize + headerLength;
    if (cursor_ < expectedDataSize_) return std::nullopt;

    // Extract payload (skip header)
    std::vector<uint8_t> packetBuffer(packetSize);
    std::memcpy(packetBuffer.data(), buffer_.data() + headerLength, packetSize);

    // Decrypt based on transform method
    if (useNewDataShift_) {
        // NEW_DATA_SHIFT: subtract IV[0] from every byte, then shift IV
        uint8_t iv0 = aes_->getIV()[0];
        for (int i = 0; i < packetSize; i++) {
            packetBuffer[i] -= iv0;
        }
        aes_->shiftIV();
    } else {
        // AES + SHIFT_IV
        aes_->transformAES(packetBuffer.data(), packetSize);
        aes_->shiftIV();
    }

    // Remove processed data from buffer
    cursor_ -= expectedDataSize_;
    if (cursor_ > 0) {
        std::memmove(buffer_.data(), buffer_.data() + expectedDataSize_, cursor_);
    }

    // Extract opcode (first 2 bytes, little-endian)
    uint16_t opcode = 0;
    if (packetSize >= 2) {
        opcode = static_cast<uint16_t>(packetBuffer[0] | (packetBuffer[1] << 8));
    }

    // Build result
    DecryptedPacket pkt;
    pkt.timestamp = timestamp;
    pkt.outbound = outbound_;
    pkt.opcode = opcode;
    // Payload is everything after opcode
    if (packetSize > 2) {
        pkt.payload.assign(packetBuffer.begin() + 2, packetBuffer.end());
    }
    pkt.length = static_cast<uint32_t>(pkt.payload.size());

    // Check for opcode encryption packet (inbound opcode 0x46)
    if (!outbound_ && opcode == 0x46 && pkt.payload.size() >= 4) {
        int32_t bufferSize = static_cast<int32_t>(
            pkt.payload[0] | (pkt.payload[1] << 8) |
            (pkt.payload[2] << 16) | (pkt.payload[3] << 24)
        );
        if (bufferSize > 0 && static_cast<int>(pkt.payload.size()) >= 4 + bufferSize) {
            encryptedOpcodes_ = parseOpcodeEncryption(
                pkt.payload.data() + 4, static_cast<int>(pkt.payload.size()) - 4, bufferSize);
            opcodeEncrypted_ = true;
        }
        std::cout << "Encrypted opcodes: " << encryptedOpcodes_.size() << std::endl;
    }

    // Replace encrypted opcode with real opcode for outbound packets
    if (opcodeEncrypted_ && outbound_) {
        auto it = encryptedOpcodes_.find(static_cast<int>(opcode));
        if (it != encryptedOpcodes_.end()) {
            pkt.opcode = it->second;
        }
    }

    // Generate hex dump of payload (after opcode)
    pkt.hexDump = toHexDump(pkt.payload.data(), pkt.payload.size());

    // Reset expected size for next packet
    expectedDataSize_ = 4;

    return pkt;
}

std::unordered_map<int, uint16_t> MapleStream::parseOpcodeEncryption(
    const uint8_t* data, int dataLen, int bufferSize)
{
    std::unordered_map<int, uint16_t> result;

    // 3DES-ECB decrypt
    // Key: "BrN=r54jQp2@yP6G" (16 bytes) -> expand to 24 bytes (first 16 + first 8)
    const char* keyStr = "BrN=r54jQp2@yP6G";
    uint8_t desKey[24];
    std::memcpy(desKey, keyStr, 16);
    std::memcpy(desKey + 16, keyStr, 8);

    int decryptLen = std::min(bufferSize, dataLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return result;

    // Use 3DES-ECB decryption
    if (EVP_DecryptInit_ex(ctx, EVP_des_ede3_ecb(), nullptr, desKey, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0); // No padding

    std::vector<uint8_t> decrypted(decryptLen + 24); // extra space
    int outLen = 0, finalLen = 0;
    EVP_DecryptUpdate(ctx, decrypted.data(), &outLen, data, decryptLen);
    EVP_DecryptFinal_ex(ctx, decrypted.data() + outLen, &finalLen);
    int totalLen = outLen + finalLen;
    EVP_CIPHER_CTX_free(ctx);

    // Parse UTF-8 string: "encOp1|encOp2|encOp3|..."
    std::string opcodeStr(reinterpret_cast<const char*>(decrypted.data()), totalLen);

    // Split by '|'
    std::istringstream iss(opcodeStr);
    std::string token;
    int index = 0;

    while (std::getline(iss, token, '|')) {
        if (token.empty()) break;
        try {
            int encryptedOp = std::stoi(token);
            uint16_t realOp = static_cast<uint16_t>(index + DYNAMIC_OPCODE_BASE);

            if (result.count(encryptedOp)) {
                break;
            }
            result[encryptedOp] = realOp;
            index++;
        } catch (...) {
            break;
        }
    }

    return result;
}

} // namespace maple
