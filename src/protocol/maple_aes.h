#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <openssl/evp.h>

namespace maple {

class MapleAES {
public:
    MapleAES(uint16_t version, uint8_t locale, const uint8_t iv[4], uint8_t subVersion);
    ~MapleAES();

    MapleAES(const MapleAES&) = delete;
    MapleAES& operator=(const MapleAES&) = delete;

    // Validate encrypted packet header against current IV
    bool confirmHeader(const uint8_t* buf) const;

    // Get header length (4 or 8 bytes)
    static int getHeaderLength(const uint8_t* buf, bool oldHeader = false);

    // Get payload length from encrypted header
    static int getPacketLength(const uint8_t* buf, int bytesAvailable, bool oldHeader = false);

    // AES-ECB based XOR decryption
    void transformAES(uint8_t* data, int dataSize);

    // Shift IV using Morph function
    void shiftIV();

    // Get current IV (4 bytes)
    const uint8_t* getIV() const { return iv_; }

private:
    static void morph(uint8_t value, uint8_t* iv);

    // Generate TWMS key from version
    static std::array<uint8_t, 32> generateTWKey(uint16_t version);

    uint16_t version_;
    uint8_t iv_[4];
    EVP_CIPHER_CTX* ctx_;
    std::array<uint8_t, 32> aesKey_;

    static const uint8_t shuffleKey_[256];
    static const uint8_t defaultSecretKey_[32];
    static const char* const secretKeys_[20];
};

} // namespace maple
