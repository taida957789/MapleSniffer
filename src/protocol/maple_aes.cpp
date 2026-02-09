#include "maple_aes.h"
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <openssl/evp.h>

namespace maple {

// --- Static data ---

const uint8_t MapleAES::shuffleKey_[256] = {
    0xEC, 0x3F, 0x77, 0xA4, 0x45, 0xD0, 0x71, 0xBF, 0xB7, 0x98, 0x20, 0xFC, 0x4B, 0xE9, 0xB3, 0xE1,
    0x5C, 0x22, 0xF7, 0x0C, 0x44, 0x1B, 0x81, 0xBD, 0x63, 0x8D, 0xD4, 0xC3, 0xF2, 0x10, 0x19, 0xE0,
    0xFB, 0xA1, 0x6E, 0x66, 0xEA, 0xAE, 0xD6, 0xCE, 0x06, 0x18, 0x4E, 0xEB, 0x78, 0x95, 0xDB, 0xBA,
    0xB6, 0x42, 0x7A, 0x2A, 0x83, 0x0B, 0x54, 0x67, 0x6D, 0xE8, 0x65, 0xE7, 0x2F, 0x07, 0xF3, 0xAA,
    0x27, 0x7B, 0x85, 0xB0, 0x26, 0xFD, 0x8B, 0xA9, 0xFA, 0xBE, 0xA8, 0xD7, 0xCB, 0xCC, 0x92, 0xDA,
    0xF9, 0x93, 0x60, 0x2D, 0xDD, 0xD2, 0xA2, 0x9B, 0x39, 0x5F, 0x82, 0x21, 0x4C, 0x69, 0xF8, 0x31,
    0x87, 0xEE, 0x8E, 0xAD, 0x8C, 0x6A, 0xBC, 0xB5, 0x6B, 0x59, 0x13, 0xF1, 0x04, 0x00, 0xF6, 0x5A,
    0x35, 0x79, 0x48, 0x8F, 0x15, 0xCD, 0x97, 0x57, 0x12, 0x3E, 0x37, 0xFF, 0x9D, 0x4F, 0x51, 0xF5,
    0xA3, 0x70, 0xBB, 0x14, 0x75, 0xC2, 0xB8, 0x72, 0xC0, 0xED, 0x7D, 0x68, 0xC9, 0x2E, 0x0D, 0x62,
    0x46, 0x17, 0x11, 0x4D, 0x6C, 0xC4, 0x7E, 0x53, 0xC1, 0x25, 0xC7, 0x9A, 0x1C, 0x88, 0x58, 0x2C,
    0x89, 0xDC, 0x02, 0x64, 0x40, 0x01, 0x5D, 0x38, 0xA5, 0xE2, 0xAF, 0x55, 0xD5, 0xEF, 0x1A, 0x7C,
    0xA7, 0x5B, 0xA6, 0x6F, 0x86, 0x9F, 0x73, 0xE6, 0x0A, 0xDE, 0x2B, 0x99, 0x4A, 0x47, 0x9C, 0xDF,
    0x09, 0x76, 0x9E, 0x30, 0x0E, 0xE4, 0xB2, 0x94, 0xA0, 0x3B, 0x34, 0x1D, 0x28, 0x0F, 0x36, 0xE3,
    0x23, 0xB4, 0x03, 0xD8, 0x90, 0xC8, 0x3C, 0xFE, 0x5E, 0x32, 0x24, 0x50, 0x1F, 0x3A, 0x43, 0x8A,
    0x96, 0x41, 0x74, 0xAC, 0x52, 0x33, 0xF0, 0xD9, 0x29, 0x80, 0xB1, 0x16, 0xD3, 0xAB, 0x91, 0xB9,
    0x84, 0x7F, 0x61, 0x1E, 0xCF, 0xC5, 0xD1, 0x56, 0x3D, 0xCA, 0xF4, 0x05, 0xC6, 0xE5, 0x08, 0x49
};

const uint8_t MapleAES::defaultSecretKey_[32] = {
    0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xB4, 0x00, 0x00, 0x00,
    0x1B, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00
};

const char* const MapleAES::secretKeys_[20] = {
    "2923BE84E16CD6AE529049F1F1BBE9EBB3A6DB3C870C3E99245E0D1C06B747DE",
    "B3124DC843BB8BA61F035A7D0938251F5DD4CBFC96F5453B130D890A1CDBAE32",
    "888138616B681262F954D0E7711748780D92291D86299972DB741CFA4F37B8B5",
    "209A50EE407836FD124932F69E7D49DCAD4F14F2444066D06BC430B7323BA122",
    "F622919DE18B1FDAB0CA9902B9729D492C807EC599D5E980B2EAC9CC53BF67D6",
    "BF14D67E2DDC8E6683EF574961FF698F61CDD11E9D9C167272E61DF0844F4A77",
    "02D7E8392C53CBC9121E33749E0CF4D5D49FD4A4597E35CF3222F4CCCFD3902D",
    "48D38F75E6D91D2AE5C0F72B788187440E5F5000D4618DBE7B0515073B33821F",
    "187092DA6454CEB1853E6915F8466A0496730ED9162F6768D4F74A4AD0576876",
    "5B628A8A8F275CF7E5874A3B329B614084C6C3B1A7304A10EE756F032F9E6AEF",
    "762DD0C2C9CD68D4496A792508614014B13B6AA51128C18CD6A90B87978C2FF1",
    "10509BC8814329288AF6E99E47A18148316CCDA49EDE81A38C9810FF9A43CDCF",
    "5E4EE1309CFED9719FE2A5E20C9BB44765382A4689A982797A7678C263B126DF",
    "DA296D3E62E0961234BF39A63F895EF16D0EE36C28A11E201DCBC2033F410784",
    "0F1405651B2861C9C5E72C8E463608DCF3A88DFEBEF2EB71FFA0D03B75068C7E",
    "8778734DD0BE82BEDBC246412B8CFA307F70F0A754863295AA5B68130BE6FCF5",
    "CABE7D9F898A411BFDB84F68F6727B1499CDD30DF0443AB4A66653330BCBA110",
    "5E4CEC034C73E605B4310EAAADCFD5B0CA27FFD89D144DF4792759427C9CC1F8",
    "CD8C87202364B8A687954CB05A8D4E2D99E73DB160DEB180AD0841E96741A5D5",
    "9FE4189F15420026FE4CD12104932FB38F735340438AAF7ECA6FD5CFD3A195CE"
};

// --- Helpers ---

static uint8_t hexCharToNibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    return 0;
}

static uint8_t hexByteParse(const char* s) {
    return static_cast<uint8_t>((hexCharToNibble(s[0]) << 4) | hexCharToNibble(s[1]));
}

// --- Implementation ---

std::array<uint8_t, 32> MapleAES::generateTWKey(uint16_t version) {
    int keyIndex = version % 20;
    const char* hexStr = secretKeys_[keyIndex];

    // Parse hex string into raw bytes (32 bytes from 64 hex chars)
    uint8_t keyBuffer[32];
    for (int i = 0; i < 32; i++) {
        keyBuffer[i] = hexByteParse(hexStr + i * 2);
    }

    // Extract every 4th byte to get 8-byte seed
    uint8_t seed[8];
    for (int i = 0; i < 32; i += 4) {
        seed[i / 4] = keyBuffer[i];
    }

    // Expand 8-byte seed into 32-byte AES key (key[i*4] = seed[i], rest = 0)
    std::array<uint8_t, 32> key{};
    for (int i = 0; i < 8; i++) {
        key[i * 4] = seed[i];
    }
    return key;
}

MapleAES::MapleAES(uint16_t version, uint8_t locale, const uint8_t iv[4], uint8_t subVersion)
    : version_(version), ctx_(nullptr)
{
    std::memcpy(iv_, iv, 4);

    // For inbound stream: version is passed as (0xFFFF - build), which is negative as int16_t.
    // We need the actual version for key generation.
    uint16_t keyVersion = version;
    if (static_cast<int16_t>(version) < 0) {
        keyVersion = static_cast<uint16_t>(0xFFFF - version);
    }

    // TWMS (locale 6): generate key from secret keys
    if (locale == 6) {
        aesKey_ = generateTWKey(keyVersion);
    } else {
        // Fallback to default key
        std::memcpy(aesKey_.data(), defaultSecretKey_, 32);
    }

    // Initialize OpenSSL AES-256-ECB encryptor
    ctx_ = EVP_CIPHER_CTX_new();
    if (!ctx_) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (EVP_EncryptInit_ex(ctx_, EVP_aes_256_ecb(), nullptr, aesKey_.data(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx_);
        throw std::runtime_error("Failed to init AES-256-ECB");
    }
    // Disable padding — we handle block alignment ourselves
    EVP_CIPHER_CTX_set_padding(ctx_, 0);
}

MapleAES::~MapleAES() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
    }
}

bool MapleAES::confirmHeader(const uint8_t* buf) const {
    return (buf[0] ^ iv_[2]) == (version_ & 0xFF) &&
           (buf[1] ^ iv_[3]) == ((version_ >> 8) & 0xFF);
}

int MapleAES::getHeaderLength(const uint8_t* buf, bool oldHeader) {
    if (oldHeader) return 4;

    uint16_t ivBytes = static_cast<uint16_t>(buf[0] | (buf[1] << 8));
    uint16_t xorredSize = static_cast<uint16_t>(buf[2] | (buf[3] << 8));
    uint16_t length = static_cast<uint16_t>(xorredSize ^ ivBytes);

    if (length == 0xFF00) return 8;
    return 4;
}

int MapleAES::getPacketLength(const uint8_t* buf, int bytesAvailable, bool oldHeader) {
    if (bytesAvailable < 4) return bytesAvailable - 4; // negative = need more

    if (oldHeader) {
        return static_cast<uint16_t>(buf[2] | (buf[3] << 8));
    }

    uint16_t ivBytes = static_cast<uint16_t>(buf[0] | (buf[1] << 8));
    uint16_t xorredSize = static_cast<uint16_t>(buf[2] | (buf[3] << 8));
    uint16_t length = static_cast<uint16_t>(xorredSize ^ ivBytes);

    if (length == 0xFF00) {
        if (bytesAvailable < 8) return bytesAvailable - 8;
        int32_t bigLen = static_cast<int32_t>(
            buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24)
        );
        return (bigLen ^ ivBytes) & 0x7FFFFFFF;
    }
    return length;
}

void MapleAES::transformAES(uint8_t* data, int dataSize) {
    // Build IV block: repeat 4-byte IV to fill 16 bytes
    uint8_t ivBlock[16];
    for (int i = 0; i < 16; i++) {
        ivBlock[i] = iv_[i % 4];
    }

    // Generate XOR table by chaining AES-ECB encryptions
    // Maximum 92 blocks (for 1472 bytes max per chunk)
    static constexpr int AES_XOR_TABLE_BLOCKS = 92;
    uint8_t xorTable[AES_XOR_TABLE_BLOCKS * 16];

    int requiredBlocks = std::min((dataSize / 16) + 1, AES_XOR_TABLE_BLOCKS);

    // Encrypt ivBlock -> xorTable[0]
    int outLen = 0;
    EVP_EncryptUpdate(ctx_, xorTable, &outLen, ivBlock, 16);

    // Chain: encrypt xorTable[i] -> xorTable[i+1]
    for (int i = 0; i < requiredBlocks - 1; i++) {
        EVP_EncryptUpdate(ctx_, xorTable + ((i + 1) * 16), &outLen, xorTable + (i * 16), 16);
    }

    // Re-init context for next call (ECB is stateless but OpenSSL tracks state)
    EVP_EncryptInit_ex(ctx_, nullptr, nullptr, aesKey_.data(), nullptr);

    // XOR data with table, processing in chunks of 1456 bytes (or 1452 for big packets)
    int startOffset = 1456;
    if (dataSize >= 0xFF00) startOffset -= 4;

    int blockSize = std::min(startOffset, dataSize);
    int pos = 0;

    while (pos < dataSize) {
        int xorIdx = 0;
        for (int i = 0; i < blockSize; i++) {
            data[pos + i] ^= xorTable[xorIdx++];
        }
        pos += blockSize;
        blockSize = std::min(1460, dataSize - pos);
    }
}

void MapleAES::morph(uint8_t value, uint8_t* iv) {
    uint8_t input = value;
    uint8_t tableInput = shuffleKey_[input];
    iv[0] += static_cast<uint8_t>(shuffleKey_[iv[1]] - input);
    iv[1] -= static_cast<uint8_t>(iv[2] ^ tableInput);
    iv[2] ^= static_cast<uint8_t>(shuffleKey_[iv[3]] + input);
    iv[3] -= static_cast<uint8_t>(iv[0] - tableInput);

    // ROL32 by 3
    uint32_t val = static_cast<uint32_t>(iv[0]) |
                   (static_cast<uint32_t>(iv[1]) << 8) |
                   (static_cast<uint32_t>(iv[2]) << 16) |
                   (static_cast<uint32_t>(iv[3]) << 24);
    val = (val << 3) | (val >> 29);
    iv[0] = static_cast<uint8_t>(val & 0xFF);
    iv[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    iv[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    iv[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
}

void MapleAES::shiftIV() {
    uint8_t oldIV[4];
    std::memcpy(oldIV, iv_, 4);

    uint8_t newIV[4] = { 0xF2, 0x53, 0x50, 0xC6 };
    for (int i = 0; i < 4; i++) {
        morph(oldIV[i], newIV);
    }
    std::memcpy(iv_, newIV, 4);
}

} // namespace maple
