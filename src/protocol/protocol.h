#pragma once

#include "../capture/capture.h"
#include <string>
#include <vector>
#include <cstdint>

namespace maple {

struct Packet {
    double timestamp;
    uint32_t length;
    std::vector<uint8_t> payload;
    std::string hexDump;
    bool inbound = false; // direction, to be determined later
};

class Protocol {
public:
    // Parse a raw captured packet into our Packet structure.
    // Currently a stub: just stores hex dump of the payload.
    static Packet parse(const RawPacket& raw);

    // Generate hex dump string from binary data
    static std::string toHexDump(const uint8_t* data, size_t len, size_t maxBytes = 128);
};

} // namespace maple
