#include "protocol.h"
#include <sstream>
#include <iomanip>

namespace maple {

Packet Protocol::parse(const RawPacket& raw) {
    Packet pkt;
    pkt.timestamp = raw.timestamp;
    pkt.length = raw.len;
    pkt.payload = raw.data;
    pkt.hexDump = toHexDump(raw.data.data(), raw.data.size());
    // TODO: Implement MapleStory protocol decryption/parsing
    return pkt;
}

std::string Protocol::toHexDump(const uint8_t* data, size_t len, size_t maxBytes) {
    std::ostringstream oss;
    size_t printLen = (len < maxBytes) ? len : maxBytes;
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

} // namespace maple
