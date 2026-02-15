#pragma once

#include <cstdint>
#include <map>
#include <vector>

namespace maple {

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

} // namespace maple
