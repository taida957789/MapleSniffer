#include "tcp_reasm.h"

namespace maple {

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

    for (;;) {
        // Find the segment covering nextSeq using int32_t comparison
        // (std::map ordering breaks on uint32_t wraparound)
        auto next = staged.end();
        for (auto it = staged.begin(); it != staged.end(); ) {
            uint32_t segEnd = it->first + static_cast<uint32_t>(it->second.size());

            // Fully before nextSeq: already delivered, discard
            if (static_cast<int32_t>(segEnd - nextSeq) <= 0) {
                it = staged.erase(it);
                continue;
            }

            // At or overlapping nextSeq: deliverable
            if (static_cast<int32_t>(it->first - nextSeq) <= 0) {
                next = it;
                break;
            }

            ++it;
        }

        if (next == staged.end()) break;

        // holdLast: keep the last remaining segment pending for replacement protection
        if (holdLast && staged.size() <= 1) break;

        // Deliver new bytes (skip any overlap at the beginning)
        uint32_t offset = nextSeq - next->first;
        result.insert(result.end(), next->second.begin() + offset, next->second.end());
        nextSeq = next->first + static_cast<uint32_t>(next->second.size());
        staged.erase(next);
    }

    return result;
}

} // namespace maple
