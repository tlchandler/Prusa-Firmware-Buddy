#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>

/// Pure arithmetic behind the direction-aware, globally-bounded TCP
/// out-of-order queue caps (see TCP_OOSEQ_BYTES_LIMIT / TCP_OOSEQ_PBUFS_LIMIT
/// in lwipopts.h and ooseq_limit.cpp). Kept free of lwIP types (inline, no
/// lwIP includes) so it can be exercised by a host unit test.
namespace ooseq_limit {

// Ring bytes budget (protects the shared RX pbuf ring, pbuf_rx.cpp). Worst-case
// pinned ring ~= GLOBAL_BYTES + GLOBAL_SEGS * per-frame overhead; keep it well
// under the ring size in pbuf_rx.cpp.
inline constexpr uint32_t GLOBAL_BYTES = 4096;
inline constexpr uint32_t INBOUND_SHARE_BYTES = 3072;
inline constexpr uint32_t INBOUND_PCB_BYTES = 3072;
inline constexpr uint32_t OUTBOUND_PCB_BYTES = 4096;

// tcp_seg count budget (protects the shared MEMP_NUM_TCP_SEG pool).
inline constexpr uint16_t GLOBAL_SEGS = 5;
inline constexpr uint16_t INBOUND_SHARE_SEGS = 3;
inline constexpr uint16_t INBOUND_PCB_SEGS = 3;
inline constexpr uint16_t OUTBOUND_PCB_SEGS = 4;

namespace detail {
    // Header-only so users of the setter don't have to link the lwIP-bound
    // ooseq_limit.cpp (e.g. host unit tests of the HTTP server).
    inline std::atomic<const void *> priority_arg = nullptr;

    template <typename T>
    inline T room(T budget, T used) {
        return used < budget ? budget - used : 0;
    }
} // namespace detail

/// Max ooseq payload bytes a pcb of the given class may keep, given the
/// ooseq bytes already held by every other pcb.
inline uint32_t compute_bytes_limit(bool is_inbound, uint32_t other_all_bytes, uint32_t other_inbound_bytes) {
    const uint32_t global_room = detail::room(GLOBAL_BYTES, other_all_bytes);
    if (is_inbound) {
        const uint32_t inbound_room = detail::room(INBOUND_SHARE_BYTES, other_inbound_bytes);
        return std::min({ INBOUND_PCB_BYTES, inbound_room, global_room });
    } else {
        return std::min(OUTBOUND_PCB_BYTES, global_room);
    }
}

/// Max ooseq segments a pcb of the given class may keep, given the ooseq
/// segments already held by every other pcb.
inline uint16_t compute_segs_limit(bool is_inbound, uint16_t other_all_segs, uint16_t other_inbound_segs) {
    const uint16_t global_room = detail::room(GLOBAL_SEGS, other_all_segs);
    if (is_inbound) {
        const uint16_t inbound_room = detail::room(INBOUND_SHARE_SEGS, other_inbound_segs);
        return std::min({ INBOUND_PCB_SEGS, inbound_room, global_room });
    } else {
        return std::min(OUTBOUND_PCB_SEGS, global_room);
    }
}

/// Max ooseq payload bytes for the pcb carrying an active PrusaLink upload.
/// It gets the outbound cap; while it exists, every other pcb gets nothing.
inline uint32_t compute_priority_bytes_limit(uint32_t other_all_bytes) {
    return std::min(OUTBOUND_PCB_BYTES, detail::room(GLOBAL_BYTES, other_all_bytes));
}

/// Segment counterpart of compute_priority_bytes_limit.
inline uint16_t compute_priority_segs_limit(uint16_t other_all_segs) {
    return std::min(OUTBOUND_PCB_SEGS, detail::room(GLOBAL_SEGS, other_all_segs));
}

/// Marks pcbs whose lwIP callback arg equals `arg` as carrying a PrusaLink
/// upload. Such a pcb gets the outbound ooseq budget and starves every other
/// pcb of ooseq room for as long as it exists. The pointer is only compared,
/// never dereferenced. Pass nullptr to disable.
inline void set_priority_arg(const void *arg) {
    detail::priority_arg.store(arg, std::memory_order_relaxed);
}

/// Callback arg registered by set_priority_arg (nullptr if none).
inline const void *get_priority_arg() {
    return detail::priority_arg.load(std::memory_order_relaxed);
}

} // namespace ooseq_limit
