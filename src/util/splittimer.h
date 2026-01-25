// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_SPLITTIMER_H
#define BITCOIN_UTIL_SPLITTIMER_H

#include <attributes.h>

#include <array>
#include <cstdint>

#if defined(__APPLE__) && defined(__MACH__)
#include <mach/mach_time.h>
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(__rdtsc)
#endif

namespace {

template<unsigned N>
class SplitTimer
{
    /** The total amount of time returned by GetTotalTime() so far. */
    int64_t m_total_time{0};
    /** For every timer, its start time, incremented by m_total_time. */
    std::array<int64_t, N> m_adjusted_start_times;

    /** Get the current time. */
    static ALWAYS_INLINE uint64_t now() {
        // Inspired by https://github.com/google/benchmark/blob/main/src/cycleclock.h.
#if defined(__APPLE__) && defined(__MACH__)
        return mach_absolute_time();
#elif defined(__i386__)
        int64_t ret;
        __asm__ volatile("rdtsc" : "=A"(ret));
        return ret;
#elif defined(__x86_64__) || defined(__amd64__)
        uint64_t low, high;
        __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
        return (high << 32) | low;
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
        return __rdtsc();
#elif defined(__aarch64__)
        int64_t virtual_timer_value;
        asm volatile("mrs %0, cntvct_el0" : "=r"(virtual_timer_value));
        return virtual_timer_value;
#else
#    error "No SplitTimer::now() implementation for this platform"
#endif
    }

public:
    inline SplitTimer() noexcept = default;

    /** Start/reset timer T. */
    template<unsigned T>
    ALWAYS_INLINE void Reset() noexcept
    {
        static_assert(T < N);
        auto cur = now();
        m_adjusted_start_times[T] = cur - m_total_time;
    }

    /** Return timer T's current value, and subtract that value from all timers (including T, which
     *  is thus reset to 0). */
    template<unsigned T>
    ALWAYS_INLINE int64_t Lap() noexcept
    {
        static_assert(T < N);
        auto cur = now();
        int64_t ret = cur - m_adjusted_start_times[T] - m_total_time;
        m_total_time += ret;
        return ret;
    }

    /** Return the sum of all values returned by Lap() so far. */
    inline int64_t GetTotalTime() const noexcept { return m_total_time; }
};

} // namespace

#endif // BITCOIN_UTIL_SPLITTIMER_H
