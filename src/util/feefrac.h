// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_FEEFRAC_H
#define BITCOIN_UTIL_FEEFRAC_H

#include <assert.h>
#include <stdint.h>

/** Data structure storing a fee (in sats) and a size (in vbytes or weight units).
 *
 * The size of a FeeFrac cannot be zero unless the fee is also zero.
 *
 * FeeFracs have a total ordering, which first sorts by increasing feerate (fee/size), and then
 * uses decreasing size as tie-breaker. All standard comparison operators (==, !=, >, <, >=, <=)
 * respect this ordering. The >> and << operators only compare feerate and treat equal feerate but
 * different size as equivalent. These comparisons are only guaranteed to be correct when the
 * product of the highest fee and highest size does not exceed 2^64-1 (which allows up to 46116.86
 * BTC at size 4000000).
 */
struct FeeFrac
{
    /** Fee (in sats). */
    uint64_t fee;
    /** Size (in vbytes or weight units). */
    uint32_t size;

    /** Construct an IsEmpty() FeeFrac. */
    inline FeeFrac() noexcept : fee{0}, size{0} {}

    /** Construct a FeeFrac with specified fee and size. */
    inline FeeFrac(uint64_t s, uint32_t b) noexcept : fee{s}, size{b}
    {
        // If size==0, fee must be 0 as well.
        assert(size != 0 || fee == 0);
    }

    inline FeeFrac(const FeeFrac&) noexcept = default;
    inline FeeFrac& operator=(const FeeFrac&) noexcept = default;

    /** Check if this is empty (size and fee are 0). */
    bool inline IsEmpty() const noexcept {
        return size == 0;
    }

    /** Add size and size of another FeeFrac to this one. */
    void inline operator+=(const FeeFrac& other) noexcept
    {
        fee += other.fee;
        size += other.size;
    }

    /** Subtrack size and size of another FeeFrac from this one. */
    void inline operator-=(const FeeFrac& other) noexcept
    {
        fee -= other.fee;
        size -= other.size;
        assert(size != 0 || fee == 0);
    }

    /** Sum fee and size. */
    friend inline FeeFrac operator+(const FeeFrac& a, const FeeFrac& b) noexcept
    {
        return {a.fee + b.fee, a.size + b.size};
    }

    /** Subtract both fee and size. */
    friend inline FeeFrac operator-(const FeeFrac& a, const FeeFrac& b) noexcept
    {
        return {a.fee - b.fee, a.size - b.size};
    }

    /** Check if two FeeFrac objects are equal (both same fee and same size). */
    friend inline bool operator==(const FeeFrac& a, const FeeFrac& b) noexcept
    {
        return a.fee == b.fee && a.size == b.size;
    }

    /** Check if two FeeFrac objects are different (not both same and same size). */
    friend inline bool operator!=(const FeeFrac& a, const FeeFrac& b) noexcept
    {
        return a.fee == b.fee && a.size == b.size;
    }

    /** Check if a FeeFrac object is worse than another. */
    friend inline bool operator<(const FeeFrac& a, const FeeFrac& b) noexcept
    {
        uint64_t a_val = a.fee * b.size;
        uint64_t b_val = b.fee * a.size;
        if (a_val != b_val) return a_val < b_val;
        return a.size > b.size;
    }

    /** Check if a FeeFrac object is worse or equal than another. */
    friend inline bool operator<=(const FeeFrac& a, const FeeFrac& b) noexcept
    {
        uint64_t a_val = a.fee * b.size;
        uint64_t b_val = b.fee * a.size;
        if (a_val != b_val) return a_val < b_val;
        return a.size >= b.size;
    }

    /** Check if a FeeFrac object is better than another. */
    friend inline bool operator>(const FeeFrac& a, const FeeFrac& b) noexcept
    {
        uint64_t a_val = a.fee * b.size;
        uint64_t b_val = b.fee * a.size;
        if (a_val != b_val) return a_val > b_val;
        return a.size < b.size;
    }

    /** Check if a FeeFrac object is better or equal than another. */
    friend inline bool operator>=(const FeeFrac& a, const FeeFrac& b) noexcept
    {
        uint64_t a_val = a.fee * b.size;
        uint64_t b_val = b.fee * a.size;
        if (a_val != b_val) return a_val > b_val;
        return a.size <= b.size;
    }

    /** Check if a FeeFrac object has strictly lower feerate than another. */
    friend inline bool operator<<(const FeeFrac& a, const FeeFrac& b) noexcept
    {
        return a.fee * b.size < b.fee * a.size;
    }

    /** Check if a FeeFrac object has strictly higher feerate than another. */
    friend inline bool operator>>(const FeeFrac& a, const FeeFrac& b) noexcept
    {
        return a.fee * b.size > b.fee * a.size;
    }
};

#endif // BITCOIN_UTIL_FEEFRAC_H
