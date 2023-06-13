// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BITSET_H
#define BITCOIN_UTIL_BITSET_H

#include <array>
#include <cstdint>
#include <limits>
#include <type_traits>

#ifdef _MSC_VER
#  include <intrin.h>
#endif

namespace bitset_detail {

/** Compute the trailing zeroes of a non-zero value. */
template<typename I>
unsigned inline CountTrailingZeroes(I v) noexcept
{
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);
    constexpr auto BITS = std::numeric_limits<I>::digits;
#if HAVE_BUILTIN_CTZ
    constexpr auto BITS_U = std::numeric_limits<unsigned>::digits;
    if constexpr (BITS <= BITS_U) return __builtin_ctz(v);
#endif
#if HAVE_BUILTIN_CTZL
    constexpr auto BITS_UL = std::numeric_limits<unsigned long>::digits;
    if constexpr (BITS <= BITS_UL) return __builtin_ctzl(v);
#endif
#if HAVE_BUILTIN_CTZLL
    constexpr auto BITS_ULL = std::numeric_limits<unsigned long long>::digits;
    if constexpr (BITS <= BITS_ULL) return __builtin_ctzll(v);
#endif
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
#  pragma intrinsic(_BitScanForward)
    if constexpr (BITS <= 32) {
        unsigned long ret;
        _BitScanForward(&ret, v);
        return ret;
    }
#endif
#if defined(_MSC_VER) && defined(_M_X64)
#  pragma intrinsic(_BitScanForward64)
    if constexpr (BITS <= 64) {
        unsigned long ret;
        _BitScanForward64(&ret, v);
        return ret;
    }
#endif
    if constexpr (BITS <= 32) {
        static constexpr uint8_t DEBRUIJN[32] = {
            0x00, 0x01, 0x02, 0x18, 0x03, 0x13, 0x06, 0x19,
            0x16, 0x04, 0x14, 0x0A, 0x10, 0x07, 0x0C, 0x1A,
            0x1F, 0x17, 0x12, 0x05, 0x15, 0x09, 0x0F, 0x0B,
            0x1E, 0x11, 0x08, 0x0E, 0x1D, 0x0D, 0x1C, 0x1B
        };
        return DEBRUIJN[(uint32_t)((v & uint32_t(-v)) * uint32_t{0x04D7651FU}) >> 27];
    } else {
        static_assert(BITS <= 64);
        static constexpr uint8_t DEBRUIJN[64] = {
            0x00, 0x01, 0x02, 0x53, 0x03, 0x07, 0x54, 0x27,
            0x04, 0x38, 0x41, 0x08, 0x34, 0x55, 0x48, 0x28,
            0x62, 0x05, 0x39, 0x46, 0x44, 0x42, 0x22, 0x09,
            0x24, 0x35, 0x59, 0x56, 0x49, 0x18, 0x29, 0x11,
            0x63, 0x52, 0x06, 0x26, 0x37, 0x40, 0x33, 0x47,
            0x61, 0x45, 0x43, 0x21, 0x23, 0x58, 0x17, 0x10,
            0x51, 0x25, 0x36, 0x32, 0x60, 0x20, 0x57, 0x16,
            0x50, 0x31, 0x19, 0x15, 0x30, 0x14, 0x13, 0x12
        };
        return DEBRUIJN[(uint64_t)((v & uint64_t(-v)) * uint64_t{0x022FDD63CC95386D}) >> 58];
    }
}

/** Count the number of bits set in an unsigned integer type. */
template<typename I>
unsigned inline PopCount(I v)
{
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);
    constexpr auto BITS = std::numeric_limits<I>::digits;
    // Algorithms from https://en.wikipedia.org/wiki/Hamming_weight#Efficient_implementation.
    // These seem to be faster than __builtin_popcount when compiling for non-SSE4 on x86_64.
    if constexpr (BITS <= 32) {
        v -= (v >> 1) & 0x55555555;
        v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
        v = (v + (v >> 4)) & 0x0f0f0f0f;
        v += v >> 8;
        v += v >> 16;
        return v & 0x3f;
    } else {
        static_assert(BITS <= 64);
        v -= (v >> 1) & 0x5555555555555555;
        v = (v & 0x3333333333333333) + ((v >> 2) & 0x3333333333333333);
        v = (v + (v >> 4)) & 0x0f0f0f0f0f0f0f0f;
        return (v * uint64_t{0x0101010101010101}) >> 56;
    }
}

/** A bitset implementation backed by a single integer of type I. */
template<typename I>
class IntBitSet
{
    // Only binary, unsigned, integer, types allowed.
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);

    /** Integer whose bits represent this bitset. */
    I m_val;

    /** Internal constructor with a given integer as contents. */
    IntBitSet(I val) noexcept : m_val{val} {}

    /** Dummy type to return using end(). Only used for comparing with Iterator. */
    class IteratorEnd
    {
        friend class IntBitSet;
        IteratorEnd() = default;
    public:
        IteratorEnd(const IteratorEnd&) = default;
    };

    /** Iterator type returned by begin(), which efficiently iterates all set values. */
    class Iterator
    {
        friend class IntBitSet;
        I m_val;
        unsigned m_pos;

        Iterator(I val) noexcept : m_val(val), m_pos(0)
        {
            if (m_val != 0) m_pos = CountTrailingZeroes(m_val);
        }
    public:
        Iterator() = delete;
        Iterator(const Iterator&) noexcept = default;
        Iterator& operator=(const Iterator&) noexcept = default;

        friend bool operator!=(const Iterator& a, const IteratorEnd&) noexcept
        {
            return a.m_val != 0;
        }

        friend bool operator==(const Iterator& a, const IteratorEnd&) noexcept
        {
            return a.m_val == 0;
        }

        Iterator& operator++() noexcept
        {
            m_val &= m_val - I{1U};
            if (m_val != 0) m_pos = CountTrailingZeroes(m_val);
            return *this;
        }

        const unsigned& operator*() const noexcept { return m_pos; }
    };

public:
    /** Number of elements this set type supports. */
    static constexpr unsigned MAX_SIZE = std::numeric_limits<I>::digits;

    /** Construct an empty set. */
    IntBitSet() noexcept : m_val{0} {}
    /** Copy a set. */
    IntBitSet(const IntBitSet&) noexcept = default;
    /** Copy-assign a set. */
    IntBitSet& operator=(const IntBitSet&) noexcept = default;

    /** Construct a set with elements 0..count-1. */
    static IntBitSet Full(unsigned count) noexcept {
        IntBitSet ret;
        if (count) ret.m_val = I(~I{0}) >> (MAX_SIZE - count);
        return ret;
    }

    /** Compute the size of a set (number of elements). */
    unsigned Count() const noexcept { return PopCount(m_val); }
    /** Add an element to a set. */
    void Add(unsigned pos) noexcept { m_val |= I{1U} << pos; }
    /** Remove an element from a set. */
    void Remove(unsigned pos) noexcept { m_val &= ~I(I{1U} << pos); }
    /** Find if an element is in the set. */
    bool operator[](unsigned pos) const noexcept { return (m_val >> pos) & 1U; }
    /** Check if a set is empty. */
    bool IsEmpty() const noexcept { return m_val == 0; }

    Iterator begin() const noexcept { return Iterator(m_val); }
    IteratorEnd end() const noexcept { return IteratorEnd(); }

    /** Find the first element (requires !IsEMpty()). */
    unsigned First() const noexcept { return CountTrailingZeroes(m_val); }
    /** Update this to be the union of this and a. */
    IntBitSet& operator|=(const IntBitSet& a) noexcept { m_val |= a.m_val; return *this; }
    /** Update this to be intersection of this and a. */
    IntBitSet& operator&=(const IntBitSet& a) noexcept { m_val &= a.m_val; return *this; }
    /** Construct a new set that is the interaction of a and b. */
    friend IntBitSet operator&(const IntBitSet& a, const IntBitSet& b) noexcept { return {I(a.m_val & b.m_val)}; }
    /** Construct a new set that is the union of a and b. */
    friend IntBitSet operator|(const IntBitSet& a, const IntBitSet& b) noexcept { return {I(a.m_val | b.m_val)}; }
    /** Construct a new set that is a minus b. */
    friend IntBitSet operator/(const IntBitSet& a, const IntBitSet& b) noexcept { return {I(a.m_val & ~b.m_val)}; }
    /** Check if set a and set b are identical. */
    friend bool operator!=(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val != b.m_val; }
    /** Check if set a and set b are different. */
    friend bool operator==(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val == b.m_val; }
    /** Check if set a is a superset of set b. */
    friend bool operator>>(const IntBitSet& a, const IntBitSet& b) noexcept { return (b.m_val & ~a.m_val) == 0; }
    /** Check if set a is a subset of set b. */
    friend bool operator<<(const IntBitSet& a, const IntBitSet& b) noexcept { return (a.m_val & ~b.m_val) == 0; }
};

/** A bitset implementation backed by N integers of type I. */
template<typename I, unsigned N>
class MultiIntBitSet
{
    // Only binary, unsigned, integer, types allowed.
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);

    /** The number of bits per integer. */
    static constexpr unsigned LIMB_BITS = std::numeric_limits<I>::digits;

    /** Array whose member integers store the bits of the set. */
    std::array<I, N> m_val;

    class IteratorEnd
    {
        friend class MultiIntBitSet;
        IteratorEnd() = default;
    public:
        IteratorEnd(const IteratorEnd&) = default;
    };

    class Iterator
    {
        friend class MultiIntBitSet;
        const std::array<I, N>* m_ptr;
        I m_val;
        unsigned m_pos;
        unsigned m_idx;

        Iterator(const std::array<I, N>* ptr) noexcept : m_ptr(ptr), m_idx(0)
        {
            do {
                m_val = (*m_ptr)[m_idx];
                if (m_val) {
                    m_pos = CountTrailingZeroes(m_val) + m_idx * LIMB_BITS;
                    break;
                }
                ++m_idx;
            } while(m_idx < N);
        }

    public:
        Iterator() = delete;
        Iterator(const Iterator&) noexcept = default;
        Iterator& operator=(const Iterator&) noexcept = default;

        friend bool operator!=(const Iterator& a, const IteratorEnd&) noexcept
        {
            return a.m_idx != N;
        }

        friend bool operator==(const Iterator& a, const IteratorEnd&) noexcept
        {
            return a.m_idx == N;
        }

        Iterator& operator++() noexcept
        {
            m_val &= m_val - I{1U};
            if (m_val == 0) {
                while (true) {
                    ++m_idx;
                    if (m_idx == N) break;
                    m_val = (*m_ptr)[m_idx];
                    if (m_val) {
                        m_pos = CountTrailingZeroes(m_val) + m_idx * LIMB_BITS;
                        break;
                    }
                }
            } else {
                m_pos = CountTrailingZeroes(m_val) + m_idx * LIMB_BITS;
            }
            return *this;
        }

        const unsigned& operator*() const noexcept { return m_pos; }
    };

public:
    static constexpr unsigned MAX_SIZE = LIMB_BITS * N;

    MultiIntBitSet() noexcept : m_val{} {}
    MultiIntBitSet(const MultiIntBitSet&) noexcept = default;
    MultiIntBitSet& operator=(const MultiIntBitSet&) noexcept = default;

    void Add(unsigned pos) noexcept { m_val[pos / LIMB_BITS] |= I{1U} << (pos % LIMB_BITS); }
    void Remove(unsigned pos) noexcept { m_val[pos / LIMB_BITS] &= ~I(I{1U} << (pos % LIMB_BITS)); }
    bool operator[](unsigned pos) const noexcept { return (m_val[pos / LIMB_BITS] >> (pos % LIMB_BITS)) & 1U; }

    static MultiIntBitSet Full(unsigned count) noexcept {
        MultiIntBitSet ret;
        if (count) {
            unsigned i = 0;
            while (count > LIMB_BITS) {
                ret.m_val[i++] = ~I{0};
                count -= LIMB_BITS;
            }
            ret.m_val[i] = I(~I{0}) >> (LIMB_BITS - count);
        }
        return ret;
    }

    unsigned Count() const noexcept
    {
        unsigned ret{0};
        for (I v : m_val) ret += PopCount(v);
        return ret;
    }

    bool IsEmpty() const noexcept
    {
        for (auto v : m_val) {
            if (v != 0) return false;
        }
        return true;
    }

    Iterator begin() const noexcept { return Iterator(&m_val); }
    IteratorEnd end() const noexcept { return IteratorEnd(); }

    unsigned First() const noexcept
    {
        unsigned p = 0;
        while (m_val[p] == 0) ++p;
        return CountTrailingZeroes(m_val[p]) + p * LIMB_BITS;
    }

    MultiIntBitSet& operator|=(const MultiIntBitSet& a) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            m_val[i] |= a.m_val[i];
        }
        return *this;
    }

    MultiIntBitSet& operator&=(const MultiIntBitSet& a) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            m_val[i] &= a.m_val[i];
        }
        return *this;
    }

    friend MultiIntBitSet operator&(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        MultiIntBitSet r;
        for (unsigned i = 0; i < N; ++i) {
            r.m_val[i] = a.m_val[i] & b.m_val[i];
        }
        return r;
    }

    friend MultiIntBitSet operator|(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        MultiIntBitSet r;
        for (unsigned i = 0; i < N; ++i) {
            r.m_val[i] = a.m_val[i] | b.m_val[i];
        }
        return r;
    }

    friend MultiIntBitSet operator/(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        MultiIntBitSet r;
        for (unsigned i = 0; i < N; ++i) {
            r.m_val[i] = a.m_val[i] & ~b.m_val[i];
        }
        return r;
    }

    friend bool operator>>(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            if (b.m_val[i] & ~a.m_val[i]) return false;
        }
        return true;
    }

    friend bool operator<<(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            if (a.m_val[i] & ~b.m_val[i]) return false;
        }
        return true;
    }

    friend bool operator!=(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept { return a.m_val != b.m_val; }
    friend bool operator==(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept { return a.m_val == b.m_val; }
};

} // namespace bitset_detail

template<unsigned BITS>
using BitSet = std::conditional_t<(BITS <= 32), bitset_detail::IntBitSet<uint32_t>,
               std::conditional_t<(BITS <= std::numeric_limits<size_t>::digits), bitset_detail::IntBitSet<size_t>,
               bitset_detail::MultiIntBitSet<size_t, (BITS + std::numeric_limits<size_t>::digits - 1) / std::numeric_limits<size_t>::digits>>>;

#endif // BITCOIN_UTIL_BITSET_H
