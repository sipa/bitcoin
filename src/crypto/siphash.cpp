// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/siphash.h>

#include <uint256.h>

#include <bit>
#include <cassert>
#include <span>

static constexpr uint64_t SIPHASH_FINALIZER_UNPADDED = 0x6465646461706E75;

#define SIPROUND do { \
    v0 += v1; v1 = std::rotl(v1, 13); v1 ^= v0; \
    v0 = std::rotl(v0, 32); \
    v2 += v3; v3 = std::rotl(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = std::rotl(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = std::rotl(v1, 17); v1 ^= v2; \
    v2 = std::rotl(v2, 32); \
} while (0)

CSipHasher::CSipHasher(uint64_t k0, uint64_t k1) : m_state{k0, k1} {}

CSipHasher& CSipHasher::Write(uint64_t data)
{
    uint64_t v0 = m_state.v[0], v1 = m_state.v[1], v2 = m_state.v[2], v3 = m_state.v[3];

    assert(m_count % 8 == 0);

    v3 ^= data;
    SIPROUND;
    SIPROUND;
    v0 ^= data;

    m_state.v[0] = v0;
    m_state.v[1] = v1;
    m_state.v[2] = v2;
    m_state.v[3] = v3;

    m_count += 8;
    return *this;
}

CSipHasher& CSipHasher::Write(std::span<const unsigned char> data)
{
    uint64_t v0 = m_state.v[0], v1 = m_state.v[1], v2 = m_state.v[2], v3 = m_state.v[3];
    uint64_t t = m_tmp;
    uint8_t c = m_count;

    while (data.size() > 0) {
        t |= uint64_t{data.front()} << (8 * (c % 8));
        c++;
        if ((c & 7) == 0) {
            v3 ^= t;
            SIPROUND;
            SIPROUND;
            v0 ^= t;
            t = 0;
        }
        data = data.subspan(1);
    }

    m_state.v[0] = v0;
    m_state.v[1] = v1;
    m_state.v[2] = v2;
    m_state.v[3] = v3;
    m_count = c;
    m_tmp = t;

    return *this;
}

uint64_t CSipHasher::Finalize() const
{
    uint64_t v0 = m_state.v[0], v1 = m_state.v[1], v2 = m_state.v[2], v3 = m_state.v[3];

    uint64_t t = m_tmp | (((uint64_t)m_count) << 56);

    v3 ^= t;
    SIPROUND;
    SIPROUND;
    v0 ^= t;
    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

SipHasher13UJ::SipHasher13UJ(uint64_t k0, uint64_t k1) noexcept : m_state{k0, k1} {}

SipHasher13UJ& SipHasher13UJ::Write(uint64_t data) noexcept
{
    uint64_t v0 = m_state.v[0], v1 = m_state.v[1], v2 = m_state.v[2], v3 = m_state.v[3];

    v3 ^= data;
    SIPROUND;
    v0 ^= data;

    m_state.v[0] = v0;
    m_state.v[1] = v1;
    m_state.v[2] = v2;
    m_state.v[3] = v3;

    return *this;
}

SipHasher13UJ& SipHasher13UJ::WriteJumbo(const uint256& data) noexcept
{
    uint64_t v0 = m_state.v[0], v1 = m_state.v[1], v2 = m_state.v[2], v3 = m_state.v[3];

    v3 ^= data.GetUint64(0);
    v0 ^= data.GetUint64(1);
    v1 ^= data.GetUint64(2);
    v2 ^= data.GetUint64(3);
    SIPROUND;
    v0 ^= data.GetUint64(0);
    v1 ^= data.GetUint64(1);
    v2 ^= data.GetUint64(2);
    v3 ^= data.GetUint64(3);

    m_state.v[0] = v0;
    m_state.v[1] = v1;
    m_state.v[2] = v2;
    m_state.v[3] = v3;

    return *this;
}

uint64_t SipHasher13UJ::Finalize() const noexcept
{
    uint64_t v0 = m_state.v[0], v1 = m_state.v[1], v2 = m_state.v[2], v3 = m_state.v[3];

    v2 ^= SIPHASH_FINALIZER_UNPADDED;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t PresaltedSipHasher::operator()(const uint256& val) const noexcept
{
    uint64_t v0 = m_state.v[0], v1 = m_state.v[1], v2 = m_state.v[2], v3 = m_state.v[3];
    uint64_t d = val.GetUint64(0);
    v3 ^= d;

    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(1);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(2);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(3);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    v3 ^= (uint64_t{4}) << 59;
    SIPROUND;
    SIPROUND;
    v0 ^= (uint64_t{4}) << 59;
    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

/** Specialized implementation for efficiency */
uint64_t PresaltedSipHasher::operator()(const uint256& val, uint32_t extra) const noexcept
{
    uint64_t v0 = m_state.v[0], v1 = m_state.v[1], v2 = m_state.v[2], v3 = m_state.v[3];
    uint64_t d = val.GetUint64(0);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(1);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(2);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(3);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = ((uint64_t{36}) << 56) | extra;
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t PresaltedSipHasher13UJ::operator()(const uint256& val) const noexcept
{
    uint64_t v0 = m_state.v[0], v1 = m_state.v[1], v2 = m_state.v[2], v3 = m_state.v[3];

    const uint64_t d0 = val.GetUint64(0);
    const uint64_t d1 = val.GetUint64(1);
    const uint64_t d2 = val.GetUint64(2);
    const uint64_t d3 = val.GetUint64(3);
    v3 ^= d0;
    v0 ^= d1;
    v1 ^= d2;
    v2 ^= d3;
    SIPROUND;
    v0 ^= d0;
    v1 ^= d1;
    v2 ^= d2;
    v3 ^= d3;

    v2 ^= SIPHASH_FINALIZER_UNPADDED;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

/** Specialized implementation for efficiency */
uint64_t PresaltedSipHasher13UJ::operator()(const uint256& val, uint64_t extra) const noexcept
{
    uint64_t v0 = m_state.v[0], v1 = m_state.v[1], v2 = m_state.v[2], v3 = m_state.v[3];

    const uint64_t d0 = val.GetUint64(0);
    const uint64_t d1 = val.GetUint64(1);
    const uint64_t d2 = val.GetUint64(2);
    const uint64_t d3 = val.GetUint64(3);
    v3 ^= d0;
    v0 ^= d1;
    v1 ^= d2;
    v2 ^= d3;
    SIPROUND;
    v0 ^= d0;
    v1 ^= d1;
    v2 ^= d2;
    v3 ^= d3;

    v3 ^= extra;
    SIPROUND;
    v0 ^= extra;

    v2 ^= SIPHASH_FINALIZER_UNPADDED;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}
