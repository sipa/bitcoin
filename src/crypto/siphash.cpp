// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/siphash.h>

#include <uint256.h>

#include <cassert>
#include <span>

using siphash_detail::Compress1;
using siphash_detail::Compress2;
using siphash_detail::Finalize3U;
using siphash_detail::Finalize4;

CSipHasher::CSipHasher(uint64_t k0, uint64_t k1) : m_state{k0, k1} {}

CSipHasher& CSipHasher::Write(uint64_t data)
{
    uint64_t v0{m_state.v[0]}, v1{m_state.v[1]}, v2{m_state.v[2]}, v3{m_state.v[3]};

    assert(m_count % 8 == 0);

    Compress2(v0, v1, v2, v3, data);

    m_state.v[0] = v0; m_state.v[1] = v1; m_state.v[2] = v2; m_state.v[3] = v3;

    m_count += 8;
    return *this;
}

CSipHasher& CSipHasher::Write(std::span<const unsigned char> data)
{
    uint64_t v0{m_state.v[0]}, v1{m_state.v[1]}, v2{m_state.v[2]}, v3{m_state.v[3]};
    uint64_t t{m_tmp};
    uint8_t c{m_count};

    while (data.size() > 0) {
        t |= uint64_t{data.front()} << (8 * (c % 8));
        c++;
        if ((c & 7) == 0) {
            Compress2(v0, v1, v2, v3, t);
            t = 0;
        }
        data = data.subspan(1);
    }

    m_state.v[0] = v0; m_state.v[1] = v1; m_state.v[2] = v2; m_state.v[3] = v3;
    m_count = c;
    m_tmp = t;

    return *this;
}

uint64_t CSipHasher::Finalize() const
{
    uint64_t v0{m_state.v[0]}, v1{m_state.v[1]}, v2{m_state.v[2]}, v3{m_state.v[3]};
    Compress2(v0, v1, v2, v3, m_tmp | (uint64_t{m_count} << 56));
    return Finalize4(v0, v1, v2, v3);
}

SipHasher13UJ& SipHasher13UJ::Write(uint64_t data) noexcept
{
    Compress1(m_state.v[0], m_state.v[1], m_state.v[2], m_state.v[3], data);
    return *this;
}

SipHasher13UJ& SipHasher13UJ::WriteJumbo(const uint256& hash) noexcept
{
    Compress1(m_state.v[0], m_state.v[1], m_state.v[2], m_state.v[3], hash);
    return *this;
}

uint64_t SipHasher13UJ::Finalize() const noexcept
{
    return Finalize3U(m_state.v[0], m_state.v[1], m_state.v[2], m_state.v[3]);
}

uint64_t PresaltedSipHasher::operator()(const uint256& val) const noexcept
{
    uint64_t v0{m_state.v[0]}, v1{m_state.v[1]}, v2{m_state.v[2]}, v3{m_state.v[3]};
    Compress2(v0, v1, v2, v3, val.GetUint64(0));
    Compress2(v0, v1, v2, v3, val.GetUint64(1));
    Compress2(v0, v1, v2, v3, val.GetUint64(2));
    Compress2(v0, v1, v2, v3, val.GetUint64(3));
    Compress2(v0, v1, v2, v3, uint64_t{4} << 59);
    return Finalize4(v0, v1, v2, v3);
}

/** Specialized implementation for efficiency */
uint64_t PresaltedSipHasher::operator()(const uint256& val, uint32_t extra) const noexcept
{
    uint64_t v0{m_state.v[0]}, v1{m_state.v[1]}, v2{m_state.v[2]}, v3{m_state.v[3]};
    Compress2(v0, v1, v2, v3, val.GetUint64(0));
    Compress2(v0, v1, v2, v3, val.GetUint64(1));
    Compress2(v0, v1, v2, v3, val.GetUint64(2));
    Compress2(v0, v1, v2, v3, val.GetUint64(3));
    Compress2(v0, v1, v2, v3, (uint64_t{36} << 56) | extra);
    return Finalize4(v0, v1, v2, v3);
}
