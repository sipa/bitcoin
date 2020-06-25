// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BITPACK_H
#define BITCOIN_UTIL_BITPACK_H

#include <crypto/common.h>

#include <vector>

#include <stdint.h>

class BitPack
{
    std::vector<uint8_t> m_data;

public:
    BitPack(size_t size) : m_data((size + 63) / 8, false) {}

    uint64_t Read(const unsigned bits, const size_t pos) const
    {
        return (ReadLE64(m_data.data() + (pos >> 3)) << (64 - bits - (pos & 7))) >> (64 - bits);
    }

    void Write(const unsigned bits, const size_t pos, const uint64_t val)
    {
        uint8_t* ptr = m_data.data() + (pos >> 3);
        unsigned offset = pos & 7;
        uint64_t data = ReadLE64(ptr);
        uint64_t mask = (0xFFFFFFFFFFFFFFFF >> (64 - bits)) << offset;
        WriteLE64(ptr, (data & ~mask) | (val << offset));
    }

    uint64_t ReadAndAdvance(const unsigned bits, size_t& pos) const
    {
        uint64_t ret = Read(bits, pos);
        pos += bits;
        return ret;
    }

    void WriteAndAdvance(const unsigned bits, size_t& pos, const uint64_t val)
    {
        Write(bits, pos, val);
        pos += bits;
    }

    bool GetBit(const size_t pos) const
    {
        return (m_data[pos / 8] >> (pos & 7)) & 1;
    }

    void Prefetch(const size_t pos) const
    {
        __builtin_prefetch(m_data.data() + (pos >> 3), 0, 1);
    }
};

#endif // BITCOIN_UTIL_BITPACK_H
