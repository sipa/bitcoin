// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BITPACK_H
#define BITCOIN_UTIL_BITPACK_H

#include <vector>

#include <stdint.h>

class BitPack
{
    std::vector<uint64_t> m_data;

public:
    BitPack(size_t size) : m_data((size + 63) / 64, false) {}

    uint64_t Read(const unsigned bits, const size_t pos) const
    {
        if (bits == 0) return 0;
        const size_t index_begin = pos / 64;
        const size_t index_end = (pos + bits - 1) / 64;
        const unsigned offset = pos & 63;
        if (index_begin == index_end) {
            return (m_data[index_begin] << (64 - bits - offset)) >> (64 - bits);
        } else {
            return (m_data[index_begin] >> offset) | ((m_data[index_end] << (128 - bits - offset)) >> (64 - bits));
        }
    }

    void Write(const unsigned bits, const size_t pos, const uint64_t val)
    {
        if (bits == 0) return;
        const size_t index_begin = pos / 64;
        const size_t index_end = (pos + bits - 1) / 64;
        const unsigned offset = pos & 63;
        if (index_begin == index_end) {
            uint64_t mask = ((0xFFFFFFFFFFFFFFFF >> offset) << (64 - bits)) >> (64 - bits - offset);
            m_data[index_begin] = (m_data[index_begin] & ~mask) | (val << offset);
        } else {
            m_data[index_begin] = ((m_data[index_begin] << (64 - offset)) >> (64 - offset)) | (val << offset);
            m_data[index_end] = ((m_data[index_end] >> (bits + offset - 64)) << (bits + offset - 64)) | (val >> (64 - offset));
        }
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
        return (m_data[pos / 64] >> (pos & 63)) & 1;
    }
};

#endif // BITCOIN_UTIL_BITPACK_H
