// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/bitpack.h>

#include <test/fuzz/fuzz.h>

#include <vector>

#include <assert.h>
#include <stdint.h>

FUZZ_TARGET(bitpack)
{
    if (buffer.size() < 1) return;

    unsigned count = buffer[0] + 1;
    BitPack pack(count);
    std::vector<bool> vec(count, false);

    auto it = buffer.begin() + 1;
    while (it != buffer.end()) {
        if (buffer.end() - it < 3) return;

        size_t offset = ((*(it)) + uint16_t{*(it + 1)}) % count;
        unsigned bits = std::min<unsigned>(count - offset, (((*(it + 2)) >> 1) & 63) + 1);
        bool write = *(it + 2) & 1;
        it += 3;

        if (write) {
            if (buffer.end() - it < bits) return;
            uint64_t val = 0;
            for (unsigned pos = 0; pos < bits; ++pos) {
                bool bit = *(it++) & 1;
                vec[offset + pos] = bit;
                val |= (uint64_t{bit} << pos);
            }
            pack.Write(bits, offset, val);
        } else {
            uint64_t read = pack.Read(bits, offset);
            for (unsigned pos = 0; pos < bits; ++pos) {
                assert(((read >> pos) & 1) == vec[offset + pos]);
            }
        }
    }

    for (unsigned pos = 0; pos < count; ++pos) {
        assert(vec[pos] == pack.GetBit(pos));
    }
}
