// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <span.h>
#include <test/fuzz/util.h>
#include <util/bitset.h>

#include <bitset>
#include <vector>

namespace {

/** Pop the first byte from a Span<const uint8_t>, and return it. */
uint8_t ReadByte(Span<const uint8_t>& buffer)
{
    if (buffer.empty()) return 0;
    uint8_t ret = buffer.front();
    buffer = buffer.subspan(1);
    return ret;
}

/** Perform a simulation fuzz test on BitSet type S. */
template<typename S>
void TestType(Span<const uint8_t> buffer)
{
    using Sim = std::bitset<S::MAX_SIZE>;
    // Up to four real BitSets.
    std::vector<S> real;
    // Up to four std::bitsets with the same corresponding contents.
    std::vector<Sim> sim;

    /* Compare sim[idx] with real[idx], using all inspector operations. */
    auto compare_fn = [&](unsigned idx) {
        /* iterators and operator[] */
        auto it = real[idx].begin();
        unsigned first = S::MAX_SIZE;
        for (unsigned i = 0; i < S::MAX_SIZE; ++i) {
            bool match = (it != real[idx].end()) && *it == i;
            assert(sim[idx][i] == real[idx][i]);
            assert(match == real[idx][i]);
            assert((it == real[idx].end()) != (it != real[idx].end()));
            if (match) {
                ++it;
                if (first == S::MAX_SIZE) first = i;
            }
        }
        assert(it == real[idx].end());
        assert(!(it != real[idx].end()));
        /* IsEmpty */
        assert(sim[idx].none() == real[idx].IsEmpty());
        /* First */
        if (sim[idx].any()) {
            assert(first == real[idx].First());
        }
        /* Count */
        assert(sim[idx].count() == real[idx].Count());
    };

    LIMITED_WHILE(buffer.size() > 0, 1000) {
        unsigned command = ReadByte(buffer) % 15;
        unsigned args = ReadByte(buffer);
        unsigned dest = args & 3, src = (args >> 2) & 3, aux = (args >> 4) & 3;
        if (sim.size()) {
            dest = dest % sim.size();
            src = (dest + src + 1) % sim.size();
            aux = (src + aux + 1) % sim.size();
        }
        if (command == 0) {
            /* Add */
            unsigned val = ReadByte(buffer) % S::MAX_SIZE;
            if (dest < sim.size()) {
                assert(sim[dest][val] == real[dest][val]);
                sim[dest][val] = true;
                real[dest].Add(val);
            }
        } else if (command == 1) {
            /* Remove */
            unsigned val = ReadByte(buffer) % S::MAX_SIZE;
            if (dest < sim.size()) {
                assert(sim[dest][val] == real[dest][val]);
                sim[dest][val] = false;
                real[dest].Remove(val);
            }
        } else if (command == 2) {
            /* Construct empty. */
            if (sim.size() < 4) {
                sim.resize(sim.size() + 1);
                real.resize(real.size() + 1);
            }
        } else if (command == 3) {
            /* Destruct. */
            if (!sim.empty()) {
                compare_fn(sim.size() - 1);
                sim.pop_back();
                real.pop_back();
            }
        } else if (command == 4) {
            /* Copy construct. */
            if (sim.size() < 4 && src < sim.size()) {
                sim.emplace_back(sim[src]);
                real.emplace_back(real[src]);
            }
        } else if (command == 5) {
            /* Copy assign. */
            if (src < sim.size() && dest < sim.size()) {
                compare_fn(dest);
                sim[dest] = sim[src];
                real[dest] = real[src];
            }
        } else if (command == 6) {
            /* Full construct + copy assign. */
            unsigned len = ReadByte(buffer) % S::MAX_SIZE;
            if (dest < sim.size()) {
                compare_fn(dest);
                sim[dest].reset();
                for (unsigned i = 0; i < len; ++i) sim[dest][i] = true;
                real[dest] = S::Full(len);
            }
        } else if (command == 7) {
            /* Iterator copy based compare. */
            unsigned val = ReadByte(buffer) % S::MAX_SIZE;
            if (src < sim.size()) {
                /* In a first loop, compare begin..end, and copy to it_copy at some point. */
                auto it = real[src].begin(), it_copy = it;
                for (unsigned i = 0; i < S::MAX_SIZE; ++i) {
                    if (i == val) it_copy = it;
                    bool match = (it != real[src].end()) && *it == i;
                    assert(match == sim[src][i]);
                    if (match) ++it;
                }
                assert(it == real[src].end());
                /* Then compare from the copied point again to end. */
                for (unsigned i = val; i < S::MAX_SIZE; ++i) {
                    bool match = (it_copy != real[src].end()) && *it_copy == i;
                    assert(match == sim[src][i]);
                    if (match) ++it_copy;
                }
                assert(it_copy == real[src].end());
            }
        } else if (command == 8) {
            /* operator|= */
            if (src < sim.size() && dest < sim.size()) {
                compare_fn(dest);
                sim[dest] |= sim[src];
                real[dest] |= real[src];
            }
        } else if (command == 9) {
            /* operator&= */
            if (src < sim.size() && dest < sim.size()) {
                compare_fn(dest);
                sim[dest] &= sim[src];
                real[dest] &= real[src];
            }
        } else if (command == 10) {
            /* operator| */
            if (src < sim.size() && dest < sim.size() && aux < sim.size()) {
                compare_fn(dest);
                sim[dest] = sim[src] | sim[aux];
                real[dest] = real[src] | real[aux];
            }
        } else if (command == 11) {
            /* operator& */
            if (src < sim.size() && dest < sim.size() && aux < sim.size()) {
                compare_fn(dest);
                sim[dest] = sim[src] & sim[aux];
                real[dest] = real[src] & real[aux];
            }
        } else if (command == 12) {
            /* operator/ */
            if (src < sim.size() && dest < sim.size() && aux < sim.size()) {
                compare_fn(dest);
                sim[dest] = sim[src] & ~sim[aux];
                real[dest] = real[src] / real[aux];
            }
        } else if (command == 13) {
            /* operator>> and operator<< */
            if (src < sim.size() && aux < sim.size()) {
                bool res = (sim[aux] & ~sim[src]).none();
                assert((real[src] >> real[aux]) == res);
                assert((real[aux] << real[src]) == res);
            }
        } else if (command == 14) {
            /* operator== and operator!= */
            if (src < sim.size() && aux < sim.size()) {
                assert((sim[src] == sim[aux]) == (real[src] == real[aux]));
                assert((sim[src] != sim[aux]) == (real[src] != real[aux]));
            }
        }
    }

    /* Fully compare the final state. */
    for (unsigned i = 0; i < sim.size(); ++i) {
        compare_fn(i);
    }
}

} // namespace

FUZZ_TARGET(bitset)
{
    unsigned typdat = ReadByte(buffer) % 16;
    if (typdat == 0) {
        /* 16 bits */
        TestType<bitset_detail::IntBitSet<uint16_t>>(buffer);
        TestType<bitset_detail::MultiIntBitSet<uint16_t, 1>>(buffer);
    } else if (typdat == 1) {
        /* 32 bits */
        TestType<bitset_detail::MultiIntBitSet<uint16_t, 2>>(buffer);
        TestType<bitset_detail::IntBitSet<uint32_t>>(buffer);
    } else if (typdat == 2) {
        /* 48 bits */
        TestType<bitset_detail::MultiIntBitSet<uint16_t, 3>>(buffer);
    } else if (typdat == 3) {
        /* 64 bits */
        TestType<bitset_detail::IntBitSet<uint64_t>>(buffer);
        TestType<bitset_detail::MultiIntBitSet<uint64_t, 1>>(buffer);
        TestType<bitset_detail::MultiIntBitSet<uint32_t, 2>>(buffer);
        TestType<bitset_detail::MultiIntBitSet<uint16_t, 4>>(buffer);
    } else if (typdat == 4) {
        /* 96 bits */
        TestType<bitset_detail::MultiIntBitSet<uint32_t, 3>>(buffer);
    } else if (typdat == 5) {
        /* 128 bits */
        TestType<bitset_detail::MultiIntBitSet<uint64_t, 2>>(buffer);
        TestType<bitset_detail::MultiIntBitSet<uint32_t, 4>>(buffer);
    } else if (typdat == 6) {
        /* 192 bits */
        TestType<bitset_detail::MultiIntBitSet<uint64_t, 3>>(buffer);
    } else if (typdat == 7) {
        /* 256 bits */
        TestType<bitset_detail::MultiIntBitSet<uint64_t, 4>>(buffer);
    }
}
