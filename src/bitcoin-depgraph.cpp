// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <stdint.h>

#include <bit>
#include <tuple>

#include <random.h>
#include <compat/compat.h>
#include <util/feefrac.h>
#include <util/bitset.h>
#include <cluster_linearize.h>
#include <util/translation.h>

#include <iostream>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {


class Xoshiro256PP : public RandomMixin<InsecureRandomContext>
{
    uint64_t m_s0;
    uint64_t m_s1;
    uint64_t m_s2;
    uint64_t m_s3;

    [[nodiscard]] constexpr static uint64_t SplitMix64(uint64_t& seedval) noexcept
    {
        uint64_t z = (seedval += 0x9e3779b97f4a7c15);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

public:
    constexpr explicit Xoshiro256PP(uint64_t seedval) noexcept
        : m_s0(SplitMix64(seedval)),
          m_s1(SplitMix64(seedval)),
          m_s2(SplitMix64(seedval)),
          m_s3(SplitMix64(seedval)) {}

    constexpr void Reseed(uint64_t seedval) noexcept
    {
        FlushCache();
        m_s0 = SplitMix64(seedval);
        m_s1 = SplitMix64(seedval);
        m_s2 = SplitMix64(seedval);
        m_s3 = SplitMix64(seedval);
    }

    constexpr uint64_t rand64() noexcept
    {
        const uint64_t result = std::rotl(m_s0 + m_s3, 23) + m_s0;
        const uint64_t t = m_s1 << 17;
        m_s2 ^= m_s0;
        m_s3 ^= m_s1;
        m_s1 ^= m_s2;
        m_s0 ^= m_s3;
        m_s2 ^= t;
        m_s3 = std::rotl(m_s3, 45);
        return result;
    }
};

template<std::unsigned_integral SizeType, typename Key, typename Value>
class MathFuzzStore
{
    const SizeType m_dataset_size;
    Xoshiro256PP m_rng;
    static constexpr KEY_SIZE = std::tuple_size_v<Key>;
    static constexpr size_t MISSING = size_t(-1);

    struct Entry
    {
        Key key;
        Value value;
        std::vector<std::byte> input;
        std::array<SizeType, KEY_SIZE> pos;
    };

    std::vector<Entry> m_entries;

    std::map<Key, std::array<std::vector<size_t>, KEY_SIZE>> m_datasets;

public:
    MathFuzzer(size_t dataset_size, uint64_t rng_seed) : m_dataset_size(dataset_size), m_rng(rng_seed) {}

    unsigned Add(Key&& key, Value&& value, std::vector<std::byte> input) noexcept
    {
        
    }
}

template<typename Key, typename Value, typename Mutator>
class MathFuzzer
{
    const size_t m_dataset_size;
    Mutator m_mutator;
    Xoshiro256PP m_rng;
    static constexpr KEY_SIZE = std::tuple_size_v<Key>;


public:
    MathFuzzer(size_t dataset_size, uint64_t rng_seed) : m_dataset_size(dataset_size), m_rng(rng_seed), m_mutator(m_rng.rand64()) {}

    void Step() noexcept
    {
        
    }
};

} // namespace

MAIN_FUNCTION
{
}
