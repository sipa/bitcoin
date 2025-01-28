// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <stdint.h>

#include <bit>
#include <tuple>

#include <random.h>
#include <compat/compat.h>
#include <uint256.h>
#include <util/feefrac.h>
#include <util/bitset.h>
#include <cluster_linearize.h>
#include <util/translation.h>
#include <crypto/sha256.h>
#include <crypto/siphash.h>

#include <iostream>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

#define SIPROUND do { \
    v0 += v1; v1 = std::rotl(v1, 13); v1 ^= v0; \
    v0 = std::rotl(v0, 32); \
    v2 += v3; v3 = std::rotl(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = std::rotl(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = std::rotl(v1, 17); v1 ^= v2; \
    v2 = std::rotl(v2, 32); \
} while (0)

uint64_t SimpleSipHash13(const uint256& val, uint64_t e1, uint64_t e2) noexcept
{
    uint64_t v0 = 0x736f6d6570736575ULL;
    uint64_t v1 = 0x646f72616e646f6dULL;
    uint64_t v2 = 0x6c7967656e657261ULL;
    uint64_t v3 = 0x7465646279746573ULL;

    v3 ^= val.GetUint64(0);
    SIPROUND;
    v0 ^= val.GetUint64(0);
    v3 ^= val.GetUint64(1);
    SIPROUND;
    v0 ^= val.GetUint64(1);
    v3 ^= val.GetUint64(2);
    SIPROUND;
    v0 ^= val.GetUint64(2);
    v3 ^= val.GetUint64(3);
    SIPROUND;
    v0 ^= val.GetUint64(3);
    v3 ^= e1;
    SIPROUND;
    v0 ^= e1;
    v3 ^= e2;
    SIPROUND;
    v0 ^= e2;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

class Xoshiro256PP : public RandomMixin<InsecureRandomContext>
{
    uint64_t m_s0;
    uint64_t m_s1;
    uint64_t m_s2;
    uint64_t m_s3;

    [[nodiscard]] constexpr static inline uint64_t SplitMix64(uint64_t& seedval) noexcept
    {
        uint64_t z = (seedval += 0x9e3779b97f4a7c15);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

public:
    constexpr inline explicit Xoshiro256PP(uint64_t seedval) noexcept
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

    constexpr inline uint64_t rand64() noexcept
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
    static constexpr VALUE_SIZE = std::tuple_size_v<Value>;
    static constexpr SizeType MISSING_ENTRY = SizeType(-1);
    static constexpr size_t MISSING_POS = size_t(-1);
    static constexpr uint64_t K0 = 0x6ed7c7b1b2748d39;
    static constexpr uint64_t K1 = 0x2a6a1074578e5b8a;

    using MapType = std::map<Key, std::array<std::vector<size_t>, KEY_SIZE>>;
    MapType m_datasets;

    struct Entry
    {
        MapType::iterator key_it;
        Value value;
        uint256 hash;
        std::vector<std::byte> input;
        std::array<SizeType, KEY_SIZE> pos;
    };

    std::vector<Entry> m_entries;

    std::map<Key, std::array<std::vector<size_t>, KEY_SIZE>> m_datasets;

    static uint256 HashInput(const std::vector<std::byte>& input) noexcept
    {
        uint256 hash;
        CSHA256().Write((const uint8_t*)input.data(), input.size).Finalize(hash.data());
        return hash;
    }

public:
    MathFuzzer(size_t dataset_size, uint64_t rng_seed) :
        m_dataset_size(dataset_size),
        m_rng(rng_seed) {}

    unsigned Add(Key&& key, Value&& value, std::vector<std::byte> input) noexcept
    {

        auto& dataset = m_datasets[key];
        if (dataset[0].size() == 0) {
            for (unsigned i = 0; i < KEY_SIZE; ++i) {
                dataset[i].resize(m_dataset_size);
            }
        }

        std::optional<uint256> hash;
        SizeType idx[KEY_SIZE];
        bool store[KEY_SIZE];
        bool any_store = false;
        for (unsigned i = 0; i < _SIZE; ++i) {
            idx[i] = m_rng.randrange(m_dataset_size);
            if (dataset[i][idx[i]] == MISSING) {
                store[i] = true;
            } else {
                auto& old_entry = m_entries[dataset[i][idx[i]]];
                if (std::get<i>(value) != std::get<i>(old_entry.value)) {
                    store[i] = (std::get<i>(value) > std::get<i>(old_entry.value));
                } else if (m_rng.randbool()) {
                    if (!hash.has_value()) hash = HashInput(input);
                    auto old_rand = SimpleSipHash13(old_entry.hash, i, idx[i]);
                    auto new_rand = SimpleSipHash13(*hash, i, idx[i]);
                    store[i] = (new_rand < old_rand);
                }
            }
            any_store = any_store || store[i];
        }
        if (!any_store) return;
        if (!hash.has_value()) hash = HashInput(input);
        auto new_entry = m_entries.emplace_back();
        new_entry->key = std::move(key);
        new_entry->value = std::move(value);
        new_entry->hash = std::move(*hash);
        new_entry->input = std::move(input);
        for (unsigned i = 0; i < KEY_SIZE;

            if (std::get<i>(value) > dataset[i][idx[i]]) {
                store = true;
            } else 
        }
        
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
