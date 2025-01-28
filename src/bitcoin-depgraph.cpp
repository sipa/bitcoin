// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <stdint.h>

#include <bit>
#include <map>
#include <span>
#include <tuple>

#include <random.h>
#include <compat/compat.h>
#include <uint256.h>
#include <util/check.h>
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

uint64_t SimpleSipHash13(uint64_t k0, uint64_t k1, const uint256& val) noexcept
{
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

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
    {
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

template<std::unsigned_integral PosType, typename Key, typename Value>
class MathFuzzStore
{
    const PosType m_dataset_size;
    Xoshiro256PP m_rng;
    static constexpr auto VALUE_SIZE = std::tuple_size_v<Value>;
    static constexpr PosType MISSING_POS = PosType(-1);
    static constexpr size_t MISSING_ENTRY_IDX = size_t(-1);

    struct DataSet
    {
        static_assert(std::numeric_limits<PosType>::radix == 2);
        static constexpr auto POS_BITS = std::numeric_limits<PosType>::digits;

        uint64_t pos_k0{0}, pos_k1{0};
        uint64_t rank_k0{0}, rank_k1{0};
        std::vector<size_t> entry_idx;

        DataSet() noexcept = default;

        DataSet(PosType dataset_size, Xoshiro256PP& rng) noexcept
        {
            pos_k0 = rng.rand64();
            rank_k0 = rng.rand64();
            pos_k1 = rng.rand64();
            rank_k1 = rng.rand64();
            entry_idx.assign(dataset_size, MISSING_ENTRY_IDX);
        }

        PosType Pos(PosType dataset_size, const uint256& hash) noexcept
        {
            return ((SimpleSipHash13(pos_k0, pos_k1, hash) >> POS_BITS) * dataset_size) >> (64 - POS_BITS);
        }

        uint64_t Rank(const uint256& hash) noexcept
        {
            return SimpleSipHash13(rank_k0, rank_k1, hash);
        }

        inline size_t& operator[](PosType pos) noexcept { return entry_idx[pos]; }
        inline size_t operator[](PosType pos) const noexcept { return entry_idx[pos]; }
    };

    using MapType = std::map<Key, std::array<DataSet, VALUE_SIZE>>;
    MapType m_datasets;

    struct Entry
    {
        MapType::iterator key_it;
        Value value;
        uint256 hash;
        std::vector<std::byte> input;
        std::array<PosType, VALUE_SIZE> pos;
    };

    std::vector<Entry> m_entries;

    static uint256 HashInput(const std::vector<std::byte>& input) noexcept
    {
        uint256 hash;
        CSHA256().Write((const uint8_t*)input.data(), input.size()).Finalize(hash.data());
        return hash;
    }

    void Swap(size_t idx1, size_t idx2) noexcept
    {
        auto& entry1 = m_entries[idx1];
        auto& entry2 = m_entries[idx2];
        std::swap(entry1, entry2);
        for (unsigned i = 0; i < VALUE_SIZE; ++i) {
            if (entry1.pos[i] != MISSING_POS) entry1.key_it->second[i][entry1.pos[i]] = idx1;
            if (entry2.pos[i] != MISSING_POS) entry2.key_it->second[i][entry2.pos[i]] = idx2;
        }
    }

    void Clear(size_t idx, unsigned value_idx) noexcept
    {
        auto& entry = m_entries[idx];
        Assume(entry.pos[value_idx] != MISSING_POS);
        entry.key_it->second[value_idx][entry.pos[value_idx]] = MISSING_ENTRY_IDX;
        entry.pos[value_idx] = MISSING_POS;
        bool survives{false};
        for (unsigned i = 0; i < VALUE_SIZE; ++i) {
            if (entry.pos[i] != MISSING_POS) survives = true;
        }
        if (!survives) {
            if (idx != m_entries.size() - 1) Swap(idx, m_entries.size() - 1);
            m_entries.pop_back();
        }
    }

    unsigned AddHashed(Key&& key, Value&& value, std::vector<std::byte>&& input, const uint256& hash) noexcept
    {
        auto [dataset_it, added] = m_datasets.try_emplace(std::move(key));
        auto& dataset = dataset_it->second;
        if (added) {
            for (unsigned i = 0; i < VALUE_SIZE; ++i) {
                dataset[i] = DataSet(m_dataset_size, m_rng);
            }
        }

        PosType pos[VALUE_SIZE];
        bool store[VALUE_SIZE];
        bool any_store = false;
        for (unsigned i = 0; i < VALUE_SIZE; ++i) {
            pos[i] = dataset[i].Pos(m_dataset_size, hash);
            auto old_entry_idx = dataset[i][pos[i]];
            if (old_entry_idx == MISSING_ENTRY_IDX) {
                store[i] = true;
            } else {
                auto& old_entry = m_entries[old_entry_idx];
                if (value[i] != old_entry.value[i]) {
                    store[i] = value[i] > old_entry.value[i];
                } else if (m_rng.randbool()) {
                    auto old_rank = dataset[i].Rank(old_entry.hash);
                    auto new_rank = dataset[i].Rank(hash);
                    store[i] = (new_rank > old_rank);
                }
                if (store[i]) Clear(old_entry_idx, i);
            }
            any_store = any_store || store[i];
        }
        if (!any_store) return 0;
        auto new_entry_pos = m_entries.size();
        auto& new_entry = m_entries.emplace_back();
        new_entry.key_it = dataset_it;
        new_entry.value = std::move(value);
        new_entry.hash = hash;
        new_entry.input = std::move(input);
        unsigned ret{0};
        for (unsigned i = 0; i < VALUE_SIZE; ++i) {
            if (store[i]) {
                new_entry.pos[i] = pos[i];
                dataset[i][pos[i]] = new_entry_pos;
                ++ret;
            } else {
                new_entry.pos[i] = MISSING_POS;
            }
        }
        return ret;
    }

public:
    MathFuzzStore(size_t dataset_size, uint64_t rng_seed) :
        m_dataset_size(dataset_size),
        m_rng(rng_seed) {}


    unsigned Add(Key&& key, Value&& value, std::vector<std::byte>&& input) noexcept
    {
        uint256 hash = HashInput(input);
        return AddHashed(std::move(key), std::move(value), std::move(input), hash);
    }

    std::span<const std::byte> Get() noexcept
    {
        return m_entries[m_rng.randrange(m_entries.size())].input;
    }

    void SanityCheck() const noexcept
    {
        size_t sum_entry_counts{0};
        std::vector<const std::array<DataSet, VALUE_SIZE>*> entry_datasets;
        for (size_t entry_idx = 0; entry_idx < m_entries.size(); ++entry_idx) {
            const auto& entry = m_entries[entry_idx];
            assert(entry.hash == HashInput(entry.input));
            entry_datasets.push_back(&entry.key_it->second);
            for (unsigned i = 0; i < VALUE_SIZE; ++i) {
                if (entry.pos[i] != MISSING_POS) {
                    assert(entry.key_it->second[i][entry.pos[i]] == entry_idx);
                    ++sum_entry_counts;
                }
            }
        }

        size_t sum_pos_counts{0};
        std::vector<const std::array<DataSet, VALUE_SIZE>*> pos_datasets;
        for (const auto& [key, datasets] : m_datasets) {
            pos_datasets.push_back(&datasets);
            for (unsigned i = 0; i < VALUE_SIZE; ++i) {
                assert(datasets[i].entry_idx.size() == m_dataset_size);
                for (PosType pos = 0; pos < m_dataset_size; ++pos) {
                    if (datasets[i][pos] != MISSING_ENTRY_IDX) {
                        assert(m_entries[datasets[i][pos]].pos[i] == pos);
                        ++sum_pos_counts;
                    }
                }
            }
        }
        assert(sum_entry_counts == sum_pos_counts);

        std::sort(entry_datasets.begin(), entry_datasets.end());
        entry_datasets.erase(std::unique(entry_datasets.begin(), entry_datasets.end()), entry_datasets.end());
        std::sort(pos_datasets.begin(), pos_datasets.end());
        assert(entry_datasets == pos_datasets);
    }

    size_t size() const noexcept { return m_entries.size(); }
};

} // namespace

MAIN_FUNCTION
{
    using KeyType = uint8_t;
    using ValueType = std::array<uint16_t, 2>;
    using PosType = uint16_t;
    MathFuzzStore<PosType, KeyType, ValueType> store(1000, 11);
    Xoshiro256PP rng(1111);
    for (int i = 0; i < 10000000; ++i) {
        int bits = rng.randrange(20);
        uint32_t val = rng.randbits(bits);
        std::vector<std::byte> data((bits + 7) / 8);
        for (unsigned byte = 0; byte < data.size(); ++byte) {
            data[byte] = std::byte(val >> (8 * byte));
        }
        uint8_t key = (std::rotl<uint32_t>(std::rotl<uint32_t>(std::rotl<uint32_t>(val * 1651584489, 15) * 562543487, 17) * 6142148373, 15) * 212547481) >> 24;
        uint16_t val1 = (std::rotl<uint32_t>(std::rotl<uint32_t>(std::rotl<uint32_t>(val * 2741282479, 15) * 362143881, 17) * 52365481, 15) * 3115747417) >> 16;
        uint16_t val2 = (std::rotl<uint32_t>(std::rotl<uint32_t>(std::rotl<uint32_t>(val * 3631264657, 15) * 162144853, 17) * 52165483, 15) * 175757415) >> 16;
        ValueType value{val1, val2};
        store.Add(std::move(key), std::move(value), std::move(data));
        store.Get();
    }
    store.SanityCheck();
    std::cerr << store.size() << "\n";
    return 0;
}
