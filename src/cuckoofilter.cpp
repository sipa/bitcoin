// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuckoofilter.h>

#include <crypto/common.h>
#include <crypto/siphash.h>
#include <random.h>
#include <util/bitpack.h>
#include <util/int_utils.h>

#include <algorithm>
#include <array>
#include <cmath>

#include <assert.h>
#include <stdint.h>

#include <map>
#include <set>

namespace {

inline uint32_t ReduceOnce(uint32_t x, uint32_t m) { return (x < m) ? x : x - m; }
inline uint32_t SubtractMod(uint32_t x, uint32_t y, uint32_t m) { return ReduceOnce(x + m - y, m); }

RollingCuckooFilter::Params ChooseParams(uint32_t window, unsigned fpbits, double alpha, int max_access)
{
    static constexpr unsigned GEN_BITS[] = {3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    bool have_ret = false;
    RollingCuckooFilter::Params ret;
    if (fpbits < 10) fpbits = 10;
    for (unsigned gen_bits : GEN_BITS) {
        RollingCuckooFilter::Params params;
        params.m_fpr_bits = fpbits + 1 + RollingCuckooFilter::BUCKET_BITS;
        params.m_gen_bits = gen_bits;
        unsigned gens = params.Generations();
        uint64_t gen_size = (uint64_t{window} + gens - 2) / (gens - 1);
        if (gen_size > 0xFFFFFFFF) continue;
        params.m_gen_size = gen_size;
        uint64_t max_used = params.MaxEntries();
        uint64_t table_size = std::ceil(std::max(64.0, max_used / std::min(alpha, max_used < 1024 ? 0.9 : 0.95)));
        uint64_t buckets = ((table_size + 2 * RollingCuckooFilter::BUCKET_SIZE - 1) >> (1 + RollingCuckooFilter::BUCKET_BITS)) << 1;
        if (buckets > 0x7FFFFFFF) continue;
        params.m_buckets = buckets;
        if (!have_ret || params.TableBits() < ret.TableBits()) {
            ret = params;
            have_ret = true;
        }
    }
    assert(have_ret);
    if (max_access) {
        ret.m_max_kicks = max_access;
    } else {
        double real_alpha = (double)ret.m_gen_size * ret.Generations() / (ret.m_buckets << RollingCuckooFilter::BUCKET_BITS);
        if (real_alpha < 0.850001) {
            ret.m_max_kicks = std::ceil(std::max(16.0, 2.884501 * std::log(window) - 2.0));
        } else if (real_alpha < 0.900001) {
            ret.m_max_kicks = std::ceil(std::max(29.0, 5.104926 * std::log(window) - 5.0));
        } else if (real_alpha < 0.950001) {
            ret.m_max_kicks = std::ceil(std::max(125.0, 18.75451 * std::log(window) - 25.0));
        }
    }
    return ret;
}

} // namespace

bool RollingCuckooFilter::IsActive(uint32_t gen) const
{
    if (m_this_gen >= gen && m_this_gen < gen + m_gens) return true;
    if (gen > m_gens && m_this_gen < gen - m_gens) return true;
    return false;
}

RollingCuckooFilter::RollingCuckooFilter(uint32_t window, unsigned fpbits, double alpha, int max_access, bool deterministic) :
    RollingCuckooFilter(ChooseParams(window, fpbits, alpha, max_access), deterministic) {}

RollingCuckooFilter::RollingCuckooFilter(const Params& params, bool deterministic) :
    m_params(params),
    m_bits_per_bucket(params.BucketBits()),
    m_gens(params.Generations()),
    m_max_entries(params.MaxEntries()),
    m_rng(deterministic),
    m_phi_k0(m_rng.rand64()), m_phi_k1(m_rng.rand64()), m_h1_k0(m_rng.rand64()), m_h1_k1(m_rng.rand64()),
    m_data(size_t{m_params.m_buckets} * m_bits_per_bucket)
{
/*
    // Self test bucket encoder/decoder (needs commenting out "Wipe expired entries")
    for (unsigned i = 0; i < 1000; ++i) {
        uint32_t index = m_rng.randrange(m_params.m_buckets);
        DecodedBucket bucket;
        for (unsigned j = 0; j < BUCKET_SIZE; ++j) {
            bucket.m_entries[j].m_fpr = m_rng.randbits(m_params.m_fpr_bits);
        }
        bucket.m_entries[0].m_gen = m_rng.randrange(2 * m_gens);
        bucket.m_entries[1].m_gen = ReduceOnce(bucket.m_entries[0].m_gen + m_rng.randrange(m_gens), 2 * m_gens);
        bucket.m_entries[2].m_gen = ReduceOnce(bucket.m_entries[0].m_gen + m_rng.randrange(m_gens), 2 * m_gens);
        bucket.m_entries[3].m_gen = ReduceOnce(bucket.m_entries[0].m_gen + m_rng.randrange(m_gens), 2 * m_gens);
        Shuffle(std::begin(bucket.m_entries), std::end(bucket.m_entries), m_rng);
        std::set<std::pair<uint64_t, unsigned>> entries_a, entries_b;
        for (unsigned j = 0; j < BUCKET_SIZE; ++j) {
            printf("Entries A: %llu %lu\n", (unsigned long long)bucket.m_entries[j].m_fpr, (unsigned long)bucket.m_entries[j].m_gen);
            entries_a.emplace(bucket.m_entries[j].m_fpr, bucket.m_entries[j].m_gen);
        }
        SaveBucket(index, std::move(bucket));
        bucket = DecodedBucket{};
        bucket = LoadBucket(index);
        for (unsigned j = 0; j < BUCKET_SIZE; ++j) {
            printf("Entries B: %llu %lu\n", (unsigned long long)bucket.m_entries[j].m_fpr, (unsigned long)bucket.m_entries[j].m_gen);
            entries_b.emplace(bucket.m_entries[j].m_fpr, bucket.m_entries[j].m_gen);
        }
        printf("\n");
        assert(entries_a == entries_b);
    }
*/
}

RollingCuckooFilter::DecodedBucket RollingCuckooFilter::LoadBucket(uint32_t index) const
{
    DecodedBucket bucket;
    uint64_t offset = uint64_t{index} * m_bits_per_bucket;
    uint32_t gen_shift = 0;
    int num = 0;
    for (unsigned pos = 0; pos < BUCKET_SIZE; ++pos) {
        bucket.m_entries[pos].m_fpr = m_data.ReadAndAdvance(m_params.m_fpr_bits, offset);
        if (bucket.m_entries[pos].m_fpr == 0) break;
        ++num;
        bucket.m_entries[pos].m_gen = m_data.ReadAndAdvance(m_params.m_gen_bits, offset);
    }

    bucket.m_num_entries = num;

    return bucket;
}

void RollingCuckooFilter::SaveBucket(uint32_t index, DecodedBucket&& bucket)
{
    // Wipe expired entries
    unsigned pos =0;
    while (pos < bucket.m_num_entries) {
        if (!IsActive(bucket.m_entries[pos].m_gen)) {
            --bucket.m_num_entries;
            bucket.m_entries[pos].m_fpr = 0;
            std::swap(bucket.m_entries[pos], bucket.m_entries[bucket.m_num_entries]);
        } else {
            ++pos;
        }
    }

    pos = 0;
    uint64_t offset = uint64_t{index} * m_bits_per_bucket;
    while (pos < bucket.m_num_entries) {
        m_data.WriteAndAdvance(m_params.m_fpr_bits, offset, bucket.m_entries[pos].m_fpr);
        m_data.WriteAndAdvance(m_params.m_gen_bits, offset, bucket.m_entries[pos].m_gen);
        ++pos;
    }
    if (bucket.m_num_entries != BUCKET_SIZE) m_data.WriteAndAdvance(m_params.m_fpr_bits, offset, 0);
}

uint64_t RollingCuckooFilter::Fingerprint(Span<const unsigned char> data) const
{
    uint64_t hash = CSipHasher(m_phi_k0, m_phi_k1).Write(data.data(), data.size()).Finalize();
    return MapIntoRange(hash, 0xFFFFFFFFFFFFFFFF >> (64 - m_params.m_fpr_bits)) + 1U;
}

uint32_t RollingCuckooFilter::Index1(Span<const unsigned char> data) const
{
    uint64_t hash = CSipHasher(m_h1_k0, m_h1_k1).Write(data.data(), data.size()).Finalize();
    return MapIntoRange(hash, m_params.m_buckets);
}

uint32_t RollingCuckooFilter::OtherIndex(uint32_t index, uint64_t fpr) const
{
    // Map fpr approximately uniformly to range 1..m_buckets-1. This expression works well in simulations.
    uint64_t a = 1 + (((fpr & 0xFFFFFFFF) * (m_params.m_buckets - 1) + 1) >> std::min(32U, m_params.m_fpr_bits));

    // We need an operation $ such that other_index = a $ index. If the number of buckets is
    // a power of two, XOR can be used. However, all we need is:
    // - If a != 0, (a $ x != x); otherwise an entry would only have one location
    // - (a $ (a $ x) == x); otherwise we would not be able to recover the first index from the second
    // - If x != y, an a exists such that (a $ x = y); guarantees uniformity
    //
    // These properties together imply that $ defines a quasigroup with left identity 0, and the
    // added property that a$(a$x)=x. One construction with these properties for any even order is:
    // - 0 $ x = x
    // - a $ 0 = a
    // - x $ x = 0
    // - a $ x = 1 + ((2(a-1) - (x-1)) mod (order-1)) otherwise
    //
    // Credit: https://twitter.com/danrobinson/status/1272267659313176578
    if (index == 0) return a;
    if (index == a) return 0;
    return SubtractMod(ReduceOnce((a - 1) << 1, m_params.m_buckets - 1), index - 1, m_params.m_buckets - 1) + 1U;
}

int RollingCuckooFilter::Find(uint32_t index, uint64_t fpr) const
{
    uint64_t offset = uint64_t{index} * m_bits_per_bucket;
    for (unsigned pos = 0; pos < BUCKET_SIZE; ++pos) {
        // Decode the fpr (per entry).
        auto read_fpr = m_data.ReadAndAdvance(m_params.m_fpr_bits, offset);
        if (read_fpr == 0) break;
        if (read_fpr == fpr) {
            if (IsActive(m_data.ReadAndAdvance(m_params.m_gen_bits, offset))) {
                return pos;
            }
            return -1;
        } else {
            offset += m_params.m_gen_bits;
        }
    }
    return -1;
}

bool RollingCuckooFilter::AddEntryToBucket(DecodedBucket& bucket, uint64_t fpr, unsigned gen) const
{
    if (bucket.m_num_entries < BUCKET_SIZE) {
        bucket.m_entries[bucket.m_num_entries].m_fpr = fpr;
        bucket.m_entries[bucket.m_num_entries].m_gen = gen;
        ++bucket.m_num_entries;
        return true;
    }

    for (unsigned pos = 0; pos < bucket.m_num_entries; ++pos) {
        if (!IsActive(bucket.m_entries[pos].m_gen)) {
            bucket.m_entries[pos].m_fpr = fpr;
            bucket.m_entries[pos].m_gen = gen;
            return true;
        }
    }

    return false;
}

int RollingCuckooFilter::CountFree(const DecodedBucket& bucket) const
{
    int cnt = BUCKET_SIZE - bucket.m_num_entries;
    for (unsigned pos = 0; pos < bucket.m_num_entries; ++pos) {
        cnt += (!IsActive(bucket.m_entries[pos].m_gen));
    }
    return cnt;
}

int RollingCuckooFilter::AddEntry(DecodedBucket& bucket, uint32_t index1, uint32_t index2, uint64_t fpr, unsigned gen, int access)
{
    while (access > 1) {
        // Try adding the entry to bucket
        if (AddEntryToBucket(bucket, fpr, gen)) {
            SaveBucket(index1, std::move(bucket));
            return access;
        }

        // Pick a position in bucket to evict
        unsigned pos = m_rng.randbits(BUCKET_BITS);
        std::swap(fpr, bucket.m_entries[pos].m_fpr);
        std::swap(gen, bucket.m_entries[pos].m_gen);
        SaveBucket(index1, std::move(bucket));

        // Compute the alternative index for the (fpr,gen) that was swapped out.
        index2 = OtherIndex(index1, fpr);
        std::swap(index1, index2);
        --access;
        bucket = LoadBucket(index1);
    }

    uint32_t min_index = std::min(index1, index2);
    m_overflow.emplace(std::make_pair(fpr, min_index), std::make_pair(gen, index1 != min_index));
    m_max_overflow = std::max(m_max_overflow, m_overflow.size());

    return 0;
}

bool RollingCuckooFilter::Check(Span<const unsigned char> data) const
{
    uint32_t index1 = Index1(data);
    m_data.Prefetch(uint64_t{index1} * m_bits_per_bucket);
    uint64_t fpr = Fingerprint(data);
    uint32_t index2 = OtherIndex(index1, fpr);
    m_data.Prefetch(uint64_t{index2} * m_bits_per_bucket);
    if (Find(index1, fpr) != -1) return true;
    if (Find(index2, fpr) != -1) return true;
    return m_overflow.size() ? m_overflow.count({fpr, std::min(index1, index2)}) > 0 : 0;
}

void RollingCuckooFilter::Insert(Span<const unsigned char> data)
{
    uint64_t buckets_times_count = m_count_this_cycle * m_params.m_buckets;

    // Sweep entries. The condition is "swept_this_cycle < buckets * (count_this_cycle / max_entries)",
    // but written without division.
    while (m_swept_this_cycle * m_max_entries < buckets_times_count) {
        SaveBucket(m_swept_this_cycle, LoadBucket(m_swept_this_cycle));
        ++m_swept_this_cycle;
    }

    if (m_count_this_gen == m_params.m_gen_size) {
        // Start a new generation
        m_this_gen = ReduceOnce(m_this_gen + 1, m_gens * 2);
        m_count_this_gen = 0;
        if (m_this_gen == 0 || m_this_gen == m_gens) {
            m_count_this_cycle = 0;
            m_swept_this_cycle = 0;
        }
    }

    ++m_count_this_cycle;
    ++m_count_this_gen;

    int max_access = m_params.m_max_kicks;

    uint64_t fpr = Fingerprint(data);
    uint64_t index1 = Index1(data);
    --max_access;
    int fnd1 = Find(index1, fpr);
    if (fnd1 != -1) {
        // Entry already present in index1; update generation there.
        DecodedBucket bucket = LoadBucket(index1);
        bucket.m_entries[fnd1].m_gen = m_this_gen;
        SaveBucket(index1, std::move(bucket));
    } else {
        uint64_t index2 = OtherIndex(index1, fpr);
        --max_access;
        int fnd2 = Find(index2, fpr);
        if (fnd2 != -1) {
            // Entry already present in index2; update generation there;
            DecodedBucket bucket = LoadBucket(index2);
            bucket.m_entries[fnd2].m_gen = m_this_gen;
            SaveBucket(index2, std::move(bucket));
        } else {
            DecodedBucket bucket1 = LoadBucket(index1);
            int free1 = CountFree(bucket1);
            if (free1 == BUCKET_SIZE) {
                // Bucket1 is entirely empty. Store it there.
                AddEntryToBucket(bucket1, fpr, m_this_gen);
                SaveBucket(index1, std::move(bucket1));
            } else {
                DecodedBucket bucket2 = LoadBucket(index2);
                int free2 = CountFree(bucket2);
                if (free2 > free1) {
                    // Bucket2 has more space than bucket1; store it there.
                    AddEntryToBucket(bucket2, fpr, m_this_gen);
                    SaveBucket(index2, std::move(bucket2));
                } else if (free1) {
                    // Bucket1 has some space, and bucket2 has not more space.
                    AddEntryToBucket(bucket1, fpr, m_this_gen);
                    SaveBucket(index1, std::move(bucket1));
                } else {
                    // No space in either bucket. Start an insertion cycle randomly.
                    if (m_rng.randbool()) {
                        max_access = AddEntry(bucket1, index1, index2, fpr, m_this_gen, max_access + 1);
                    } else {
                        max_access = AddEntry(bucket2, index2, index1, fpr, m_this_gen, max_access + 1);
                    }
                }
            }
        }
    }

    while (max_access && !m_overflow.empty()) {
        auto it = m_overflow.begin();
        auto [key, value] = *it;
        auto [gen, max_is_next] = value;
        auto [fpr, index1] = key;
        uint32_t index2 = OtherIndex(index1, fpr);
        if (max_is_next) std::swap(index1, index2);
        m_overflow.erase(it);
        if (IsActive(gen)) {
            DecodedBucket bucket = LoadBucket(index1);
            max_access = AddEntry(bucket, index1, index2, fpr, gen, max_access);
        }
    }
}
