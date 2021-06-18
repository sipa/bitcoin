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

/** Compact encoding for tuples for 4 numbers a=0..2M-1, b=0..M-1, c=0..M-b-1, d=0..M-b-c-1. */
template<unsigned M, unsigned BITS, typename BType, typename CType>
class GenerationCoder
{
    BType m_table_b[M] = {0};
    CType m_table_c[M] = {0};

    static constexpr uint32_t A_FACTOR = (M*(M*(M + 3) + 2))/6;

public:
    constexpr uint32_t Encode(uint32_t a, uint32_t b, uint32_t c, uint32_t d) const
    {
        return A_FACTOR*a + m_table_b[b] + (c*(2*M + 1 - 2*b - c)) / 2 + d;
    }

    std::array<uint32_t, 4> Decode(uint32_t v) const
    {
        // The encode expression is linear in a; retrieve it using simple division
        const uint32_t a = v / A_FACTOR;
        v -=  A_FACTOR * a;
        // Find b by bisection.
        const uint32_t b = std::upper_bound(&m_table_b[1], &m_table_b[M], v) - &m_table_b[1];
        v -= m_table_b[b] - m_table_c[b];
        // Find b+c by bisection.
        const uint32_t bc = std::upper_bound(&m_table_c[b+1], &m_table_c[M], v) - &m_table_c[1];
        v -= m_table_c[bc];
        // All but the last term has been subtracted from v; what remains is d.
        return {a, b, bc - b, v};
    }

    constexpr GenerationCoder()
    {
        for (uint32_t i = 0; i < M; ++i) {
            m_table_b[i] = (i*(i*i + 3*(M*(M + 2 - i) - i) + 2)) / 6;
            m_table_c[i] = (i*(2*M + 1 - i)) / 2;
        }
    }

/*
    void Selftest() const {
        for (uint32_t a = 0; a < 2 * M; ++a) {
            for (uint32_t b = 0; b < M; ++b) {
                for (uint32_t c = 0; b + c < M; ++c) {
                    for (uint32_t d = 0; b + c + d < M; ++d) {
                        uint32_t enc = Encode(a, b, c, d);
                        auto dec = Decode(enc);
                        assert(dec[0] == a);
                        assert(dec[1] == b);
                        assert(dec[2] == c);
                        assert(dec[3] == d);
                    }
                }
            }
        }
    }
*/

    static constexpr unsigned Range() { return M; }
    static constexpr unsigned Bits() { return BITS; }
};

/** Coder that packs (a=0..27, b=0..13, c=0..13-b, d=0..13-b-c) in 14 bits. */
constexpr GenerationCoder<14, 14, uint16_t, uint8_t> ENCODER_14;
/** Coder that packs (a=0..39, b=0..19, c=0..19-b, d=0..19-b-c) in 16 bits. */
constexpr GenerationCoder<20, 16, uint16_t, uint8_t> ENCODER_16;
/** Coder that packs (a=0..47, b=0..23, c=0..23-b, d=0..23-b-b) in 17 bits. */
constexpr GenerationCoder<24, 17, uint16_t, uint16_t> ENCODER_17;
/** Coder that packs (a=0..57, b=0..28, c=0..28-b, d=0..28-b-c) in 18 bits. */
constexpr GenerationCoder<29, 18, uint16_t, uint16_t> ENCODER_18;
/** Coder that packs (a=0..81, b=0..40, c=0..40-b, d=0..40-b-c) in 20 bits. */
constexpr GenerationCoder<41, 20, uint16_t, uint16_t> ENCODER_20;
/** Coder that packs (a=0..97, b=0..48, c=0..48-b, d=0..48-b-c) in 21 bits. */
constexpr GenerationCoder<49, 21, uint16_t, uint16_t> ENCODER_21;

/*
class Checker {
public:
    Checker() {
        ENCODER_14.Selftest();
        ENCODER_16.Selftest();
        ENCODER_17.Selftest();
        ENCODER_18.Selftest();
        ENCODER_20.Selftest();
        ENCODER_21.Selftest();
    }
};
static Checker checker;
*/

unsigned Generations(unsigned gen_cbits)
{
    switch (gen_cbits) {
    case 14: return ENCODER_14.Range();
    case 16: return ENCODER_16.Range();
    case 17: return ENCODER_17.Range();
    case 18: return ENCODER_18.Range();
    case 20: return ENCODER_20.Range();
    case 21: return ENCODER_21.Range();
    }
    assert(false);
}

uint32_t Encode(const std::array<uint32_t, 4>& data, unsigned compressed_bits)
{
    switch (compressed_bits) {
    case 14: return ENCODER_14.Encode(data[0], data[1], data[2], data[3]);
    case 16: return ENCODER_16.Encode(data[0], data[1], data[2], data[3]);
    case 17: return ENCODER_17.Encode(data[0], data[1], data[2], data[3]);
    case 18: return ENCODER_18.Encode(data[0], data[1], data[2], data[3]);
    case 20: return ENCODER_20.Encode(data[0], data[1], data[2], data[3]);
    case 21: return ENCODER_21.Encode(data[0], data[1], data[2], data[3]);
    }
    assert(false);
}

std::array<uint32_t, 4> Decode(uint32_t v, unsigned compressed_bits)
{
    switch (compressed_bits) {
    case 14: return ENCODER_14.Decode(v);
    case 16: return ENCODER_16.Decode(v);
    case 17: return ENCODER_17.Decode(v);
    case 18: return ENCODER_18.Decode(v);
    case 20: return ENCODER_20.Decode(v);
    case 21: return ENCODER_21.Decode(v);
    }
    assert(false);
}

RollingCuckooFilter::Params ChooseParams(uint32_t window, unsigned fpbits, double alpha, int max_access)
{
    static constexpr unsigned GEN_CBITS[] = {14, 16, 17, 18, 20, 21};
    bool have_ret = false;
    RollingCuckooFilter::Params ret;
    if (fpbits < 10) fpbits = 10;
    for (unsigned gen_cbits : GEN_CBITS) {
        RollingCuckooFilter::Params params;
        params.m_fpr_bits = fpbits + 1 + RollingCuckooFilter::BUCKET_BITS;
        params.m_gen_cbits = gen_cbits;
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

unsigned RollingCuckooFilter::Params::Generations() const
{
    return ::Generations(m_gen_cbits);
}

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
    for (unsigned pos = 0; pos < BUCKET_SIZE; ++pos) {
        // Decode the fpr (per entry).
        bucket.m_entries[pos].m_fpr = m_data.ReadAndAdvance(m_params.m_fpr_bits, offset);
    }
    // Decode compressed gen bits (shared across the whole bucket).
    auto compressed_gens = Decode(m_data.ReadAndAdvance(m_params.m_gen_cbits, offset), m_params.m_gen_cbits);
    for (unsigned pos = 0; pos < BUCKET_SIZE; ++pos) {
        gen_shift = ReduceOnce(gen_shift + compressed_gens[pos], 2 * m_gens);
        bucket.m_entries[pos].m_gen = gen_shift;
    }

    return bucket;
}

void RollingCuckooFilter::SaveBucket(uint32_t index, DecodedBucket&& bucket)
{
    // Wipe expired entries
    for (unsigned pos = 0; pos < BUCKET_SIZE; ++pos) {
        if (bucket.m_entries[pos].m_fpr == 0 || !IsActive(bucket.m_entries[pos].m_gen)) {
            bucket.m_entries[pos] = DecodedEntry{0, m_this_gen};
        }
    }

    // Sort the bucket entries using a fixed sorting network.
    const DecodedEntry* entries[7] = {
        &bucket.m_entries[0],
        &bucket.m_entries[1],
        &bucket.m_entries[2],
        &bucket.m_entries[3]
    };
    if (entries[0]->m_gen > entries[2]->m_gen) std::swap(entries[0], entries[2]);
    if (entries[1]->m_gen > entries[3]->m_gen) std::swap(entries[1], entries[3]);
    if (entries[0]->m_gen > entries[1]->m_gen) std::swap(entries[0], entries[1]);
    if (entries[2]->m_gen > entries[3]->m_gen) std::swap(entries[2], entries[3]);
    if (entries[1]->m_gen > entries[2]->m_gen) std::swap(entries[1], entries[2]);
    // Avoid the need for wrap-around logic.
    entries[4] = entries[0];
    entries[5] = entries[1];
    entries[6] = entries[2];

    // Find the oldest entry. This is the entry for which no other entries for the m_gens before it exist.
    int oldest_pos = -1;
    if (entries[BUCKET_SIZE - 1]->m_gen < entries[0]->m_gen + m_gens) {
        oldest_pos = 0;
    } else {
        for (unsigned pos = 1; pos < BUCKET_SIZE; ++pos) {
            if (entries[pos - 1]->m_gen + m_gens < entries[pos]->m_gen) {
                oldest_pos = pos;
                break;
            }
        }
        assert(oldest_pos != -1);
    }

    // Store fprs
    uint64_t offset = uint64_t{index} * m_bits_per_bucket;
    for (unsigned pos = 0; pos < BUCKET_SIZE; ++pos) {
        // Store fpr
        m_data.WriteAndAdvance(m_params.m_fpr_bits, offset, entries[oldest_pos + pos]->m_fpr);
    }
    // Store compressed high gen bits
    uint32_t a = entries[oldest_pos]->m_gen;
    uint32_t b = SubtractMod(entries[oldest_pos + 1]->m_gen, entries[oldest_pos]->m_gen, 2 * m_gens);
    uint32_t c = SubtractMod(entries[oldest_pos + 2]->m_gen, entries[oldest_pos + 1]->m_gen, 2 * m_gens);
    uint32_t d = SubtractMod(entries[oldest_pos + 3]->m_gen, entries[oldest_pos + 2]->m_gen, 2 * m_gens);
    m_data.WriteAndAdvance(m_params.m_gen_cbits, offset, Encode({a, b, c, d}, m_params.m_gen_cbits));
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
    uint32_t gen_shift = 0;
    int ret = -1;
    for (unsigned pos = 0; pos < BUCKET_SIZE; ++pos) {
        // Decode the fpr (per entry).
        if (m_data.ReadAndAdvance(m_params.m_fpr_bits, offset) == fpr) {
            ret = pos;
            offset += m_params.m_fpr_bits * (BUCKET_SIZE - pos - 1);
            break;
        }
    }
    if (ret == -1) return -1;
    // Decode compressed gen bits (shared across the whole bucket).
    auto compressed_gens = Decode(m_data.ReadAndAdvance(m_params.m_gen_cbits, offset), m_params.m_gen_cbits);
    for (unsigned pos = 0;; ++pos) {
        // Decode the additional gen bits (per entry).
        gen_shift = ReduceOnce(gen_shift + compressed_gens[pos], 2 * m_gens);
        if (ret == (int)pos) {
            if (IsActive(gen_shift)) return ret;
            return -1;
        }
    }
}

bool RollingCuckooFilter::AddEntryToBucket(DecodedBucket& bucket, uint64_t fpr, unsigned gen) const
{
    assert(fpr != 0);
    for (unsigned pos = 0; pos < BUCKET_SIZE; ++pos) {
        if (bucket.m_entries[pos].m_fpr == 0 || !IsActive(bucket.m_entries[pos].m_gen)) {
            bucket.m_entries[pos] = DecodedEntry{fpr, gen};
            return true;
        }
    }
    return false;
}

int RollingCuckooFilter::CountFree(const DecodedBucket& bucket) const
{
    int cnt = 0;
    for (unsigned pos = 0; pos < BUCKET_SIZE; ++pos) {
        cnt += (bucket.m_entries[pos].m_fpr == 0 || !IsActive(bucket.m_entries[pos].m_gen));
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
