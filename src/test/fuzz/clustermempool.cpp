// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <time.h>
#include <cmath>

#include <algorithm>
#include <bitset>
#include <vector>
#include <queue>

#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>

#include <assert.h>

#include <iostream>

namespace {

template<typename I>
int inline CountTrailingZeroes(I v)
{
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);
    constexpr auto digits = std::numeric_limits<I>::digits;
    constexpr auto digits_u = std::numeric_limits<unsigned>::digits;
    constexpr auto digits_ul = std::numeric_limits<unsigned long>::digits;
    constexpr auto digits_ull = std::numeric_limits<unsigned long long>::digits;
    if constexpr (digits >= digits_u) {
        return __builtin_ctz(v);
    } else if constexpr (digits >= digits_ul) {
        return __builtin_ctzl(v);
    } else {
        static_assert(digits >= digits_ull);
        return __builtin_ctzll(v);
    }
}

template<typename SizeType, SizeType Size>
class UnionFind
{
    SizeType m_ref[Size];
    SizeType m_size;

public:
    void Init(SizeType size)
    {
        m_size = size;
        for (SizeType i = 0; i < m_size; ++i) {
            m_ref[i] = i;
        }
    }

    explicit UnionFind(SizeType size)
    {
        Init(size);
    }

    SizeType Find(SizeType idx)
    {
        SizeType start = idx;
        while (m_ref[idx] != idx) {
            idx = m_ref[idx];
        }
        while (m_ref[start] != idx) {
            SizeType prev = start;
            start = m_ref[start];
            m_ref[prev] = idx;
        }
        return idx;
    }

    void Union(SizeType a, SizeType b)
    {
        m_ref[Find(a)] = Find(b);
    }
};

enum class FeeRateOperator
{
    HIGHER,
    LOWER,
    DIFFERENT
};

enum class EqualFeeRate
{
    ALLOWED,
    NOT_ALLOWED,
    IF_SIZE_SMALLER,
    IF_SIZE_NOT_LARGER
};

struct FeeAndSize
{
    uint64_t sats;
    uint32_t bytes;

    FeeAndSize() : sats{0}, bytes{0} {}

    FeeAndSize(uint64_t s, uint32_t b) : sats{s}, bytes{b}
    {
        assert(bytes != 0 || sats == 0);
    }

    FeeAndSize(const FeeAndSize&) = default;
    FeeAndSize& operator=(const FeeAndSize&) = default;

    bool IsEmpty() const {
        return bytes == 0;
    }

    void operator+=(const FeeAndSize& other)
    {
        sats += other.sats;
        bytes += other.bytes;
    }

    friend FeeAndSize operator+(const FeeAndSize& a, const FeeAndSize& b)
    {
        return FeeAndSize{a.sats + b.sats, a.bytes + b.bytes};
    }

    friend std::ostream& operator<<(std::ostream& o, const FeeAndSize& data)
    {
        o << "(" << data.sats << "/" << data.bytes << "=" << ((double)data.sats / data.bytes) << ")";
        return o;
    }
};

template<FeeRateOperator DIR, EqualFeeRate EQ>
bool FeeRateCompare(const FeeAndSize& a, const FeeAndSize& b)
{
    if (__builtin_expect(((a.sats | b.sats) >> 32) != 0, false)) {
        unsigned __int128 v1 = (unsigned __int128)(a.sats) * b.bytes;
        unsigned __int128 v2 = (unsigned __int128)(b.sats) * a.bytes;
        if (v1 != v2) {
            if constexpr (DIR == FeeRateOperator::LOWER) {
                return v1 < v2;
            } else if constexpr (DIR == FeeRateOperator::HIGHER) {
                return v1 > v2;
            } else {
                static_assert(DIR == FeeRateOperator::DIFFERENT);
                return true;
            }
        }
    } else {
        uint64_t v1 = uint64_t{(uint32_t)a.sats} * b.bytes;
        uint64_t v2 = uint64_t{(uint32_t)b.sats} * a.bytes;
        if (v1 != v2) {
            if constexpr (DIR == FeeRateOperator::LOWER) {
                return v1 < v2;
            } else if constexpr (DIR == FeeRateOperator::HIGHER) {
                return v1 > v2;
            } else {
                static_assert(DIR == FeeRateOperator::DIFFERENT);
                return true;
            }
        }
    }
    if constexpr (EQ == EqualFeeRate::NOT_ALLOWED) {
        return false;
    } else if constexpr (EQ == EqualFeeRate::ALLOWED) {
        return true;
    } else if constexpr (EQ == EqualFeeRate::IF_SIZE_SMALLER) {
        return a.bytes < b.bytes;
    } else {
        static_assert(EQ == EqualFeeRate::IF_SIZE_NOT_LARGER);
        return a.bytes <= b.bytes;
    }
}

/** Determine whether a has higher feerate than b, or has the same feerate but smaller size. */
bool FeeRateBetter(const FeeAndSize& a, const FeeAndSize& b)
{
    return FeeRateCompare<FeeRateOperator::HIGHER, EqualFeeRate::IF_SIZE_SMALLER>(a, b);
}

/** Determine whether a has higher feerate then b. */
bool JustFeeRateBetter(const FeeAndSize& a, const FeeAndSize& b)
{
    return FeeRateCompare<FeeRateOperator::HIGHER, EqualFeeRate::NOT_ALLOWED>(a, b);
}

/** Determine whether a has higher feerate, or has the same feerate but the same or smaller size. */
bool FeeRateBetterOrEqual(const FeeAndSize& a, const FeeAndSize& b)
{
    return FeeRateCompare<FeeRateOperator::HIGHER, EqualFeeRate::IF_SIZE_NOT_LARGER>(a, b);
}

/** A bitset implementation backed by a single integer of type I. */
template<typename I>
class IntBitSet
{
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);

    I m_val;

    IntBitSet(I val) : m_val{val} {}

public:
    static const unsigned SIZE = std::numeric_limits<I>::digits;

    IntBitSet() noexcept : m_val{0} {}
    IntBitSet(const IntBitSet&) noexcept = default;
    IntBitSet& operator=(const IntBitSet&) noexcept = default;

    void Set(unsigned pos) noexcept { m_val |= I{1U} << pos; }
    bool operator[](unsigned pos) const noexcept { return (m_val >> pos) & 1U; }
    bool None() const noexcept { return m_val == 0; }
    bool Any() const noexcept { return m_val != 0; }

    unsigned StripLowest() noexcept
    {
        int ret = CountTrailingZeroes(m_val);
        m_val &= m_val - I{1U};
        return ret;
    }

    IntBitSet& operator|=(const IntBitSet& a) { m_val |= a.m_val; return *this; }
    friend IntBitSet operator&(const IntBitSet& a, const IntBitSet& b) { return IntBitSet{a.m_val & b.m_val}; }
    friend IntBitSet operator|(const IntBitSet& a, const IntBitSet& b) { return IntBitSet{a.m_val | b.m_val}; }
    friend IntBitSet operator/(const IntBitSet& a, const IntBitSet& b) { return IntBitSet{a.m_val & ~b.m_val}; }
    friend bool operator<(const IntBitSet& a, const IntBitSet& b) { return a.m_val < b.m_val; }
    friend bool operator!=(const IntBitSet& a, const IntBitSet& b) { return a.m_val != b.m_val; }
    friend bool operator==(const IntBitSet& a, const IntBitSet& b) { return a.m_val == b.m_val; }

    friend std::ostream& operator<<(std::ostream& s, const IntBitSet& bs)
    {
        s << "[";
        size_t cnt = 0;
        for (size_t i = 0; i < SIZE; ++i) {
            if (bs[i]) {
                if (cnt) s << ",";
                ++cnt;
                s << i;
            }
        }
        s << "]";
        return s;
    }
};

/** Data type to represent cluster input.
 *
 * cluster[i].first is tx_i's fee and size.
 * cluster[i].second[j] is true iff tx_i spends one or more of tx_j's outputs.
 */
template<typename S>
using Cluster = std::vector<std::pair<FeeAndSize, S>>;

/** String serialization for debug output of Cluster. */
template<typename S>
std::ostream& operator<<(std::ostream& o, const Cluster<S>& cluster)
{
    o << "Cluster{";
    for (size_t i = 0; i < cluster.size(); ++i) {
        if (i) o << ",";
        o << i << ":" << cluster[i].first << cluster[i].second;
    }
    o << "}";
    return o;
}

/** Load a Cluster from fuzz provider. */
template<typename S>
Cluster<S> FuzzReadCluster(FuzzedDataProvider& provider, bool only_complete)
{
    Cluster<S> ret;
    while (ret.size() < S::SIZE && provider.remaining_bytes()) {
        if (only_complete && provider.remaining_bytes() < 4U + ret.size()) break;
        uint64_t sats = provider.ConsumeIntegralInRange<uint32_t>(0, 0xFFFF);
        uint32_t bytes = provider.ConsumeIntegralInRange<uint32_t>(1, 0x10000);
        S deps;
        for (size_t i = 0; i < ret.size(); ++i) {
            if (provider.ConsumeBool()) deps.Set(i);
        }
        ret.emplace_back(FeeAndSize{sats, bytes}, std::move(deps));
    }
    return ret;
}

/** Determine if select is a connected subset in the given cluster. */
template<typename S>
bool IsConnectedSubset(const Cluster<S>& cluster, const S& select)
{
    /* Trivial case. */
    if (select.None()) return true;

    /* Build up UF data structure. */
    UnionFind<unsigned, S::SIZE> uf(cluster.size());
    S todo{select};
    while (todo.Any()) {
        unsigned pos = todo.StripLowest();
        S deps = cluster[pos].second & select;
        while (deps.Any()) uf.Union(pos, deps.StripLowest());
    }

    /* Test that all selected entries in uf have the same representative. */
    todo = select;
    unsigned root = uf.Find(todo.StripLowest());
    while (todo.Any()) {
        if (uf.Find(todo.StripLowest()) != root) return false;
    }
    return true;
}

/** Precomputation data structure with all ancestor sets of a cluster. */
template<typename S>
class AncestorSets
{
    std::vector<S> m_ancestorsets;

public:
    explicit AncestorSets(const Cluster<S>& cluster)
    {
        // Initialize: every transaction's ancestor set is itself plus direct parents.
        m_ancestorsets.resize(cluster.size());
        for (size_t i = 0; i < cluster.size(); ++i) {
            m_ancestorsets[i] = cluster[i].second;
            m_ancestorsets[i].Set(i);
        }

        // Compute transitive closure of "merge your ancestors' ancestors into your
        // ancestor set".
        bool changed;
        do {
            changed = false;
            for (size_t i = 0; i < cluster.size(); ++i) {
                for (size_t dep = 0; dep < cluster.size(); ++dep) {
                    if (i != dep && m_ancestorsets[i][dep]) {
                        S merged = m_ancestorsets[i] | m_ancestorsets[dep];
                        if (merged != m_ancestorsets[i]) {
                            changed = true;
                            m_ancestorsets[i] = merged;
                        }
                    }
                }
            }
        } while(changed);
    }

    AncestorSets() = default;
    AncestorSets(const AncestorSets&) = delete;
    AncestorSets(AncestorSets&&) = default;
    AncestorSets& operator=(const AncestorSets&) = delete;
    AncestorSets& operator=(AncestorSets&&) = default;

    const S& operator[](unsigned pos) const noexcept { return m_ancestorsets[pos]; }
    size_t Size() const noexcept { return m_ancestorsets.size(); }
};

/** Precomputation data structure with all descendant sets of a cluster. */
template<typename S>
class DescendantSets
{
    std::vector<S> m_descendantsets;

public:
    explicit DescendantSets(const AncestorSets<S>& anc)
    {
        m_descendantsets.resize(anc.Size());
        for (size_t i = 0; i < anc.Size(); ++i) {
            S ancs = anc[i];
            while (ancs.Any()) {
                m_descendantsets[ancs.StripLowest()].Set(i);
            }
        }
    }

    DescendantSets() = default;
    DescendantSets(const DescendantSets&) = delete;
    DescendantSets(DescendantSets&&) = default;
    DescendantSets& operator=(const DescendantSets&) = delete;
    DescendantSets& operator=(DescendantSets&&) = default;

    const S& operator[](unsigned pos) const { return m_descendantsets[pos]; }
};

template<typename S>
struct CandidateSetAnalysis
{
    size_t num_candidate_sets{0};
    S best_candidate_set{};
    FeeAndSize best_candidate_feerate{};

    size_t max_queue_size{0};
    size_t iterations{0};
    size_t comparisons{0};
    size_t threshold_iterations{0};
    size_t threshold_comparisons{0};
};

template<typename S>
FeeAndSize ComputeSetFeeRate(const Cluster<S>& cluster, S select)
{
    FeeAndSize ret;
    while (select.Any()) {
        ret += cluster[select.StripLowest()].first;
    }
    return ret;
}

/** A naive algorithm for finding the best candidate set.
 *
 * It constructs all 2^N subsets, tests if they satisfy dependency relations, and remembers the
 * best one out of those that do.
 */
template<typename S>
CandidateSetAnalysis<S> FindBestCandidateSetNaive(const Cluster<S>& cluster, const S& done)
{
    assert(cluster.size() <= 25);
    CandidateSetAnalysis<S> ret;

    // Iterate over all subsets of the cluster ((setval >> i) & 1 => tx i is included).
    for (uint32_t setval = 0; (setval >> cluster.size()) == 0; ++setval) {
        // Convert setval to a bitset, and also compute the merged ancestors of it in req.
        S bitset, req;
        for (unsigned i = 0; i < cluster.size(); ++i) {
            if ((setval >> i) & 1U) {
                bitset.Set(i);
                req = req | cluster[i].second;
            }
        }
        // None of the already done transactions may be included again.
        if ((done & bitset).Any()) continue;
        // We only consider non-empty additions.
        if (bitset.None()) continue;
        // All dependencies have to be satisfied.
        S unmet = req / (bitset | done);
        if (unmet.Any()) continue;
        // Only connected subsets are considered.
        if (!IsConnectedSubset(cluster, bitset)) continue;

        // Update statistics in ret to account for this new candidate.
        ++ret.num_candidate_sets;
        FeeAndSize feerate = ComputeSetFeeRate(cluster, bitset);
        if (ret.best_candidate_set.None() || FeeRateBetter(feerate, ret.best_candidate_feerate)) {
            ret.best_candidate_set = bitset;
            ret.best_candidate_feerate = feerate;
        }
    }

    return ret;
}

/** An O(2^n) algorithm for finding the best candidate set.
 *
 * It efficiently constructs all valid candidate sets, and remembers the best one.
 */
template<typename S>
CandidateSetAnalysis<S> FindBestCandidateSetExhaustive(const Cluster<S>& cluster, const AncestorSets<S>& anc, const S& done)
{
    // Queue of work units. Each consists of:
    // - inc: bitset of transactions definitely included (always includes done)
    // - exc: bitset of transactions definitely excluded
    // - feerate: the feerate of (included / done)
    std::vector<std::tuple<S, S, FeeAndSize>> queue;
    queue.emplace_back(done, S{}, FeeAndSize{});

    CandidateSetAnalysis<S> ret;

    // Process the queue.
    while (!queue.empty()) {
        ++ret.iterations;
        // Pop top element of the queue.
        auto [inc, exc, feerate] = queue.back();
        queue.pop_back();
        bool inc_none = inc == done;
        // Look for a transaction to include.
        for (size_t i = 0; i < cluster.size(); ++i) {
            // Conditions:
            // - !inc[i]: we can't add anything already included
            // - !exc[i]: we can't add anything already excluded
            // - (exc & anc[i]).None: ancestry of what we include cannot have excluded transactions
            // - inc_none || !((inc & anc[i]) / done).None(): either:
            //   - we're starting from an empty set (apart from done)
            //   - if not, the ancestry of what we add must overlap with what we already have, in
            //     not yet done transactions (to guarantee (inc / done) is always connected).
            if (!inc[i] && !exc[i] && (exc & anc[i]).None() && (inc_none || !((inc & anc[i]) / done).None())) {
                // First, add a queue item with i added to exc. Inc is unchanged, so feerate is
                // unchanged as well.
                auto new_exc = exc;
                new_exc.Set(i);
                queue.emplace_back(inc, new_exc, feerate);

                // Then, add a queue item with i (plus ancestry) added to inc. We need to compute
                // an updated feerate here to account for what was added.
                auto new_inc = inc | anc[i];
                FeeAndSize new_feerate = feerate + ComputeSetFeeRate(cluster, new_inc / inc);
                queue.emplace_back(new_inc, exc, new_feerate);

                // Update statistics in ret to account for this new candidate (new_inc / done).
                ++ret.num_candidate_sets;
                if (ret.best_candidate_set.None() || FeeRateBetter(new_feerate, ret.best_candidate_feerate)) {
                    ret.best_candidate_set = new_inc / done;
                    ret.best_candidate_feerate = new_feerate;
                }
                ret.max_queue_size = std::max(queue.size(), ret.max_queue_size);
                break;
            }
        }
    }

    return ret;
}

/** Precomputation data structure for sorting a cluster based on individual feerate. */
template<typename S>
struct SortedCluster
{
    Cluster<S> m_sorted_cluster;
    AncestorSets<S> m_ancestorsets;
    DescendantSets<S> m_descendantsets;
    std::vector<unsigned> m_original_to_sorted;
    std::vector<unsigned> m_sorted_to_original;

public:
    const Cluster<S>& GetCluster() const noexcept { return m_sorted_cluster; }
    const S& GetAncestorSet(unsigned pos) const noexcept { return m_ancestorsets[pos]; }
    const S& GetDescendantSet(unsigned pos) const noexcept { return m_descendantsets[pos]; }

    S OriginalToSorted(S val) const noexcept
    {
        S ret;
        while (val.Any()) {
            ret.Set(m_original_to_sorted[val.StripLowest()]);
        }
        return ret;
    }

    S SortedToOriginal(S val) const noexcept
    {
        S ret;
        while (val.Any()) {
            ret.Set(m_sorted_to_original[val.StripLowest()]);
        }
        return ret;
    }

    SortedCluster(const Cluster<S>& cluster)
    {
        // Allocate vectors.
        m_sorted_to_original.resize(cluster.size());
        m_original_to_sorted.resize(cluster.size());
        m_sorted_cluster.resize(cluster.size());

        // Compute m_sorted_to_original mapping.
        std::iota(m_sorted_to_original.begin(), m_sorted_to_original.end(), 0U);
        std::sort(m_sorted_to_original.begin(), m_sorted_to_original.end(), [&](unsigned i, unsigned j) {
            return FeeRateBetter(cluster[i].first, cluster[j].first);
        });

        // Use m_sorted_to_original to fill m_sorted_cluster and m_original_to_sorted.
        for (size_t i = 0; i < cluster.size(); ++i) {
            m_original_to_sorted[m_sorted_to_original[i]] = i;
        }

        for (size_t i = 0; i < cluster.size(); ++i) {
            m_sorted_cluster[i].first = cluster[m_sorted_to_original[i]].first;
            m_sorted_cluster[i].second = OriginalToSorted(cluster[m_sorted_to_original[i]].second);
        }

        // Compute AncestorSets and DescendantSets.
        m_ancestorsets = AncestorSets(m_sorted_cluster);
        m_descendantsets = DescendantSets(m_ancestorsets);
    }
};

template<typename S>
std::pair<S, FeeAndSize> FindBestAncestorSet(const Cluster<S>& cluster, const AncestorSets<S>& anc, const S& done)
{
    FeeAndSize best_feerate;
    S best_set;

    for (size_t i = 0; i < cluster.size(); ++i) {
        FeeAndSize feerate = ComputeSetFeeRate(cluster, anc[i]);
        if (i == 0 || FeeRateBetter(feerate, best_feerate)) {
            best_feerate = feerate;
            best_set = anc[i];
        }
    }

    return {best_set, best_feerate};
}

/** An efficient algorithm for finding the best candidate set. Believed to be O(~1.6^n). */
template<typename S>
CandidateSetAnalysis<S> FindBestCandidateSetEfficient(const SortedCluster<S>& scluster, const S& done)
{
    const Cluster<S>& cluster = scluster.GetCluster();
    // Queue of work units. Each consists of:
    // - inc: bitset of transactions definitely included (always includes done)
    // - exc: bitset of transactions definitely excluded
    // - inc_feerate: the feerate of (included / done)
    // - pot_feerate: a conservative upper bound on the feerate for any candidate set that includes
    //                all of inc and does not include any of exc.
    std::vector<std::tuple<S, S, FeeAndSize, FeeAndSize>> queue;

    CandidateSetAnalysis<S> ret;

    S all;
    for (unsigned i = 0; i < cluster.size(); ++i) {
        all.Set(i);
    }

    S best_candidate;
    FeeAndSize best_feerate;

    auto add_fn = [&](S inc, S exc, FeeAndSize inc_feerate, bool inc_changed) {
        FeeAndSize pot_feerate = inc_feerate;
        S satisfied = inc;
        S required;
        S undecided = all / (inc | exc);
        while (undecided.Any()) {
            unsigned pos = undecided.StripLowest();
            bool to_add = pot_feerate.IsEmpty();
            if (!to_add) {
                ++ret.comparisons;
                if (!JustFeeRateBetter(cluster[pos].first, pot_feerate)) break;
            }
            pot_feerate += cluster[pos].first;
            satisfied.Set(pos);
            required |= scluster.GetAncestorSet(pos);
            if ((required / satisfied).None()) {
                inc = satisfied;
                inc_feerate = pot_feerate;
                inc_changed = true;
            }
        }

        if (pot_feerate.IsEmpty()) return;
        if (inc_changed) {
            assert(!inc_feerate.IsEmpty());
            bool new_best = best_feerate.IsEmpty();
            if (!new_best) {
                ++ret.comparisons;
                new_best = FeeRateBetter(inc_feerate, best_feerate);
            }
            if (new_best) {
                best_feerate = inc_feerate;
                best_candidate = inc;
            }
        }
        if ((all / (inc | exc)).Any()) {
            queue.emplace_back(inc, exc, inc_feerate, pot_feerate);
            ret.max_queue_size = std::max(ret.max_queue_size, queue.size());
        }
    };

    add_fn(scluster.OriginalToSorted(done), S{}, FeeAndSize{}, false);

    while (queue.size()) {
        ++ret.iterations;

/*
        size_t rand = GLOBAL_RNG() % queue.size();
        if (rand) {
            std::swap(*(queue.end() - 1), *(queue.end() - 1 - rand));
        }
*/

        auto [inc, exc, inc_feerate, pot_feerate] = queue.back();
        queue.pop_back();
        assert(pot_feerate.bytes > 0);
        if (!best_feerate.IsEmpty()) {
            ++ret.comparisons;
            if (FeeRateBetterOrEqual(best_feerate, pot_feerate)) continue;
        }

        auto undecided = all / (inc | exc);
        assert(undecided.Any());
        unsigned pos = undecided.StripLowest();
        add_fn(inc, exc | scluster.GetDescendantSet(pos), inc_feerate, false);
        auto new_inc = inc | scluster.GetAncestorSet(pos);
        auto new_inc_feerate = inc_feerate + ComputeSetFeeRate(cluster, new_inc / inc);
        add_fn(new_inc, exc, new_inc_feerate, true);
    }

    ret.best_candidate_set = scluster.SortedToOriginal(best_candidate) / done;
    ret.best_candidate_feerate = best_feerate;
    return ret;
}


struct FullLinearizationStats
{
    size_t iterations{0};
    size_t comparisons{0};
};

template<typename S>
FullLinearizationStats LinearizeClusterEfficient(const Cluster<S>& cluster)
{
    FullLinearizationStats ret;

    S all, done;
    for (unsigned i = 0; i < cluster.size(); ++i) all.Set(i);

    SortedCluster<S> scluster(cluster);

    while ((all / done).Any()) {
        auto cand_analysis = FindBestCandidateSetEfficient(scluster, done);
/*
        assert(!cand_analysis.best_candidate_set.None());
        assert((cand_analysis.best_candidate_set / all).None());
        assert((done & cand_analysis.best_candidate_set).None());
        auto recomp = ComputeSetFeeRate(cluster, cand_analysis.best_candidate_set);
        assert(recomp.sats == cand_analysis.best_candidate_feerate.sats);
        assert(recomp.bytes == cand_analysis.best_candidate_feerate.bytes);
*/
        ret.iterations += cand_analysis.iterations;
        ret.comparisons += cand_analysis.comparisons;
        done |= cand_analysis.best_candidate_set;
    }

    return ret;
}

using BitSet = IntBitSet<uint64_t>;

/*
#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

inline uint64_t RdSeed() noexcept
{
    uint8_t ok;
    uint64_t r1;
    do {
        __asm__ volatile (".byte 0x48, 0x0f, 0xc7, 0xf8; setc %1" : "=a"(r1), "=q"(ok) :: "cc"); // rdseed %rax
        if (ok) break;
        __asm__ volatile ("pause");
    } while(true);
    return r1;
}

class RNG
{
    uint64_t v0 = RdSeed(), v1 = RdSeed(), v2 = RdSeed(), v3 = RdSeed();

    static uint64_t SplitMix64(uint64_t& x)
    {
        uint64_t z = (x += 0x9e3779b97f4a7c15);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

public:
    RNG() : v0{RdSeed()}, v1{RdSeed()}, v2{RdSeed()}, v3{RdSeed()} {}

    explicit RNG(uint64_t seed)
    {
        v0 = SplitMix64(seed);
        v1 = SplitMix64(seed);
        v2 = SplitMix64(seed);
        v3 = SplitMix64(seed);
    }

    uint64_t operator()()
    {
        const uint64_t result = ROTL(v0 + v3, 23) + v0;
        const uint64_t t = v1 << 17;
        v2 ^= v0;
        v3 ^= v1;
        v1 ^= v2;
        v0 ^= v3;
        v2 ^= t;
        v3 = ROTL(v3, 45);
        return result;
    }
};

RNG GLOBAL_RNG;
*/

} // namespace

FUZZ_TARGET(clustermempool_exhaustive_equals_naive)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/true);

    AncestorSets anc(cluster);
    BitSet done;
    for (size_t i = 0; i < cluster.size(); ++i) {
        if (provider.ConsumeBool()) {
            done |= anc[i];
        }
    }

    auto ret_naive = FindBestCandidateSetNaive(cluster, done);
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done);

    assert(ret_exhaustive.num_candidate_sets == ret_naive.num_candidate_sets);
    assert(ret_exhaustive.best_candidate_feerate.sats == ret_naive.best_candidate_feerate.sats);
    assert(ret_exhaustive.best_candidate_feerate.bytes == ret_naive.best_candidate_feerate.bytes);
}

FUZZ_TARGET(clustermempool_efficient_equals_exhaustive)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/true);

    AncestorSets anc(cluster);
    BitSet done;
    for (size_t i = 0; i < cluster.size(); ++i) {
        if (provider.ConsumeBool()) {
            done |= anc[i];
        }
    }

//    std::cerr << "CLUSTER=" << cluster << " DONE=" << done << std::endl;

    SortedCluster<BitSet> scluster(cluster);

//    std::cerr << "- SCLUSTER: CLUSTER=" << scluster.GetCluster() << " DONE=" << scluster.OriginalToSorted(done) << std::endl;

    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done);
    auto ret_efficient = FindBestCandidateSetEfficient(scluster, done);

//    std::cerr << "- EXHAUSTIVE: " << ret_exhaustive.best_candidate_set << " " << ret_exhaustive.best_candidate_feerate << std::endl;
//    std::cerr << "- EFFICIENT:  " << ret_efficient.best_candidate_set << " " << ret_efficient.best_candidate_feerate << std::endl;

    assert(ret_exhaustive.best_candidate_feerate.sats == ret_efficient.best_candidate_feerate.sats);
    assert(ret_exhaustive.best_candidate_feerate.bytes == ret_efficient.best_candidate_feerate.bytes);
}

FUZZ_TARGET(clustermempool_efficient_equals_exhaustive_nodone)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/false);

    AncestorSets anc(cluster);

/*    auto [_, anc_feerate] = FindBestAncestorSet(cluster, anc, {});*/

    SortedCluster<BitSet> scluster(cluster);

    auto ret_efficient = FindBestCandidateSetEfficient(scluster, {});
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, {});

    assert(ret_exhaustive.best_candidate_feerate.sats == ret_efficient.best_candidate_feerate.sats);
    assert(ret_exhaustive.best_candidate_feerate.bytes == ret_efficient.best_candidate_feerate.bytes);

    static std::array<size_t, 30> MAX_COMPS;
    static std::array<size_t, 30> MAX_ITERS;
    static std::array<size_t, 30> MAX_QUEUE;

    if (ret_efficient.comparisons > MAX_COMPS[cluster.size()]) {
        MAX_COMPS[cluster.size()] = ret_efficient.comparisons;
        std::cerr << "COMPS:";
        for (size_t i = 0; i <= 26; ++i) {
            if (MAX_COMPS[i]) {
                std::cerr << " " << i << ":" << MAX_COMPS[i];
            }
        }
        std::cerr << std::endl;
    }

    if (ret_efficient.iterations > MAX_ITERS[cluster.size()]) {
        MAX_ITERS[cluster.size()] = ret_efficient.iterations;
        std::cerr << "ITERS:";
        for (size_t i = 0; i <= 26; ++i) {
            if (MAX_ITERS[i]) {
                std::cerr << " " << i << ":" << MAX_ITERS[i];
            }
        }
        std::cerr << std::endl;
    }

    if (ret_efficient.max_queue_size > MAX_QUEUE[cluster.size()]) {
        MAX_QUEUE[cluster.size()] = ret_efficient.max_queue_size;
        std::cerr << "QUEUE:";
        for (size_t i = 0; i <= 26; ++i) {
            if (MAX_QUEUE[i]) {
                std::cerr << " " << i << ":" << MAX_QUEUE[i];
            }
        }
        std::cerr << std::endl;
    }
}

FUZZ_TARGET(clustermempool_efficient_full)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/false);
    if (cluster.size() > 26) return;

    BitSet all;
    for (unsigned i = 0; i < cluster.size(); ++i) all.Set(i);
    if (!IsConnectedSubset(cluster, all)) return;

/*    std::cerr << "CLUSTER " << cluster << std::endl;*/

    std::vector<std::pair<double, FullLinearizationStats>> durations;
    durations.reserve(11);

    for (unsigned i = 0; i < 11; ++i) {
        struct timespec measure_start, measure_stop;
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_start);
        auto stats = LinearizeClusterEfficient(cluster);
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_stop);
        double duration = (double)((int64_t)measure_stop.tv_sec - (int64_t)measure_start.tv_sec) + 0.000000001*(double)((int64_t)measure_stop.tv_nsec - (int64_t)measure_start.tv_nsec);
        durations.emplace_back(duration, stats);
    }

    std::sort(durations.begin(), durations.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    const auto& [duration, stats] = durations[5];

    std::cerr << "LINEARIZE(" << cluster.size() << ") time=" << duration << " iters=" << stats.iterations << " time/iters=" << (duration / stats.iterations) << " comps=" << stats.comparisons << " time/comps=" << (duration / stats.comparisons) << std::endl;
}
