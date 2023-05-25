// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CLUSTER_LINEARIZE_H
#define BITCOIN_CLUSTER_LINEARIZE_H

#include <stdint.h>

#include <algorithm>
#include <limits>
#include <numeric>
#include <vector>

#include <assert.h>

namespace {

/** Wrapper around __builtin_ctz[l][l] for supporting unsigned integer types. */
template<typename I>
unsigned inline CountTrailingZeroes(I v)
{
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);
    constexpr auto digits = std::numeric_limits<I>::digits;
    constexpr auto digits_u = std::numeric_limits<unsigned>::digits;
    constexpr auto digits_ul = std::numeric_limits<unsigned long>::digits;
    constexpr auto digits_ull = std::numeric_limits<unsigned long long>::digits;
    if constexpr (digits <= digits_u) {
        return __builtin_ctz(v);
    } else if constexpr (digits <= digits_ul) {
        return __builtin_ctzl(v);
    } else {
        static_assert(digits <= digits_ull);
        return __builtin_ctzll(v);
    }
}

/** Wrapper around __builtin_popcount[l][l] for supporting unsigned integer types. */
template<typename I>
unsigned inline PopCount(I v)
{
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);
    constexpr auto digits = std::numeric_limits<I>::digits;
    constexpr auto digits_u = std::numeric_limits<unsigned>::digits;
    constexpr auto digits_ul = std::numeric_limits<unsigned long>::digits;
    constexpr auto digits_ull = std::numeric_limits<unsigned long long>::digits;
    if constexpr (digits <= digits_u) {
        return __builtin_popcount(v);
    } else if constexpr (digits <= digits_ul) {
        return __builtin_popcountl(v);
    } else {
        static_assert(digits <= digits_ull);
        return __builtin_popcountll(v);
    }
}

/** Data structure storing a fee (in sats) and a size (in vbytes or weight units). */
struct FeeAndSize
{
    uint64_t sats;
    uint32_t bytes;

    /** Construct an IsEmpty() FeeAndSize. */
    FeeAndSize() : sats{0}, bytes{0} {}

    /** Construct a FeeAndSize with specified fee and size. */
    FeeAndSize(uint64_t s, uint32_t b) : sats{s}, bytes{b}
    {
        // If bytes==0, sats must be 0 as well.
        assert(bytes != 0 || sats == 0);
    }

    FeeAndSize(const FeeAndSize&) = default;
    FeeAndSize& operator=(const FeeAndSize&) = default;

    /** Check if this is empty (size, and implicitly fee, 0). */
    bool IsEmpty() const {
        return bytes == 0;
    }

    /** Add size and bytes of another FeeAndSize to this one. */
    void operator+=(const FeeAndSize& other)
    {
        sats += other.sats;
        bytes += other.bytes;
    }

    friend FeeAndSize operator+(const FeeAndSize& a, const FeeAndSize& b)
    {
        return FeeAndSize{a.sats + b.sats, a.bytes + b.bytes};
    }

};

enum class EqualFeeRate
{
    NOT_ALLOWED,
    IF_SIZE_SMALLER,
    IF_SIZE_NOT_LARGER
};

/** Function for accurately comparing the feerates of two non-empty FeeAndSize objects. */
template<EqualFeeRate EQ>
bool FeeRateHigher(const FeeAndSize& a, const FeeAndSize& b)
{
    if (__builtin_expect(((a.sats | b.sats) >> 32) != 0, false)) {
        unsigned __int128 v1 = (unsigned __int128)(a.sats) * b.bytes;
        unsigned __int128 v2 = (unsigned __int128)(b.sats) * a.bytes;
        if (v1 != v2) {
            return v1 > v2;
        }
    } else {
        uint64_t v1 = uint64_t{(uint32_t)a.sats} * b.bytes;
        uint64_t v2 = uint64_t{(uint32_t)b.sats} * a.bytes;
        if (v1 != v2) {
            return v1 > v2;
        }
    }
    if constexpr (EQ == EqualFeeRate::NOT_ALLOWED) {
        return false;
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
    return FeeRateHigher<EqualFeeRate::IF_SIZE_SMALLER>(a, b);
}

/** Determine whether a has higher feerate then b. */
bool JustFeeRateBetter(const FeeAndSize& a, const FeeAndSize& b)
{
    return FeeRateHigher<EqualFeeRate::NOT_ALLOWED>(a, b);
}

/** Determine whether a has higher feerate, or has the same feerate but the same or smaller size. */
bool FeeRateBetterOrEqual(const FeeAndSize& a, const FeeAndSize& b)
{
    return FeeRateHigher<EqualFeeRate::IF_SIZE_NOT_LARGER>(a, b);
}

/** A bitset implementation backed by a single integer of type I. */
template<typename I>
class IntBitSet
{
    // Only binary, unsigned, integer, types allowed.
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);

    /** Integer whose bits represent this bitset. */
    I m_val;

    IntBitSet(I val) noexcept : m_val{val} {}

    /** Class of objects returned by Elements(). */
    class BitPopper
    {
        I m_val;
        friend class IntBitSet;
        BitPopper(I val) noexcept : m_val(val) {}
    public:
        explicit operator bool() const noexcept { return m_val != 0; }

        unsigned Next() noexcept
        {
            int ret = CountTrailingZeroes(m_val);
            m_val &= m_val - I{1U};
            return ret;
        }
    };

public:
    static constexpr unsigned MAX_SIZE = std::numeric_limits<I>::digits;

    IntBitSet() noexcept : m_val{0} {}
    IntBitSet(const IntBitSet&) noexcept = default;
    IntBitSet& operator=(const IntBitSet&) noexcept = default;

    unsigned Count() const noexcept { return PopCount(m_val); }
    void Set(unsigned pos) noexcept { m_val |= I{1U} << pos; }
    bool operator[](unsigned pos) const noexcept { return (m_val >> pos) & 1U; }
    bool None() const noexcept { return m_val == 0; }
    bool Any() const noexcept { return m_val != 0; }
    BitPopper Elements() const noexcept { return BitPopper(m_val); }
    IntBitSet& operator|=(const IntBitSet& a) noexcept { m_val |= a.m_val; return *this; }
    friend IntBitSet operator&(const IntBitSet& a, const IntBitSet& b) noexcept { return IntBitSet{a.m_val & b.m_val}; }
    friend IntBitSet operator|(const IntBitSet& a, const IntBitSet& b) noexcept { return IntBitSet{a.m_val | b.m_val}; }
    friend IntBitSet operator/(const IntBitSet& a, const IntBitSet& b) noexcept { return IntBitSet{a.m_val & ~b.m_val}; }
    friend bool operator<(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val < b.m_val; }
    friend bool operator!=(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val != b.m_val; }
    friend bool operator==(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val == b.m_val; }
};

/** A bitset implementation backed by N integers of type I. */
template<typename I, unsigned N>
class MultiIntBitSet
{
    // Only binary, unsigned, integer, types allowed.
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);
    static constexpr unsigned LIMB_BITS = std::numeric_limits<I>::digits;

    std::array<I, N> m_val;

    class BitPopper
    {
        std::array<I, N> m_val;
        mutable unsigned m_idx;
        friend class MultiIntBitSet;
        BitPopper(const std::array<I, N>& val) : m_val(val), m_idx{0} {}

    public:
        explicit operator bool() const noexcept
        {
            while (m_idx < N && m_val[m_idx] == 0) ++m_idx;
            return m_idx < N;
        }

        unsigned Next() noexcept
        {
            while (m_val[m_idx] == 0) ++m_idx;
            assert(m_idx < N);
            int ret = CountTrailingZeroes(m_val[m_idx]);
            m_val[m_idx] &= m_val[m_idx] - I{1U};
            return ret + m_idx * LIMB_BITS;
        }
    };

public:
    static constexpr unsigned MAX_SIZE = LIMB_BITS * N;

    MultiIntBitSet() noexcept : m_val{} {}
    MultiIntBitSet(const MultiIntBitSet&) noexcept = default;
    MultiIntBitSet& operator=(const MultiIntBitSet&) noexcept = default;

    void Set(unsigned pos) noexcept { m_val[pos / LIMB_BITS] |= I{1U} << (pos % LIMB_BITS); }
    bool operator[](unsigned pos) const noexcept { return (m_val[pos / LIMB_BITS] >> (pos % LIMB_BITS)) & 1U; }

    unsigned Count() const noexcept
    {
        unsigned ret{0};
        for (I v : m_val) ret += PopCount(v);
        return ret;
    }

    bool None() const noexcept
    {
        for (auto v : m_val) {
            if (v != 0) return false;
        }
        return true;
    }

    bool Any() const noexcept
    {
        for (auto v : m_val) {
            if (v != 0) return true;
        }
        return false;
    }

    BitPopper Elements() const noexcept { return BitPopper(m_val); }

    MultiIntBitSet& operator|=(const MultiIntBitSet& a) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            m_val[i] |= a.m_val[i];
        }
        return *this;
    }

    friend MultiIntBitSet operator&(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        MultiIntBitSet r;
        for (unsigned i = 0; i < N; ++i) {
            r.m_val[i] = a.m_val[i] & b.m_val[i];
        }
        return r;
    }

    friend MultiIntBitSet operator|(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        MultiIntBitSet r;
        for (unsigned i = 0; i < N; ++i) {
            r.m_val[i] = a.m_val[i] | b.m_val[i];
        }
        return r;
    }

    friend MultiIntBitSet operator/(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        MultiIntBitSet r;
        for (unsigned i = 0; i < N; ++i) {
            r.m_val[i] = a.m_val[i] & ~b.m_val[i];
        }
        return r;
    }

    friend bool operator<(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept { return a.m_val < b.m_val; }
    friend bool operator!=(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept { return a.m_val != b.m_val; }
    friend bool operator==(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept { return a.m_val == b.m_val; }
};

/** Data type to represent cluster input.
 *
 * cluster[i].first is tx_i's fee and size.
 * cluster[i].second[j] is true iff tx_i spends one or more of tx_j's outputs.
 */
template<typename S>
using Cluster = std::vector<std::pair<FeeAndSize, S>>;

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

    AncestorSets() noexcept = default;
    AncestorSets(const AncestorSets&) = delete;
    AncestorSets(AncestorSets&&) noexcept = default;
    AncestorSets& operator=(const AncestorSets&) = delete;
    AncestorSets& operator=(AncestorSets&&) noexcept = default;

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
            auto ancestors{anc[i].Elements()};
            while (ancestors) {
                m_descendantsets[ancestors.Next()].Set(i);
            }
        }
    }

    DescendantSets() noexcept = default;
    DescendantSets(const DescendantSets&) = delete;
    DescendantSets(DescendantSets&&) noexcept = default;
    DescendantSets& operator=(const DescendantSets&) = delete;
    DescendantSets& operator=(DescendantSets&&) noexcept = default;

    const S& operator[](unsigned pos) const noexcept { return m_descendantsets[pos]; }
};

/** Output of FindBestCandidateSet* functions. */
template<typename S>
struct CandidateSetAnalysis
{
    /** Total number of candidate sets found/considered. */
    size_t num_candidate_sets{0};
    /** Best found candidate set. */
    S best_candidate_set{};
    /** Fee and size of best found candidate set. */
    FeeAndSize best_candidate_feerate{};

    /** Maximum search queue size. */
    size_t max_queue_size{0};
    /** Total number of queue processing iterations performed. */
    size_t iterations{0};
    /** Number of feerate comparisons performed. */
    size_t comparisons{0};
};

/** Compute the combined fee and size of a subset of a cluster. */
template<typename S>
FeeAndSize ComputeSetFeeRate(const Cluster<S>& cluster, const S& select)
{
    FeeAndSize ret;
    auto todo{select.Elements()};
    while (todo) {
        ret += cluster[todo.Next()].first;
    }
    return ret;
}

/** Precomputation data structure for sorting a cluster based on individual feerate. */
template<typename S>
struct SortedCluster
{
    /** The cluster in individual feerate sorted order (both itself and its dependencies) */
    Cluster<S> m_sorted_cluster;
    /** AncestorSets object with ancestor sets corresponding to m_sorted_cluster ordering. */
    AncestorSets<S> m_ancestorsets;
    /** DescendantSets object with descendant sets corresponding to m_sorted_cluster ordering. */
    DescendantSets<S> m_descendantsets;
    /** Mapping from the original order (input to constructor) to sorted order. */
    std::vector<unsigned> m_original_to_sorted;
    /** Mapping back from sorted order to the order given to the constructor. */
    std::vector<unsigned> m_sorted_to_original;

public:
    /** Get sorted cluster object. */
    const Cluster<S>& GetCluster() const noexcept { return m_sorted_cluster; }
    /** Get ancestor set (using sorted order indexing) */
    const S& GetAncestorSet(unsigned pos) const noexcept { return m_ancestorsets[pos]; }
    /** Get descendant set (using sorted order indexing) */
    const S& GetDescendantSet(unsigned pos) const noexcept { return m_descendantsets[pos]; }

    /** Given a set with indexes in original order, compute one in sorted order. */
    S OriginalToSorted(const S& val) const noexcept
    {
        S ret;
        auto todo{val.Elements()};
        while (todo) {
            ret.Set(m_original_to_sorted[todo.Next()]);
        }
        return ret;
    }

    /** Given a set with indexes in sorted order, compute on in original order. */
    S SortedToOriginal(const S& val) const noexcept
    {
        S ret;
        auto todo{val.Elements()};
        while (todo) {
            ret.Set(m_sorted_to_original[todo.Next()]);
        }
        return ret;
    }

    /** Construct a sorted cluster object given a (non-sorted) cluster as input. */
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

/** Given a cluster and its ancestor sets, find the one with the highest feerate. */
template<typename S>
CandidateSetAnalysis<S> FindBestAncestorSet(const Cluster<S>& cluster, const AncestorSets<S>& anc, const S& done)
{
    FeeAndSize best_feerate;
    S best_set;
    CandidateSetAnalysis<S> ret;
    ret.max_queue_size = 1;

    for (size_t i = 0; i < cluster.size(); ++i) {
        if (done[i]) continue;
        ++ret.iterations;
        ++ret.num_candidate_sets;
        FeeAndSize feerate = ComputeSetFeeRate(cluster, anc[i] / done);
        assert(!feerate.IsEmpty());
        bool new_best = best_feerate.IsEmpty();
        if (!new_best) {
            ++ret.comparisons;
            new_best = FeeRateBetter(feerate, best_feerate);
        }
        if (new_best) {
            best_feerate = feerate;
            best_set = anc[i];
        }
    }

    ret.best_candidate_set = best_set / done;
    ret.best_candidate_feerate = best_feerate;

    return ret;
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

    // Compute "all" set, with all the cluster's transaction.
    S all;
    for (unsigned i = 0; i < cluster.size(); ++i) all.Set(i);

    S best_candidate;
    FeeAndSize best_feerate;

    // Internal add function: given inc/exc, inc's feerate, and whether inc can possibly be a new
    // best (inc_changed), add an item to the work queue and perform other bookkeeping.
    auto add_fn = [&](S inc, S exc, FeeAndSize inc_feerate, bool inc_changed) {
        // In the loop below, we do two things simultaneously:
        // - compute the pot_feerate for the queue item.
        // - perform "jump ahead", which may add additional transactions to inc
        /** The new potential feerate. */
        FeeAndSize pot_feerate = inc_feerate;
        /** The set of transactions corresponding to that potential feerate. */
        S pot = inc;
        /** The set of ancestors of everything in pot, combined. */
        S required;
        // Loop over all undecided transactions (not yet included or excluded), from high to low feerate.
        auto undecided{(all / (inc | exc)).Elements()};
        while (undecided) {
            unsigned pos = undecided.Next();
            // Determine if adding transaction pos to pot (ignoring topology) would improve it. If not,
            // we're done updating pot/pot_feerate (and inc/inc_feerate).
            if (!pot_feerate.IsEmpty()) {
                ++ret.comparisons;
                if (!JustFeeRateBetter(cluster[pos].first, pot_feerate)) break;
            }
            // Add the transaction to pot/pot_feerate.
            pot_feerate += cluster[pos].first;
            pot.Set(pos);
            // Update the combined ancestors of pot.
            required |= scluster.GetAncestorSet(pos);
            // If at this point pot covers all its own ancestors, it means pot is topologically
            // valid. Perform jump ahead (update inc/inc_feerate to match pot/pot_feerate).
            if ((required / pot).None()) {
                inc = pot;
                inc_feerate = pot_feerate;
                inc_changed = true;
            }
        }

        // If the potential feerate is nothing, this is certainly uninteresting to work on.
        if (pot_feerate.IsEmpty()) return;

        // If inc is different from inc of the parent work item that spawned it, consider whether
        // it's the new best we've seen.
        if (inc_changed) {
            ++ret.num_candidate_sets;
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

        // Only if there are undecided transaction left besides inc and exc actually add it to the
        // queue.
        if ((all / (inc | exc)).Any()) {
            queue.emplace_back(inc, exc, inc_feerate, pot_feerate);
            ret.max_queue_size = std::max(ret.max_queue_size, queue.size());
        }
    };

    // Start by adding a work queue item corresponding to just what's done beforehand.
    add_fn(scluster.OriginalToSorted(done), S{}, FeeAndSize{}, false);

    // Work processing loop.
    while (queue.size()) {
        ++ret.iterations;

        // Pop the last element of the queue.
        auto [inc, exc, inc_feerate, pot_feerate] = queue.back();
        queue.pop_back();

        // If this item's potential feerate is worse than the best seen so far, drop it.
        assert(pot_feerate.bytes > 0);
        if (!best_feerate.IsEmpty()) {
            ++ret.comparisons;
            if (FeeRateBetterOrEqual(best_feerate, pot_feerate)) continue;
        }

        // Decide which transaction to split on (highest undecidedindividual feerate one left).
        auto undecided{(all / (inc | exc)).Elements()};
        assert(!!undecided);
        unsigned pos = undecided.Next();

        // Consider adding a work item corresponding to that transaction excluded.
        add_fn(inc, exc | scluster.GetDescendantSet(pos), inc_feerate, false);

        // Consider adding a work item corresponding to that transaction included.
        auto new_inc = inc | scluster.GetAncestorSet(pos);
        auto new_inc_feerate = inc_feerate + ComputeSetFeeRate(cluster, new_inc / inc);
        add_fn(new_inc, exc, new_inc_feerate, true);
    }

    // Translate the best found candidate to the old sort order and return.
    ret.best_candidate_set = scluster.SortedToOriginal(best_candidate) / done;
    ret.best_candidate_feerate = best_feerate;
    return ret;
}

template<typename S>
std::vector<unsigned> LinearizeCluster(const Cluster<S>& cluster)
{
    std::vector<unsigned> ret;
    ret.reserve(cluster.size());

    S all, done;
    unsigned left = cluster.size();
    for (unsigned i = 0; i < cluster.size(); ++i) all.Set(i);

    AncestorSets<S> anc(cluster);
    SortedCluster<S> scluster(cluster);

    while (left > 0) {
        CandidateSetAnalysis<S> analysis;
        if (left > 10) {
            analysis = FindBestAncestorSet(cluster, anc, done);
        } else {
            analysis = FindBestCandidateSetEfficient(scluster, done);
        }
        assert(!analysis.best_candidate_set.None());
        assert((analysis.best_candidate_set & done).None());
        size_t old_size = ret.size();
        auto to_set{analysis.best_candidate_set.Elements()};
        while (to_set) {
            ret.emplace_back(to_set.Next());
        }
        std::sort(ret.begin() + old_size, ret.end(), [&](unsigned a, unsigned b) {
            return anc[a].Count() < anc[b].Count();
        });
        done |= analysis.best_candidate_set;
        left -= analysis.best_candidate_set.Count();
    }

    return ret;
}

} // namespace

#endif // BITCOIN_CLUSTER_LINEARIZE_H
