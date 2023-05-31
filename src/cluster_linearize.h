// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CLUSTER_LINEARIZE_H
#define BITCOIN_CLUSTER_LINEARIZE_H

#include <stdint.h>

#include <algorithm>
#include <limits>
#include <numeric>
#include <optional>
#include <vector>

#include <assert.h>

namespace cluster_linearize {

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

    /** Subtrack size and bytes of another FeeAndSize from this one. */
    void operator-=(const FeeAndSize& other)
    {
        sats -= other.sats;
        bytes -= other.bytes;
    }

    friend FeeAndSize operator+(const FeeAndSize& a, const FeeAndSize& b)
    {
        return FeeAndSize{a.sats + b.sats, a.bytes + b.bytes};
    }

    /** Compare two FeeAndSize objects (both same fee and size). */
    friend bool operator==(const FeeAndSize& a, const FeeAndSize& b)
    {
        return a.sats == b.sats && a.bytes == b.bytes;
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

    static IntBitSet Full(unsigned count) noexcept {
        IntBitSet ret;
        for (unsigned i = 0; i < count; ++i) ret.Set(i);
        return ret;
    }

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

    static MultiIntBitSet Full(unsigned count) noexcept {
        MultiIntBitSet ret;
        for (unsigned i = 0; i < count; ++i) ret.Set(i);
        return ret;
    }

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

        // Propagate
        for (unsigned i = 0; i < cluster.size(); ++i) {
            // At this point, m_ancestorsets[a][b] is true iff b is an ancestor of a and there is
            // a path from a to b through the subgraph consisting of {a, b} union {0..(i-1)}.
            S to_merge = m_ancestorsets[i];
            for (unsigned j = 0; j < cluster.size(); ++j) {
                if (m_ancestorsets[j][i]) {
                    m_ancestorsets[j] |= to_merge;
                }
            }
        }
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
    /** Index of the chosen transaction (ancestor set algorithm only). */
    unsigned chosen_transaction{0};

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

/** Precomputed ancestor feerates. */
template<typename S>
class AncestorSetFeerates
{
    std::vector<FeeAndSize> m_anc_feerates;

public:
    /** Construct a precomputed ancestor set feerate object for given cluster/done. */
    explicit AncestorSetFeerates(const Cluster<S>& cluster, const AncestorSets<S>& anc, const S& done) noexcept
    {
        m_anc_feerates.resize(cluster.size());
        for (unsigned i = 0; i < cluster.size(); ++i) {
            if (!done[i]) {
                m_anc_feerates[i] = ComputeSetFeeRate(cluster, anc[i] / done);
            }
        }
    }

    /** Update the precomputed data structure to reflect that new_done was added to done. */
    void Done(const Cluster<S>& cluster, const AncestorSets<S>& anc, const S& new_done) noexcept
    {
        for (unsigned i = 0; i < cluster.size(); ++i) {
            m_anc_feerates[i] -= ComputeSetFeeRate(cluster, anc[i] & new_done);
        }
    }

    /* Same as Done, but using descendant information (more efficient). */
    void DoneDesc(const Cluster<S>& cluster, const DescendantSets<S>& desc, const S& new_done) noexcept
    {
        auto todo{new_done.Elements()};
        while (todo) {
            unsigned pos = todo.Next();
            FeeAndSize feerate = cluster[pos].first;
            auto todo_desc{(desc[pos] / new_done).Elements()};
            while (todo_desc) {
                m_anc_feerates[todo_desc.Next()] -= feerate;
            }
        }
    }

    const FeeAndSize& operator[](unsigned i) const noexcept { return m_anc_feerates[i]; }
};

/** Precomputation data structure for sorting a cluster based on individual feerate. */
template<typename S>
struct SortedCluster
{
    /** The cluster in individual feerate sorted order (both itself and its dependencies) */
    Cluster<S> cluster;
    /** Mapping from the original order (input to constructor) to sorted order. */
    std::vector<unsigned> original_to_sorted;
    /** Mapping back from sorted order to the order given to the constructor. */
    std::vector<unsigned> sorted_to_original;

    /** Given a set with indexes in original order, compute one in sorted order. */
    S OriginalToSorted(const S& val) const noexcept
    {
        S ret;
        auto todo{val.Elements()};
        while (todo) {
            ret.Set(original_to_sorted[todo.Next()]);
        }
        return ret;
    }

    /** Given a set with indexes in sorted order, compute on in original order. */
    S SortedToOriginal(const S& val) const noexcept
    {
        S ret;
        auto todo{val.Elements()};
        while (todo) {
            ret.Set(sorted_to_original[todo.Next()]);
        }
        return ret;
    }

    /** Construct a sorted cluster object given a (non-sorted) cluster as input. */
    SortedCluster(const Cluster<S>& orig_cluster)
    {
        // Allocate vectors.
        sorted_to_original.resize(orig_cluster.size());
        original_to_sorted.resize(orig_cluster.size());
        cluster.resize(orig_cluster.size());
        // Compute sorted_to_original mapping.
        std::iota(sorted_to_original.begin(), sorted_to_original.end(), 0U);
        std::sort(sorted_to_original.begin(), sorted_to_original.end(), [&](unsigned i, unsigned j) {
            return FeeRateBetter(orig_cluster[i].first, orig_cluster[j].first);
        });
        // Use sorted_to_original to fill original_to_sorted.
        for (size_t i = 0; i < orig_cluster.size(); ++i) {
            original_to_sorted[sorted_to_original[i]] = i;
        }
        // Use sorted_to_original to fill cluster.
        for (size_t i = 0; i < orig_cluster.size(); ++i) {
            cluster[i].first = orig_cluster[sorted_to_original[i]].first;
            cluster[i].second = OriginalToSorted(orig_cluster[sorted_to_original[i]].second);
        }
    }
};

/** Given a cluster and its ancestor sets, find the one with the highest feerate. */
template<typename S>
CandidateSetAnalysis<S> FindBestAncestorSet(const Cluster<S>& cluster, const AncestorSets<S>& anc, const AncestorSetFeerates<S>& anc_feerates, const S& done)
{
    CandidateSetAnalysis<S> ret;
    ret.max_queue_size = 1;

    for (size_t i = 0; i < cluster.size(); ++i) {
        if (done[i]) continue;
        ++ret.iterations;
        ++ret.num_candidate_sets;
        FeeAndSize feerate = anc_feerates[i];
        assert(!feerate.IsEmpty());
        bool new_best = ret.best_candidate_feerate.IsEmpty();
        if (!new_best) {
            ++ret.comparisons;
            new_best = FeeRateBetter(feerate, ret.best_candidate_feerate);
        }
        if (new_best) {
            ret.best_candidate_feerate = feerate;
            ret.best_candidate_set = anc[i] / done;
            ret.chosen_transaction = i;
        }
    }

    return ret;
}

/** An efficient algorithm for finding the best candidate set. Believed to be O(~1.6^n).
 *
 * cluster must be sorted (see SortedCluster) by individual feerate, and anc/desc/done must use
 * the same indexing as cluster.
 */
template<typename S>
CandidateSetAnalysis<S> FindBestCandidateSetEfficient(const Cluster<S>& cluster, const AncestorSets<S>& anc, const DescendantSets<S>& desc, const AncestorSetFeerates<S>& anc_feerates, const S& done)
{
    // Queue of work units. Each consists of:
    // - inc: bitset of transactions definitely included (always includes done)
    // - exc: bitset of transactions definitely excluded
    // - inc_feerate: the feerate of (included / done)
    // - pot_feerate: a conservative upper bound on the feerate for any candidate set that includes
    //                all of inc and does not include any of exc.
    std::vector<std::tuple<S, S, FeeAndSize, FeeAndSize>> queue;

    CandidateSetAnalysis<S> ret;

    // Compute "all" set, with all the cluster's transaction.
    S all = S::Full(cluster.size());
    if (done == all) return ret;

    S best_candidate;
    FeeAndSize best_feerate;

    // Internal add function: given inc/exc, inc's feerate, and whether inc can possibly be a new
    // best seen so far, add an item to the work queue and perform other bookkeeping.
    auto add_fn = [&](S inc, S exc, FeeAndSize inc_feerate, bool inc_may_be_best) {
        // In the loop below, we do two things simultaneously:
        // - compute the pot_feerate for the new queue item.
        // - perform "jump ahead", which may add additional transactions to inc
        /** The new potential feerate. */
        FeeAndSize pot_feerate = inc_feerate;
        /** The set of transactions corresponding to that potential feerate. */
        S pot = inc;
        /** The set of ancestors of everything in pot, combined. */
        S pot_ancestors;
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
            pot_ancestors |= anc[pos];
            // If at this point pot covers all its own ancestors, it means pot is topologically
            // valid. Perform jump ahead (update inc/inc_feerate to match pot/pot_feerate).
            if ((pot_ancestors / pot).None()) {
                inc = pot;
                inc_feerate = pot_feerate;
                inc_may_be_best = true;
            }
        }

        // If the potential feerate is nothing, this is certainly uninteresting to work on.
        if (pot_feerate.IsEmpty()) return;

        // If inc is different from inc of the parent work item that spawned it, consider whether
        // it's the new best we've seen.
        if (inc_may_be_best) {
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

        // Only if there are undecided transactions left besides inc and exc actually add it to the
        // queue.
        if ((all / (inc | exc)).Any()) {
            queue.emplace_back(inc, exc, inc_feerate, pot_feerate);
            ret.max_queue_size = std::max(ret.max_queue_size, queue.size());
        }
    };

    // Find best ancestor set to seed the search. Add a queue item corresponding to the transaction
    // with the highest ancestor set feerate excluded, and one with it included.
    auto ret_ancestor = FindBestAncestorSet(cluster, anc, anc_feerates, done);
    add_fn(done, desc[ret_ancestor.chosen_transaction], {}, false);
    add_fn(done | ret_ancestor.best_candidate_set, {}, ret_ancestor.best_candidate_feerate, true);

    // Work processing loop.
    while (queue.size()) {
        ++ret.iterations;

        // Pop the last element of the queue.
        auto [inc, exc, inc_feerate, pot_feerate] = queue.back();
        queue.pop_back();

        // If this item's potential feerate is not better than the best seen so far, drop it.
        assert(pot_feerate.bytes > 0);
        if (!best_feerate.IsEmpty()) {
            ++ret.comparisons;
            if (FeeRateBetterOrEqual(best_feerate, pot_feerate)) continue;
        }

        // Decide which transaction to split on (highest undecided individual feerate one left).
        auto undecided{(all / (inc | exc)).Elements()};
        assert(undecided);
        auto pos = undecided.Next();

        // Consider adding a work item corresponding to that transaction excluded. As nothing is
        // being added to inc, this new entry cannot be a new best.
        add_fn(inc, exc | desc[pos], inc_feerate, false);

        // Consider adding a work item corresponding to that transaction included. Since only
        // connected subgraphs can be optimal candidates, if there is no overlap between the
        // parent's included transactions (inc) and the ancestors of the newly added transaction
        // (outside of done), we know it cannot possibly be the new best.
        // One exception to this is the first addition after an empty inc (inc=done). However,
        // due to the preseeding with the best ancestor set, we know that anything better must
        // necessarily consist of the union of at least two ancestor sets, and this is not a
        // concern.
        auto new_inc = inc | anc[pos];
        auto new_inc_feerate = inc_feerate + ComputeSetFeeRate(cluster, new_inc / inc);
        bool may_be_new_best = ((inc & anc[pos]) / done).Any();
        add_fn(new_inc, exc, new_inc_feerate, may_be_new_best);
    }

    // Return.
    ret.best_candidate_set = best_candidate / done;
    ret.best_candidate_feerate = best_feerate;
    return ret;
}

/** Compute a full linearization of a cluster (vector of cluster indices). */
template<typename S>
std::vector<unsigned> LinearizeCluster(const Cluster<S>& cluster)
{
    std::vector<unsigned> ret;
    ret.reserve(cluster.size());
    S done;
    unsigned left = cluster.size();

    // Precompute stuff.
    SortedCluster<S> scluster(cluster);
    AncestorSets<S> anc(scluster.cluster);
    DescendantSets<S> desc(anc);
    // Precompute ancestor set sizes, to help with topological sort.
    std::vector<unsigned> anccount(cluster.size(), 0);
    for (unsigned i = 0; i < cluster.size(); ++i) {
        anccount[i] = anc[i].Count();
    }
    AncestorSetFeerates anc_feerates(scluster.cluster, anc, done);

    // Iterate while there are transactions left.
    while (left > 0) {
        // Invoke function to find a good/best candidate.
        CandidateSetAnalysis<S> analysis;
        if (left > 10) {
            analysis = FindBestAncestorSet(scluster.cluster, anc, anc_feerates, done);
        } else {
            analysis = FindBestCandidateSetEfficient(scluster.cluster, anc, desc, anc_feerates, done);
        }

        // Sanity checks.
        assert(!analysis.best_candidate_set.None()); // Must be at least one transaction
        assert((analysis.best_candidate_set & done).None()); // Cannot overlap with processed ones.

        // Append candidate's transactions to linearization, and topologically sort them.
        size_t old_size = ret.size();
        auto to_set{analysis.best_candidate_set.Elements()};
        while (to_set) {
            ret.emplace_back(to_set.Next());
        }
        std::sort(ret.begin() + old_size, ret.end(), [&](unsigned a, unsigned b) {
            return anccount[a] < anccount[b];
        });

        // Update bookkeeping to reflect newly added transactions.
        left -= analysis.best_candidate_set.Count();
        if (!left) break; // Bail out quickly if nothing left.
        done |= analysis.best_candidate_set;
        // Update precomputed ancestor feerates.
        anc_feerates.DoneDesc(scluster.cluster, desc, analysis.best_candidate_set);
#if 0
        // Verify that precomputed ancestor feerates are correct.
        for (unsigned i = 0; i < cluster.size(); ++i) {
            if (!done[i]) {
                assert(anc_feerates[i] == ComputeSetFeeRate(scluster.cluster, anc[i] / done));
            }
        }
#endif
    }

    // Map linearization back from sorted cluster indices to original indices.
    for (unsigned i = 0; i < cluster.size(); ++i) {
        ret[i] = scluster.sorted_to_original[ret[i]];
    }

    return ret;
}

/** Deserialize a number, in little-endian 7 bit format, top bit set = more bytes. */
template<typename Fn>
uint64_t DeserializeNumberBase128(Fn&& getbyte)
{
    uint64_t ret{0};
    for (int i = 0; i < 10; ++i) {
        uint8_t b = getbyte();
        ret |= ((uint64_t)(b & uint8_t{0x7F})) << (7 * i);
        if ((b & 0x80) == 0) break;
    }
    return ret;
}

/** Serialize a number, in little-endian 7 bit format, top bit set = more bytes. */
template<typename Fn>
void SerializeNumberBase128(uint64_t val, Fn&& putbyte)
{
    for (int i = 0; i < 10; ++i) {
        uint8_t b = (val >> (7 * i)) & 0x7F;
        val &= ~(uint64_t{0x7F} << (7 * i));
        if (val) {
            putbyte(b | 0x80);
        } else {
            putbyte(b);
            break;
        }
    }
}

/** Serialize a topologically ordered cluster in the following format:
 *
 * - For every transaction:
 *   - Base128 encoding of its byte size (at least 1, max 2^22-1).
 *   - Base128 encoding of its fee in sats (max 2^51-1).
 *   - For each of its parents:
 *     - Base128 encoding of child_idx - parent_idx (at least 1).
 *   - A zero byte
 * - A zero byte
 */
template<typename Fn, typename S>
void SerializeCluster(const Cluster<S>& cluster, Fn&& putbyte)
{
    for (unsigned i = 0; i < cluster.size(); ++i) {
        SerializeNumberBase128(cluster[i].first.bytes, putbyte);
        SerializeNumberBase128(cluster[i].first.sats, putbyte);
        for (unsigned j = 0; j < i; ++j) {
            if (cluster[i].second[i - 1 - j]) {
                SerializeNumberBase128(j + 1, putbyte);
            }
        }
        putbyte(uint8_t{0});
    }
    putbyte(uint8_t{0});
}

/** Deserialize a cluster in the same format as SerializeCluster (overflows wrap). */
template<typename S, typename Fn>
Cluster<S> DeserializeCluster(Fn&& getbyte)
{
    Cluster<S> ret;
    while (true) {
        uint32_t bytes = DeserializeNumberBase128(getbyte) & 0x3fffff; /* Just above 4000000 */
        if (bytes == 0) break;
        uint64_t sats = DeserializeNumberBase128(getbyte) & 0x7ffffffffffff; /* Just above 21000000 * 100000000 */
        S parents;
        while (true) {
            unsigned b = DeserializeNumberBase128(getbyte) % (ret.size() + 1);
            if (b == 0) break;
            parents.Set(ret.size() - b);
        }
        if (ret.size() < S::MAX_SIZE) {
            ret.emplace_back(FeeAndSize{sats, bytes}, std::move(parents));
        }
    }
    return ret;
}

uint8_t ReadSpanByte(Span<const unsigned char>& data)
{
    if (data.empty()) return 0;
    uint8_t val = data[0];
    data = data.subspan(1);
    return val;
}

/** Deserialize a cluster from a Span of bytes. */
template<typename S>
Cluster<S> DecodeCluster(Span<const unsigned char>& data)
{
    return DeserializeCluster<S>([&]() { return ReadSpanByte(data); });
}

/** Encode a cluster to a vector of bytes. */
template<typename S>
std::vector<unsigned char> EncodeCluster(const Cluster<S>& cluster)
{
    std::vector<unsigned char> ret;
    SerializeCluster(cluster, [&](uint8_t val) { ret.emplace_back(val); });
    return ret;
}

/** Minimize the set of parents of every cluster transaction, without changing ancestry. */
template<typename S>
void WeedCluster(Cluster<S>& cluster, const AncestorSets<S>& ancs)
{
    std::vector<std::pair<unsigned, unsigned>> mapping(cluster.size());
    for (unsigned i = 0; i < cluster.size(); ++i) {
        mapping[i] = {ancs[i].Count(), i};
    }
    std::sort(mapping.begin(), mapping.end());
    for (unsigned i = 0; i < cluster.size(); ++i) {
        const auto& [_anc_count, idx] = mapping[i];
        S parents;
        S cover;
        cover.Set(idx);
        for (unsigned j = 0; j < i; ++j) {
            const auto& [_anc_count_j, idx_j] = mapping[i - 1 - j];
            if (ancs[idx][idx_j] && !cover[idx_j]) {
                parents.Set(idx_j);
                cover |= ancs[idx_j];
            }
        }
        assert(cover == ancs[idx]);
        cluster[idx].second = std::move(parents);
    }
}

/** Construct a new cluster with done removed from a given cluster.
 *
 * The result is also topologically sorted, first including highest individual-feerate
 * transactions among those whose dependencies are satisfied. */
template<typename S>
Cluster<S> TruncateCluster(const Cluster<S>& cluster, S done)
{
    Cluster<S> ret;
    std::vector<unsigned> mapping;
    while (true) {
        std::optional<std::pair<FeeAndSize, unsigned>> best;
        for (unsigned i = 0; i < cluster.size(); ++i) {
            if (done[i]) continue;
            if ((cluster[i].second / done).Any()) continue;
            std::pair<FeeAndSize, unsigned> key{cluster[i].first, i};
            if (!best.has_value() ||
                FeeRateBetter(key.first, best->first) ||
                (key.first == best->first && key.second < best->second)) {
                best = key;
            }
        }
        if (!best.has_value()) break;
        const unsigned idx = best->second;
        done.Set(idx);
        mapping.push_back(idx);
        S parents;
        for (unsigned i = 0; i < mapping.size(); ++i) {
            unsigned idx_i = mapping[i];
            if (cluster[idx].second[idx_i]) parents.Set(i);
        }
        ret.emplace_back(cluster[idx].first, parents);
    }
    return ret;
}

/** Minimize a cluster, sort it topologically, and serialize to byte vector. */
template<typename S>
std::vector<unsigned char> DumpCluster(Cluster<S> cluster)
{
    AncestorSets<S> anc(cluster);
    WeedCluster(cluster, anc);
    return EncodeCluster(TruncateCluster(cluster, {}));
}

} // namespace

} // namespace linearize_cluster

#endif // BITCOIN_CLUSTER_LINEARIZE_H
