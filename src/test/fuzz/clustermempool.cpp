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

/** Wrapper around __builtin_ctz[l][l] for supporting unsigned integer types. */
template<typename I>
int inline CountTrailingZeroes(I v)
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

/** Union-Find data structure. */
template<typename SizeType, SizeType Size>
class UnionFind
{
    SizeType m_ref[Size];
    SizeType m_size;

public:
    /** Initialize a UF data structure with size items, each in their own partition. */
    void Init(SizeType size)
    {
        m_size = size;
        for (SizeType i = 0; i < m_size; ++i) {
            m_ref[i] = i;
        }
    }

    /** Construct a UF data structure with size items, each in their own partition. */
    explicit UnionFind(SizeType size)
    {
        Init(size);
    }

    /** Find a representative of the partition that item idx is in. */
    SizeType Find(SizeType idx)
    {
        SizeType start = idx;
        // Chase references to make idx be the representative.
        while (m_ref[idx] != idx) {
            idx = m_ref[idx];
        }
        // Update all references along the way to point to idx.
        while (m_ref[start] != idx) {
            SizeType prev = start;
            start = m_ref[start];
            m_ref[prev] = idx;
        }
        return idx;
    }

    /** Merge the partitions that item a and item b are in. */
    void Union(SizeType a, SizeType b)
    {
        m_ref[Find(a)] = Find(b);
    }
};

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

    friend std::ostream& operator<<(std::ostream& o, const FeeAndSize& data)
    {
        o << "(" << data.sats << "/" << data.bytes << "=" << ((double)data.sats / data.bytes) << ")";
        return o;
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

    /** Class of objects returned by OneBits(). */
    class BitPopper
    {
        I m_val;
        friend class IntBitSet;
        BitPopper(I val) noexcept : m_val(val) {}
    public:
        explicit operator bool() const noexcept { return m_val != 0; }

        unsigned Pop() noexcept
        {
            int ret = CountTrailingZeroes(m_val);
            m_val &= m_val - I{1U};
            return ret;
        }
    };

public:
    static constexpr unsigned SIZE = std::numeric_limits<I>::digits;

    IntBitSet() noexcept : m_val{0} {}
    IntBitSet(const IntBitSet&) noexcept = default;
    IntBitSet& operator=(const IntBitSet&) noexcept = default;

    void Set(unsigned pos) noexcept { m_val |= I{1U} << pos; }
    bool operator[](unsigned pos) const noexcept { return (m_val >> pos) & 1U; }
    bool None() const noexcept { return m_val == 0; }
    bool Any() const noexcept { return m_val != 0; }
    BitPopper OneBits() const noexcept { return BitPopper(m_val); }
    IntBitSet& operator|=(const IntBitSet& a) noexcept { m_val |= a.m_val; return *this; }
    friend IntBitSet operator&(const IntBitSet& a, const IntBitSet& b) noexcept { return IntBitSet{a.m_val & b.m_val}; }
    friend IntBitSet operator|(const IntBitSet& a, const IntBitSet& b) noexcept { return IntBitSet{a.m_val | b.m_val}; }
    friend IntBitSet operator/(const IntBitSet& a, const IntBitSet& b) noexcept { return IntBitSet{a.m_val & ~b.m_val}; }
    friend bool operator<(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val < b.m_val; }
    friend bool operator!=(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val != b.m_val; }
    friend bool operator==(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val == b.m_val; }

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

/** A bitset implementation backed by N integers of type I. */
template<typename I, unsigned N>
class MultiIntBitSet
{
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

        unsigned Pop() noexcept
        {
            while (m_val[m_idx] == 0) ++m_idx;
            assert(m_idx < N);
            int ret = CountTrailingZeroes(m_val[m_idx]);
            m_val[m_idx] &= m_val[m_idx] - I{1U};
            return ret + m_idx * LIMB_BITS;
        }
    };

public:
    static constexpr unsigned SIZE = LIMB_BITS * N;

    MultiIntBitSet() noexcept : m_val{} {}
    MultiIntBitSet(const MultiIntBitSet&) noexcept = default;
    MultiIntBitSet& operator=(const MultiIntBitSet&) noexcept = default;

    void Set(unsigned pos) noexcept { m_val[pos / LIMB_BITS] |= I{1U} << (pos % LIMB_BITS); }
    bool operator[](unsigned pos) const noexcept { return (m_val[pos / LIMB_BITS] >> (pos % LIMB_BITS)) & 1U; }

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

    BitPopper OneBits() const noexcept { return BitPopper(m_val); }

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

    friend std::ostream& operator<<(std::ostream& s, const MultiIntBitSet& bs)
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
    auto todo{select.OneBits()};
    while (todo) {
        unsigned pos = todo.Pop();
        auto deps{(cluster[pos].second & select).OneBits()};
        while (deps) uf.Union(pos, deps.Pop());
    }

    /* Test that all selected entries in uf have the same representative. */
    todo = select.OneBits();
    unsigned root = uf.Find(todo.Pop());
    while (todo) {
        if (uf.Find(todo.Pop()) != root) return false;
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
            auto ancestors{anc[i].OneBits()};
            while (ancestors) {
                m_descendantsets[ancestors.Pop()].Set(i);
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
    auto todo{select.OneBits()};
    while (todo) {
        ret += cluster[todo.Pop()].first;
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
    assert(cluster.size() <= 25); // This becomes really unwieldy for large clusters
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
        auto todo{val.OneBits()};
        while (todo) {
            ret.Set(m_original_to_sorted[todo.Pop()]);
        }
        return ret;
    }

    /** Given a set with indexes in sorted order, compute on in original order. */
    S SortedToOriginal(const S& val) const noexcept
    {
        S ret;
        auto todo{val.OneBits()};
        while (todo) {
            ret.Set(m_sorted_to_original[todo.Pop()]);
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
std::pair<S, FeeAndSize> FindBestAncestorSet(const Cluster<S>& cluster, const AncestorSets<S>& anc, const S& done)
{
    FeeAndSize best_feerate;
    S best_set;

    for (size_t i = 0; i < cluster.size(); ++i) {
        if (done[i]) continue;
        FeeAndSize feerate = ComputeSetFeeRate(cluster, anc[i] / done);
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
        auto undecided{(all / (inc | exc)).OneBits()};
        while (undecided) {
            unsigned pos = undecided.Pop();
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
        auto undecided{(all / (inc | exc)).OneBits()};
        assert(!!undecided);
        unsigned pos = undecided.Pop();

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

using BitSet = MultiIntBitSet<uint64_t, 2>;
//using BitSet = IntBitSet<uint64_t>;

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

    // Read cluster from fuzzer.
    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/true);
    // Compute ancestor sets.
    AncestorSets anc(cluster);
    // Find a topologically (but not necessarily connect) subset to set as "done" already.
    BitSet done;
    for (size_t i = 0; i < cluster.size(); ++i) {
        if (provider.ConsumeBool()) {
            done |= anc[i];
        }
    }

    // Run both algorithms.
    auto ret_naive = FindBestCandidateSetNaive(cluster, done);
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done);

    // Compute number of candidate sets and best feerate of found result.
    assert(ret_exhaustive.num_candidate_sets == ret_naive.num_candidate_sets);
    assert(ret_exhaustive.best_candidate_feerate.sats == ret_naive.best_candidate_feerate.sats);
    assert(ret_exhaustive.best_candidate_feerate.bytes == ret_naive.best_candidate_feerate.bytes);

    // We cannot require that the actual candidate returned is identical, because there may be
    // multiple, and the algorithms iterate in different order. Instead, recompute the feerate of
    // the candidate returned by the exhaustive one and check that it matches the claimed value.
    auto feerate_exhaustive = ComputeSetFeeRate(cluster, ret_exhaustive.best_candidate_set);
    assert(feerate_exhaustive.sats == ret_exhaustive.best_candidate_feerate.sats);
    assert(feerate_exhaustive.bytes == ret_exhaustive.best_candidate_feerate.bytes);
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

    SortedCluster<BitSet> scluster(cluster);

    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done);
    auto ret_efficient = FindBestCandidateSetEfficient(scluster, done);
    auto feerate_efficient = ComputeSetFeeRate(cluster, ret_efficient.best_candidate_set);

    assert(ret_exhaustive.best_candidate_feerate.sats == ret_efficient.best_candidate_feerate.sats);
    assert(ret_exhaustive.best_candidate_feerate.bytes == ret_efficient.best_candidate_feerate.bytes);
    assert(feerate_efficient.sats == ret_exhaustive.best_candidate_feerate.sats);
    assert(feerate_efficient.bytes == ret_exhaustive.best_candidate_feerate.bytes);
}

FUZZ_TARGET(clustermempool_efficient_equals_exhaustive_nodone)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/false);

    BitSet all;
    for (unsigned i = 0; i < cluster.size(); ++i) all.Set(i);
    if (!IsConnectedSubset(cluster, all)) return;

    AncestorSets anc(cluster);

/*    auto [_, anc_feerate] = FindBestAncestorSet(cluster, anc, {});*/

    SortedCluster<BitSet> scluster(cluster);

    auto ret_efficient = FindBestCandidateSetEfficient(scluster, {});
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, {});

    assert(ret_exhaustive.best_candidate_feerate.sats == ret_efficient.best_candidate_feerate.sats);
    assert(ret_exhaustive.best_candidate_feerate.bytes == ret_efficient.best_candidate_feerate.bytes);

/*
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
*/
}

FUZZ_TARGET(clustermempool_efficient_equals_exhaustive_mul5)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    Cluster<BitSet> orig_cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/false);
    if (orig_cluster.size() * 5 > 128) return;

    BitSet orig_all;
    for (unsigned i = 0; i < orig_cluster.size(); ++i) orig_all.Set(i);
    if (!IsConnectedSubset(orig_cluster, orig_all)) return;

    BitSet done, all;
    Cluster<BitSet> cluster;
    for (size_t i = 0; i < orig_cluster.size(); ++i) {
        // Item 5*i
        done.Set(5 * i);
        cluster.emplace_back(orig_cluster[i].first, BitSet{});

        // Item 5*i+1 (= original i)
        all.Set(5 * i + 1);
        BitSet parents;
        auto todo{orig_cluster[i].second.OneBits()};
        while (todo) {
            parents.Set(todo.Pop() * 5 + 1);
        }
        cluster.emplace_back(orig_cluster[i].first, std::move(parents));

        // Item 5*i+2
        all.Set(5 * i + 1);
        done.Set(5 * i + 2);
        cluster.emplace_back(orig_cluster[i].first, BitSet{});

        // Item 5*i+3
        done.Set(5 * i + 3);
        cluster.emplace_back(orig_cluster[i].first, BitSet{});

        // Item 5*i+4
        done.Set(5 * i + 4);
        cluster.emplace_back(orig_cluster[i].first, BitSet{});
    }
    assert(cluster.size() == orig_cluster.size() * 5);
    assert(IsConnectedSubset(cluster, all));

    AncestorSets anc(cluster);

/*    auto [_, anc_feerate] = FindBestAncestorSet(cluster, anc, {});*/

    SortedCluster<BitSet> scluster(cluster);

    auto ret_efficient = FindBestCandidateSetEfficient(scluster, done);
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done);
    auto feerate_efficient = ComputeSetFeeRate(cluster, ret_efficient.best_candidate_set);

    assert(ret_exhaustive.best_candidate_feerate.sats == ret_efficient.best_candidate_feerate.sats);
    assert(ret_exhaustive.best_candidate_feerate.bytes == ret_efficient.best_candidate_feerate.bytes);
    assert(feerate_efficient.sats == ret_exhaustive.best_candidate_feerate.sats);
    assert(feerate_efficient.bytes == ret_exhaustive.best_candidate_feerate.bytes);

    static unsigned prev{0};
    if (cluster.size() > prev) {
        prev = cluster.size();
        std::cerr << "SIZE " << prev << std::endl;
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
