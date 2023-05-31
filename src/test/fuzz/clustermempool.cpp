// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <time.h>

#include <vector>

#include <crypto/siphash.h>
#include <cluster_linearize.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>

#include <assert.h>

#include <iostream>

using namespace cluster_linearize;

namespace {

std::ostream& operator<<(std::ostream& o, const FeeAndSize& data)
{
    o << "(" << data.sats << "/" << data.bytes << "=" << ((double)data.sats / data.bytes) << ")";
    return o;
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

template<typename I>
std::ostream& operator<<(std::ostream& s, const IntBitSet<I>& bs)
{
    s << "[";
    size_t cnt = 0;
    for (size_t i = 0; i < bs.MAX_SIZE; ++i) {
        if (bs[i]) {
            if (cnt) s << ",";
            ++cnt;
            s << i;
        }
    }
    s << "]";
    return s;
}

template<typename I, unsigned N>
std::ostream& operator<<(std::ostream& s, const MultiIntBitSet<I, N>& bs)
{
    s << "[";
    size_t cnt = 0;
    for (size_t i = 0; i < bs.MAX_SIZE; ++i) {
        if (bs[i]) {
            if (cnt) s << ",";
            ++cnt;
            s << i;
        }
    }
    s << "]";
    return s;
}

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

/** Determine if select is a connected subset in the given cluster. */
template<typename S>
bool IsConnectedSubset(const Cluster<S>& cluster, const S& select)
{
    /* Trivial case. */
    if (select.None()) return true;

    /* Build up UF data structure. */
    UnionFind<unsigned, S::MAX_SIZE> uf(cluster.size());
    auto todo{select.Elements()};
    while (todo) {
        unsigned pos = todo.Next();
        auto deps{(cluster[pos].second & select).Elements()};
        while (deps) uf.Union(pos, deps.Next());
    }

    /* Test that all selected entries in uf have the same representative. */
    todo = select.Elements();
    unsigned root = uf.Find(todo.Next());
    while (todo) {
        if (uf.Find(todo.Next()) != root) return false;
    }
    return true;
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

template<typename Fn>
uint64_t DeserializeNumber(Fn&& getbyte)
{
    uint64_t ret{0};
    for (int i = 0; i < 10; ++i) {
        uint8_t b = getbyte();
        ret |= ((uint64_t)(b & uint8_t{0x7F})) << (7 * i);
        if ((b & 0x80) == 0) break;
    }
    return ret;
}

template<typename Fn>
void SerializeNumber(uint64_t val, Fn&& putbyte)
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

template<typename S, typename Fn>
Cluster<S> DeserializeCluster(Fn&& getbyte)
{
    Cluster<S> ret;
    while (true) {
        uint32_t bytes = DeserializeNumber(getbyte) & 0x3fffff; /* Just above 4000000 */
        if (bytes == 0) break;
        uint64_t sats = DeserializeNumber(getbyte) & 0x7ffffffffffff; /* Just above 21000000 * 100000000 */
        S parents;
        while (true) {
            uint8_t b = getbyte() % (ret.size() + 1);
            if (b == 0) break;
            parents.Set(ret.size() - b);
        }
        if (ret.size() < S::MAX_SIZE) {
            ret.emplace_back(FeeAndSize{sats, bytes}, std::move(parents));
        }
    }
    return ret;
}

template<typename S>
Cluster<S> DecodeCluster(Span<const unsigned char>& data)
{
    size_t pos = 0;
    auto getbyte = [&]() -> uint8_t {
        if (pos < data.size()) {
            return data[pos++];
        } else {
            return 0;
        }
    };
    auto ret = DeserializeCluster<S>(getbyte);
    data = data.subspan(pos);
    return ret;
}

template<typename S>
S DecodeDone(Span<const unsigned char>& data, const AncestorSets<S>& ancs)
{
    S ret;
    while (!data.empty()) {
        uint8_t val = data[0] % (ancs.Size() + 1);
        data = data.subspan(1);
        if (val == 0) break;
        ret |= ancs[ancs.Size() - val];
    }
    return ret;
}

template<typename Fn, typename S>
void SerializeCluster(const Cluster<S>& cluster, Fn&& putbyte)
{
    for (unsigned i = 0; i < cluster.size(); ++i) {
        SerializeNumber(cluster[i].first.bytes, putbyte);
        SerializeNumber(cluster[i].first.sats, putbyte);
        for (unsigned j = 0; j < i; ++j) {
            if (cluster[i].second[i - 1 - j]) {
                putbyte(j + 1);
            }
        }
        putbyte(uint8_t{0});
    }
    putbyte(uint8_t{0});
}

template<typename S>
std::vector<unsigned char> EncodeCluster(const Cluster<S>& cluster)
{
    std::vector<unsigned char> ret;
    auto putbyte = [&](uint8_t val) { ret.emplace_back(val); };
    SerializeCluster(cluster, putbyte);
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
 * The result is also topologically sorted, first including a highest individual-feerate
 * transaction among those whose dependencies are satisfied. */
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

template<typename S>
bool IsTopologicallyOrdered(const Cluster<S>& cluster)
{
    for (unsigned i = 0; i < cluster.size(); ++i) {
        auto todo{cluster[i].second.Elements()};
        while (todo) {
            unsigned pos = todo.Next();
            if (pos >= i) return false;
        }
    }
    return true;
}

template<typename T, unsigned N>
class KeepBest
{
    static_assert(N >= 1);
    unsigned m_count{0};
    T m_vals[N]; /* m_vals[0]=best m_vals[1..m_count-1]=minheap of the rest */

public:
    KeepBest() = default;
    bool Any() const { return m_count > 0; }
    const T& Best() const { return m_vals[0]; }

    bool Add(T&& arg)
    {
        if (m_count == 0) {
            m_vals[0] = std::move(arg);
            ++m_count;
            return true;
        }
        bool ret = false;
        if (arg > m_vals[0]) {
            std::swap(arg, m_vals[0]);
            ret = true;
        }
        if constexpr (N > 1) {
            if (m_count < N) {
                m_vals[m_count] = std::move(arg);
                ++m_count;
                if (m_count == N) {
                    std::make_heap(std::begin(m_vals) + 1, std::end(m_vals), std::greater<T>{});
                }
                return true;
            }
            if (arg > m_vals[1]) {
                std::pop_heap(std::begin(m_vals) + 1, std::end(m_vals), std::greater<T>{});
                m_vals[N - 1] = std::move(arg);
                std::push_heap(std::begin(m_vals) + 1, std::end(m_vals), std::greater<T>{});
                return true;
            }
        }
        return ret;
    }
};

struct StatEntry
{
    uint64_t stat;
    size_t cluster_size;
};

bool operator>(const StatEntry& a, const StatEntry& b) {
    if (a.stat > b.stat) return true;
    if (a.stat < b.stat) return false;
    if (a.cluster_size > b.cluster_size) return false;
    if (a.cluster_size < b.cluster_size) return true;
    return false;
}

/*using BitSet = MultiIntBitSet<uint64_t, 2>;*/
using BitSet = IntBitSet<uint64_t>;

} // namespace

FUZZ_TARGET(clustermempool_exhaustive_equals_naive)
{
    // Read cluster from fuzzer.
    Cluster<BitSet> cluster = DecodeCluster<BitSet>(buffer);
    if (cluster.size() > 15) return;

    // Compute ancestor sets.
    AncestorSets anc(cluster);
    // Find a topologically (but not necessarily connect) subset to set as "done" already.
    BitSet done = DecodeDone(buffer, anc);

    // Run both algorithms.
    auto ret_naive = FindBestCandidateSetNaive(cluster, done);
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done);

    // Compute number of candidate sets and best feerate of found result.
    assert(ret_exhaustive.num_candidate_sets == ret_naive.num_candidate_sets);
    assert(ret_exhaustive.best_candidate_feerate == ret_naive.best_candidate_feerate);

    // We cannot require that the actual candidate returned is identical, because there may be
    // multiple, and the algorithms iterate in different order. Instead, recompute the feerate of
    // the candidate returned by the exhaustive one and check that it matches the claimed value.
    auto feerate_exhaustive = ComputeSetFeeRate(cluster, ret_exhaustive.best_candidate_set);
    assert(feerate_exhaustive == ret_exhaustive.best_candidate_feerate);
}

FUZZ_TARGET(clustermempool_efficient_equals_exhaustive)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Read cluster from fuzzer.
    Cluster<BitSet> cluster = DecodeCluster<BitSet>(buffer);
    if (cluster.size() > 20) return;
    // Compute ancestor sets.
    AncestorSets anc(cluster);

    // Find a topologically (but not necessarily connected) subset to set as "done" already.
    BitSet done = DecodeDone<BitSet>(buffer, anc);

    // Sort the cluster by individual feerate.
    SortedCluster<BitSet> cluster_sorted(cluster);
    // Compute ancestor sets.
    AncestorSets<BitSet> anc_sorted(cluster_sorted.cluster);
    // Compute descendant sets.
    DescendantSets<BitSet> desc_sorted(anc_sorted);
    // Convert done to sorted ordering.
    BitSet done_sorted = cluster_sorted.OriginalToSorted(done);
    // Precompute ancestor set feerates in sorted ordering.
    AncestorSetFeerates<BitSet> anc_sorted_feerate(cluster_sorted.cluster, anc_sorted, done_sorted);

    // Run both algorithms.
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done);
    auto ret_efficient = FindBestCandidateSetEfficient(cluster_sorted.cluster, anc_sorted, desc_sorted, anc_sorted_feerate, done_sorted);

    // Compare best found feerates.
    assert(ret_exhaustive.best_candidate_feerate == ret_efficient.best_candidate_feerate);

    // We cannot require that the actual candidate returned is identical, because there may be
    // multiple, and the algorithms iterate in different order. Instead, recompute the feerate of
    // the candidate returned by the efficient one and check that it matches the claimed value.
    auto feerate_efficient = ComputeSetFeeRate(cluster_sorted.cluster, ret_efficient.best_candidate_set);
    assert(feerate_efficient == ret_exhaustive.best_candidate_feerate);
}

FUZZ_TARGET(clustermempool_linearize)
{
    Cluster<BitSet> cluster = DecodeCluster<BitSet>(buffer);

    BitSet all = BitSet::Full(cluster.size());
    if (!IsConnectedSubset(cluster, all)) return;

    std::vector<std::pair<double, std::vector<unsigned>>> results;
    results.reserve(11);

    for (unsigned i = 0; i < 11; ++i) {
        struct timespec measure_start, measure_stop;
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_start);
        auto linearization = LinearizeCluster(cluster);
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_stop);
        double duration = (double)((int64_t)measure_stop.tv_sec - (int64_t)measure_start.tv_sec) + 0.000000001*(double)((int64_t)measure_stop.tv_nsec - (int64_t)measure_start.tv_nsec);
        results.emplace_back(duration, linearization);
    }

    std::sort(results.begin(), results.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    const auto& [duration, linearization] = results[5];

    BitSet satisfied;
    assert(linearization.size() == cluster.size());
    for (unsigned idx : linearization) {
        assert((cluster[idx].second / satisfied).None());
        satisfied.Set(idx);
    }
    assert(satisfied == all);

    std::cerr << "LINEARIZE(" << cluster.size() << ") time=" << duration /*<< " iters=" << stats.iterations << " time/iters=" << (duration / stats.iterations) << " comps=" << stats.comparisons << " time/comps=" << (duration / stats.comparisons)*/ << std::endl;
}

FUZZ_TARGET(clustermempool_ancestorset)
{
    Cluster<BitSet> cluster = DecodeCluster<BitSet>(buffer);
    SortedCluster<BitSet> sorted(cluster);

/*    std::cerr << "CLUSTER " << cluster << std::endl;*/

    AncestorSets<BitSet> anc(sorted.cluster);

    for (unsigned i = 0; i < cluster.size(); ++i) {
        BitSet ancs{sorted.cluster[i].second}; // Start with direct parents.
        assert(!ancs[i]); // Transaction cannot have themself as parent.
        // Add existing ancestors' parents until set no longer changes.
        while (true) {
            BitSet next_ancs = ancs;
            auto todo{ancs.Elements()};
            while (todo) {
                next_ancs |= sorted.cluster[todo.Next()].second;
            }
            if (next_ancs == ancs) break;
            ancs = next_ancs;
        }
        assert(!ancs[i]); // No cycles allowed.
        ancs.Set(i);
        assert(anc[i] == ancs); // Compare against AncestorSets output.
    }
}

FUZZ_TARGET(clustermempool_encoding_roundtrip)
{
    Cluster<BitSet> cluster = DecodeCluster<BitSet>(buffer);
    std::vector<unsigned char> encoded = EncodeCluster(cluster);
    encoded.pop_back();
    Span<const unsigned char> span(encoded);
    Cluster<BitSet> cluster2 = DecodeCluster<BitSet>(span);
    assert(cluster == cluster2);
}

FUZZ_TARGET(clustermempool_weedcluster)
{
    Cluster<BitSet> cluster = DecodeCluster<BitSet>(buffer);
    AncestorSets<BitSet> anc(cluster);
    WeedCluster(cluster, anc);
    AncestorSets<BitSet> anc_weed(cluster);
    for (unsigned i = 0; i < cluster.size(); ++i) {
        assert(anc[i] == anc_weed[i]);
    }
}

FUZZ_TARGET(clustermempool_truncate)
{
    Cluster<BitSet> cluster = DecodeCluster<BitSet>(buffer);
    if (cluster.size() > 15) return;

    BitSet all = BitSet::Full(cluster.size());
    if (!IsConnectedSubset(cluster, all)) return;

    SortedCluster<BitSet> sorted(cluster);
    AncestorSets<BitSet> anc(sorted.cluster);

    BitSet done;

    for (unsigned i = 0; i < cluster.size(); ++i) {
        if (buffer.empty()) break;
        if (buffer[0] & 1) {
            done |= anc[i];
        }
        buffer = buffer.subspan(1);
    }

    auto ret1 = FindBestCandidateSetExhaustive(sorted.cluster, anc, done);
    WeedCluster(sorted.cluster, anc);
    Cluster<BitSet> trunc = TruncateCluster(sorted.cluster, done);
    assert(IsTopologicallyOrdered(trunc));
    AncestorSets<BitSet> trunc_anc(trunc);
    auto ret2 = FindBestCandidateSetExhaustive(trunc, trunc_anc, {});
    assert(ret1.num_candidate_sets == ret2.num_candidate_sets);
    assert(ret1.best_candidate_feerate == ret2.best_candidate_feerate);
}

FUZZ_TARGET(clustermempool_efficient_limits)
{
    Cluster<BitSet> cluster = DecodeCluster<BitSet>(buffer);
    if (cluster.size() > 20) return;

    BitSet all = BitSet::Full(cluster.size());
    if (!IsConnectedSubset(cluster, all)) return;

    SortedCluster<BitSet> sorted_cluster(cluster);
    AncestorSets<BitSet> anc(sorted_cluster.cluster);
    DescendantSets<BitSet> desc(anc);
    AncestorSetFeerates<BitSet> anc_feerates(sorted_cluster.cluster, anc, {});
    WeedCluster(sorted_cluster.cluster, anc);

    struct Stats
    {
        BitSet done;
        size_t cluster_left;
        size_t iterations;
        size_t comparisons;
        size_t max_queue_size;
        size_t tot_iterations{0};
        size_t tot_comparisons{0};
    };
    std::vector<Stats> stats;
    stats.reserve(cluster.size());

    BitSet done;
    while (done != all) {
        auto ret = FindBestCandidateSetEfficient(sorted_cluster.cluster, anc, desc, anc_feerates, done);

        // Sanity checks
        // - claimed feerate matches
        auto feerate = ComputeSetFeeRate(sorted_cluster.cluster, ret.best_candidate_set);
        assert(feerate == ret.best_candidate_feerate);
        // - topologically consistent
        BitSet merged_ancestors = done;
        auto todo{ret.best_candidate_set.Elements()};
        while (todo) {
            merged_ancestors |= anc[todo.Next()];
        }
        assert((done | ret.best_candidate_set) == merged_ancestors);
        // - if small enough, matches exhaustive search feerate
        unsigned left = (all / done).Count();
        if (left <= 10) {
            auto ret_exhaustive = FindBestCandidateSetExhaustive(sorted_cluster.cluster, anc, done);
            assert(ret_exhaustive.best_candidate_feerate == ret.best_candidate_feerate);
        }

        // Update statistics.
        stats.push_back({done, left, ret.iterations, ret.comparisons, ret.max_queue_size, 0, 0});

        // Update done to include added candidate.
        done |= ret.best_candidate_set;
        anc_feerates.Done(sorted_cluster.cluster, anc, ret.best_candidate_set);
    }

    size_t cumul_iterations{0}, cumul_comparisons{0};
    for (auto it = stats.rbegin(); it != stats.rend(); ++it) {
        cumul_iterations += it->iterations;
        it->tot_iterations = cumul_iterations;
        cumul_comparisons += it->comparisons;
        it->tot_comparisons = cumul_comparisons;
    }


    using BestStats = KeepBest<StatEntry, 1>;

    static std::array<BestStats, BitSet::MAX_SIZE+1> COMPS;
    static std::array<BestStats, BitSet::MAX_SIZE+1> ITERS;
    static std::array<BestStats, BitSet::MAX_SIZE+1> QUEUE;
    static std::array<BestStats, BitSet::MAX_SIZE+1> TOT_COMPS;
    static std::array<BestStats, BitSet::MAX_SIZE+1> TOT_ITERS;

    bool comps_updated{false}, iters_updated{false}, queue_updated{false}, tot_comps_updated{false}, tot_iters_updated{false};

    for (const auto& entry : stats) {
        bool do_save = false;
        if (COMPS[entry.cluster_left].Add(StatEntry{entry.comparisons, cluster.size()})) do_save = comps_updated = true;
        if (ITERS[entry.cluster_left].Add(StatEntry{entry.iterations, cluster.size()})) do_save = iters_updated = true;
        if (QUEUE[entry.cluster_left].Add(StatEntry{entry.max_queue_size, cluster.size()})) do_save = queue_updated = true;
        if (TOT_COMPS[entry.cluster_left].Add(StatEntry{entry.tot_comparisons, cluster.size()})) do_save = tot_comps_updated = true;
        if (TOT_ITERS[entry.cluster_left].Add(StatEntry{entry.tot_iterations, cluster.size()})) do_save = tot_iters_updated = true;
        if (do_save) {
            auto trunc = TruncateCluster(sorted_cluster.cluster, entry.done);
            auto enc = EncodeCluster(trunc);
            enc.pop_back();
            FuzzSave(enc);
        }
    }

    if (iters_updated) {
        std::cerr << "ITERS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (ITERS[i].Any()) {
                std::cerr << " " << i << ":" << ITERS[i].Best().stat;
            }
        }
        std::cerr << std::endl;
    }

    if (comps_updated) {
        std::cerr << "COMPS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (COMPS[i].Any()) {
                std::cerr << " " << i << ":" << COMPS[i].Best().stat;
            }
        }
        std::cerr << std::endl;
    }

    if (queue_updated) {
        std::cerr << "QUEUE:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (QUEUE[i].Any()) {
                std::cerr << " " << i << ":" << QUEUE[i].Best().stat;
            }
        }
        std::cerr << std::endl;
    }

    if (tot_iters_updated) {
        std::cerr << "TOT_ITERS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (TOT_ITERS[i].Any()) {
                std::cerr << " " << i << ":" << TOT_ITERS[i].Best().stat;
            }
        }
        std::cerr << std::endl;
    }

    if (tot_comps_updated) {
        std::cerr << "TOT_COMPS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (TOT_COMPS[i].Any()) {
                std::cerr << " " << i << ":" << TOT_COMPS[i].Best().stat;
            }
        }
        std::cerr << std::endl;
    }
}
