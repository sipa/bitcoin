// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <time.h>

#include <vector>

#include <cluster_linearize.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>

#include <assert.h>

#include <iostream>

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

/** Load a Cluster from fuzz provider. */
template<typename S>
Cluster<S> FuzzReadCluster(FuzzedDataProvider& provider, bool only_complete, bool no_values, bool permute)
{
    std::vector<unsigned> permutation;
    Cluster<S> ret;
    while (ret.size() < S::MAX_SIZE && provider.remaining_bytes()) {
        if (only_complete && provider.remaining_bytes() < (no_values ? 0U : 4U) + (permute && ret.size()) + ret.size()) break;
        uint64_t sats = no_values ? ret.size() : provider.ConsumeIntegralInRange<uint32_t>(0, 0xFFFF);
        uint32_t bytes = no_values ? 1U : provider.ConsumeIntegralInRange<uint32_t>(1, 0x10000);
        S deps;
        for (size_t i = 0; i < ret.size(); ++i) {
            if (provider.ConsumeBool()) deps.Set(i);
        }
        ret.emplace_back(FeeAndSize{sats, bytes}, std::move(deps));
        if (permute) {
            unsigned location = ret.size() > 1 ? provider.ConsumeIntegralInRange<unsigned>(0, ret.size() - 1) : 0;
            permutation.emplace_back(ret.size() - 1);
            if (location != ret.size() - 1) {
                std::swap(permutation[location], permutation.back());
                std::swap(ret[location], ret.back());
            }
        }
    }

    if (permute) {
        for (auto& entry : ret) {
            S parents;
            for (size_t i = 0; i < permutation.size(); ++i) {
                if (entry.second[permutation[i]]) {
                    parents.Set(i);
                }
            }
            entry.second = parents;
        }
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

template<typename Fn, typename S>
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

/*using BitSet = MultiIntBitSet<uint64_t, 2>;*/
using BitSet = IntBitSet<uint64_t>;


} // namespace

FUZZ_TARGET(clustermempool_exhaustive_equals_naive)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Read cluster from fuzzer.
    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/true, /*no_values=*/false, /*permute=*/false);
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
    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/true, /*no_values=*/false, /*permute=*/false);
    // Compute ancestor sets.
    AncestorSets anc(cluster);

    // Find a topologically (but not necessarily connected) subset to set as "done" already.
    BitSet done;
    for (size_t i = 0; i < cluster.size(); ++i) {
        if (provider.ConsumeBool()) {
            done |= anc[i];
        }
    }

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
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/false, /*no_values=*/false, /*permute=*/false);

    BitSet all;
    for (unsigned i = 0; i < cluster.size(); ++i) all.Set(i);
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
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/true, /*no_values=*/true, /*permute=*/true);

/*    std::cerr << "CLUSTER " << cluster << std::endl;*/

    AncestorSets<BitSet> anc(cluster);

    for (unsigned i = 0; i < cluster.size(); ++i) {
        BitSet ancs{cluster[i].second}; // Start with direct parents.
        assert(!ancs[i]); // Transaction cannot have themself as parent.
        // Add existing ancestors' parents until set no longer changes.
        while (true) {
            BitSet next_ancs = ancs;
            auto todo{ancs.Elements()};
            while (todo) {
                next_ancs |= cluster[todo.Next()].second;
            }
            if (next_ancs == ancs) break;
            ancs = next_ancs;
        }
        assert(!ancs[i]); // No cycles allowed.
        ancs.Set(i);
        assert(anc[i] == ancs); // Compare against AncestorSets output.
    }
}

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

FUZZ_TARGET(clustermempool_efficient_limits)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    Cluster<BitSet> cluster = FuzzReadCluster<BitSet>(provider, /*only_complete=*/false, /*no_values=*/false, /*permute=*/false);

    BitSet all;
    for (unsigned i = 0; i < cluster.size(); ++i) all.Set(i);
    if (!IsConnectedSubset(cluster, all)) return;

    SortedCluster<BitSet> sorted_cluster(cluster);
    AncestorSets<BitSet> anc(sorted_cluster.cluster);
    DescendantSets<BitSet> desc(anc);
    AncestorSetFeerates<BitSet> anc_feerates(sorted_cluster.cluster, anc, {});

    struct Stats
    {
        size_t cluster_left;
        size_t iterations;
        size_t comparisons;
        size_t max_queue_size;
        size_t tot_iterations{0};
        size_t tot_comparisons{0};
        Stats(size_t left, size_t iters, size_t comps, size_t qs) : cluster_left{left}, iterations{iters}, comparisons{comps}, max_queue_size{qs} {}
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
        stats.emplace_back(/*left=*/left, /*iters=*/ret.iterations, /*comps=*/ret.comparisons, /*qs=*/ret.max_queue_size);

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
        if (COMPS[entry.cluster_left].Add(StatEntry{entry.comparisons, cluster.size()})) comps_updated = true;
        if (ITERS[entry.cluster_left].Add(StatEntry{entry.iterations, cluster.size()})) iters_updated = true;
        if (QUEUE[entry.cluster_left].Add(StatEntry{entry.max_queue_size, cluster.size()})) queue_updated = true;
        if (TOT_COMPS[entry.cluster_left].Add(StatEntry{entry.tot_comparisons, cluster.size()})) tot_comps_updated = true;
        if (TOT_ITERS[entry.cluster_left].Add(StatEntry{entry.tot_iterations, cluster.size()})) tot_iters_updated = true;
    }

    bool do_save{false};

    if (iters_updated) {
        std::cerr << "ITERS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (ITERS[i].Any()) {
                std::cerr << " " << i << ":" << ITERS[i].Best().stat;
            }
        }
        std::cerr << std::endl;
        do_save = true;
    }

    if (comps_updated) {
        std::cerr << "COMPS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (COMPS[i].Any()) {
                std::cerr << " " << i << ":" << COMPS[i].Best().stat;
            }
        }
        std::cerr << std::endl;
        do_save = true;
    }

    if (queue_updated) {
        std::cerr << "QUEUE:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (QUEUE[i].Any()) {
                std::cerr << " " << i << ":" << QUEUE[i].Best().stat;
            }
        }
        std::cerr << std::endl;
        do_save = true;
    }

    if (tot_iters_updated) {
        std::cerr << "TOT_ITERS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (TOT_ITERS[i].Any()) {
                std::cerr << " " << i << ":" << TOT_ITERS[i].Best().stat;
            }
        }
        std::cerr << std::endl;
        do_save = true;
    }

    if (tot_comps_updated) {
        std::cerr << "TOT_COMPS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (TOT_COMPS[i].Any()) {
                std::cerr << " " << i << ":" << TOT_COMPS[i].Best().stat;
            }
        }
        std::cerr << std::endl;
        do_save = true;
    }

    if (do_save) {
        FuzzSave(buffer);
    }
}
