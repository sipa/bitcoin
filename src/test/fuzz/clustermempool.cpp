// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <time.h>

#include <vector>

#include <cluster_linearize.h>
#include <test/fuzz/fuzz.h>
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
    if (select.IsEmpty()) return true;

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
                bitset.Add(i);
                req = req | cluster[i].second;
            }
        }
        // None of the already done transactions may be included again.
        if (!(done & bitset).IsEmpty()) continue;
        // We only consider non-empty additions.
        if (bitset.IsEmpty()) continue;
        // All dependencies have to be satisfied.
        if (!((bitset | done) >> req)) continue;
        // Only connected subsets are considered.
        if (!IsConnectedSubset(cluster, bitset)) continue;

        // Update statistics in ret to account for this new candidate.
        ++ret.num_candidate_sets;
        FeeAndSize feerate = ComputeSetFeeRate(cluster, bitset);
        if (ret.best_candidate_feerate.IsEmpty() || FeeRateBetter(feerate, ret.best_candidate_feerate)) {
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
            // - (exc & anc[i]).IsEmpty(): ancestry of what we include cannot have excluded transactions
            // - inc_none || !(done >> (inc & anc[i])): either:
            //   - we're starting from an empty set (apart from done)
            //   - if not, the ancestry of what we add must overlap with what we already have, in
            //     not yet done transactions (to guarantee (inc / done) is always connected).
            if (!inc[i] && !exc[i] && (exc & anc[i]).IsEmpty() && (inc_none || !(done >> (inc & anc[i])))) {
                // First, add a queue item with i added to exc. Inc is unchanged, so feerate is
                // unchanged as well.
                auto new_exc = exc;
                new_exc.Add(i);
                queue.emplace_back(inc, new_exc, feerate);

                // Then, add a queue item with i (plus ancestry) added to inc. We need to compute
                // an updated feerate here to account for what was added.
                auto new_inc = inc | anc[i];
                FeeAndSize new_feerate = feerate + ComputeSetFeeRate(cluster, new_inc / inc);
                queue.emplace_back(new_inc, exc, new_feerate);

                // Update statistics in ret to account for this new candidate (new_inc / done).
                ++ret.num_candidate_sets;
                if (ret.best_candidate_feerate.IsEmpty() || FeeRateBetter(new_feerate, ret.best_candidate_feerate)) {
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

template<typename S>
S DecodeDone(Span<const unsigned char>& data, const AncestorSets<S>& ancs)
{
    S ret;
    while (true) {
        unsigned pos = DeserializeNumberBase128(data) % (ancs.Size() + 1);
        if (pos == 0) break;
        ret |= ancs[ancs.Size() - pos];
    }
    return ret;
}

template<typename T>
class MaxVal
{
    std::optional<T> m_val;

public:
    bool Set(T&& val)
    {
        if (!m_val.has_value() || val > *m_val) {
            m_val = std::move(val);
            return true;
        }
        return false;
    }

    explicit operator bool() const { return m_val.has_value(); }
    const T& operator*() const { return *m_val; }
    const T* operator->() const { return &*m_val; }
};

struct ClusterStat
{
    uint64_t stat;
    size_t cluster_size;
    size_t buffer_size;

    bool friend operator>(const ClusterStat& a, const ClusterStat& b)
    {
        if (a.stat != b.stat) return a.stat > b.stat;
        if (a.cluster_size != b.cluster_size) return a.cluster_size < b.cluster_size;
        return a.buffer_size < b.buffer_size;
    }
};

/*using BitSet = MultiIntBitSet<uint64_t, 2>;*/
using BitSet = IntBitSet<uint64_t>;

} // namespace

FUZZ_TARGET(clustermempool_exhaustive_equals_naive)
{
    // Read cluster from fuzzer.
    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);
    if (cluster.size() > 15) return;

    // Compute ancestor sets.
    AncestorSets anc(cluster);
    if (!IsAcyclic(anc)) return;
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
    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);
    // Compute ancestor sets.
    AncestorSets anc(cluster);
    if (!IsAcyclic(anc)) return;
    // Find a topological subset to set as "done" already.
    BitSet done = DecodeDone<BitSet>(buffer, anc);
    if (cluster.size() - done.Count() > 20) return;
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
    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);

    BitSet all = BitSet::Full(cluster.size());
    if (!IsConnectedSubset(cluster, all)) return;
    AncestorSets<BitSet> anc(cluster);
    if (!IsAcyclic(anc)) return;

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
        assert(satisfied >> cluster[idx].second);
        satisfied.Add(idx);
    }
    assert(satisfied == all);

    std::cerr << "LINEARIZE(" << cluster.size() << ") time=" << duration /*<< " iters=" << stats.iterations << " time/iters=" << (duration / stats.iterations) << " comps=" << stats.comparisons << " time/comps=" << (duration / stats.comparisons)*/ << std::endl;
}

FUZZ_TARGET(clustermempool_ancestorset)
{
    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);
    AncestorSets<BitSet> anc(cluster);
    // Note: no requirement that cluster is acyclic.

    for (unsigned i = 0; i < cluster.size(); ++i) {
        BitSet ancs;
        ancs.Add(i); // Start with transaction itself
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
        assert(anc[i] == ancs); // Compare against AncestorSets output.
    }
}

FUZZ_TARGET(clustermempool_encoding_roundtrip)
{
    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);
    std::vector<unsigned char> encoded;
    SerializeCluster(cluster, encoded);
    encoded.pop_back();
    Span<const unsigned char> span(encoded);
    Cluster<BitSet> cluster2 = DeserializeCluster<BitSet>(span);
    assert(cluster == cluster2);
}

FUZZ_TARGET(clustermempool_weedcluster)
{
    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);
    AncestorSets<BitSet> anc(cluster);
    if (!IsAcyclic(anc)) return;
    WeedCluster(cluster, anc);
    AncestorSets<BitSet> anc_weed(cluster);
    for (unsigned i = 0; i < cluster.size(); ++i) {
        assert(anc[i] == anc_weed[i]);
    }
}

FUZZ_TARGET(clustermempool_trim)
{
    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);
    if (cluster.size() > 20) return;

    BitSet all = BitSet::Full(cluster.size());
    if (!IsConnectedSubset(cluster, all)) return;

    SortedCluster<BitSet> sorted(cluster);
    AncestorSets<BitSet> anc(sorted.cluster);
    if (!IsAcyclic(anc)) return;

    BitSet done = DecodeDone<BitSet>(buffer, anc);

    DescendantSets<BitSet> desc(anc);
    AncestorSetFeerates<BitSet> anc_feerates(sorted.cluster, anc, done);
    auto eff1 = FindBestCandidateSetEfficient(sorted.cluster, anc, desc, anc_feerates, done);
    WeedCluster(sorted.cluster, anc);
    Cluster<BitSet> trim = TrimCluster(sorted.cluster, done);
    AncestorSets<BitSet> trim_anc(trim);
    DescendantSets<BitSet> trim_desc(trim_anc);
    AncestorSetFeerates<BitSet> trim_anc_feerates(trim, trim_anc, {});
    auto eff2 = FindBestCandidateSetEfficient(trim, trim_anc, trim_desc, trim_anc_feerates, {});
    assert(eff1.best_candidate_feerate == eff2.best_candidate_feerate);
    assert(eff1.max_queue_size == eff2.max_queue_size);
    assert(eff1.iterations == eff2.iterations);
    assert(eff1.comparisons == eff2.comparisons);

    if (cluster.size() <= 15) {
        auto ret1 = FindBestCandidateSetExhaustive(sorted.cluster, anc, done);
        auto ret2 = FindBestCandidateSetExhaustive(trim, trim_anc, {});
        assert(ret1.num_candidate_sets == ret2.num_candidate_sets);
        assert(ret1.best_candidate_feerate == ret2.best_candidate_feerate);
        assert(ret1.best_candidate_feerate == eff1.best_candidate_feerate);
    }
}

FUZZ_TARGET(clustermempool_efficient_limits)
{
    auto initial_buffer = buffer;

    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);
    if (cluster.size() > 26) return;

//    std::cerr << "CLUSTER " << cluster << std::endl;

    BitSet all = BitSet::Full(cluster.size());
    bool connected = IsConnectedSubset(cluster, all);

    SortedCluster<BitSet> sorted(cluster);
    AncestorSets<BitSet> anc(sorted.cluster);
    if (!IsAcyclic(anc)) return;
    DescendantSets<BitSet> desc(anc);
    AncestorSetFeerates<BitSet> anc_feerates(sorted.cluster, anc, {});
    WeedCluster(sorted.cluster, anc);

    struct Stats
    {
        BitSet done;
        size_t cluster_left;
        size_t iterations;
        size_t comparisons;
        size_t max_queue_size;
        bool left_connected;
        size_t tot_iterations{0};
        size_t tot_comparisons{0};
    };
    std::vector<Stats> stats;
    stats.reserve(cluster.size());

    BitSet done;
    while (done != all) {
        auto ret = FindBestCandidateSetEfficient(sorted.cluster, anc, desc, anc_feerates, done);

        // Sanity checks
        // - connectedness of candidate
        assert(IsConnectedSubset(sorted.cluster, ret.best_candidate_set));
        // - claimed feerate matches
        auto feerate = ComputeSetFeeRate(sorted.cluster, ret.best_candidate_set);
        assert(feerate == ret.best_candidate_feerate);
        // - topologically consistent
        BitSet merged_ancestors = done;
        auto todo{ret.best_candidate_set.Elements()};
        while (todo) {
            merged_ancestors |= anc[todo.Next()];
        }
        assert((done | ret.best_candidate_set) == merged_ancestors);
        unsigned left = (all / done).Count();
        // - if small enough, matches exhaustive search feerate
#if 1
        if (left <= 10) {
            auto ret_exhaustive = FindBestCandidateSetExhaustive(sorted.cluster, anc, done);
            assert(ret_exhaustive.best_candidate_feerate == ret.best_candidate_feerate);
        }
#endif

        // Update statistics.
        stats.push_back({done, left, ret.iterations, ret.comparisons, ret.max_queue_size, connected, 0, 0});

        // Update done to include added candidate.
        done |= ret.best_candidate_set;
        anc_feerates.Done(sorted.cluster, desc, ret.best_candidate_set);
        if (connected) {
            connected = IsConnectedSubset(sorted.cluster, all / done);
        }
    }

    size_t cumul_iterations{0}, cumul_comparisons{0};
    for (auto it = stats.rbegin(); it != stats.rend(); ++it) {
        cumul_iterations += it->iterations;
        it->tot_iterations = cumul_iterations;
        cumul_comparisons += it->comparisons;
        it->tot_comparisons = cumul_comparisons;
    }


    static std::array<MaxVal<ClusterStat>, BitSet::MAX_SIZE+1> COMPS{};
    static std::array<MaxVal<ClusterStat>, BitSet::MAX_SIZE+1> ITERS{};
    static std::array<MaxVal<ClusterStat>, BitSet::MAX_SIZE+1> QUEUE{};
    static std::array<MaxVal<ClusterStat>, BitSet::MAX_SIZE+1> TOT_COMPS{};
    static std::array<MaxVal<ClusterStat>, BitSet::MAX_SIZE+1> TOT_ITERS{};
    static std::array<MaxVal<ClusterStat>, BitSet::MAX_SIZE+1> DIS_COMPS{};
    static std::array<MaxVal<ClusterStat>, BitSet::MAX_SIZE+1> DIS_ITERS{};
    static std::array<MaxVal<ClusterStat>, BitSet::MAX_SIZE+1> DIS_QUEUE{};
    static std::array<MaxVal<ClusterStat>, BitSet::MAX_SIZE+1> DIS_TOT_COMPS{};
    static std::array<MaxVal<ClusterStat>, BitSet::MAX_SIZE+1> DIS_TOT_ITERS{};

    bool comps_updated{false}, iters_updated{false}, queue_updated{false}, tot_comps_updated{false}, tot_iters_updated{false};
    bool dis_comps_updated{false}, dis_iters_updated{false}, dis_queue_updated{false}, dis_tot_comps_updated{false}, dis_tot_iters_updated{false};

    bool global_do_save = false;

    for (const auto& entry : stats) {
        bool do_save = false;
        if (DIS_COMPS[entry.cluster_left].Set({entry.comparisons, cluster.size(), initial_buffer.size()})) do_save = dis_comps_updated = true;
        if (DIS_ITERS[entry.cluster_left].Set({entry.iterations, cluster.size(), initial_buffer.size()})) do_save = dis_iters_updated = true;
        if (DIS_QUEUE[entry.cluster_left].Set({entry.max_queue_size, cluster.size(), initial_buffer.size()})) do_save = dis_queue_updated = true;
        if (DIS_TOT_COMPS[entry.cluster_left].Set({entry.tot_comparisons, cluster.size(), initial_buffer.size()})) do_save = dis_tot_comps_updated = true;
        if (DIS_TOT_ITERS[entry.cluster_left].Set({entry.tot_iterations, cluster.size(), initial_buffer.size()})) do_save = dis_tot_iters_updated = true;
        if (entry.left_connected) {
            if (COMPS[entry.cluster_left].Set({entry.comparisons, cluster.size(), initial_buffer.size()})) do_save = comps_updated = true;
            if (ITERS[entry.cluster_left].Set({entry.iterations, cluster.size(), initial_buffer.size()})) do_save = iters_updated = true;
            if (QUEUE[entry.cluster_left].Set({entry.max_queue_size, cluster.size(), initial_buffer.size()})) do_save = queue_updated = true;
            if (TOT_COMPS[entry.cluster_left].Set({entry.tot_comparisons, cluster.size(), initial_buffer.size()})) do_save = tot_comps_updated = true;
            if (TOT_ITERS[entry.cluster_left].Set({entry.tot_iterations, cluster.size(), initial_buffer.size()})) do_save = tot_iters_updated = true;
        }
        if (do_save) {
            auto trim = TrimCluster(sorted.cluster, entry.done);
            assert(trim.size() == entry.cluster_left);
            std::vector<unsigned char> enc;
            SerializeCluster(trim, enc);
            enc.pop_back();
            FuzzSave(enc);
            Span<const unsigned char> reload_buffer(enc);
            Cluster<BitSet> reload = DeserializeCluster<BitSet>(reload_buffer);
            assert(trim == reload);
            global_do_save = true;
#if 0
            SortedCluster<BitSet> sorted_trim(trim);
            assert(sorted_trim.cluster == trim);
            AncestorSets<BitSet> anc_trim(sorted_trim.cluster);
            assert(IsAcyclic(anc_trim));
            assert(IsConnectedSubset(trim, BitSet::Full(trim.size())) == entry.connected);
            AncestorSetFeerates<BitSet> anc_feerates_trim(sorted_trim.cluster, anc_trim, {});
            DescendantSets<BitSet> desc_trim(anc_trim);
            WeedCluster(sorted_trim.cluster, anc_trim);
            auto redo = FindBestCandidateSetEfficient(sorted_trim.cluster, anc_trim, desc_trim, anc_feerates_trim, {});
            assert(redo.iterations == entry.iterations);
            assert(redo.comparisons == entry.comparisons);
            assert(redo.max_queue_size == entry.max_queue_size);
#endif
        }
    }

    if (iters_updated) {
        std::cerr << "ITERS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (ITERS[i]) {
                std::cerr << " " << i << ":" << ITERS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (comps_updated) {
        std::cerr << "COMPS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (COMPS[i]) {
                std::cerr << " " << i << ":" << COMPS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (queue_updated) {
        std::cerr << "QUEUE:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (QUEUE[i]) {
                std::cerr << " " << i << ":" << QUEUE[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (tot_iters_updated) {
        std::cerr << "TOT_ITERS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (TOT_ITERS[i]) {
                std::cerr << " " << i << ":" << TOT_ITERS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (tot_comps_updated) {
        std::cerr << "TOT_COMPS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (TOT_COMPS[i]) {
                std::cerr << " " << i << ":" << TOT_COMPS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (dis_iters_updated) {
        std::cerr << "DIS_ITERS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (DIS_ITERS[i]) {
                std::cerr << " " << i << ":" << DIS_ITERS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (comps_updated) {
        std::cerr << "DIS_COMPS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (DIS_COMPS[i]) {
                std::cerr << " " << i << ":" << DIS_COMPS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (queue_updated) {
        std::cerr << "DIS_QUEUE:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (DIS_QUEUE[i]) {
                std::cerr << " " << i << ":" << DIS_QUEUE[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (tot_iters_updated) {
        std::cerr << "DIS_TOT_ITERS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (DIS_TOT_ITERS[i]) {
                std::cerr << " " << i << ":" << DIS_TOT_ITERS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (tot_comps_updated) {
        std::cerr << "DIS_TOT_COMPS:";
        for (size_t i = 0; i <= BitSet::MAX_SIZE; ++i) {
            if (DIS_TOT_COMPS[i]) {
                std::cerr << " " << i << ":" << DIS_TOT_COMPS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (global_do_save) {
        FuzzSave(initial_buffer);
    }
}
