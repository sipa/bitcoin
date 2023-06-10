// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <time.h>

#include <vector>

#include <cluster_linearize.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/xoroshiro128plusplus.h>
#include <util/feefrac.h>

#include <assert.h>

#include <iostream>

using namespace cluster_linearize;

namespace {

template<typename S>
bool IsMul64Compatible(const Cluster<S>& c)
{
    uint64_t sum_fee{0};
    uint32_t sum_size{0};
    for (const auto& [fee_and_size, _parents] : c) {
        sum_fee += fee_and_size.fee;
        if (sum_fee < fee_and_size.fee) return false;
        sum_size += fee_and_size.size;
        if (sum_size < fee_and_size.size) return false;
    }
    uint64_t high = (sum_fee >> 32) * sum_size;
    uint64_t low = (sum_fee & 0xFFFFFFFF) * sum_size;
    high += low >> 32;
    return (high >> 32) == 0;
}

std::ostream& operator<<(std::ostream& o, const FeeFrac& data)
{
    o << "(" << data.fee << "/" << data.size << "=" << ((double)data.fee / data.size) << ")";
    return o;
}

template<typename S>
void DrawCluster(std::ostream& o, const Cluster<S>& cluster)
{
    o << "digraph{rankdir=\"BT\";";
    for (unsigned i = 0; i < cluster.size(); ++i) {
        o << "t" << i << "[label=\"" << (double(cluster[i].first.fee) / cluster[i].first.size) << "\\n" << cluster[i].first.fee << " / " << cluster[i].first.size << "\"];";
    }
    for (unsigned i = 0; i < cluster.size(); ++i) {
        auto todo{cluster[i].second.Elements()};
        while (todo) {
            o << "t" << i << "->t" << todo.Next() << ";";
        }
    }
    o << "}";
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
        FeeFrac feefrac = ComputeSetFeeFrac(cluster, bitset);
        if (ret.best_candidate_feefrac.IsEmpty() || feefrac > ret.best_candidate_feefrac) {
            ret.best_candidate_set = bitset;
            ret.best_candidate_feefrac = feefrac;
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
    // - inc: set of transactions definitely included (always includes done)
    // - exc: set of transactions definitely excluded
    // - feefrac: the FeeFrac of (included / done)
    std::vector<std::tuple<S, S, FeeFrac>> queue;
    queue.emplace_back(done, S{}, FeeFrac{});

    CandidateSetAnalysis<S> ret;

    // Process the queue.
    while (!queue.empty()) {
        ++ret.iterations;
        // Pop top element of the queue.
        auto [inc, exc, feefrac] = queue.back();
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
                // First, add a queue item with i added to exc. Inc is unchanged, so feefrac is
                // unchanged as well.
                auto new_exc = exc;
                new_exc.Add(i);
                queue.emplace_back(inc, new_exc, feefrac);

                // Then, add a queue item with i (plus ancestry) added to inc. We need to compute
                // an updated feefrac here to account for what was added.
                auto new_inc = inc | anc[i];
                FeeFrac new_feefrac = feefrac + ComputeSetFeeFrac(cluster, new_inc / inc);
                queue.emplace_back(new_inc, exc, new_feefrac);

                // Update statistics in ret to account for this new candidate (new_inc / done).
                ++ret.num_candidate_sets;
                if (ret.best_candidate_feefrac.IsEmpty() || new_feefrac > ret.best_candidate_feefrac) {
                    ret.best_candidate_set = new_inc / done;
                    ret.best_candidate_feefrac = new_feefrac;
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
    if (!IsMul64Compatible(cluster)) return;

    // Compute ancestor sets.
    AncestorSets anc(cluster);
    if (!IsAcyclic(anc)) return;
    // Find a topologically (but not necessarily connect) subset to set as "done" already.
    BitSet done = DecodeDone(buffer, anc);

    // Run both algorithms.
    auto ret_naive = FindBestCandidateSetNaive(cluster, done);
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done);

    // Compute number of candidate sets and best feefrac of found result.
    assert(ret_exhaustive.num_candidate_sets == ret_naive.num_candidate_sets);
    assert(ret_exhaustive.best_candidate_feefrac == ret_naive.best_candidate_feefrac);

    // We cannot require that the actual candidate returned is identical, because there may be
    // multiple, and the algorithms iterate in different order. Instead, recompute the FeeFrac of
    // the candidate returned by the exhaustive one and check that it matches the claimed value.
    auto feefrac_exhaustive = ComputeSetFeeFrac(cluster, ret_exhaustive.best_candidate_set);
    assert(feefrac_exhaustive == ret_exhaustive.best_candidate_feefrac);
}

FUZZ_TARGET(clustermempool_efficient_equals_exhaustive)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Read cluster from fuzzer.
    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);
    if (!IsMul64Compatible(cluster)) return;
    // Compute ancestor sets.
    AncestorSets anc(cluster);
    if (!IsAcyclic(anc)) return;
    // Find a topological subset to set as "done" already.
    BitSet done = DecodeDone<BitSet>(buffer, anc);
    if (cluster.size() - done.Count() > 20) return;
    // Sort the cluster by individual FeeFrac.
    SortedCluster<BitSet> cluster_sorted(cluster);
    // Compute ancestor sets.
    AncestorSets<BitSet> anc_sorted(cluster_sorted.cluster);
    // Compute descendant sets.
    DescendantSets<BitSet> desc_sorted(anc_sorted);
    // Convert done to sorted ordering.
    BitSet done_sorted = cluster_sorted.OriginalToSorted(done);
    // Precompute ancestor set FreeFracs in sorted ordering.
    AncestorSetFeeFracs<BitSet> anc_sorted_feefrac(cluster_sorted.cluster, anc_sorted, done_sorted);

    // Run both algorithms.
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done);
    auto ret_efficient = FindBestCandidateSetEfficient<QueueStyle::DFS>(cluster_sorted.cluster, anc_sorted, desc_sorted, anc_sorted_feefrac, done_sorted, nullptr);

    // Compare best found FeeFracs.
    assert(ret_exhaustive.best_candidate_feefrac == ret_efficient.best_candidate_feefrac);

    // We cannot require that the actual candidate returned is identical, because there may be
    // multiple, and the algorithms iterate in different order. Instead, recompute the FeeFrac of
    // the candidate returned by the efficient one and check that it matches the claimed value.
    auto feefrac_efficient = ComputeSetFeeFrac(cluster_sorted.cluster, ret_efficient.best_candidate_set);
    assert(feefrac_efficient == ret_exhaustive.best_candidate_feefrac);
}

FUZZ_TARGET(clustermempool_linearize)
{
    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);
    if (!IsMul64Compatible(cluster)) return;

    BitSet all = BitSet::Full(cluster.size());
    if (!IsConnectedSubset(cluster, all)) return;
    AncestorSets<BitSet> anc(cluster);
    if (!IsAcyclic(anc)) return;

    std::vector<std::pair<double, std::vector<unsigned>>> results;
    results.reserve(11);

    for (unsigned i = 0; i < 11; ++i) {
        struct timespec measure_start, measure_stop;
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_start);
        auto linearization = LinearizeCluster(cluster, 15);
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
    if (!IsMul64Compatible(cluster)) return;
    if (cluster.size() > 20) return;

    BitSet all = BitSet::Full(cluster.size());
    if (!IsConnectedSubset(cluster, all)) return;

    SortedCluster<BitSet> sorted(cluster);
    AncestorSets<BitSet> anc(sorted.cluster);
    if (!IsAcyclic(anc)) return;

    BitSet done = DecodeDone<BitSet>(buffer, anc);

    DescendantSets<BitSet> desc(anc);
    AncestorSetFeeFracs<BitSet> anc_feefracs(sorted.cluster, anc, done);
    auto eff1 = FindBestCandidateSetEfficient<QueueStyle::DFS>(sorted.cluster, anc, desc, anc_feefracs, done, nullptr);
    WeedCluster(sorted.cluster, anc);
    Cluster<BitSet> trim = TrimCluster(sorted.cluster, done);
    AncestorSets<BitSet> trim_anc(trim);
    DescendantSets<BitSet> trim_desc(trim_anc);
    AncestorSetFeeFracs<BitSet> trim_anc_feefracs(trim, trim_anc, {});
    auto eff2 = FindBestCandidateSetEfficient<QueueStyle::DFS>(trim, trim_anc, trim_desc, trim_anc_feefracs, {}, nullptr);
    assert(eff1.best_candidate_feefrac == eff2.best_candidate_feefrac);
    assert(eff1.max_queue_size == eff2.max_queue_size);
    assert(eff1.iterations == eff2.iterations);
    assert(eff1.comparisons == eff2.comparisons);

    if (cluster.size() <= 15) {
        auto ret1 = FindBestCandidateSetExhaustive(sorted.cluster, anc, done);
        auto ret2 = FindBestCandidateSetExhaustive(trim, trim_anc, {});
        assert(ret1.num_candidate_sets == ret2.num_candidate_sets);
        assert(ret1.best_candidate_feefrac == ret2.best_candidate_feefrac);
        assert(ret1.best_candidate_feefrac == eff1.best_candidate_feefrac);
    }
}

template<QueueStyle QS, typename S>
void FullStatsProcess(const std::string& name, const Cluster<S>& cluster, const SortedCluster<S>& sorted, const AncestorSets<S>& anc, const DescendantSets<S>& desc, XoRoShiRo128PlusPlus& rng)
{
    uint64_t tot_iters{0};
    uint64_t tot_comps{0};
    uint64_t max_queue{0};
    unsigned todo = cluster.size();
    S done;
    AncestorSetFeeFracs<S> anc_feefracs(sorted.cluster, anc, {});
    while (todo) {
        auto ret = FindBestCandidateSetEfficient<QS>(sorted.cluster, anc, desc, anc_feefracs, done, rng);
        tot_iters += ret.iterations;
        tot_comps += ret.comparisons;
        max_queue = std::max<uint64_t>(max_queue, ret.max_queue_size);
        done |= ret.best_candidate_set;
        todo -= ret.best_candidate_set.Count();
        anc_feefracs.Done(sorted.cluster, desc, ret.best_candidate_set);
    }
    std::cerr << "- " << name << ": iterations=" << tot_iters << " comparisons=" << tot_comps << " max_queue=" << max_queue << std::endl;
}

FUZZ_TARGET(clustermempool_full_stats)
{
    using BS = MultiIntBitSet<uint64_t, 4>;
    auto cluster = DeserializeCluster<BS>(buffer);
    if (!IsMul64Compatible(cluster)) return;
    XoRoShiRo128PlusPlus rng(0x1337133713371337);

    SortedCluster<BS> sorted(cluster);
    AncestorSets<BS> anc(sorted.cluster);
    if (!IsAcyclic(anc)) return;
    DescendantSets<BS> desc(anc);

    std::cerr << "CLUSTER " << cluster << std::endl;
    std::cerr << "- GRAPH "; DrawCluster(std::cerr, cluster); std::cerr << std::endl;

    FullStatsProcess<QueueStyle::DFS>("DFS", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::DFS_EXC>("DFS_EXC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::RANDOM>("RANDOM", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::BEST_ACHIEVED_FEEFRAC>("BEST_ACHIEVED_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::HIGHEST_ACHIEVED_FEE>("HIGHEST_ACHIEVED_FEE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::HIGHEST_ACHIEVED_SIZE>("HIGHEST_ACHIEVED_SIZE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::BEST_POTENTIAL_FEEFRAC>("BEST_POTENTIAL_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::HIGHEST_POTENTIAL_FEE>("HIGHEST_POTENTIAL_FEE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::HIGHEST_POTENTIAL_SIZE>("HIGHEST_POTENTIAL_SIZE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::BEST_GAIN_FEEFRAC>("BEST_GAIN_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::HIGHEST_GAIN_FEE>("HIGHEST_GAIN_FEE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::HIGHEST_GAIN_SIZE>("HIGHEST_GAIN_SIZE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::WORST_ACHIEVED_FEEFRAC>("WORST_ACHIEVED_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::LOWEST_ACHIEVED_FEE>("LOWEST_ACHIEVED_FEE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::LOWEST_ACHIEVED_SIZE>("LOWEST_ACHIEVED_SIZE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::WORST_POTENTIAL_FEEFRAC>("WORST_POTENTIAL_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::LOWEST_POTENTIAL_FEE>("LOWEST_POTENTIAL_FEE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::LOWEST_POTENTIAL_SIZE>("LOWEST_POTENTIAL_SIZE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::WORST_GAIN_FEEFRAC>("WORST_GAIN_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::LOWEST_GAIN_FEE>("LOWEST_GAIN_FEE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::LOWEST_GAIN_SIZE>("LOWEST_GAIN_SIZE", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::MOST_ADVANCED_BEST_POTENTIAL_FEEFRAC>("MOST_ADVANCED_BEST_POTENTIAL_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::LEAST_ADVANCED_BEST_POTENTIAL_FEEFRAC>("LEAST_ADVANCED_BEST_POTENTIAL_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::MOST_LEFT_BEST_POTENTIAL_FEEFRAC>("MOST_LEFT_BEST_POTENTIAL_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::LEAST_LEFT_BEST_POTENTIAL_FEEFRAC>("LEAST_LEFT_BEST_POTENTIAL_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::MOST_INC_BEST_POTENTIAL_FEEFRAC>("MOST_INC_BEST_POTENTIAL_FEEFRAC", cluster, sorted, anc, desc, rng);
    FullStatsProcess<QueueStyle::LEAST_INC_BEST_POTENTIAL_FEEFRAC>("LEAST_INC_BEST_POTENTIAL_FEEFRAC", cluster, sorted, anc, desc, rng);
}

FUZZ_TARGET(clustermempool_efficient_limits)
{
    auto initial_buffer = buffer;

    Cluster<BitSet> cluster = DeserializeCluster<BitSet>(buffer);
    if (cluster.size() > 26) return;
    if (!IsMul64Compatible(cluster)) return;

//    std::cerr << "CLUSTER " << cluster << std::endl;

    BitSet all = BitSet::Full(cluster.size());
    bool connected = IsConnectedSubset(cluster, all);

    SortedCluster<BitSet> sorted(cluster);
    AncestorSets<BitSet> anc(sorted.cluster);
    if (!IsAcyclic(anc)) return;
    DescendantSets<BitSet> desc(anc);
    AncestorSetFeeFracs<BitSet> anc_feefracs(sorted.cluster, anc, {});
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
        auto ret = FindBestCandidateSetEfficient<QueueStyle::DFS>(sorted.cluster, anc, desc, anc_feefracs, done, nullptr);

        // Sanity checks
        // - connectedness of candidate
        assert(IsConnectedSubset(sorted.cluster, ret.best_candidate_set));
        // - claimed FeeFrac matches
        auto feefrac = ComputeSetFeeFrac(sorted.cluster, ret.best_candidate_set);
        assert(feefrac == ret.best_candidate_feefrac);
        // - topologically consistent
        BitSet merged_ancestors = done;
        auto todo{ret.best_candidate_set.Elements()};
        while (todo) {
            merged_ancestors |= anc[todo.Next()];
        }
        assert((done | ret.best_candidate_set) == merged_ancestors);
        unsigned left = (all / done).Count();
        // - if small enough, matches exhaustive search FeeFrac
#if 1
        if (left <= 10) {
            auto ret_exhaustive = FindBestCandidateSetExhaustive(sorted.cluster, anc, done);
            assert(ret_exhaustive.best_candidate_feefrac == ret.best_candidate_feefrac);
        }
#endif

        // Update statistics.
        stats.push_back({done, left, ret.iterations, ret.comparisons, ret.max_queue_size, connected, 0, 0});

        // Update done to include added candidate.
        done |= ret.best_candidate_set;
        anc_feefracs.Done(sorted.cluster, desc, ret.best_candidate_set);
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
            AncestorSetFeeFracs<BitSet> anc_feefracs_trim(sorted_trim.cluster, anc_trim, {});
            DescendantSets<BitSet> desc_trim(anc_trim);
            WeedCluster(sorted_trim.cluster, anc_trim);
            auto redo = FindBestCandidateSetEfficient<QueueStyle::DFS>(sorted_trim.cluster, anc_trim, desc_trim, anc_feefracs_trim, {}, nullptr);
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
