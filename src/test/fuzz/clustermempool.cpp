// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <time.h>

#include <iostream>
#include <vector>

#include <util/bitset.h>
#include <util/feefrac.h>
#include <util/strencodings.h>

#include <cluster_linearize.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/xoroshiro128plusplus.h>

#include <assert.h>

#include <iostream>

using namespace cluster_linearize;

namespace {

template<typename S>
void DrawCluster(std::ostream& o, const Cluster<S>& cluster)
{
    o << "digraph{rankdir=\"BT\";";
    for (unsigned i = 0; i < cluster.size(); ++i) {
        o << "t" << i << "[label=\"" << (double(cluster[i].first.fee) / cluster[i].first.size) << "\\n" << cluster[i].first.fee << " / " << cluster[i].first.size << "\"];";
    }
    for (unsigned i = 0; i < cluster.size(); ++i) {
        for (unsigned val : cluster[i].second) {
            o << "t" << i << "->t" << val << ";";
        }
    }
    o << "}";
}

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
    return (high >> 30) == 0;
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


/** Determine if select is a connected subset in the given cluster. */
template<typename S>
bool IsConnectedSubset(const Cluster<S>& cluster, const S& select)
{
    /* Trivial case. */
    if (select.None()) return true;

    /* Build up UF data structure. */
    UnionFind<unsigned, S::Size()> uf(cluster.size());
    for (unsigned pos : select) {
        for (unsigned dep : cluster[pos].second & select) {
            uf.Union(pos, dep);
        }
    }

    /* Test that all selected entries in uf have the same representative. */
    auto it = select.begin();
    unsigned root = uf.Find(*it);
    ++it;
    while (it != select.end()) {
        if (uf.Find(*it) != root) return false;
        ++it;
    }
    return true;
}

/** A naive algorithm for finding the best candidate set.
 *
 * It constructs all 2^N subsets, tests if they satisfy dependency relations, and remembers the
 * best one out of those that do.
 */
template<typename S>
CandidateSetAnalysis<S> FindBestCandidateSetNaive(const Cluster<S>& cluster, const S& done, const S& after)
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
        if (((done | after) & bitset).Any()) continue;
        // We only consider non-empty additions.
        if (bitset.None()) continue;
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
CandidateSetAnalysis<S> FindBestCandidateSetExhaustive(const Cluster<S>& cluster, const AncestorSets<S>& anc, const S& done, const S& after)
{
    // Queue of work units. Each consists of:
    // - inc: set of transactions definitely included (always includes done)
    // - exc: set of transactions definitely excluded
    // - feefrac: the FeeFrac of (included / done)
    std::vector<std::tuple<S, S, FeeFrac>> queue;
    queue.emplace_back(done, after, FeeFrac{});

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
            if (!inc[i] && !exc[i] && (exc & anc[i]).None() && (inc_none || !(done >> (inc & anc[i])))) {
                // First, add a queue item with i added to exc. Inc is unchanged, so feefrac is
                // unchanged as well.
                auto new_exc = exc;
                new_exc.Set(i);
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

template<typename S>
S DecodeAfter(Span<const unsigned char>& data, const DescendantSets<S>& descs, const S& done)
{
    S ret;
    while (true) {
        unsigned pos = DeserializeNumberBase128(data) % (descs.Size() + 1);
        if (pos == 0) break;
        if (!done[descs.Size() - pos]) {
            ret |= descs[descs.Size() - pos];
        }
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
using FuzzBitSet = BitSet<64>;

} // namespace

FUZZ_TARGET(clustermempool_exhaustive_equals_naive)
{
    // Read cluster from fuzzer.
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer);
    if (cluster.size() > 15) return;
    if (!IsMul64Compatible(cluster)) return;

    // Compute ancestor sets.
    AncestorSets anc(cluster);
    if (!IsAcyclic(anc)) return;
    DescendantSets desc(anc);
    // Find a topologically (but not necessarily connect) subset to set as "done" already.
    FuzzBitSet done = DecodeDone(buffer, anc);
    FuzzBitSet after = DecodeAfter(buffer, desc, done);

    // Run both algorithms.
    auto ret_naive = FindBestCandidateSetNaive(cluster, done, after);
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done, after);

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
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer);
    if (cluster.size() >= FuzzBitSet::Size()) return;
    if (!IsMul64Compatible(cluster)) return;
    // Compute ancestor sets.
    AncestorSets anc(cluster);
    if (!IsAcyclic(anc)) return;
    // Find a topological subset to set as "done" already.
    FuzzBitSet done = DecodeDone(buffer, anc);
    DescendantSets desc(anc);
    FuzzBitSet after = DecodeAfter(buffer, desc, done);
    if (cluster.size() - done.Count() - after.Count() > 20) return;
    // Sort the cluster by individual FeeFrac.
    SortedCluster<FuzzBitSet> cluster_sorted(cluster);
    // Compute ancestor sets.
    AncestorSets<FuzzBitSet> anc_sorted(cluster_sorted.cluster);
    // Compute descendant sets.
    DescendantSets<FuzzBitSet> desc_sorted(anc_sorted);
    // Convert done to sorted ordering.
    FuzzBitSet done_sorted = cluster_sorted.OriginalToSorted(done);
    FuzzBitSet after_sorted = cluster_sorted.OriginalToSorted(after);
    // Precompute ancestor set FreeFracs in sorted ordering.
    AncestorSetFeeFracs<FuzzBitSet> anc_sorted_feefrac(cluster_sorted.cluster, anc_sorted, done_sorted);

    // Run both algorithms.
    auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done, after);
    auto ret_efficient = FindBestCandidateSetEfficient(cluster_sorted.cluster, anc_sorted, desc_sorted, anc_sorted_feefrac, done_sorted, after_sorted, 0);

    // Compare best found FeeFracs.
    assert(ret_exhaustive.best_candidate_feefrac == ret_efficient.best_candidate_feefrac);

    // We cannot require that the actual candidate returned is identical, because there may be
    // multiple, and the algorithms iterate in different order. Instead, recompute the FeeFrac of
    // the candidate returned by the efficient one and check that it matches the claimed value.
    auto feefrac_efficient = ComputeSetFeeFrac(cluster_sorted.cluster, ret_efficient.best_candidate_set);
    assert(feefrac_efficient == ret_exhaustive.best_candidate_feefrac);
}

template<typename BS>
void LinearizeBenchmark(Span<const unsigned char> buffer)
{
    auto cluster = DeserializeCluster<BS>(buffer);
    if (!IsMul64Compatible(cluster)) return;

    AncestorSets<BS> anc(cluster);
    if (!IsAcyclic(anc)) return;

    std::vector<std::tuple<double, size_t, size_t>> results;
    results.reserve(11);

    for (unsigned i = 0; i < 11; ++i) {
        struct timespec measure_start, measure_stop;
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_start);
        auto analysis = LinearizeCluster(cluster, BS::Size(), 0);
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_stop);
        double duration = (double)((int64_t)measure_stop.tv_sec - (int64_t)measure_start.tv_sec) + 0.000000001*(double)((int64_t)measure_stop.tv_nsec - (int64_t)measure_start.tv_nsec);
        results.emplace_back(duration, analysis.iterations, analysis.comparisons);
    }

    std::sort(results.begin(), results.end(), [](const auto& a, const auto& b) { return std::get<0>(a) < std::get<0>(b); });
    const auto [duration, iterations, comparisons] = results[5];
    std::cerr << "LINEARIZE clustersize " << cluster.size() << ", duration " << (duration * 1000.0) << "ms, iterations " << iterations << ", " << (1000000000.0 * duration / iterations) << "ns/iter, comparisons " << comparisons << ", " << (1000000000.0 * duration / comparisons) << "ns/comp" << std::endl;
}

FUZZ_TARGET(clustermempool_linearize_benchmark)
{
    auto buffer_copy = buffer;
    auto cluster_small = DeserializeCluster<BitSet<64>>(buffer_copy);
    if (!IsMul64Compatible(cluster_small)) return;

    if (cluster_small.size() <= 32) {
        LinearizeBenchmark<BitSet<32>>(buffer);
    } else if (cluster_small.size() <= 64) {
        LinearizeBenchmark<BitSet<64>>(buffer);
    } else if (cluster_small.size() <= 128) {
        LinearizeBenchmark<BitSet<128>>(buffer);
    } else if (cluster_small.size() <= 192) {
        LinearizeBenchmark<BitSet<192>>(buffer);
    } else if (cluster_small.size() <= 256) {
        LinearizeBenchmark<BitSet<256>>(buffer);
    } else if (cluster_small.size() <= 512) {
        LinearizeBenchmark<BitSet<512>>(buffer);
    } else if (cluster_small.size() <= 1024) {
        LinearizeBenchmark<BitSet<1024>>(buffer);
    } else if (cluster_small.size() <= 2048) {
        LinearizeBenchmark<BitSet<2048>>(buffer);
    } else if (cluster_small.size() <= 4096) {
        LinearizeBenchmark<BitSet<4096>>(buffer);
    } else if (cluster_small.size() <= 8192) {
        LinearizeBenchmark<BitSet<8192>>(buffer);
    } else {
        return;
    }
}

FUZZ_TARGET(clustermempool_ancestorset)
{
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer);
    if (cluster.size() > FuzzBitSet::Size()) return;
    AncestorSets<FuzzBitSet> anc(cluster);
    // Note: no requirement that cluster is acyclic.

    for (unsigned i = 0; i < cluster.size(); ++i) {
        FuzzBitSet ancs;
        ancs.Set(i); // Start with transaction itself
        // Add existing ancestors' parents until set no longer changes.
        while (true) {
            FuzzBitSet next_ancs = ancs;
            for (unsigned val : ancs) {
                next_ancs |= cluster[val].second;
            }
            if (next_ancs == ancs) break;
            ancs = next_ancs;
        }
        assert(anc[i] == ancs); // Compare against AncestorSets output.
    }
}

FUZZ_TARGET(clustermempool_encoding_roundtrip)
{
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer);
    if (cluster.size() > FuzzBitSet::Size()) return;
    std::vector<unsigned char> encoded;
    SerializeCluster(cluster, encoded);
    encoded.pop_back();
    Span<const unsigned char> span(encoded);
    Cluster<FuzzBitSet> cluster2 = DeserializeCluster<FuzzBitSet>(span);
    assert(cluster == cluster2);
}

FUZZ_TARGET(clustermempool_weedcluster)
{
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer);
    if (cluster.size() > FuzzBitSet::Size()) return;
    AncestorSets<FuzzBitSet> anc(cluster);
    if (!IsAcyclic(anc)) return;
    WeedCluster(cluster, anc);
    AncestorSets<FuzzBitSet> anc_weed(cluster);
    for (unsigned i = 0; i < cluster.size(); ++i) {
        assert(anc[i] == anc_weed[i]);
    }
}

FUZZ_TARGET(clustermempool_trim)
{
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer);
    if (!IsMul64Compatible(cluster)) return;
    if (cluster.size() > 20) return;

    FuzzBitSet all = FuzzBitSet::Fill(cluster.size());
    if (!IsConnectedSubset(cluster, all)) return;

    SortedCluster<FuzzBitSet> sorted(cluster);
    AncestorSets<FuzzBitSet> anc(sorted.cluster);
    if (!IsAcyclic(anc)) return;
    DescendantSets<FuzzBitSet> desc(anc);

    FuzzBitSet done = DecodeDone<FuzzBitSet>(buffer, anc);
    FuzzBitSet after = DecodeAfter<FuzzBitSet>(buffer, desc, done);

    AncestorSetFeeFracs<FuzzBitSet> anc_feefracs(sorted.cluster, anc, done);
    auto eff1 = FindBestCandidateSetEfficient(sorted.cluster, anc, desc, anc_feefracs, done, after, 0);
    WeedCluster(sorted.cluster, anc);
    Cluster<FuzzBitSet> trim = TrimCluster(sorted.cluster, done | after);
    AncestorSets<FuzzBitSet> trim_anc(trim);
    DescendantSets<FuzzBitSet> trim_desc(trim_anc);
    AncestorSetFeeFracs<FuzzBitSet> trim_anc_feefracs(trim, trim_anc, {});
    auto eff2 = FindBestCandidateSetEfficient(trim, trim_anc, trim_desc, trim_anc_feefracs, {}, {}, 0);
    assert(eff1.best_candidate_feefrac == eff2.best_candidate_feefrac);
    assert(eff1.max_queue_size == eff2.max_queue_size);
    assert(eff1.iterations == eff2.iterations);
    assert(eff1.comparisons == eff2.comparisons);

    if (cluster.size() <= 15) {
        auto ret1 = FindBestCandidateSetExhaustive(sorted.cluster, anc, done, after);
        auto ret2 = FindBestCandidateSetExhaustive(trim, trim_anc, {}, {});
        assert(ret1.num_candidate_sets == ret2.num_candidate_sets);
        assert(ret1.best_candidate_feefrac == ret2.best_candidate_feefrac);
        assert(ret1.best_candidate_feefrac == eff1.best_candidate_feefrac);
    }
}

FUZZ_TARGET(clustermempool_efficient_limits)
{
    auto buffer_tmp = buffer;
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer_tmp);
    if (cluster.size() > 18) return;
    if (!IsMul64Compatible(cluster)) return;

//    std::cerr << "CLUSTER " << cluster << std::endl;

    FuzzBitSet all = FuzzBitSet::Fill(cluster.size());
    bool connected = IsConnectedSubset(cluster, all);

    SortedCluster<FuzzBitSet> sorted(cluster);
    AncestorSets<FuzzBitSet> anc(sorted.cluster);
    if (!IsAcyclic(anc)) return;
    DescendantSets<FuzzBitSet> desc(anc);
    AncestorSetFeeFracs<FuzzBitSet> anc_feefracs(sorted.cluster, anc, {});
    WeedCluster(sorted.cluster, anc);

    struct Stats
    {
        FuzzBitSet done;
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

    FuzzBitSet done;
    while (done != all) {
        CandidateSetAnalysis<FuzzBitSet> ret;
        auto single_viable = SingleViableTransaction(sorted.cluster, done);
        if (single_viable) {
            ret.best_candidate_set.Set(*single_viable);
        } else {
            ret = FindBestCandidateSetEfficient(sorted.cluster, anc, desc, anc_feefracs, done, {}, 0);
            // Sanity checks
            // - connectedness of candidate
            assert(IsConnectedSubset(sorted.cluster, ret.best_candidate_set));
            // - claimed FeeFrac matches
            auto feefrac = ComputeSetFeeFrac(sorted.cluster, ret.best_candidate_set);
            assert(feefrac == ret.best_candidate_feefrac);
            // - topologically consistent
            FuzzBitSet merged_ancestors = done;
            for (unsigned val : ret.best_candidate_set) {
                merged_ancestors |= anc[val];
            }
            assert((done | ret.best_candidate_set) == merged_ancestors);
        }
        unsigned left = (all / done).Count();
        // - if small enough, matches exhaustive search FeeFrac
#if 1
        if (left <= 10 && !single_viable) {
            auto ret_exhaustive = FindBestCandidateSetExhaustive(sorted.cluster, anc, done, {});
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


    static std::array<MaxVal<ClusterStat>, FuzzBitSet::Size()+1> COMPS{};
    static std::array<MaxVal<ClusterStat>, FuzzBitSet::Size()+1> ITERS{};
    static std::array<MaxVal<ClusterStat>, FuzzBitSet::Size()+1> QUEUE{};
    static std::array<MaxVal<ClusterStat>, FuzzBitSet::Size()+1> TOT_COMPS{};
    static std::array<MaxVal<ClusterStat>, FuzzBitSet::Size()+1> TOT_ITERS{};
    static std::array<MaxVal<ClusterStat>, FuzzBitSet::Size()+1> DIS_COMPS{};
    static std::array<MaxVal<ClusterStat>, FuzzBitSet::Size()+1> DIS_ITERS{};
    static std::array<MaxVal<ClusterStat>, FuzzBitSet::Size()+1> DIS_QUEUE{};
    static std::array<MaxVal<ClusterStat>, FuzzBitSet::Size()+1> DIS_TOT_COMPS{};
    static std::array<MaxVal<ClusterStat>, FuzzBitSet::Size()+1> DIS_TOT_ITERS{};

    bool comps_updated{false}, iters_updated{false}, queue_updated{false}, tot_comps_updated{false}, tot_iters_updated{false};
    bool dis_comps_updated{false}, dis_iters_updated{false}, dis_queue_updated{false}, dis_tot_comps_updated{false}, dis_tot_iters_updated{false};

    bool global_do_save = false;

    for (const auto& entry : stats) {
        bool do_save = false;
        if (DIS_COMPS[entry.cluster_left].Set({entry.comparisons, cluster.size(), buffer.size()})) do_save = dis_comps_updated = true;
        if (DIS_ITERS[entry.cluster_left].Set({entry.iterations, cluster.size(), buffer.size()})) do_save = dis_iters_updated = true;
        if (DIS_QUEUE[entry.cluster_left].Set({entry.max_queue_size, cluster.size(), buffer.size()})) do_save = dis_queue_updated = true;
        if (DIS_TOT_COMPS[entry.cluster_left].Set({entry.tot_comparisons, cluster.size(), buffer.size()})) do_save = dis_tot_comps_updated = true;
        if (DIS_TOT_ITERS[entry.cluster_left].Set({entry.tot_iterations, cluster.size(), buffer.size()})) do_save = dis_tot_iters_updated = true;
        if (entry.left_connected) {
            if (COMPS[entry.cluster_left].Set({entry.comparisons, cluster.size(), buffer.size()})) do_save = comps_updated = true;
            if (ITERS[entry.cluster_left].Set({entry.iterations, cluster.size(), buffer.size()})) do_save = iters_updated = true;
            if (QUEUE[entry.cluster_left].Set({entry.max_queue_size, cluster.size(), buffer.size()})) do_save = queue_updated = true;
            if (TOT_COMPS[entry.cluster_left].Set({entry.tot_comparisons, cluster.size(), buffer.size()})) do_save = tot_comps_updated = true;
            if (TOT_ITERS[entry.cluster_left].Set({entry.tot_iterations, cluster.size(), buffer.size()})) do_save = tot_iters_updated = true;
        }
        if (do_save) {
            auto trim = TrimCluster(sorted.cluster, entry.done);
            assert(trim.size() == entry.cluster_left);
            std::vector<unsigned char> enc;
            SerializeCluster(trim, enc);
            enc.pop_back();
            FuzzSave(enc);
            Span<const unsigned char> reload_buffer(enc);
            Cluster<FuzzBitSet> reload = DeserializeCluster<FuzzBitSet>(reload_buffer);
            assert(trim == reload);
            global_do_save = true;
#if 0
            SortedCluster<FuzzBitSet> sorted_trim(trim);
            assert(sorted_trim.cluster == trim);
            AncestorSets<FuzzBitSet> anc_trim(sorted_trim.cluster);
            assert(IsAcyclic(anc_trim));
            assert(IsConnectedSubset(trim, FuzzBitSet::Fill(trim.size())) == entry.connected);
            AncestorSetFeeFracs<FuzzBitSet> anc_feefracs_trim(sorted_trim.cluster, anc_trim, {});
            DescendantSets<FuzzBitSet> desc_trim(anc_trim);
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
        for (size_t i = 0; i <= FuzzBitSet::Size(); ++i) {
            if (ITERS[i]) {
                std::cerr << " " << i << ":" << ITERS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (comps_updated) {
        std::cerr << "COMPS:";
        for (size_t i = 0; i <= FuzzBitSet::Size(); ++i) {
            if (COMPS[i]) {
                std::cerr << " " << i << ":" << COMPS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (queue_updated) {
        std::cerr << "QUEUE:";
        for (size_t i = 0; i <= FuzzBitSet::Size(); ++i) {
            if (QUEUE[i]) {
                std::cerr << " " << i << ":" << QUEUE[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (tot_iters_updated) {
        std::cerr << "TOT_ITERS:";
        for (size_t i = 0; i <= FuzzBitSet::Size(); ++i) {
            if (TOT_ITERS[i]) {
                std::cerr << " " << i << ":" << TOT_ITERS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (tot_comps_updated) {
        std::cerr << "TOT_COMPS:";
        for (size_t i = 0; i <= FuzzBitSet::Size(); ++i) {
            if (TOT_COMPS[i]) {
                std::cerr << " " << i << ":" << TOT_COMPS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (dis_iters_updated) {
        std::cerr << "DIS_ITERS:";
        for (size_t i = 0; i <= FuzzBitSet::Size(); ++i) {
            if (DIS_ITERS[i]) {
                std::cerr << " " << i << ":" << DIS_ITERS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (comps_updated) {
        std::cerr << "DIS_COMPS:";
        for (size_t i = 0; i <= FuzzBitSet::Size(); ++i) {
            if (DIS_COMPS[i]) {
                std::cerr << " " << i << ":" << DIS_COMPS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (queue_updated) {
        std::cerr << "DIS_QUEUE:";
        for (size_t i = 0; i <= FuzzBitSet::Size(); ++i) {
            if (DIS_QUEUE[i]) {
                std::cerr << " " << i << ":" << DIS_QUEUE[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (tot_iters_updated) {
        std::cerr << "DIS_TOT_ITERS:";
        for (size_t i = 0; i <= FuzzBitSet::Size(); ++i) {
            if (DIS_TOT_ITERS[i]) {
                std::cerr << " " << i << ":" << DIS_TOT_ITERS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (tot_comps_updated) {
        std::cerr << "DIS_TOT_COMPS:";
        for (size_t i = 0; i <= FuzzBitSet::Size(); ++i) {
            if (DIS_TOT_COMPS[i]) {
                std::cerr << " " << i << ":" << DIS_TOT_COMPS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (global_do_save) {
        FuzzSave(buffer);
    }
}

FUZZ_TARGET(clustermempool_linearize_optimal)
{
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer);
    if (cluster.size() > 18) return;
    if (!IsMul64Compatible(cluster)) return;

    FuzzBitSet all = FuzzBitSet::Fill(cluster.size());
    if (!IsConnectedSubset(cluster, all)) return;

    AncestorSets<FuzzBitSet> anc(cluster);
    if (!IsAcyclic(anc)) return;

    auto lin = LinearizeCluster(cluster, FuzzBitSet::Size(), 0);

    // Check topology
    FuzzBitSet satisfied;
    for (unsigned i : lin.linearization) {
        assert(satisfied >> cluster[i].second);
        satisfied.Set(i);
    }

    // Compare chunks with exhaustive optimal.
    FuzzBitSet done;
    for (const auto& [feefrac, chunk] : ChunkLinearization(cluster, lin.linearization)) {
        auto ret_exhaustive = FindBestCandidateSetExhaustive(cluster, anc, done, {});
        assert(ret_exhaustive.best_candidate_feefrac == feefrac);
        done |= chunk;
    }
}

template<typename BS>
LinearizationResult LinearizeAncLimit(Span<const unsigned char> buffer)
{
    auto cluster = DeserializeCluster<BS>(buffer);
    if (!IsMul64Compatible(cluster)) return {};

    AncestorSets<BS> anc(cluster);
    if (!IsAcyclic(anc)) return {};

    return LinearizeCluster(cluster, 0, 0);
}

template<typename BS>
std::vector<unsigned char> ReserializeCluster(Span<const unsigned char> buffer)
{
    auto cluster = DeserializeCluster<BS>(buffer);
    return DumpCluster(cluster);
}

FUZZ_TARGET(clustermempool_linearize_anclimit)
{
    auto buffer_tmp = buffer;
    auto cluster_small = DeserializeCluster<BitSet<64>>(buffer_tmp);
    if (!IsMul64Compatible(cluster_small)) return;

    LinearizationResult lin;
    if (cluster_small.size() <= 32) {
        lin = LinearizeAncLimit<BitSet<32>>(buffer);
    } else if (cluster_small.size() <= 64) {
        lin = LinearizeAncLimit<BitSet<64>>(buffer);
    } else if (cluster_small.size() <= 128) {
        lin = LinearizeAncLimit<BitSet<128>>(buffer);
    } else if (cluster_small.size() <= 192) {
        lin = LinearizeAncLimit<BitSet<192>>(buffer);
    } else if (cluster_small.size() <= 256) {
        lin = LinearizeAncLimit<BitSet<256>>(buffer);
    } else {
        return;
    }

    if (lin.iterations == 0 || lin.comparisons == 0) return;

    static std::array<MaxVal<ClusterStat>, 257> COMPS{};
    static std::array<MaxVal<ClusterStat>, 257> ITERS{};

    bool comps_updated = COMPS[cluster_small.size()].Set({lin.comparisons, 0, buffer.size()});
    bool iters_updated = ITERS[cluster_small.size()].Set({lin.iterations, 0, buffer.size()});

    if (comps_updated) {
        std::cerr << "COMPS:";
        for (size_t i = 0; i <= 256; ++i) {
            if (COMPS[i]) {
                std::cerr << " " << i << ":" << COMPS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (iters_updated) {
        std::cerr << "ITERS:";
        for (size_t i = 0; i <= 256; ++i) {
            if (ITERS[i]) {
                std::cerr << " " << i << ":" << ITERS[i]->stat;
            }
        }
        std::cerr << std::endl;
    }

    if (comps_updated || iters_updated) {
        FuzzSave(buffer);
        auto reser = ReserializeCluster<BitSet<256>>(buffer);
        FuzzSave(reser);
    }
}

FUZZ_TARGET(clustermempool_add_bottom_improves)
{
    auto buffer_tmp = buffer;
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer);
    if (cluster.size() > 12) return;
    if (!IsMul64Compatible(cluster)) return;
    AncestorSets<FuzzBitSet> anc(cluster);
    if (!IsAcyclic(anc)) return;
    DescendantSets<FuzzBitSet> desc(anc);
    FuzzBitSet after = DecodeAfter<FuzzBitSet>(buffer, desc, {});
    if (after.None()) return;
    if (after >> FuzzBitSet::Fill(cluster.size())) return;

//    std::cerr << std::endl << "FULL: " << cluster << std::endl;
//    std::cerr << "AFTER: " << after << std::endl;
    auto lin_full = LinearizeCluster(cluster, 20, 0);
    auto chunk_full = ChunkLinearization(cluster, lin_full.linearization);
    std::map<unsigned, FeeFrac> feefrac_full;
    for (const auto& [feefrac, chunk] : chunk_full) {
//        std::cerr << "- CHUNK " << chunk << " feerate=" << feefrac << std::endl;
        for (auto idx : chunk) {
            feefrac_full[idx] = feefrac;
        }
    }

    std::vector<unsigned> full_to_shrink(cluster.size());
    std::vector<unsigned> shrink_to_full(cluster.size() - after.Count());
    unsigned idx{0};
    for (unsigned i = 0; i < cluster.size(); ++i) {
        if (after[i]) {
            full_to_shrink[i] = -1;
        } else {
            full_to_shrink[i] = idx;
            shrink_to_full[idx] = i;
            ++idx;
        }
    }
    Cluster<FuzzBitSet> cluster_shrink(idx);
    assert(idx == shrink_to_full.size());
    for (unsigned i = 0; i < cluster_shrink.size(); ++i) {
        cluster_shrink[i].first = cluster[shrink_to_full[i]].first;
        cluster_shrink[i].second = FuzzBitSet{};
        for (unsigned j = 0; j < cluster_shrink.size(); ++j) {
            if (cluster[shrink_to_full[i]].second[shrink_to_full[j]]) {
                cluster_shrink[i].second.Set(j);
            }
        }
    }
//    std::cerr << "SHRINK: " << cluster_shrink << std::endl;

    auto lin_shrink = LinearizeCluster(cluster_shrink, 20, 0);
    auto chunk_shrink = ChunkLinearization(cluster_shrink, lin_shrink.linearization);
    for (const auto& [feefrac, chunk] : chunk_shrink) {
//        std::cerr << "- CHUNK " << chunk << " feerate=" << feefrac << std::endl;
        for (auto idx : chunk) {
//            std::cerr << "- full tx" << shrink_to_full[idx] << " feerate " << feefrac_full[shrink_to_full[idx]] << ", shrink tx" << idx << " feerate " << feefrac << std::endl;
            assert(!(feefrac_full[shrink_to_full[idx]] << feefrac));
        }
    }

    static std::pair<uint64_t, size_t> scores[32][32] = {};
    auto& score_box = scores[cluster.size()][cluster_shrink.size()];
    uint64_t score = uint64_t{lin_full.comparisons} * std::min<uint64_t>(lin_full.comparisons - lin_shrink.comparisons, lin_shrink.comparisons);
    if (score > score_box.first) {
        std::cerr << "len=" << buffer_tmp.size() << " score=" << score_box.first << "->" << score << " full=" << cluster.size() << "(comp=" << lin_full.comparisons << ") shrink=" << cluster_shrink.size() << "(comp=" << lin_shrink.comparisons << ")" << std::endl;
        score_box = {score, buffer_tmp.size()};
        FuzzSave(buffer_tmp);
    } else if (score == score_box.first && buffer_tmp.size() < score_box.second) {
        std::cerr << "len=" << score_box.second << "->" << buffer_tmp.size() << " score=" << score << " full=" << cluster.size() << "(comp=" << lin_full.comparisons << ") shrink=" << cluster_shrink.size() << "(comp=" << lin_shrink.comparisons << ")" << std::endl;
        score_box = {score, buffer_tmp.size()};
        FuzzSave(buffer_tmp);
    }
}

namespace {

/** Compute FeeFrac diagram for a cluster linearization. */
template<typename BS>
std::vector<FeeFrac> GetLinearizationDiagram(const std::vector<std::pair<FeeFrac, BS>>& chunks)
{
    std::vector<FeeFrac> ret;
    ret.push_back(FeeFrac{});
    for (const auto& chunk : chunks) {
        ret.push_back(ret.back() + chunk.first);
    }
    return ret;
}

int CompareFeeFracWithDiagram(const FeeFrac& ff, Span<const FeeFrac> diagram)
{
    assert(diagram.size() > 0);
    unsigned not_above = 0;
    unsigned not_below = diagram.size() - 1;
    if (ff.size < diagram[not_above].size) return 0;
    if (ff.size > diagram[not_below].size) return 0;
    while (not_below > not_above + 1) {
        unsigned mid = (not_below + not_above) / 2;
        if (diagram[mid].size <= ff.size) not_above = mid;
        if (diagram[mid].size >= ff.size) not_below = mid;
    }
    if (not_below == not_above) {
        if (ff.fee > diagram[not_below].fee) return 1;
        if (ff.fee < diagram[not_below].fee) return -1;
        return 0;
    }
    uint64_t left = ff.fee*diagram[not_below].size + diagram[not_above].fee*ff.size + diagram[not_below].fee*diagram[not_above].size;
    uint64_t right = ff.size*diagram[not_below].fee + diagram[not_above].size*ff.fee + diagram[not_below].size*diagram[not_above].fee;
    if (left > right) return 1;
    if (left < right) return -1;
    return 0;
}

std::optional<int> CompareDiagrams(Span<const FeeFrac> dia1, Span<const FeeFrac> dia2)
{
    bool all_ge = true;
    bool all_le = true;
    for (const auto p1 : dia1) {
        int cmp = CompareFeeFracWithDiagram(p1, dia2);
        if (cmp < 0) all_ge = false;
        if (cmp > 0) all_le = false;
    }
    for (const auto p2 : dia2) {
        int cmp = CompareFeeFracWithDiagram(p2, dia1);
        if (cmp < 0) all_le = false;
        if (cmp > 0) all_ge = false;
    }
    if (all_ge && all_le) return 0;
    if (all_ge && !all_le) return 1;
    if (!all_ge && all_le) return -1;
    return std::nullopt;
}

/** Determine chunk feerate for every transaction. 0/0 for non-included ones. */
template<typename BS>
std::vector<FeeFrac> GetChunkFeerates(const Cluster<BS>& cluster, BS done, BS after)
{
    SortedCluster<FuzzBitSet> sorted(cluster);
    AncestorSets<FuzzBitSet> anc_sorted(sorted.cluster);
    assert(IsAcyclic(anc_sorted));
    DescendantSets<FuzzBitSet> desc_sorted(anc_sorted);
    BS done_sorted = sorted.OriginalToSorted(done);
    BS after_sorted = sorted.OriginalToSorted(after);

    AncestorSetFeeFracs<FuzzBitSet> anc_feefracs(sorted.cluster, anc_sorted, done_sorted | after_sorted);
    std::vector<FeeFrac> ret(sorted.cluster.size());
    auto all = BS::Fill(sorted.cluster.size());
    while ((done_sorted | after_sorted) != all) {
        auto res = FindBestCandidateSetEfficient(sorted.cluster, anc_sorted, desc_sorted, anc_feefracs, done_sorted, after_sorted, 0);
        for (auto idx : res.best_candidate_set) {
            ret[sorted.sorted_to_original[idx]] = res.best_candidate_feefrac;
        }
        anc_feefracs.Done(sorted.cluster, desc_sorted, res.best_candidate_set);
        done_sorted |= res.best_candidate_set;
    }
    return ret;
}

} // namespace

FUZZ_TARGET(clustermempool_replacement_heuristic)
{
    auto buffer_tmp = buffer;
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer);
    if (cluster.size() > 7) return;
    if (!IsMul64Compatible(cluster)) return;
    AncestorSets<FuzzBitSet> anc(cluster);
    if (!IsAcyclic(anc)) return;
    DescendantSets<FuzzBitSet> desc(anc);
    auto all = FuzzBitSet::Fill(cluster.size());

    // Decide eviction set.
    FuzzBitSet evict = DecodeAfter<FuzzBitSet>(buffer, desc, {});

    // Decide add set.
    unsigned num_leaves{0};
    for (auto idx : all / evict) {
        if (desc[idx].Count() == 1) ++num_leaves;
    }
    if (num_leaves == 0) return;
    num_leaves = DeserializeNumberBase128(buffer) % num_leaves;
    FuzzBitSet add{};
    for (auto idx : all / evict) {
        if (desc[idx].Count() == 1) {
            if (num_leaves == 0) {
                add.Set(idx);
                break;
            }
            --num_leaves;
        }
    }
    assert(num_leaves == 0);
    assert(add.Count() == 1);

    // Guarantee absolute fee goes up.
    auto evict_feefrac = ComputeSetFeeFrac(cluster, evict);
    auto add_feefrac = ComputeSetFeeFrac(cluster, add);
    if (add_feefrac.fee <= evict_feefrac.fee) return;

    // Analyse.
    auto original_feerates = GetChunkFeerates(cluster, {}, add);
    auto replaced_feerates = GetChunkFeerates(cluster, {}, evict);
    for (auto idx : all / (add | evict)) {
        if (original_feerates[idx] >> replaced_feerates[idx]) return;
    }

    std::cerr << "CLUSTER " << cluster << " evict=" << evict << " add=" << add << std::endl;
}

FUZZ_TARGET(clustermempool_find_incomparable)
{
    Cluster<FuzzBitSet> cluster = DeserializeCluster<FuzzBitSet>(buffer);
    if (cluster.size() < 2) return;
    if (cluster.size() > 6) return;
    if (!IsMul64Compatible(cluster)) return;
    AncestorSets<FuzzBitSet> anc(cluster);
    if (!IsAcyclic(anc)) return;
    FuzzBitSet all = FuzzBitSet::Fill(cluster.size());
    if (!IsConnectedSubset(cluster, all)) return;

    std::cerr << std::endl;
    std::cerr << "START" << std::endl;

    std::vector<unsigned> lin1 = LinearizeCluster(cluster, 0, 0).linearization;

    std::vector<unsigned> lin2;
    FuzzBitSet todo2 = FuzzBitSet::Fill(cluster.size());
    while (todo2.Any()) {
        unsigned leaves{0};
        for (auto i : todo2) {
            if ((anc[i] & todo2).Count() == 1) {
                ++leaves;
            }
        }
        assert(leaves > 0);
        unsigned choice = DeserializeNumberBase128(buffer) % leaves;
        for (auto i : todo2) {
            if ((anc[i] & todo2).Count() == 1) {
                if (choice == 0) {
                    lin2.push_back(i);
                    todo2 /= anc[i];
                    break;
                }
                --choice;
            }
        }
    }

    if (lin1 == lin2) return;

    auto chunks1 = ChunkLinearization(cluster, lin1);
    auto chunks2 = ChunkLinearization(cluster, lin2);

    auto diag1 = GetLinearizationDiagram(chunks1);
    auto diag2 = GetLinearizationDiagram(chunks2);

    if (CompareDiagrams(diag1, diag2).has_value()) return;

    auto lin3 = MergeLinearizations(cluster, lin1, lin2, anc);
    auto chunks3 = ChunkLinearization(cluster, lin3);
    auto diag3 = GetLinearizationDiagram(chunks3);

    auto cmp31 = CompareDiagrams(diag3, diag1);
    auto cmp32 = CompareDiagrams(diag3, diag2);

    static uint64_t succ{0};
    ++succ;
    if ((succ & (succ - 1U)) == 0) {
        std::cerr << "... " << succ << " done" << std::endl;
    }

    if (cmp31 != 1 || cmp32 != 1) {
        std::cerr << "CLUSTER:" << cluster << std::endl;
        std::cerr << "LIN1:" << lin1 << " " << chunks1 << std::endl;
        std::cerr << "LIN2:" << lin2 << " " << chunks2 << std::endl;
        std::cerr << "MERG:" << lin3 << " " << chunks3 << std::endl;

        auto lin4 = LinearizeCluster(cluster, 20, 0).linearization;
        auto chunks4 = ChunkLinearization(cluster, lin4);
        auto diag4 = GetLinearizationDiagram(chunks4);
        assert(CompareDiagrams(diag4, diag1) == 1);
        assert(CompareDiagrams(diag4, diag2) == 1);
        assert(CompareDiagrams(diag4, diag3) == 1);
        std::cerr << "BEST:" << lin4 << " " << chunks4 << std::endl;

        assert(false);
    }
}
