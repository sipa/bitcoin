// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CLUSTER_LINEARIZE_H
#define BITCOIN_CLUSTER_LINEARIZE_H

#include <span.h>

#include <stdint.h>
#include <algorithm>
#include <limits>
#include <numeric>
#include <optional>
#include <vector>
#include <tuple>

#include <util/bitset.h>
#include <util/feefrac.h>
#include <test/util/xoroshiro128plusplus.h>

#include <assert.h>

#if !defined(DEBUG_LINEARIZE)
#  if defined(PROVIDE_FUZZ_MAIN_FUNCTION)
#    define DEBUG_LINEARIZE 0
#  else
#    define DEBUG_LINEARIZE 1
#  endif
#endif

namespace cluster_linearize {

namespace {

/** Data type to represent cluster input.
 *
 * cluster[i].first is tx_i's fee and size.
 * cluster[i].second[j] is true iff tx_i spends one or more of tx_j's outputs.
 */
template<typename S>
using Cluster = std::vector<std::pair<FeeFrac, S>>;

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
            // a path from a to b through the subgraph consisting of {a, b, 0, 1, ..(i-1)}.
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
            for (unsigned j : anc[i]) {
                m_descendantsets[j].Set(i);
            }
        }
    }

    DescendantSets() noexcept = default;
    DescendantSets(const DescendantSets&) = delete;
    DescendantSets(DescendantSets&&) noexcept = default;
    DescendantSets& operator=(const DescendantSets&) = delete;
    DescendantSets& operator=(DescendantSets&&) noexcept = default;

    const S& operator[](unsigned pos) const noexcept { return m_descendantsets[pos]; }
    size_t Size() const noexcept { return m_descendantsets.size(); }
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
    FeeFrac best_candidate_feefrac{};
    /** Index of the chosen transaction (ancestor set algorithm only). */
    unsigned chosen_transaction{0};

    /** Maximum search queue size. */
    size_t max_queue_size{0};
    /** Total number of queue processing iterations performed. */
    size_t iterations{0};
    /** Number of feefrac comparisons performed. */
    size_t comparisons{0};
};

/** Compute the combined fee and size of a subset of a cluster. */
template<typename S>
FeeFrac ComputeSetFeeFrac(const Cluster<S>& cluster, const S& select)
{
    FeeFrac ret;
    for (unsigned i : select) ret += cluster[i].first;
    return ret;
}

/** Precomputed ancestor FeeFracs. */
template<typename S>
class AncestorSetFeeFracs
{
    std::vector<FeeFrac> m_anc_feefracs;
    S m_done;

public:
    /** Construct a precomputed AncestorSetFeeFracs object for given cluster/done. */
    explicit AncestorSetFeeFracs(const Cluster<S>& cluster, const AncestorSets<S>& anc, const S& done) noexcept
    {
        m_anc_feefracs.resize(cluster.size());
        m_done = done;
        for (unsigned i = 0; i < cluster.size(); ++i) {
            if (!done[i]) {
                m_anc_feefracs[i] = ComputeSetFeeFrac(cluster, anc[i] / done);
            }
        }
    }

    /** Update the precomputed data structure to reflect that set new_done was added to done. */
    void Done(const Cluster<S>& cluster, const DescendantSets<S>& desc, const S& new_done) noexcept
    {
#if DEBUG_LINEARIZE
        assert((m_done & new_done).None());
#endif
        m_done |= new_done;
        for (unsigned pos : new_done) {
            FeeFrac feefrac = cluster[pos].first;
            for (unsigned i : desc[pos] / m_done) {
                m_anc_feefracs[i] -= feefrac;
            }
        }
    }

    /** Update the precomputed data structure to reflect that transaction new_done was added to done. */
    void Done(const Cluster<S>& cluster, const DescendantSets<S>& desc, unsigned new_done) noexcept
    {
#if DEBUG_LINEARIZE
        assert(!m_done[new_done]);
#endif
        m_done.Set(new_done);
        FeeFrac feefrac = cluster[new_done].first;
        for (unsigned i : desc[new_done] / m_done) {
            m_anc_feefracs[i] -= feefrac;
        }
    }

    const FeeFrac& operator[](unsigned i) const noexcept { return m_anc_feefracs[i]; }
};

/** Precomputation data structure for sorting a cluster based on individual transaction FeeFrac. */
template<typename S>
struct SortedCluster
{
    /** The cluster in individual FeeFrac sorted order (both itself and its dependencies) */
    Cluster<S> cluster;
    /** Mapping from the original order (input to constructor) to sorted order. */
    std::vector<unsigned> original_to_sorted;
    /** Mapping back from sorted order to the order given to the constructor. */
    std::vector<unsigned> sorted_to_original;

    /** Given a set with indexes in original order, compute one in sorted order. */
    S OriginalToSorted(const S& val) const noexcept
    {
        S ret;
        for (unsigned i : val) ret.Set(original_to_sorted[i]);
        return ret;
    }

    /** Given a set with indexes in sorted order, compute on in original order. */
    S SortedToOriginal(const S& val) const noexcept
    {
        S ret;
        for (unsigned i : val) ret.Set(sorted_to_original[i]);
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
            if (orig_cluster[i].first == orig_cluster[j].first) {
                return i < j;
            }
            return orig_cluster[i].first > orig_cluster[j].first;
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

/** Given a cluster and its ancestor sets, find the one with the best FeeFrac. */
template<typename S, bool OutputIntermediate = false>
CandidateSetAnalysis<S> FindBestAncestorSet(const Cluster<S>& cluster, const AncestorSets<S>& anc, const AncestorSetFeeFracs<S>& anc_feefracs, const S& done, const S& after)
{
    CandidateSetAnalysis<S> ret;
    ret.max_queue_size = 1;

    for (size_t i = 0; i < cluster.size(); ++i) {
        if (done[i] || after[i]) continue;
        ++ret.iterations;
        ++ret.num_candidate_sets;
        const FeeFrac& feefrac = anc_feefracs[i];
#if DEBUG_LINEARIZE
        assert(!feefrac.IsEmpty());
#endif
        bool new_best = ret.best_candidate_feefrac.IsEmpty();
        if (!new_best) {
            ++ret.comparisons;
            new_best = feefrac > ret.best_candidate_feefrac;
        }
        if (new_best) {
            ret.best_candidate_feefrac = feefrac;
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
CandidateSetAnalysis<S> FindBestCandidateSetEfficient(const Cluster<S>& cluster, const AncestorSets<S>& anc, const DescendantSets<S>& desc, const AncestorSetFeeFracs<S>& anc_feefracs, const S& done, const S& after, uint64_t seed)
{
    /** Data structure with aggregated results. */
    CandidateSetAnalysis<S> ret;
    /** The set of all undecided transactions (everything except done or after). */
    auto todo = S::Fill(cluster.size()) / (done | after);
    // Bail out quickly if we're given a (remaining) cluster that is empty.
    if (todo.None()) return ret;

    /** Type for work queue items.
     *
     * Each consists of:
     * - inc: bitset of transactions definitely included. For every transaction in it, all its
     *        ancestors are also in it. This always includes done.
     * - exc: bitset of transactions definitely excluded. For every transaction in it, all its
     *        descendants are also in it. This always includes after.
     * - pot: the superset of inc, non-overlapping with exc, with the best possible feefrac. It
     *        may include transactions whose ancestors are not all included. It is always a strict
     *        superset of inc (otherwise this work item would be unimprovable, and therefore
     *        should not be in any queue).
     * - inc_feefrac: equal to ComputeSetFeeFrac(cluster, inc / done).
     * - pot_feefrac: equal to ComputeSetFeeFrac(cluster, pot / done). */
    using QueueElem = std::tuple<S, S, S, FeeFrac, FeeFrac>;
    /** Queues with work items. */
    static constexpr unsigned NUM_QUEUES = 4;
    std::vector<QueueElem> queue[NUM_QUEUES];
    /** Sum of total number of queue items across all queues. */
    unsigned queue_tot{0};
    /** Very fast local random number generator. */
    XoRoShiRo128PlusPlus rng(seed);
    /** The best found candidate set so far, including done. */
    S best_candidate;
    /** Equal to ComputeSetFeeFrac(cluster, best_candidate / done). */
    FeeFrac best_feefrac;
    /** The number of insertions so far into the queues in total. */
    unsigned insert_count{0};

    /** Internal add function.
     *
     * - inc: included set of transactions for new item; must include done and own ancestors.
     * - exc: excluded set of transactions for new item; must include after and own descendants.
     * - pot: superset of inc, non-overlapping with exc, and subset of the new item's pot. The
     *        function will add missing transactions to pot as needed, so it doesn't need to be
     *        the actual new item's pot set.
     * - inc_feefrac: equal to ComputeSetFeeFrac(cluster, inc / done).
     * - pot_feefrac: equal to ComputeSetFeeFrac(cluster, pot / done).
     * - inc_may_be_best: whether the possibility exists that inc_feefrac > best_feefrac.
     */
    auto add_fn = [&](const S& init_inc, const S& exc, S&& pot, FeeFrac&& inc_feefrac, FeeFrac&& pot_feefrac, bool inc_may_be_best) {
        // Add missing entries to pot (and pot_feefrac). We iterate over all undecided transactions
        // excluding pot.
        for (unsigned pos : todo / (pot | exc)) {
            // Determine if adding transaction pos to pot (ignoring topology) would improve it. If
            // not, we're done updating pot.
            ++ret.iterations;
            if (!pot_feefrac.IsEmpty()) {
                ++ret.comparisons;
                if (!(cluster[pos].first >> pot_feefrac)) break;
            }
            pot_feefrac += cluster[pos].first;
            pot.Set(pos);
        }

        // If (pot / done) is empty, this is certainly uninteresting to work on.
        if (pot_feefrac.IsEmpty()) return;

        // If any transaction in pot has only missing ancestors in pot, add it (and its ancestors)
        // to inc. This is legal because any topologically-valid subset of pot must be part of the
        // best possible candidate reachable from this state. To see this:
        // - The feefrac of every element of (pot / inc) is higher than that of (pot / done),
        //   which on its turn is higher than that of (inc / done).
        // - Thus, the feefrac of any non-empty subset of (pot / inc) is higher than that of the
        //   set (inc / done) plus any amount of undecided transactions (including ones in pot).
        // - Let A be a topologically-valid subset of pot, then every transaction in A must be
        //   part of the best candidate reachable from this state:
        //   - Assume A is not a subset of C, the best possible candidate set.
        //   - Then A union C has higher feefrac than C itself.
        //   - But A union C is also topologically valid, as both A and C are.
        //   - That is a contradiction, because we assumed C was the best possible.
        bool updated_inc{false};
        S inc = init_inc;
        // Iterate over all transactions in pot that are not yet included in inc.
        for (unsigned pos : pot / inc) {
            ++ret.iterations;
            // If that transaction's ancestors are a subset of pot, and the transaction is
            // (still) not part of inc, we can merge it together with its ancestors to inc.
            if (!inc[pos] && (pot >> anc[pos])) {
                inc |= anc[pos];
                updated_inc = true;
            }
        }
        // If anything was added to inc this way, recompute inc_feefrac, remembering that
        // the new inc_feefrac may now be the new best.
        if (updated_inc) {
            inc_feefrac += ComputeSetFeeFrac(cluster, inc / init_inc);
            inc_may_be_best = true;
        }

        // If inc_feefrac may be the new best, check whether it actually is, and if so, update
        // best_feefrac and the associated best_candidate set.
        if (inc_may_be_best) {
            ++ret.num_candidate_sets;
#if DEBUG_LINEARIZE
            assert(!inc_feefrac.IsEmpty());
#endif
            bool new_best = best_feefrac.IsEmpty();
            if (!new_best) {
                ++ret.comparisons;
                new_best = inc_feefrac > best_feefrac;
            }
            if (new_best) {
                best_feefrac = inc_feefrac;
                best_candidate = inc;
            }
        }

        // Only if any transactions with feefrac better than inc_feefrac exist add this entry to the
        // queue. If not, it is unimprovable, and it is not worth exploring further.
        if (pot_feefrac == inc_feefrac) return;

        // Construct a new work item in one of the queues, in a round-robin fashion, and update
        // statistics.
        queue[insert_count % NUM_QUEUES].emplace_back(std::move(inc), std::move(exc), std::move(pot), std::move(inc_feefrac), std::move(pot_feefrac));
        ++insert_count;
        ++queue_tot;
        ret.max_queue_size = std::max<size_t>(ret.max_queue_size, queue_tot);
    };

    // Find connected components of the cluster, and add queue entries for each which exclude all
    // the other components. This prevents the search further down from considering candidates
    // that span multiple components (as those are necessarily suboptimal).
    auto to_cover = todo;
    while (true) {
        ++ret.iterations;
        // Start with one transaction that hasn't been covered with connected components yet.
        S component;
        component.Set(to_cover.First());
        S added = component;
        // Compute the transitive closure of "is ancestor or descendant of but not done or after".
        while (true) {
            ++ret.iterations;
            S prev_component = component;
            for (unsigned i : added) {
                component |= anc[i];
                component |= desc[i];
            }
            component /= (done | after);
            if (prev_component == component) break;
            added = component / prev_component;
        }
        // Find highest ancestor feerate transaction in the component using the precomputed values.
        FeeFrac best_ancestor_feefrac;
        unsigned best_ancestor_tx{0};
        for (unsigned i : component) {
            bool new_best = best_ancestor_feefrac.IsEmpty();
            if (!new_best) {
                ++ret.comparisons;
                new_best = anc_feefracs[i] > best_ancestor_feefrac;
            }
            if (new_best) {
                best_ancestor_tx = i;
                best_ancestor_feefrac = anc_feefracs[i];
            }
        }
        // Add queue entries corresponding to the inclusion and the exclusion of that highest
        // ancestor feerate transaction. This guarantees that regardless of how many iterations
        // are performed later, the best found is always at least as good as the best ancestor set.
        auto exclude_others = todo / component;
        add_fn(done, after | desc[best_ancestor_tx] | exclude_others, S{done}, {}, {}, false);
        auto inc{done | anc[best_ancestor_tx]};
        add_fn(inc, after | exclude_others, S{inc}, FeeFrac{best_ancestor_feefrac}, std::move(best_ancestor_feefrac), true);
        // Update the set of transactions to cover, and finish if there are none left.
        to_cover /= component;
        if (to_cover.None()) break;
    }

    // Work processing loop.
    while (queue_tot) {
        ++ret.iterations;

        // Find a queue to pop a work item from.
        unsigned queue_idx;
        do {
            queue_idx = rng() % NUM_QUEUES;
        } while (queue[queue_idx].empty());

        // If this item's potential feefrac is not better than the best seen so far, drop it.
        const auto& pot_feefrac_ref = std::get<4>(queue[queue_idx].back());
#if DEBUG_LINEARIZE
        assert(pot_feefrac_ref.size > 0);
#endif
        if (!best_feefrac.IsEmpty()) {
            ++ret.comparisons;
            if (pot_feefrac_ref <= best_feefrac) {
                queue[queue_idx].pop_back();
                --queue_tot;
                continue;
            }
        }

        // Move the work item from the queue to local variables, popping it.
        auto [inc, exc, pot, inc_feefrac, pot_feefrac] = std::move(queue[queue_idx].back());
        queue[queue_idx].pop_back();
        --queue_tot;

        // Decide which transaction to split on (create new work items; one with it included, one
        // with it excluded).
        //
        // Among the (undecided) ancestors and descendants of the best individual feefrac undecided
        // transaction, pick the one which:
        // - Minimizes the size of the largest of the undecided sets after including or excluding.
        // - If the above is equal, the one that minimizes the other branch's undecided set size.
        // - If the above are equal, the one with the best individual feefrac.
        unsigned pos = 0;
        std::optional<std::pair<unsigned, unsigned>> pos_counts;
        auto remain = todo / inc;
        remain /= exc;
        unsigned first = remain.First();
        for (unsigned i : (anc[first] | desc[first]) & remain) {
            ++ret.iterations;
            std::pair<unsigned, unsigned> counts{(remain / anc[i]).Count(), (remain / desc[i]).Count()};
            if (counts.first < counts.second) std::swap(counts.first, counts.second);
            if (!pos_counts.has_value() || counts < *pos_counts) {
                pos = i;
                pos_counts = counts;
            }
        }

        // Consider adding a work item corresponding to that transaction excluded. As nothing is
        // being added to inc, this new entry cannot be a new best.
        add_fn(inc, exc | desc[pos], pot / desc[pos], FeeFrac{inc_feefrac}, pot_feefrac - ComputeSetFeeFrac(cluster, pot & desc[pos]), false);

        // Consider adding a work item corresponding to that transaction included. Since only
        // connected subgraphs can be optimal candidates, if there is no overlap between the
        // parent's included transactions (inc) and the ancestors of the newly added transaction
        // (outside of done), we know it cannot possibly be the new best.
        // One exception to this is the first addition after an empty inc (inc=done). However,
        // due to the preseeding with the best ancestor set, we know that anything better must
        // necessarily consist of the union of at least two ancestor sets, and this is not a
        // concern.
        bool may_be_new_best = !(done >> (inc & anc[pos]));
        inc_feefrac += ComputeSetFeeFrac(cluster, anc[pos] / inc);
        pot_feefrac += ComputeSetFeeFrac(cluster, anc[pos] / pot);
        inc |= anc[pos];
        pot |= anc[pos];
        add_fn(inc, exc, std::move(pot), std::move(inc_feefrac), std::move(pot_feefrac), may_be_new_best);
    }

    // Return the best seen candidate set.
    ret.best_candidate_set = best_candidate / done;
    ret.best_candidate_feefrac = best_feefrac;
    return ret;
}

struct LinearizationResult
{
    std::vector<unsigned> linearization;
    size_t iterations{0};
    size_t comparisons{0};
};

template<typename S>
std::optional<unsigned> SingleViableTransaction(const Cluster<S>& cluster, const S& done)
{
    unsigned num_viable = 0;
    unsigned first_viable = 0;
    for (unsigned i : S::Fill(cluster.size()) / done) {
        if (done >> cluster[i].second) {
            if (++num_viable == 2) return {};
            first_viable = i;
        }
    }
#if DEBUG_LINEARIZE
    assert(num_viable == 1);
#endif
    return {first_viable};
}

[[maybe_unused]] std::ostream& operator<<(std::ostream& o, const FeeFrac& data)
{
    o << "(" << data.fee << "/" << data.size << "=" << ((double)data.fee / data.size) << ")";
    return o;
}

[[maybe_unused]] std::ostream& operator<<(std::ostream& o, Span<const unsigned> data)
{
    o << '{';
    bool first = true;
    for (unsigned i : data) {
        if (first) {
            first = false;
        } else {
            o << ',';
        }
        o << i;
    }
    o << '}';
    return o;
}

template<typename I>
std::ostream& operator<<(std::ostream& s, const bitset_detail::IntBitSet<I>& bs)
{
    s << "[";
    size_t cnt = 0;
    for (size_t i = 0; i < bs.Size(); ++i) {
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
std::ostream& operator<<(std::ostream& s, const bitset_detail::MultiIntBitSet<I, N>& bs)
{
    s << "[";
    size_t cnt = 0;
    for (size_t i = 0; i < bs.Size(); ++i) {
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

/** Compute a full linearization of a cluster (vector of cluster indices). */
template<typename S>
LinearizationResult LinearizeCluster(const Cluster<S>& cluster, unsigned optimal_limit, uint64_t seed)
{
    LinearizationResult ret;
    ret.linearization.reserve(cluster.size());
    auto all = S::Fill(cluster.size());

    /** Very fast local random number generator. */
    XoRoShiRo128PlusPlus rng(seed);

    std::vector<std::tuple<S, S, bool, std::optional<unsigned>>> queue;
    queue.reserve(cluster.size() * 2);
    queue.emplace_back(S{}, S{}, true, std::nullopt);
    std::vector<unsigned> bottleneck_list;
    bottleneck_list.reserve(cluster.size());

    // Precompute stuff.
    SortedCluster<S> sorted(cluster);
    AncestorSets<S> anc(sorted.cluster);
    DescendantSets<S> desc(anc);
    // Precompute ancestor set sizes, to help with topological sort.
    std::vector<unsigned> anccount(cluster.size(), 0);
    for (unsigned i = 0; i < cluster.size(); ++i) {
        anccount[i] = anc[i].Count();
    }
    AncestorSetFeeFracs anc_feefracs(sorted.cluster, anc, {});

    while (!queue.empty()) {
        auto [done, after, maybe_bottlenecks, single] = queue.back();
        queue.pop_back();

        if (single) {
            ret.linearization.push_back(*single);
            anc_feefracs.Done(sorted.cluster, desc, *single);
            continue;
        }

        auto todo = all / (done | after);
        if (todo.None()) continue;
        unsigned left = todo.Count();

        if (left == 1) {
            unsigned idx = todo.First();
            ret.linearization.push_back(idx);
            anc_feefracs.Done(sorted.cluster, desc, idx);
            continue;
        }

        if (maybe_bottlenecks) {
            // Find bottlenecks in the current graph.
            auto bottlenecks = todo;
            for (unsigned i : todo) {
                ++ret.iterations;
                bottlenecks &= (anc[i] | desc[i]);
                if (bottlenecks.None()) break;
            }

            if (bottlenecks.Any()) {
                bottleneck_list.clear();
                for (unsigned i : bottlenecks) bottleneck_list.push_back(i);
                std::sort(bottleneck_list.begin(), bottleneck_list.end(), [&](unsigned a, unsigned b) { return anccount[a] > anccount[b]; });
                for (unsigned i : bottleneck_list) {
                    queue.emplace_back(done | anc[i], after, false, std::nullopt);
                    queue.emplace_back(S{}, S{}, false, i);
                    after |= desc[i];
                }
                queue.emplace_back(done, after, false, std::nullopt);
                continue;
            }
        }

        CandidateSetAnalysis<S> analysis;
        if (left > optimal_limit) {
            analysis = FindBestAncestorSet(sorted.cluster, anc, anc_feefracs, done, after);
        } else {
            analysis = FindBestCandidateSetEfficient(sorted.cluster, anc, desc, anc_feefracs, done, after, rng() ^ ret.iterations);
        }

        // Sanity checks.
#if DEBUG_LINEARIZE
        assert(analysis.best_candidate_set.Any()); // Must be at least one transaction
        assert((analysis.best_candidate_set & (done | after)).None()); // Cannot overlap with processed ones.
#endif

        // Update statistics.
        ret.iterations += analysis.iterations;
        ret.comparisons += analysis.comparisons;

        // Append candidate's transactions to linearization, and topologically sort them.
        size_t old_size = ret.linearization.size();
        for (unsigned selected : analysis.best_candidate_set) {
            ret.linearization.emplace_back(selected);
        }
        std::sort(ret.linearization.begin() + old_size, ret.linearization.end(), [&](unsigned a, unsigned b) {
            if (anccount[a] == anccount[b]) return a < b;
            return anccount[a] < anccount[b];
        });

        // Update bookkeeping
        done |= analysis.best_candidate_set;
        anc_feefracs.Done(sorted.cluster, desc, analysis.best_candidate_set);
        queue.emplace_back(done, after, true, std::nullopt);
    }

    // Map linearization back from sorted cluster indices to original indices.
    for (unsigned i = 0; i < cluster.size(); ++i) {
        ret.linearization[i] = sorted.sorted_to_original[ret.linearization[i]];
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

/** Deserialize a number, in little-endian 7 bit format, top bit set = more size. */
uint64_t DeserializeNumberBase128(Span<const unsigned char>& data)
{
    uint64_t ret{0};
    for (int i = 0; i < 10; ++i) {
        uint8_t b = ReadSpanByte(data);
        ret |= ((uint64_t)(b & uint8_t{0x7F})) << (7 * i);
        if ((b & 0x80) == 0) break;
    }
    return ret;
}

/** Serialize a number, in little-endian 7 bit format, top bit set = more size. */
void SerializeNumberBase128(uint64_t val, std::vector<unsigned char>& data)
{
    for (int i = 0; i < 10; ++i) {
        uint8_t b = (val >> (7 * i)) & 0x7F;
        val &= ~(uint64_t{0x7F} << (7 * i));
        if (val) {
            data.push_back(b | 0x80);
        } else {
            data.push_back(b);
            break;
        }
    }
}

/** Serialize a cluster in the following format:
 *
 * - For every transaction:
 *   - Base128 encoding of its byte size (at least 1, max 2^22-1).
 *   - Base128 encoding of its fee in fee (max 2^51-1).
 *   - For each of its direct parents:
 *     - If parent_idx < child_idx:
 *       - Base128 encoding of (child_idx - parent_idx)
 *     - If parent_idx > child_idx:
 *       - Base128 encoding of (parent_idx)
 *   - A zero byte
 * - A zero byte
 */
template<typename S>
void SerializeCluster(const Cluster<S>& cluster, std::vector<unsigned char>& data)
{
    for (unsigned i = 0; i < cluster.size(); ++i) {
        SerializeNumberBase128(cluster[i].first.size, data);
        SerializeNumberBase128(cluster[i].first.fee, data);
        for (unsigned j = 1; j <= i; ++j) {
            if (cluster[i].second[i - j]) SerializeNumberBase128(j, data);
        }
        for (unsigned j = i + 1; j < cluster.size(); ++j) {
            if (cluster[i].second[j]) SerializeNumberBase128(j, data);
        }
        data.push_back(0);
    }
    data.push_back(0);
}

/** Deserialize a cluster in the same format as SerializeCluster (overflows wrap). */
template<typename S>
Cluster<S> DeserializeCluster(Span<const unsigned char>& data)
{
    Cluster<S> ret;
    while (true) {
        uint32_t size = DeserializeNumberBase128(data) & 0x3fffff;
        if (size == 0) break;
        uint64_t fee = DeserializeNumberBase128(data) & 0x7ffffffffffff;
        S parents;
        while (true) {
            unsigned read = DeserializeNumberBase128(data);
            if (read == 0) break;
            if (read <= ret.size() && ret.size() < S::Size() + read) {
                parents.Set(ret.size() - read);
            } else {
                if (read < S::Size()) {
                    parents.Set(read);
                }
            }
        }
        ret.emplace_back(FeeFrac{fee, size}, std::move(parents));
    }
    S all = S::Fill(std::min<unsigned>(ret.size(), S::Size()));
    for (unsigned i = 0; i < ret.size(); ++i) {
        ret[i].second &= all;
    }
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
#if DEBUG_LINEARIZE
        assert(cover == ancs[idx]);
#endif
        cluster[idx].second = std::move(parents);
    }
}

/** Construct a new cluster with done removed (leaving the rest in order). */
template<typename S>
Cluster<S> TrimCluster(const Cluster<S>& cluster, const S& done)
{
    Cluster<S> ret;
    std::vector<unsigned> mapping;
    mapping.resize(cluster.size());
    ret.reserve(cluster.size() - done.Count());
    for (unsigned idx : S::Fill(cluster.size()) / done) {
        mapping[idx] = ret.size();
        ret.push_back(cluster[idx]);
    }
    for (unsigned i = 0; i < ret.size(); ++i) {
        S parents;
        for (unsigned idx : ret[i].second / done) {
            parents.Set(mapping[idx]);
        }
        ret[i].second = std::move(parents);
    }
    return ret;
}

/** Minimize a cluster, and serialize to byte vector. */
template<typename S>
std::vector<unsigned char> DumpCluster(Cluster<S> cluster)
{
    AncestorSets<S> anc(cluster);
    WeedCluster(cluster, anc);
    std::vector<unsigned char> data;
    SerializeCluster(cluster, data);
    data.pop_back();
    return data;
}

/** Test whether an ancestor set was computed from an acyclic cluster. */
template<typename S>
bool IsAcyclic(const AncestorSets<S>& anc)
{
    for (unsigned i = 0; i < anc.Size(); ++i) {
        // Determine if there is a j<i which i has as ancestor, and which has i as ancestor.
        for (unsigned j : anc[i]) {
            if (j >= i) break;
            if (anc[j][i]) return false;
        }
    }
    return true;
}

template<typename S>
std::vector<std::pair<FeeFrac, S>> ChunkLinearization(const Cluster<S>& cluster, Span<const unsigned> linearization)
{
    std::vector<std::pair<FeeFrac, S>> chunks;
    chunks.reserve(linearization.size());
    for (unsigned i : linearization) {
        S add;
        add.Set(i);
        FeeFrac add_feefrac = cluster[i].first;
        while (!chunks.empty() && add_feefrac >> chunks.back().first) {
            add |= chunks.back().second;
            add_feefrac += chunks.back().first;
            chunks.pop_back();
        }
        chunks.emplace_back(add_feefrac, add);
    }
    return chunks;
}

/** Given a cluster and a linearization for it, improve the linearization such that its chunks are
 *  all connected. It also results in decent sub-chunk ordering.
 *
 * O(n^2) in the size of the cluster in the worst case. If the input linearization is the output
 * of PostLinearization itself, runtime is O(n). */
template<typename S>
void PostLinearization(const Cluster<S>& cluster, std::vector<unsigned>& linearization, uint64_t* swaps = nullptr)
{
    struct Entry {
        /** data index for previous transaction in this chunk (cyclic). */
        unsigned prev_tx;
        // The following fields are only relevant for the heads of chunks:
        /** - data index for the head of the previous chunk (cyclic). */
        unsigned prev_chunk;
        /** - the chunk feerate. */
        FeeFrac chunk_feerate;
        /** - the set of all chunk members */
        S chunk;
        /** - the set of all chunk parents */
        S parents;
    };
    /** data[i+1] contains information about transaction 'i'. data[0] is a sentinel. */
    std::vector<Entry> data(cluster.size() + 1);
    data[0].prev_tx = 0;
    data[0].prev_chunk = 0;
    uint64_t num_swaps = 0;
    for (unsigned i : linearization) {
        // Create a new chunk with just transaction 'i' at the end.
        auto& entry = data[i + 1];
        entry.prev_tx = i + 1;
        entry.prev_chunk = data[0].prev_chunk;
        data[0].prev_chunk = i + 1;
        entry.chunk_feerate = cluster[i].first;
        assert(entry.chunk.None());
        entry.chunk.Set(i);
        entry.parents = cluster[i].second;
        // 'after_work' is the head of the chunk *after* the one we're working on.
        // We start working on the newly inserted chunk, so after_work starts at the sentinel.
        unsigned after_work = 0;
        while (true) {
            unsigned work = data[after_work].prev_chunk;
            assert(work != 0); // cannot work on the sentinel
            unsigned before_work = data[work].prev_chunk;
            // If the previous chunk is the sentinel, we are done.
            if (before_work == 0) break;
            // If the previous chunk has higher or equal feerate, we are done.
            if (!(data[before_work].chunk_feerate << data[work].chunk_feerate)) break;
            // Check whether there is a dependency on the previous chunk.
            if ((data[work].parents & data[before_work].chunk).Any()) {
                // There is a dependency; merge the chunk data.
                data[before_work].chunk_feerate += data[work].chunk_feerate;
                data[before_work].chunk |= data[work].chunk;
                data[before_work].parents = (data[before_work].parents | data[work].parents) / data[before_work].chunk;
                // Stitch the two chunks together.
                std::swap(data[before_work].prev_tx, data[work].prev_tx);
                // Continue with the now-merged chunk.
                data[after_work].prev_chunk = before_work;
            } else {
                // There is no dependency; swap the two chunks.
                data[after_work].prev_chunk = before_work;
                data[work].prev_chunk = data[before_work].prev_chunk;
                data[before_work].prev_chunk = work;
                // Continue with the now-moved previous work chunk.
                after_work = before_work;
                ++num_swaps;
            }
        }
    }
    // Iterate over the chunks, and their transactions, overwriting linearization backwards.
    auto it = linearization.end();
    unsigned work_chunk = data[0].prev_chunk;
    while (work_chunk != 0) {
        unsigned first_tx = work_chunk;
        unsigned work_tx = first_tx;
        do {
            work_tx = data[work_tx].prev_tx;
            assert(work_tx != 0);
            assert(it != linearization.begin());
            --it;
            *it = work_tx - 1;
        } while (work_tx != first_tx);
        work_chunk = data[work_chunk].prev_chunk;
    }
    assert(it == linearization.begin());
    if (swaps) *swaps = num_swaps;
}

template<typename S>
std::vector<unsigned> MergeLinearizations(const Cluster<S>& cluster, Span<const unsigned> lin1, Span<const unsigned> lin2, const AncestorSets<S>& anc)
{
    std::vector<unsigned> ret;
    ret.reserve(std::max(lin1.size(), lin2.size()));
    S todo = S::Fill(cluster.size());

    auto next_chunk_fn = [&](Span<const unsigned> lin) -> std::pair<S, FeeFrac> {
        std::pair<S, FeeFrac> run, best;
        for (unsigned i : lin) {
            if (!todo[i]) continue;
            run.first.Set(i);
            run.second += cluster[i].first;
            if (best.first.None() || run.second >> best.second) best = run;
        }
        return best;
    };

    while (todo.Any()) {
        const auto ret1 = next_chunk_fn(lin1);
        const auto ret2 = next_chunk_fn(lin2);
        assert(ret1.first.Any());
        assert(ret2.first.Any());
        std::pair<S, FeeFrac> retb;
        {
            S walk;
            FeeFrac walkrate;
            for (unsigned i : lin2) {
                if (ret1.first[i]) {
                    walk.Set(i);
                    walkrate += cluster[i].first;
                    if (retb.second.size == 0 || walkrate > retb.second) {
                        retb.first = walk;
                        retb.second = walkrate;
                    }
                    if (walkrate.size >= ret1.second.size) break;
                }
            }
        }
        {
            S walk;
            FeeFrac walkrate;
            for (unsigned i : lin1) {
                if (ret2.first[i]) {
                    walk.Set(i);
                    walkrate += cluster[i].first;
                    if (retb.second.size == 0 || walkrate > retb.second) {
                        retb.first = walk;
                        retb.second = walkrate;
                    }
                    if (walkrate.size >= ret2.second.size) break;
                }
            }
        }
        assert(retb.first.Any());
        size_t old_len = ret.size();
        todo /= retb.first;
        for (auto i : retb.first) {
            ret.push_back(i);
        }
        std::sort(ret.begin() + old_len, ret.end(), [&](unsigned a, unsigned b) { return anc[a].Count() < anc[b].Count(); });
    }
    return ret;
}

} // namespace

} // namespace linearize_cluster

#endif // BITCOIN_CLUSTER_LINEARIZE_H
