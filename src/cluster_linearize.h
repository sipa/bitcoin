// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CLUSTER_LINEARIZE_H
#define BITCOIN_CLUSTER_LINEARIZE_H

#include <algorithm>
#include <numeric>
#include <optional>
#include <stdint.h>
#include <vector>
#include <utility>

#include <random.h>
#include <util/feefrac.h>
#include <util/ringbuffer.h>

namespace cluster_linearize {

/** Data type to represent cluster input.
 *
 * cluster[i].first is tx_i's fee and size.
 * cluster[i].second[j] is true iff tx_i spends one or more of tx_j's outputs.
 */
template<typename S>
using Cluster = std::vector<std::pair<FeeFrac, S>>;

/** Data type to represent transaction indices in clusters. */
using ClusterIndex = uint32_t;

/** Data structure that holds a transaction graph's preprocessed data (fee, size, ancestors,
 *  descendants). */
template<typename S>
class DepGraph
{
    /** Information about a single transaction. */
    struct Entry
    {
        /** Fee and size of transaction itself. */
        FeeFrac feerate;
        /** All ancestors of the transaction (including itself). */
        S ancestors;
        /** All descendants of the transaction (including itself). */
        S descendants;

        friend bool operator==(const Entry&, const Entry&) noexcept = default;
        friend auto operator<=>(const Entry&, const Entry&) noexcept = default;

        Entry() noexcept = default;
        Entry(const FeeFrac& f, const S& a, const S& d) noexcept : feerate(f), ancestors(a), descendants(d) {}
    };

    /** Data for each transaction, in order. */
    std::vector<Entry> entries;

public:
    // Comparison operators.
    friend bool operator==(const DepGraph&, const DepGraph&) noexcept = default;
    friend auto operator<=>(const DepGraph&, const DepGraph&) noexcept = default;

    // Default constructors.
    DepGraph() noexcept = default;
    DepGraph(const DepGraph&) noexcept = default;
    DepGraph(DepGraph&&) noexcept = default;
    DepGraph& operator=(const DepGraph&) noexcept = default;
    DepGraph& operator=(DepGraph&&) noexcept = default;

    /** Construct a DepGraph object for ntx transactions, with no dependencies.
     *
     * Complexity: O(N) where N=ntx.
     **/
    explicit DepGraph(ClusterIndex ntx) noexcept
    {
        entries.resize(ntx);
        for (ClusterIndex i = 0; i < ntx; ++i) {
            entries[i].ancestors = S::Singleton(i);
            entries[i].descendants = S::Singleton(i);
        }
    }

    /** Construct a DepGraph object given a cluster.
     *
     * Complexity: O(N^2) where N=cluster.size().
     */
    explicit DepGraph(const Cluster<S>& cluster) noexcept : entries(cluster.size())
    {
        // Fill in fee, size, parent information.
        for (ClusterIndex i = 0; i < cluster.size(); ++i) {
            entries[i].feerate = cluster[i].first;
            entries[i].ancestors = cluster[i].second;
            // Make sure transactions are ancestors of themselves.
            entries[i].ancestors.Set(i);
        }

        // Propagate ancestor information.
        for (ClusterIndex i = 0; i < entries.size(); ++i) {
            // At this point, entries[a].ancestors[b] is true iff:
            // - a != b, and b is an ancestor of a and there is a path from a to b through the
            //   subgraph consisting of {a, b} union {0, 1, ..., (i-1)}.
            // - a == b, and b<=i.
            S to_merge = entries[i].ancestors;
            for (ClusterIndex j = 0; j < entries.size(); ++j) {
                if (entries[j].ancestors[i]) {
                    entries[j].ancestors |= to_merge;
                }
            }
        }

        // Fill in descendant information.
        for (ClusterIndex i = 0; i < entries.size(); ++i) {
            for (auto j : entries[i].ancestors) {
                entries[j].descendants.Set(i);
            }
        }
    }

    /** Construct a DepGraph object given another DepGraph and a mapping from old to new.
     *
     * Complexity: O(N^2) where N=depgraph.TxCount().
     */
    DepGraph(const DepGraph<S>& depgraph, Span<const ClusterIndex> mapping) noexcept : entries(depgraph.TxCount())
    {
        // Fill in fee, size, ancestors.
        for (ClusterIndex i = 0; i < depgraph.TxCount(); ++i) {
            const auto& input = depgraph.entries[i];
            auto& output = entries[mapping[i]];
            output.feerate = input.feerate;
            for (auto j : input.ancestors) output.ancestors.Set(mapping[j]);
        }
        // Fill in descendant information.
        for (ClusterIndex i = 0; i < entries.size(); ++i) {
            for (auto j : entries[i].ancestors) {
                entries[j].descendants.Set(i);
            }
        }
    }

    /** Get the number of transactions in the graph. Complexity: O(1). */
    auto TxCount() const noexcept { return entries.size(); }
    /** Get the feerate of a given transaction i. Complexity: O(1). */
    const FeeFrac& FeeRate(ClusterIndex i) const noexcept { return entries[i].feerate; }
    /** Get the ancestors of a given transaction i. Complexity: O(1). */
    const S& Ancestors(ClusterIndex i) const noexcept { return entries[i].ancestors; }
    /** Get the descendants of a given transaction i. Complexity: O(1). */
    const S& Descendants(ClusterIndex i) const noexcept { return entries[i].descendants; }

    /** Add a new unconnected transaction to this transaction graph (at the end), and return its
     *  ClusterIndex.
     *
     * Complexity: Amortized O(1).
     */
    ClusterIndex AddTransaction(const FeeFrac& feefrac) noexcept
    {
        ClusterIndex new_idx = TxCount();
        entries.emplace_back(feefrac, S::Singleton(new_idx), S::Singleton(new_idx));
        return new_idx;
    }

    /** Modify this transaction graph, adding a dependency between a specified parent and child.
     *
     * Complexity: O(N) where N=TxCount().
     **/
    void AddDependency(ClusterIndex parent, ClusterIndex child) noexcept
    {
        // To each ancestor of the parent, add as descendants the descendants of the child.
        const auto& chl_des = entries[child].descendants;
        for (auto anc_of_par : Ancestors(parent)) {
            entries[anc_of_par].descendants |= chl_des;
        }
        // To each descendant of the child, add as ancestors the ancestors of the parent.
        const auto& par_anc = entries[parent].ancestors;
        for (auto dec_of_chl : Descendants(child)) {
            entries[dec_of_chl].ancestors |= par_anc;
        }
    }

    /** Get the minimal set of parents a transaction has (parents which are not parents
     *  of ancestors).
     *
     * Complexity: O(N) where N=TxCount().
     */
    S GetReducedParents(ClusterIndex i) const noexcept
    {
        S ret = Ancestors(i);
        ret.Reset(i);
        for (auto a : ret) {
            if (ret[a]) {
                ret /= Ancestors(a);
                ret.Set(a);
            }
        }
        return ret;
    }

    /** Get the minimal set of children a transaction has (children which are not children
     *  of descendants).
     *
     * Complexity: O(N) where N=TxCount().
     */
    S GetReducedChildren(ClusterIndex i) const noexcept
    {
        S ret = Descendants(i);
        ret.Reset(i);
        for (auto a : ret) {
            if (ret[a]) {
                ret /= Descendants(a);
                ret.Set(a);
            }
        }
        return ret;
    }

    /** Compute the aggregate feerate of a set of nodes in this graph.
     *
     * Complexity: O(N) where N=elems.Count().
     **/
    FeeFrac FeeRate(const S& elems) const noexcept
    {
        FeeFrac ret;
        for (auto pos : elems) ret += entries[pos].feerate;
        return ret;
    }

    /** Check if this graph is acyclic.
     *
     * Complexity: O(N) where N=TxCount().
     */
    bool IsAcyclic() const noexcept
    {
        for (ClusterIndex i = 0; i < TxCount(); ++i) {
            if ((Ancestors(i) & Descendants(i)) != S::Singleton(i)) {
                return false;
            }
        }
        return true;
    }

    /** Find some connected component within the subset "left" of this graph.
     *
     * Complexity: O(ret.Count()).
     */
    S FindConnectedComponent(const S& left) const noexcept
    {
        if (left.None()) return left;
        auto first = left.First();
        S ret = Descendants(first) | Ancestors(first);
        ret &= left;
        S to_add = ret;
        to_add.Reset(first);
        do {
            S old = ret;
            for (auto add : to_add) {
                ret |= Descendants(add);
                ret |= Ancestors(add);
            }
            ret &= left;
            to_add = ret / old;
        } while (to_add.Any());
        return ret;
    }

    /** Determine if a subset is connected.
     *
     * Complexity: O(subset.Count()).
     */
    bool IsConnected(const S& subset) const noexcept
    {
        return FindConnectedComponent(subset) == subset;
    }

    /** Determine if this entire graph is connected.
     *
     * Complexity: O(TxCount()).
     */
    bool IsConnected() const noexcept { return IsConnected(S::Fill(TxCount())); }

    /** Test whether adding a dependency between parent and child is valid and meaningful.
     *
     * Complexity: O(N^2) where N=TxCount().
     */
    bool CanAddDependency(ClusterIndex parent, ClusterIndex child) const noexcept
    {
        // If child is already a descendant of parent, the dependency would be redundant.
        if (Descendants(parent)[child]) return false;
        // If child is already an ancestor of parent, the dependency would cause a cycle.
        if (Ancestors(parent)[child]) return false;
        // If there is an ancestor of parent which is a direct parent of a descendant of child,
        // that dependency will have been redundant if a dependency between parent and child is
        // added.
        for (auto i : Ancestors(parent)) {
            if (Descendants(i) && Descendants(child)) {
                if (GetReducedChildren(i) && Descendants(child)) return false;
            }
        }
        return true;
    }

    /** Append the entries of select to list in a topologically valid order.
     *
     * Complexity: O(select.Count() * log(select.Count())).
     */
    void AppendTopo(std::vector<ClusterIndex>& list, const S& select) const noexcept
    {
        ClusterIndex old_len = list.size();
        for (auto i : select) list.push_back(i);
        std::sort(list.begin() + old_len, list.end(), [&](ClusterIndex a, ClusterIndex b) noexcept {
            const auto a_anc_size = Ancestors(a).Count();
            const auto b_anc_size = Ancestors(b).Count();
            if (a_anc_size != b_anc_size) return a_anc_size < b_anc_size;
            return a < b;
        });
    }
};

/** Class encapsulating the state needed to find the best remaining ancestor set. */
template<typename S>
class AncestorCandidateFinder
{
    /** Internal dependency graph. */
    const DepGraph<S>& m_depgraph;
    /** Which transaction are left to include. */
    S m_todo;
    /** Precomputed ancestor-set feerates (only kept up-to-date for indices in m_todo). */
    std::vector<FeeFrac> m_ancestor_set_feerates;

public:
    /** Construct an AncestorCandidateFinder for a given cluster.
     *
     * Complexity: O(N^2) where N=depgraph.TxCount().
     */
    AncestorCandidateFinder(const DepGraph<S>& depgraph LIFETIMEBOUND) noexcept :
        m_depgraph(depgraph),
        m_todo{S::Fill(depgraph.TxCount())},
        m_ancestor_set_feerates(depgraph.TxCount())
    {
        // Precompute ancestor-set feerates.
        for (ClusterIndex i = 0; i < depgraph.TxCount(); ++i) {
            S anc_to_add = m_depgraph.Ancestors(i); //!< Remaining ancestors for transaction i.
            FeeFrac anc_feerate;
            // Reuse accumulated feerate from first ancestor, if usable.
            Assume(anc_to_add.Any());
            ClusterIndex first = anc_to_add.First();
            if (first < i) {
                anc_feerate = m_ancestor_set_feerates[first];
                anc_to_add /= m_depgraph.Ancestors(first);
            }
            // Add in other ancestors (which necessarily include i itself).
            Assume(anc_to_add[i]);
            for (ClusterIndex idx : anc_to_add) anc_feerate += m_depgraph.FeeRate(idx);
            // Store the result.
            m_ancestor_set_feerates[i] = anc_feerate;
        }
    }

    /** Remove a set of transactions from the set of to-be-linearized ones.
     *
     * Complexity: O(N*M) where N=depgraph.TxCount(), M=select.Count().
     */
    void MarkDone(S select) noexcept
    {
        select &= m_todo;
        m_todo /= select;
        for (auto i : select) {
            auto feerate = m_depgraph.FeeRate(i);
            for (auto j : m_depgraph.Descendants(i) & m_todo) {
                m_ancestor_set_feerates[j] -= feerate;
            }
        }
    }

    /** Find the best remaining ancestor set. Unlinearized transactions must remain.
     *
     * Complexity: O(N) where N=depgraph.TxCount();
     */
    std::pair<S, FeeFrac> FindCandidateSet() const noexcept
    {
        std::optional<ClusterIndex> best;
        for (auto i : m_todo) {
            if (best.has_value()) {
                if (!(m_ancestor_set_feerates[i] > m_ancestor_set_feerates[*best])) continue;
            }
            best = i;
        }
        Assume(best.has_value());
        return {m_depgraph.Ancestors(*best) & m_todo, m_ancestor_set_feerates[*best]};
    }
};

/** Class encapsulating the state needed to perform search for good candidate sets. */
template<typename S>
class SearchCandidateFinder
{
    /** Internal RNG. */
    InsecureRandomContext m_rng;
    /** m_sorted_to_original[i] is the original position that sorted transaction position i had. */
    std::vector<ClusterIndex> m_sorted_to_original;
    /** m_original_to_sorted[i] is the sorted position original transaction position i has. */
    std::vector<ClusterIndex> m_original_to_sorted;
    /** Internal dependency graph for the cluster (with transactions in decreasing individual
     *  feerate order). */
    DepGraph<S> m_depgraph;
    /** Which transactions are left to do (indices in m_depgraph's sorted order). */
    S m_todo;

    /** Given a set of transactions with sorted indices, get their original indices. */
    S SortedToOriginal(const S& arg) const noexcept
    {
        S ret;
        for (auto pos : arg) ret.Set(m_sorted_to_original[pos]);
        return ret;
    }

    /** Given a set of transactions with original indices, get their sorted indices. */
    S OriginalToSorted(const S& arg) const noexcept
    {
        S ret;
        for (auto pos : arg) ret.Set(m_original_to_sorted[pos]);
        return ret;
    }

public:
    /** Construct a candidate finder for a graph.
     *
     * @param[in] depgraph   Dependency graph for the to-be-linearized cluster.
     * @param[in] rng_seed   A random seed to control the search order.
     *
     * Complexity: O(N^2) where N=depgraph.Count().
     */
    SearchCandidateFinder(const DepGraph<S>& depgraph, uint64_t rng_seed) noexcept :
        m_rng(rng_seed),
        m_sorted_to_original(depgraph.TxCount()),
        m_original_to_sorted(depgraph.TxCount())
    {
        // Determine reordering mapping, by sorting by decreasing feerate.
        std::iota(m_sorted_to_original.begin(), m_sorted_to_original.end(), ClusterIndex{0});
        std::sort(m_sorted_to_original.begin(), m_sorted_to_original.end(), [&](auto a, auto b) {
            auto feerate_cmp = depgraph.FeeRate(a) <=> depgraph.FeeRate(b);
            if (feerate_cmp == 0) return a < b;
            return feerate_cmp > 0;
        });
        // Compute reverse mapping.
        for (ClusterIndex i = 0; i < depgraph.TxCount(); ++i) {
            m_original_to_sorted[m_sorted_to_original[i]] = i;
        }
        // Compute reordered dependency graph.
        m_depgraph = DepGraph(depgraph, m_original_to_sorted);
        // Set todo to the entire graph.
        m_todo = S::Fill(depgraph.TxCount());
    }

    /** Find a high-feerate topologically-valid subset of what remains of the cluster.
     *
     * @param[in,out] iterations_left    On input, an upper bound on the number of optimization
     *                                   steps that can be performed. On output, that number is
     *                                   reduced by the number of actually performed optimization
     *                                   steps.
     * @param[in] best                   A set/feerate pair with an already-known good candidate.
     *                                   This can be empty.
     * @return                           The best (highest feerate, smallest size as tiebreaker)
     *                                   topologically-valid subset of what remains of the cluster
     *                                   that was encountered during search. If iterations_left is
     *                                   nonzero on output, it is the absolute best such subset. If
     *                                   not, the feerate of the returned set will be at least as
     *                                   good as the best passed in.
     *
     * Complexity: possibly O(N * min(iterations_left, sqrt(2^N))) where N=depgraph.TxCount().
     */
    std::pair<S, FeeFrac> FindCandidateSet(uint64_t& iterations_left, std::pair<S, FeeFrac> best) noexcept
    {
        // Bail out quickly if we're given a (remaining) cluster that is empty.
        if (m_todo.None()) return {};

        if (best.second.IsEmpty()) {
            // Set best to the entire remainder if not provided.
            best.first = m_todo;
            best.second = m_depgraph.FeeRate(m_todo);
        } else {
            // Otherwise convert to internal sorted indices.
            best.first = OriginalToSorted(best.first);
        }
        Assume(!best.second.IsEmpty());
        Assume(best.first.Any());
        Assume(best.first << m_todo);

        /** Type for work queue items. */
        struct WorkItem
        {
            /** Set of transactions definitely included. This must be a subset of m_todo, and be
             *  topologically valid (includes all in-m_todo ancestors of itself). */
            S inc;
            /** Set of undecided transactions. This must be a subset of m_todo, and have no overlap
             *  with inc. The set (inc | und) must be topologically valid. */
            S und;
            /** Equal to m_depgraph.FeeRate(inc). */
            FeeFrac inc_feerate;
            /** Construct a new work item. */
            WorkItem(S&& i, S&& u, FeeFrac&& i_f) noexcept :
                inc(std::move(i)), und(std::move(u)), inc_feerate(std::move(i_f)) {}
            /** Swap two WorkItems. */
            void Swap(WorkItem& other) noexcept
            {
                swap(inc, other.inc);
                swap(und, other.und);
                swap(inc_feerate, other.inc_feerate);
            }
        };

        /** The queue of work items. */
        RingBuffer<WorkItem> queue;
        queue.reserve(std::max<size_t>(256, 2 * m_todo.Count()));

        /** Local copy of the iteration limit. */
        uint64_t iteration_limit = iterations_left;

        /** Internal function to add a work item, possibly improving it before doing so.
         *
         * - inc: the "inc" value for the new work item
         * - und: the "und" value for the new work item
         * - inc_feerate: equal to m_depgraph.FeeRate(inc)
         */
        auto add_fn = [&](S inc, S und, FeeFrac inc_feerate) noexcept {
            Assume(inc << m_todo);
            Assume(und << m_todo);
            Assume(!(inc && und));

            if (!inc_feerate.IsEmpty()) {
                // If inc_feerate is better than best_feerate, remember inc as our new best.
                if (inc_feerate > best.second) {
                    best = {inc, inc_feerate};
                }
            }

            // Make sure there are undecided transactions left to split on.
            if (und.None()) return;

            // Actually construct new work item on the queue.
            Assume(queue.size() < queue.capacity());
            queue.emplace_back(std::move(inc), std::move(und), std::move(inc_feerate));
        };

        /** Internal process function. It takes an existing work item, and splits it in two: one
         *  with a particular transaction (and its ancestors) included, and one with that
         *  transaction (and its descendants) excluded. */
        auto split_fn = [&](WorkItem&& elem) noexcept {
            // Any queue element must have undecided transactions left, otherwise there is nothing
            // to explore anymore.
            Assume(elem.und.Any());
            // The included and undecided set are all subsets of m_todo.
            Assume((m_todo >> elem.inc) && (m_todo >> elem.und));
            // Included transactions cannot be undecided.
            Assume(!(elem.inc && elem.und));
            // We must have a non-empty best.
            Assume(!best.second.IsEmpty());

            const ClusterIndex first = elem.und.First();

            // Add a work item corresponding to excluding the first undecided transaction.
            const auto& desc = m_depgraph.Descendants(first);
            add_fn(/*inc=*/elem.inc,
                   /*und=*/elem.und / desc,
                   /*inc_feefrac=*/elem.inc_feerate);

            // Add a work item corresponding to including the first undecided transaction.
            const auto anc = m_depgraph.Ancestors(first) & m_todo;
            const auto new_inc = elem.inc | anc;
            add_fn(/*inc=*/new_inc,
                   /*und=*/elem.und / anc,
                   /*inc_feefrac=*/elem.inc_feerate + m_depgraph.FeeRate(anc / elem.inc));

            // Account for the performed split.
            --iteration_limit;
        };

        // Create initial entries per connected component of m_todo. While clusters themselves are
        // generally connected, this is not necessarily try after some parts have already been
        // removed from m_todo. Without this, effort can be wasted on searching "inc" sets that
        // span multiple components.
        auto to_cover = m_todo;
        do {
            auto component = m_depgraph.FindConnectedComponent(to_cover);
            add_fn(/*inc=*/S{},
                   /*und=*/component,
                   /*inc_feefrac=*/FeeFrac{});
            to_cover /= component;
        } while (to_cover.Any());

        // Work processing loop.
        //
        // New work items are always added at the back of the queue, but items to process use a
        // hybrid approach where they can be taken from the front or the back.
        //
        // Depth-first search (DFS) corresponds to always taking from the back of the queue. This
        // is very memory-efficient (linear in the number of transactions). Breadth-first search
        // (BFS) corresponds to always taking from the front, which potentially uses more memory
        // (up to exponential in the transaction count), but seems to work better in practice.
        //
        // The approach here combines the two: use BFS (plus random swapping) until the queue grows
        // too large, at which point we temporarily switch to DFS until the size shrinks again.
        while (!queue.empty()) {
            // Randomly swap the first two items to randomize the search order.
            if (queue.size() > 1 && m_rng.randbool()) queue[0].Swap(queue[1]);

            // See if processing the first queue item (BFS) is possible without exceeding the queue
            // capacity(), assuming we process the last queue items (DFS) after that.
            const auto queuesize_for_front = queue.capacity() - queue.front().und.Count();
            Assume(queuesize_for_front >= 1);

            // Process entries from the end of the queue (DFS exploration) until it shrinks below
            // queuesize_for_front.
            while (queue.size() > queuesize_for_front) {
                if (!iteration_limit) break;
                auto elem = queue.back();
                queue.pop_back();
                split_fn(std::move(elem));
            }

            // Process one entry from the front of the queue (BFS exploration)
            if (!iteration_limit) break;
            auto elem = queue.front();
            queue.pop_front();
            split_fn(std::move(elem));
        }

        // Return what remains of the iteration limit.
        iterations_left = iteration_limit;
        // Return the found best set, converted to the original transaction indices.
        return {SortedToOriginal(best.first), best.second};
    }

    /** Remove a subset of transactions from the cluster being linearized.
     *
     * Complexity: O(N) where N=done.Count().
     */
    void MarkDone(const S& done) noexcept
    {
        m_todo /= OriginalToSorted(done);
    }
};

/** Improve a linearization of a cluster.
 *
 * @param[in]     depgraph           Dependency graph of the the cluster to be linearized.
 * @param[in,out] iteration_limit    On input, an upper bound on the number of optimization steps
 *                                   that will be performed in order to find a good linearization.
 *                                   On output the number will be reduced by the number of actually
 *                                   performed optimization steps. If that number is nonzero, the
 *                                   linearization is optimal. Otherwise it is at least as good
 *                                   as old_linearization (if provided).
 * @param[in]     rng_seed           A random number seed to control search order.
 * @param[in]     old_linearization  An existing linearization for the cluster, or empty.
 */
template<typename S>
std::vector<ClusterIndex> Linearize(const DepGraph<S>& depgraph, uint64_t& iteration_limit, uint64_t rng_seed, Span<const ClusterIndex> old_linearization = {}) noexcept
{
    std::vector<ClusterIndex> linearization;
    std::vector<std::pair<S, FeeFrac>> chunks;

    AncestorCandidateFinder anc_finder(depgraph);
    SearchCandidateFinder src_finder(depgraph, rng_seed);
    auto todo = S::Fill(depgraph.TxCount());
    linearization.reserve(depgraph.TxCount());
    bool perfect = true;

    while (todo.Any()) {
        // This is an implementation of the (single) LIMO algorithm:
        // https://delvingbitcoin.org/t/limo-combining-the-best-parts-of-linearization-search-and-merging/825
        // where S is instantiated to be the result of a bounded search, which itself is seeded
        // with the best prefix of what remains of the input linearization, or the best ancestor set.

        // First, compute the chunks of the remainder of the old linearization.
        chunks.clear();
        for (auto i : old_linearization) {
            if (todo[i]) {
                std::pair<S, FeeFrac> new_chunk{S::Singleton(i), depgraph.FeeRate(i)};
                while (!chunks.empty() && new_chunk.second >> chunks.back().second) {
                    new_chunk.first |= chunks.back().first;
                    new_chunk.second += chunks.back().second;
                    chunks.pop_back();
                }
                chunks.push_back(std::move(new_chunk));
            }
        }

        // Then initialize best to be either the best ancestor set, or the first chunk.
        auto best = anc_finder.FindCandidateSet();
        if (!chunks.empty() && chunks.front().second > best.second) {
            best = chunks.front();
        }

        // Invoke bounded search to update best, with up to half of our remaining iterations as
        // limit.
        uint64_t iterations = (iteration_limit + 1) / 2;
        iteration_limit -= iterations;
        best = src_finder.FindCandidateSet(iterations, best);
        iteration_limit += iterations;

        if (iterations == 0) {
            perfect = false;
            // If the search result is not (guaranteed to be) optimal, run intersections to make
            // sure we don't pick something that makes us unable to reach further diagram points
            // of the old linearization.
            if (!chunks.empty()) {
                std::pair<S, FeeFrac> acc;
                for (const auto& [chunk, chunk_feerate] : chunks) {
                    S intersect = chunk & best.first;
                    if (intersect.Any()) {
                        acc.first |= intersect;
                        if (acc.first == best.first) break;
                        acc.second += depgraph.FeeRate(intersect);
                        if (acc.second > best.second) {
                            best = acc;
                            break;
                        }
                    }
                }
            }
        }

        // Add to output in topological order.
        depgraph.AppendTopo(linearization, best.first);

        // Update state to reflect best is no longer to be linearization.
        todo /= best.first;
        anc_finder.MarkDone(best.first);
        src_finder.MarkDone(best.first);
    }

    // If we ever hit the local limit for one candidate, the result cannot be guaranteed to be
    // optimal. Indicate this by returning iteration_limit=0.
    if (!perfect) iteration_limit = 0;
    return linearization;
}

/** Compute the chunks for a given linearization. */
template<typename S>
std::vector<FeeFrac> ChunkLinearization(const DepGraph<S>& depgraph, Span<const ClusterIndex> linearization) noexcept
{
    std::vector<FeeFrac> ret;
    for (ClusterIndex i : linearization) {
        /** The new chunk to be added, initially a singleton. */
        auto new_chunk = depgraph.FeeRate(i);
        // As long as the new chunk has a higher feerate than the last chunk so far, absorb it.
        while (!ret.empty() && new_chunk >> ret.back()) {
            new_chunk += ret.back();
            ret.pop_back();
        }
        // Actually move that new chunk into the chunking.
        ret.push_back(std::move(new_chunk));
    }
    return ret;
}

} // namespace cluster_linearize

#endif
