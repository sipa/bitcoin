// Copyright (c) The Bitcoin Core developers
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
#include <deque>

#include <random.h>
#include <util/bitset.h>
#include <util/feefrac.h>
#include <util/ringbuffer.h>

#include <iostream>

namespace clusterlin {

/** Data type to represent cluster input.
 *
 * cluster[i].first is tx_i's fee and size.
 * cluster[i].second[j] is true iff tx_i spends one or more of tx_j's outputs.
 */
template<typename S>
using Cluster = std::vector<std::pair<FeeFrac, S>>;

/** Data type to represent chunkings of clusters.
 *
 * chunking[i].first is the set of transaction indices in chunk number i.
 * chunking[i].second is the combined fee and size of chunk number i.
 */
template<typename S>
using Chunking = std::vector<std::pair<S, FeeFrac>>;

/** Data structure that holds a transaction graph's preprocessed data (fee, size, ancestors,
 *  descendants). */
template<typename S>
class DepGraph
{
public:
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

private:
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

    /** Construct a DepGraph object for ntx transactions, with no dependencies. */
    explicit DepGraph(unsigned ntx) noexcept
    {
        entries.resize(ntx);
        for (unsigned i = 0; i < ntx; ++i) {
            entries[i].ancestors = S::Singleton(i);
            entries[i].descendants = S::Singleton(i);
        }
    }

    /** Construct a DepGraph object given fee/size and (incomplete) ancestry.
     *
     * On input, depdata[i].ancestors is expected to include at least i's direct parents, and
     * possibly other ancestors. depdata[i].descendants can contain any of i's descendants,
     * including none.
     */
    explicit DepGraph(std::vector<Entry> depdata) noexcept : entries(std::move(depdata))
    {
        // Propagate ancestor information.
        for (size_t i = 0; i < entries.size(); ++i) {
            // Make sure transactions are ancestors of themselves.
            entries[i].ancestors.Set(i);
            // At this point, entries[a].ancestors[b] is true iff:
            // - a != b, and b is an ancestor of a and there is a path from a to b through the
            //   subgraph consisting of {a, b} union {0, 1, ..., (i-1)}.
            // - a == b, and b<=i.
            S to_merge = entries[i].ancestors;
            for (size_t j = 0; j < entries.size(); ++j) {
                if (entries[j].ancestors[i]) {
                    entries[j].ancestors |= to_merge;
                }
            }
        }

        // Fill in descendant information.
        for (uint32_t i = 0; i < entries.size(); ++i) {
            for (auto j : entries[i].ancestors) {
                entries[j].descendants.Set(i);
            }
        }
    }

    /** Get the number of transactions in the graph. */
    auto TxCount() const noexcept { return entries.size(); }
    /** Get the feerate of a given transaction i. */
    const FeeFrac& FeeRate(unsigned i) const noexcept { return entries[i].feerate; }
    /** Get the ancestors of a given transaction i. */
    const S& Ancestors(unsigned i) const noexcept { return entries[i].ancestors; }
    /** Get the descendants of a given transaction i. */
    const S& Descendants(unsigned i) const noexcept { return entries[i].descendants; }

    /** Add a new unconnected transaction to this transaction graph (at the end), and return its index. */
    unsigned AddTransaction(const FeeFrac& feefrac) noexcept
    {
        unsigned new_idx = TxCount();
        entries.emplace_back(feefrac, S::Singleton(new_idx), S::Singleton(new_idx));
        return new_idx;
    }

    /** Modify this transaction graph, adding a dependency between a specified parent and child. */
    void AddDependency(unsigned parent, unsigned child) noexcept
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
     *  of ancestors). */
    S GetReducedParents(unsigned i) const noexcept
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
     *  of descendants). */
    S GetReducedChildren(unsigned i) const noexcept
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

    /** Compute the aggregate feerate of a set of nodes in this graph. */
    FeeFrac FeeRate(const S& elems) const noexcept
    {
        FeeFrac ret;
        for (auto pos : elems) ret += entries[pos].feerate;
        return ret;
    }

    /** Check if this graph is acyclic. */
    bool IsAcyclic() const noexcept
    {
        for (size_t i = 0; i < TxCount(); ++i) {
            if ((Ancestors(i) & Descendants(i)) != S::Singleton(i)) {
                return false;
            }
        }
        return true;
    }

    /** Find some connected component within the subset "left" of this graph. */
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

    /** Determine if this entire graph is connected. */
    bool IsConnected() const noexcept
    {
        return FindConnectedComponent(S::Fill(TxCount())) == S::Fill(TxCount());
    }

    /** Test whether adding a dependency between parent and child is valid and meaningful. */
    bool CanAddDependency(unsigned parent, unsigned child) const noexcept
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
};

/*
template<typename S>
std::vector<S> FindKernels(const DepGraph<S>& depgraph)
{
    std::vector<S> ret;

    struct WorkItem
    {
        S inc, exc;

        WorkItem(const S& i, const S& e) noexcept : inc(i), exc(e) {}
    };

    std::vector<WorkItem> queue;
    queue.emplace_back(S{}, S{});
    const S todo = S::Fill(depgraph.TxCount());

    // Create a new WorkItem, starting from given inc/exc, and adding/removing to_add/to_del.
    auto add_fn = [&](S inc, S exc, S to_add, S to_del) noexcept {
        // The out-of-kernel ancestors and descendants.
        S anc, des;
        if (inc.Any()) {
            anc = depgraph.Ancestors(inc.First()) / inc;
            des = depgraph.Descendants(inc.First()) / inc;
        }
        // Add entries to the kernel while there are any.
        while (to_add.Any()) {
            auto add = to_add.First();
            to_add.Reset(add);
            const auto& add_anc = depgraph.Ancestors(add);
            const auto& add_des = depgraph.Descendants(add);
            if (inc.Any()) {
                // For any two transactions in the kernel (one in inc, and add), any ancestor of
                // one that is not an ancestor of both must be part of the kernel (as these two
                // would have distinct out-of-kernel ancestors otherwise).
                to_add |= anc ^ add_anc;
                // Likewise, with descendants.
                to_add |= des ^ add_des;
                to_add /= inc;
                to_add.Reset(add);
            } else {
                // When the first transaction is added to the kernel, reprocess all the previously
                // excluded ones (as these may trigger many more exclusions).
                to_del |= exc;
            }
            inc.Set(add);
            anc = (anc | add_anc) / inc;
            des = (des | add_des) / inc;
            // Abort when inconsistent.
            if ((inc | to_add) && (exc | to_del)) return;
        }
        while (to_del.Any()) {
            auto del = to_del.First();
            to_del.Reset(del);
            exc.Set(del);
            const auto& del_anc = depgraph.Ancestors(del);
            const auto& del_des = depgraph.Descendants(del);
            if (del_des && inc) {
                to_del |= todo / del_des;
            } else if (del_anc && inc) {
                to_del |= todo / del_anc;
            } else {
                to_del |= del_anc & anc;
                to_del |= del_des & des;
            }
            to_del /= exc;
            if (inc && (exc | to_del)) return;
        }
        queue.emplace_back(inc, exc);
    };

    while (!queue.empty()) {
        S inc = std::move(queue.back().inc);
        S exc = std::move(queue.back().exc);
        queue.pop_back();

        auto left = (todo / (inc | exc));

        std::optional<unsigned> split;
        if (left.Any()) {
            if (inc.Any()) {
                unsigned first = inc.First();
                S cand = (depgraph.Descendants(first) | depgraph.Ancestors(first)) & left;
                if (cand.Any()) {
                    split = cand.First();
                }
            } else {
                split = left.First();
            }
        }

        if (!split.has_value()) {
            if (inc != todo && inc.Count() > 1) {
                ret.push_back(inc);
            }
            continue;
        }

        // Construct work item with split included.
        add_fn(inc, exc, S::Singleton(*split), {});

        // Construct work item with split excluded.
        add_fn(inc, exc, {}, S::Singleton(*split));
    }

    std::sort(ret.begin(), ret.end());
    return ret;
}
*/

template<typename S>
class Linearizer
{
    /** Internal RNG. */
    InsecureRandomContext m_rng;
    /** Internal dependency graph for the cluster (with transactions in decreasing individual
     *  feerate order). */
    DepGraph<S> m_depgraph;
    /** m_sorted_to_original[i] is the original position that sorted transaction position i had. */
    std::vector<uint32_t> m_sorted_to_original;
    /** m_original_to_sorted[i] is the sorted position original transaction position i has. */
    std::vector<uint32_t> m_original_to_sorted;
    /** Which transactions are left to do (sorted indices). */
    S m_todo;
    /** Precomputed ancestor feerates. If i is in m_todo, then m_ancestor_feefrac[i] =
     *  m_depgraph.FeeFrac(m_depgraph.Ancestors(i) & m_todo). */
    std::vector<FeeFrac> m_ancestor_feefrac;

    /** Given a set of transactions (in sorted order), get their original positions. */
    S SortedToOriginal(const S& arg) const noexcept
    {
        S ret;
        for (auto pos : arg) ret.Set(m_sorted_to_original[pos]);
        return ret;
    }

    /** Given a set of transactions (in original order), get their sorted positions. */
    S OriginalToSorted(const S& arg) const noexcept
    {
        S ret;
        for (auto pos : arg) ret.Set(m_original_to_sorted[pos]);
        return ret;
    }

public:
    /** Construct a linearizer from a Cluster. */
    Linearizer(const Cluster<S>& cluster, uint64_t rng_seed) :
        m_rng(rng_seed),
        m_sorted_to_original(cluster.size()),
        m_original_to_sorted(cluster.size()),
        m_ancestor_feefrac(cluster.size())
    {
        // Determine reordering mapping, by sorting by decreasing feerate.
        std::iota(m_sorted_to_original.begin(), m_sorted_to_original.end(), uint32_t{0});
        std::sort(m_sorted_to_original.begin(), m_sorted_to_original.end(), [&](uint32_t a, uint32_t b) {
            auto feerate_cmp = cluster[a].first <=> cluster[b].first;
            if (feerate_cmp == 0) return a < b;
            return feerate_cmp > 0;
        });
        // Compute reverse mapping.
        for (size_t i = 0; i < cluster.size(); ++i) {
            m_original_to_sorted[m_sorted_to_original[i]] = i;
        }
        // Construct initial txdata (with ancestors set to direct parents).
        std::vector<typename DepGraph<S>::Entry> txdata(cluster.size());
        for (size_t i = 0; i < cluster.size(); ++i) {
            const auto& cluster_entry = cluster[m_sorted_to_original[i]];
            txdata[i].feerate = cluster_entry.first;
            txdata[i].ancestors = OriginalToSorted(cluster_entry.second);
        }
        // Convert to full dependency graph.
        m_depgraph = DepGraph<S>(std::move(txdata));
        // Set todo to the entire cluster.
        m_todo = S::Fill(cluster.size());
        // Precompute ancestor feefracs.
        for (size_t i = 0; i < cluster.size(); ++i) {
            m_ancestor_feefrac[i] = m_depgraph.FeeRate(m_depgraph.Ancestors(i));
        }
    }

    /** Find a high-feerate topologically-valid subset of what remains of the cluster.
     *
     * @param[in,out] iterations_left    On input, an upper bound on the number of optimization
     *                                   steps that can be performed. On output, that number is
     *                                   reduced by the number of actually performed optimization
     *                                   steps.
     * @return                           The best (highest feerate, smallest size as tiebreaker)
     *                                   topologically-valid subset of what remains of the cluster
     *                                   that was encountered during search. If iterations_left is
     *                                   nonzero on output, it is the absolute best such subset. If
     *                                   not, the feerate of the returned set will be at least as
     *                                   good as the best remaining ancestor set.
     */
    S FindCandidateSet(uint64_t& iterations_left) noexcept
    {
        // Bail out quickly if we're given a (remaining) cluster that is empty.
        if (m_todo.None()) return {};

        /** Type for work queue items. */
        struct WorkItem
        {
            /** Set of transactions definitely included. This must be a subset of m_todo, and be
             *  topologically valid (includes all in-m_todo ancestors of itself). */
            S inc;
            /** Set of undecided transactions. This must be a subset of m_todo, and have no overlap
             *  with inc. The set (inc | und) must be topologically valid. */
            S und;
            /** The best (=highest feerate, and smallest as tiebreaker) superset of inc and subset
             *  of (inc | und). It does not need to be topologically valid. If inc is empty then
             *  pot must be empty too (to guarantee the property that every element of (pot / inc)
             *  has higher feerate than pot itself, see further). */
            S pot;
            /** Equal to m_depgraph.FeeRate(inc). */
            FeeFrac inc_feerate;
            /** Equal to m_depgraph.FeeRate(pot). */
            FeeFrac pot_feerate;
            /** Construct a new work item. */
            WorkItem(S&& i, S&& u, S&& p, FeeFrac&& i_f, FeeFrac&& p_f) noexcept :
                inc(std::move(i)), und(std::move(u)), pot(std::move(p)),
                inc_feerate(std::move(i_f)), pot_feerate(std::move(p_f)) {}
            /** Swap two WorkItems. */
            void Swap(WorkItem& other) noexcept
            {
                swap(inc, other.inc);
                swap(und, other.und);
                swap(pot, other.pot);
                swap(inc_feerate, other.inc_feerate);
                swap(pot_feerate, other.pot_feerate);
            }
        };

        /** The queue of work items. */
        RingBuffer<WorkItem> queue;
        queue.reserve(std::max<size_t>(256, 2 * m_todo.Count()));

        /** The best candidate set found so far (initialized in component-finding below). */
        S best;
        /** The feerate of best_candidate. */
        FeeFrac best_feerate;

        /** The set of transactions in m_todo which have feerate > best_feerate.
         *  If best_feerate.IsEmpty(), this contains the entire cluster. */
        S imp = m_todo;

        /** Local copy of the iteration limit. */
        uint64_t iteration_limit = iterations_left;

        /** Internal function to add a work item, possibly improving it before doing so.
         *
         * - inc: the "inc" value for the new work item
         * - und: the "und" value for the new work item
         * - pot: a subset of the "pot" value for the new work item (but a superset of inc).
         *        Missing transactions will be added automatically by add_fn.
         * - inc_feerate: equal to m_depgraph.FeeRate(inc)
         * - pot_feerate: equal to m_depgraph.FeeRate(pot)
         * - consider_inc: a subset of (pot / inc) of transactions to consider adding to inc, if it
         *                 can be proven they must be part of the best topologically valid superset
         *                 of inc and subset of (inc | und). Transactions that are missing from
         *                 pot are automatically considered for addition to inc.
         */
        auto add_fn = [&](S inc, S und, S pot, FeeFrac inc_feerate, FeeFrac pot_feerate, S consider_inc) noexcept {
            Assume(inc << m_todo);
            Assume(und << m_todo);
            Assume(!(inc && und));
            Assume(pot >> inc);
            Assume(pot << (inc | und));
            Assume(pot.None() == inc.None());
            Assume(consider_inc << (pot / inc));

            if (inc_feerate.IsEmpty()) {
                // If inc is empty, we leave pot/pot_feerate empty too, and don't compare it with
                // best_feerate (see split_fn); instead, just make sure there are undecided
                // transactions left to split on.
                if (und.None()) return;
            } else {
                // Add missing entries to pot (and pot_feerate). We iterate over all undecided transactions
                // excluding pot whose feerate is higher than best_feerate.
                for (auto pos : (imp & und) / pot) {
                    // Determine if adding transaction pos to pot (ignoring topology) would improve it. If
                    // not, we're done updating pot.
                    if (!(m_depgraph.FeeRate(pos) >> pot_feerate)) break;
                    pot_feerate += m_depgraph.FeeRate(pos);
                    pot.Set(pos);
                    consider_inc.Set(pos);
                }

                // The "jump ahead" optimization:
                //
                // Let S be the set of sets T of transactions for which T is topologically valid, T
                // is a superset of inc and T is a subset of (inc | und). In other words, S
                // contains all possible "inc"s compatible with the work item currently being added.
                //
                // Let B be the best element of S, so B is the highest-feerate (tie-breaking using
                // smallest size) inc compatible with the work item being added.
                //
                // It now holds that any topologically-valid subset of pot must be a subset of B.
                // To see why:
                // - Every element of (pot / inc) has a feerate higher than any element of S:
                //   - The feerate of every element of (pot / inc) is strictly higher than that of
                //     pot in its entirety. This clearly holds for the last item added to it (or it
                //     would not have been added), and all earlier items have a feerate at least as
                //     high as the last-added one.
                //   - Every element of (pot / inc) has a feerate strictly higher than inc in its
                //     entirety. This follows from the previous point and the fact that inc is not
                //     empty.
                //   - The feerate of every element of (und / pot) is less or equal to that of pot.
                //     Otherwise the first one of them would have been added to pot.
                //   - All together, elements of (pot / inc) have higher feerate than inc, and thus
                //     also higher feerate than inc completement with any subset of (und / inc).
                // - Thus, for any element T of S, adding any non-empty subset of (pot / T) to it
                //   strictly increases its feerate.
                // - No set C which is a topologically valid subset of pot can exist which is not
                //   also a subset of B.
                //   - B and C are both topologically valid, thus (B | C) is also topologically
                //     valid.
                //   - (C / B) is non-empty (because C is not a subset of B), and a subset of
                //     (pot / B), thus from the previous point it follows that (C / B) has higher
                //     feerate than B.
                //   - Thus, (B | C) is topologically valid and has a higher feerate than B. This
                //     is in contradiction with the fact that B is the highest-feerate element of
                //     S.
                //
                // As a result we can look for topologically valid subsets of pot that are not
                // subsets of inc, and union them into inc. We do so by checking the ancestry of
                // any element of consider_inc.
                const S init_inc = inc;
                for (auto pos : consider_inc) {
                    // If the transaction's ancestors are a subset of pot, we can merge it
                    // together with its ancestors to inc.
                    auto anc_todo = m_depgraph.Ancestors(pos) & m_todo;
                    if (pot >> anc_todo) inc |= anc_todo;
                }
                // Finally update und and inc_feerate to account for the added transactions.
                und /= inc;
                inc_feerate += m_depgraph.FeeRate(inc / init_inc);

                // If inc_feerate is better than best_feerate, remember inc as our new best.
                if (best_feerate.IsEmpty() || inc_feerate > best_feerate) {
                    best_feerate = inc_feerate;
                    best = inc;
                    // See if we can remove any entries from imp now.
                    while (imp.Any()) {
                        unsigned check = imp.Last();
                        if (m_depgraph.FeeRate(check) >> best_feerate) break;
                        imp.Reset(check);
                    }
                }

                // If no potential transactions exist beyond the already included ones, no improvement
                // is possible anymore.
                if (pot == inc) return;
                // At this point und must be non-empty. If it were empty then pot would equal inc.
                Assume(und.Any());
            }

            // Actually construct new work item on the queue.
            Assume(queue.size() < queue.capacity());
            queue.emplace_back(std::move(inc), std::move(und), std::move(pot), std::move(inc_feerate), std::move(pot_feerate));
        };

        /** Internal process function. It takes an existing work item, and splits it in two: one
         *  with a particular transaction (and its ancestors) included, and one with that
         *  transaction (and its descendants) excluded. */
        auto split_fn = [&](WorkItem&& elem) noexcept {
            // Any queue element must have undecided transactions left, otherwise there is nothing
            // to explore anymore.
            Assume(elem.und.Any());
            // The potential set must include the included set, and be a subset of (und | inc).
            Assume((elem.pot >> elem.inc) && (elem.pot << (elem.und | elem.inc)));
            // The potential, undecided, and (implicitly) included set are all subsets of m_todo.
            Assume((m_todo >> elem.pot) && (m_todo >> elem.und));
            // Included transactions cannot be undecided.
            Assume(!(elem.inc && elem.und));
            // If pot is empty, then so is inc.
            Assume(elem.inc_feerate.IsEmpty() == elem.pot_feerate.IsEmpty());
            // We must have a non-empty best at this point (added by add_fn, called for the
            // inclusion of the best ancestor set of at least one component of m_todo).
            Assume(!best_feerate.IsEmpty());

            // We can ignore any queue item whose potential feerate isn't better than the best seen
            // so far.
            const unsigned first = elem.und.First();
            if (!elem.pot_feerate.IsEmpty()) {
                if (elem.pot_feerate <= best_feerate) return;
            } else {
                // In case inc/pot are empty, use a simpler alternative check.
                if (m_depgraph.FeeRate(first) <= best_feerate) return;
            }

            // Decide which transaction to split on. Splitting is how new work items are added, and
            // how progress is made. One pivot transaction is chosen among the queue item's
            // undecided ones, and:
            // - A work item is (potentially) added with that transaction plus its remaining
            //   descendands excluded (removed from the und set).
            // - A work item is (potentially) added with that transaction plus its remaining
            //   ancestors included (added to the inc set).
            //
            // To decide the pivot, pick among the undecided ancestors of the highest individual
            // feerate transaction among the undecided ones the one which reduces the search space
            // most:
            // - Minimizes the size of the largest of the undecided sets after including or
            //   excluding.
            // - If the above is equal, the one that minimizes the other branch's undecided set
            //   size.
            // - If the above are equal, the one with the best individual feerate.
            unsigned pivot = 0;
            const auto select = elem.und & m_depgraph.Ancestors(first);
            Assume(select.Any());
            std::optional<std::pair<unsigned, unsigned>> pivot_counts;
            for (auto i : select) {
                std::pair<unsigned, unsigned> counts{
                    (elem.und / m_depgraph.Ancestors(i)).Count(),
                    (elem.und / m_depgraph.Descendants(i)).Count()};
                if (counts.first < counts.second) std::swap(counts.first, counts.second);
                if (!pivot_counts.has_value() || counts < *pivot_counts) {
                    pivot = i;
                    pivot_counts = counts;
                }
            }
            // Since there was at least one transaction in select, we must always find one.
            Assume(pivot_counts.has_value());

            // Consider adding a work item corresponding to that transaction excluded.
            const auto& desc = m_depgraph.Descendants(pivot);
            add_fn(/*inc=*/elem.inc,
                   /*und=*/elem.und / desc,
                   /*pot=*/elem.pot / desc,
                   /*inc_feefrac=*/elem.inc_feerate,
                   /*pot_feefrac=*/elem.pot_feerate - m_depgraph.FeeRate(elem.pot & desc),
                   /*consider_inc=*/{});

            // Consider adding a work item corresponding to that transaction included.
            const auto anc = m_depgraph.Ancestors(pivot) & m_todo;
            const auto new_inc = elem.inc | anc;
            add_fn(/*inc=*/new_inc,
                   /*und=*/elem.und / anc,
                   /*pot=*/elem.pot | anc,
                   /*inc_feefrac=*/elem.inc_feerate + m_depgraph.FeeRate(anc / elem.inc),
                   /*pot_feefrac=*/elem.pot_feerate + m_depgraph.FeeRate(anc / elem.pot),
                   /*consider_inc=*/elem.pot / new_inc);

            // Account for the performed split.
            --iteration_limit;
        };

        // Create initial entries per connected component of m_todo.
        auto to_cover = m_todo;
        do {
            auto component = m_depgraph.FindConnectedComponent(to_cover);
            to_cover /= component;
            // Find transaction with highest ancestor feerate within the component.
            std::optional<unsigned> best_ancestor_idx;
            for (auto i : component) {
                if (!best_ancestor_idx.has_value() || m_ancestor_feefrac[i] > m_ancestor_feefrac[*best_ancestor_idx]) {
                    best_ancestor_idx = i;
                }
            }
            // For each component, consider adding two work entries: one with the highest ancestor
            // feerate transaction excluded, one with it included, effectively pre-splitting each
            // component once. With this, the found candidate set will always have a feerate at
            // least equal to the highest ancestor feerate.
            auto best_ancestor_set = m_depgraph.Ancestors(*best_ancestor_idx) & m_todo;
            Assume(best_ancestor_set << component);
            add_fn(/*inc=*/S{},
                   /*und=*/component / m_depgraph.Descendants(*best_ancestor_idx),
                   /*pot=*/S{},
                   /*inc_feefrac=*/FeeFrac{},
                   /*pot_feefrac=*/FeeFrac{},
                   /*consider_inc=*/S{});
            add_fn(/*inc=*/best_ancestor_set,
                   /*und=*/component / best_ancestor_set,
                   /*pot=*/best_ancestor_set,
                   /*inc_feefrac=*/m_ancestor_feefrac[*best_ancestor_idx],
                   /*pot_feefrac=*/m_ancestor_feefrac[*best_ancestor_idx],
                   /*consider_inc=*/S{});
        } while (to_cover.Any());

        // Work processing loop.
        //
        // New work items are always added at the back of the queue, but items to process use a
        // hybrid approach where they can be taken from the front or the back.
        //
        // If they would always be taken from the back, we would effectively be performing a
        // depth-first traversal of the search tree (DFS). This has the advantage of using very
        // little memory (the number of queue items equals the depth in the search tree, and thus
        // cannot exceed the number of transactions in the cluster).
        //
        // If they would allways be taken from the front, we would effectively be performing a
        // breadth-first travel of the search tree (BFS). This uses far more memory (exponential
        // in the cluster size), but has the advantage of maximizing the time items spend in the
        // queue. This is beneficial, because any improvements to best_feerate between adding and
        // processing of a queue item reduces the computational cost of processing the item (it
        // may be dropped due to pot_feerate <= best_feefrac, and imp may shrink).
        //
        // The approach here combines the two: it generally follows a BFS-like approach, until the
        // queue grows too large, at which point we temporarily switch to DFS until the size
        // shrinks again.
        while (!queue.empty()) {
            // Randomly swap the first two items to provide unpredictability.
            if (queue.size() > 1 && m_rng.randbool()) queue[0].Swap(queue[1]);

            // We prefer processing the current first queue item as it results in BFS-like behavior.
            // If we were to do that, one item would be removed from the queue and up to two would
            // be added, a net increment of 1. Those newly added elements can then be processed
            // in DFS order, which would add up to as many elements to the queue as undecided
            // transactions left (which is at least 1 less than the undecided size of the current
            // first item). Putting that together, the current first queue item can always be
            // processed by adding no more elements as there are in its undecided set. Use this to
            // compute how small the queue can get before we can safely process the front.
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
        // Return the found best set, converted to the original transaction order.
        return SortedToOriginal(best);
    }

    /** Remove a subset of transactions from the cluster being linearized. */
    void RemoveTransactions(const S& done) noexcept
    {
        auto internal_done = OriginalToSorted(done) & m_todo;
        m_todo /= internal_done;
        for (auto i : internal_done) {
            FeeFrac feefrac = m_depgraph.FeeRate(i);
            for (auto desc : m_depgraph.Descendants(i) & m_todo) {
                m_ancestor_feefrac[desc] -= feefrac;
            }
        }
    }

    /** Get the set of remaining transactions in the cluster. */
    S GetTodo() const noexcept
    {
        return SortedToOriginal(m_todo);
    }

    /** Return whether no transactions remain in the cluster. */
    bool IsEmpty() const noexcept
    {
        return m_todo.None();
    }

    /** Append the entries of select to list in a topologically valid order. */
    void AppendTopo(std::vector<unsigned>& list, const S& select) const noexcept
    {
        auto old_len = list.size();
        for (auto i : select) list.push_back(i);
        std::sort(list.begin() + old_len, list.end(), [&](unsigned a, unsigned b) noexcept {
            const auto a_anc_size = m_depgraph.Ancestors(m_original_to_sorted[a]).Count();
            const auto b_anc_size = m_depgraph.Ancestors(m_original_to_sorted[b]).Count();
            if (a_anc_size != b_anc_size) return a_anc_size < b_anc_size;
            return a < b;
        });
    }
};

/** Construct a topologically valid linearization of a cluster.
 *
 * @param[in]     cluster            The cluster to be linearized.
 * @param[in,out] iteration_limit    On input, an upper bound on the number of optimization steps
 *                                   that will be performed in order to find a good linearization.
 *                                   On output the number will be reduced by the number of actually
 *                                   performed optimization steps. If that number is nonzero, the
 *                                   linearization is optimal. Otherwise it is at least as good as
 *                                   a linearization obtained by concatenating the best (remaining)
 *                                   ancestor sets.
 * @param[in]     rng_seed           A random number seed to tweak the operation with.
 * @return                           A vector with indices into cluster in linearized order.
 */
template<typename S>
std::vector<unsigned> Linearize(const Cluster<S>& cluster, uint64_t& iteration_limit, uint64_t rng_seed) noexcept
{
    Linearizer linearizer(cluster, rng_seed);
    std::vector<unsigned> ret;
    ret.reserve(cluster.size());
    bool hit_limit = false;
    while (!linearizer.IsEmpty()) {
        // Move 50% of the remaining iterations from iteration_limit to local_limit.
        uint64_t local_limit = iteration_limit >> 1;
        iteration_limit -= local_limit;
        // Invoke candidate-finding algorithm.
        auto candidate = linearizer.FindCandidateSet(local_limit);
        // Move unused iterations back to overall limit.
        iteration_limit += local_limit;
        if (!local_limit) hit_limit = true;
        // Append candidate set to result, and remove from linearizer.
        linearizer.AppendTopo(ret, candidate);
        linearizer.RemoveTransactions(candidate);
    }
    // If we ever hit the local limit for one candidate, the result cannot be guaranteed to be
    // optimal. Indicate this by returning iteration_limit=0.
    if (hit_limit) iteration_limit = 0;
    return ret;
}

/** Construct a Chunking for a given linearization. */
template<typename S>
Chunking<S> ChunkLinearization(const Cluster<S>& cluster, Span<const unsigned> linearization) noexcept
{
    Chunking<S> ret;
    for (unsigned i : linearization) {
        /** The new chunk to be added, initially a singleton. */
        std::pair<S, FeeFrac> new_chunk{S::Singleton(i), cluster[i].first};
        // As long as the new chunk has a higher feerate than the last chunk so far, absorb it.
        while (!ret.empty() && new_chunk.second >> ret.back().second) {
            new_chunk.first |= ret.back().first;
            new_chunk.second += ret.back().second;
            ret.pop_back();
        }
        // Actually move that new chunk into the chunking.
        ret.push_back(std::move(new_chunk));
    }
    return ret;
}

/** Perform a diagram comparison between two chunkings. */
template<typename S>
std::partial_ordering CompareChunkings(const Chunking<S>& chunking0, const Chunking<S>& chunking1) noexcept
{
    return CompareChunks(chunking0, chunking1, [](const auto& arg) noexcept { return arg.second; });
}

} // namespace clusterlin

#endif
