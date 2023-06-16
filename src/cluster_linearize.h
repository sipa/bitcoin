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

#include <util/bitset.h>
#include <util/feefrac.h>

#include <assert.h>

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

    std::vector<std::tuple<size_t, size_t, FeeFrac>> intermediate;
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

public:
    /** Construct a precomputed AncestorSetFeeFracs object for given cluster/done. */
    explicit AncestorSetFeeFracs(const Cluster<S>& cluster, const AncestorSets<S>& anc, const S& done) noexcept
    {
        m_anc_feefracs.resize(cluster.size());
        for (unsigned i = 0; i < cluster.size(); ++i) {
            if (!done[i]) {
                m_anc_feefracs[i] = ComputeSetFeeFrac(cluster, anc[i] / done);
            }
        }
    }

    /** Update the precomputed data structure to reflect that new_done was added to done. */
    void Done(const Cluster<S>& cluster, const DescendantSets<S>& desc, const S& new_done) noexcept
    {
        for (unsigned pos : new_done) {
            FeeFrac feefrac = cluster[pos].first;
            for (unsigned i : desc[pos] / new_done) {
                m_anc_feefracs[i] -= feefrac;
            }
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
CandidateSetAnalysis<S> FindBestAncestorSet(const Cluster<S>& cluster, const AncestorSets<S>& anc, const AncestorSetFeeFracs<S>& anc_feefracs, const S& done)
{
    CandidateSetAnalysis<S> ret;
    ret.max_queue_size = 1;

    for (size_t i = 0; i < cluster.size(); ++i) {
        if (done[i]) continue;
        ++ret.iterations;
        ++ret.num_candidate_sets;
        const FeeFrac& feefrac = anc_feefracs[i];
        assert(!feefrac.IsEmpty());
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

enum class QueueStyle {
    DFS,
    DFS_EXC,
    RANDOM,
    MOST_ADVANCED_BEST_POTENTIAL_FEEFRAC,
    LEAST_ADVANCED_BEST_POTENTIAL_FEEFRAC,
    MOST_LEFT_BEST_POTENTIAL_FEEFRAC,
    LEAST_LEFT_BEST_POTENTIAL_FEEFRAC,
    MOST_INC_BEST_POTENTIAL_FEEFRAC,
    LEAST_INC_BEST_POTENTIAL_FEEFRAC,
    LEAST_COVER,
    BEST_ACHIEVED_FEEFRAC,
    HIGHEST_ACHIEVED_FEE,
    HIGHEST_ACHIEVED_SIZE,
    BEST_POTENTIAL_FEEFRAC,
    HIGHEST_POTENTIAL_FEE,
    HIGHEST_POTENTIAL_SIZE,
    BEST_GAIN_FEEFRAC,
    HIGHEST_GAIN_FEE,
    HIGHEST_GAIN_SIZE,
    WORST_ACHIEVED_FEEFRAC,
    LOWEST_ACHIEVED_FEE,
    LOWEST_ACHIEVED_SIZE,
    WORST_POTENTIAL_FEEFRAC,
    LOWEST_POTENTIAL_FEE,
    LOWEST_POTENTIAL_SIZE,
    WORST_GAIN_FEEFRAC,
    LOWEST_GAIN_FEE,
    LOWEST_GAIN_SIZE,
};

/** An efficient algorithm for finding the best candidate set. Believed to be O(~1.6^n).
 *
 * cluster must be sorted (see SortedCluster) by individual feerate, and anc/desc/done must use
 * the same indexing as cluster.
 */
template<QueueStyle QS, bool Intermediate = false, typename S = void, typename RNG = void>
CandidateSetAnalysis<S> FindBestCandidateSetEfficient(const Cluster<S>& cluster, const AncestorSets<S>& anc, const DescendantSets<S>& desc, const AncestorSetFeeFracs<S>& anc_feefracs, const S& done, RNG&& rng)
{
    // Queue of work units. Each consists of:
    // - inc: bitset of transactions definitely included (always includes done)
    // - exc: bitset of transactions definitely excluded
    // - pot: bitset of the best-FeeFrac subset of transactions including inc and excluding exc
    //        (ignoring topology).
    // - inc_feefrac: the FeeFrac of (included / done)
    // - pot_feefrac: the FeeFrac of (pot / done)
    using QueueElem = std::tuple<S, S, S, FeeFrac, FeeFrac>;
    std::vector<QueueElem> queue;

    CandidateSetAnalysis<S> ret;

    // Compute "all" set, with all the cluster's transaction.
    S all = S::Fill(cluster.size());
    if (done == all) return ret;
    assert(all.Count() == cluster.size());

    auto queue_cmp_fn = [&](const QueueElem& a, const QueueElem& b) {
        if constexpr (QS == QueueStyle::BEST_ACHIEVED_FEEFRAC) {
            return std::get<3>(b) > std::get<3>(a);
        } else if constexpr (QS == QueueStyle::HIGHEST_ACHIEVED_FEE) {
            return std::get<3>(b).fee > std::get<3>(a).fee;
        } else if constexpr (QS == QueueStyle::HIGHEST_ACHIEVED_SIZE) {
            return std::get<3>(b).size > std::get<3>(a).size;
        } else if constexpr (QS == QueueStyle::BEST_POTENTIAL_FEEFRAC) {
            return std::get<4>(b) > std::get<4>(a);
        } else if constexpr (QS == QueueStyle::HIGHEST_POTENTIAL_FEE) {
            return std::get<4>(b).fee > std::get<4>(a).fee;
        } else if constexpr (QS == QueueStyle::HIGHEST_POTENTIAL_SIZE) {
            return std::get<4>(b).size > std::get<4>(a).size;
        } else if constexpr (QS == QueueStyle::BEST_GAIN_FEEFRAC) {
            auto gain_a = std::get<4>(a) - std::get<3>(a);
            auto gain_b = std::get<4>(b) - std::get<3>(b);
            return gain_b > gain_a;
        } else if constexpr (QS == QueueStyle::HIGHEST_GAIN_FEE) {
            return std::get<4>(b).fee + std::get<3>(a).fee > std::get<4>(a).fee + std::get<3>(b).fee;
        } else if constexpr (QS == QueueStyle::HIGHEST_GAIN_SIZE) {
            return std::get<4>(b).size + std::get<3>(a).size > std::get<4>(a).size + std::get<3>(b).size;
        } else if constexpr (QS == QueueStyle::WORST_ACHIEVED_FEEFRAC) {
            return std::get<3>(a) > std::get<3>(b);
        } else if constexpr (QS == QueueStyle::LOWEST_ACHIEVED_FEE) {
            return std::get<3>(a).fee > std::get<3>(b).fee;
        } else if constexpr (QS == QueueStyle::LOWEST_ACHIEVED_SIZE) {
            return std::get<3>(a).size > std::get<3>(b).size;
        } else if constexpr (QS == QueueStyle::WORST_POTENTIAL_FEEFRAC) {
            return std::get<4>(a) > std::get<4>(b);
        } else if constexpr (QS == QueueStyle::LOWEST_POTENTIAL_FEE) {
            return std::get<4>(a).fee > std::get<4>(b).fee;
        } else if constexpr (QS == QueueStyle::LOWEST_POTENTIAL_SIZE) {
            return std::get<4>(a).size > std::get<4>(b).size;
        } else if constexpr (QS == QueueStyle::WORST_GAIN_FEEFRAC) {
            auto gain_a = std::get<4>(a) - std::get<3>(a);
            auto gain_b = std::get<4>(b) - std::get<3>(b);
            return gain_a > gain_b;
        } else if constexpr (QS == QueueStyle::LOWEST_GAIN_FEE) {
            return std::get<4>(a).fee + std::get<3>(b).fee > std::get<4>(b).fee + std::get<3>(a).fee;
        } else if constexpr (QS == QueueStyle::LOWEST_GAIN_SIZE) {
            return std::get<4>(a).size + std::get<3>(b).size > std::get<4>(b).size + std::get<3>(a).size;
        } else if constexpr (QS == QueueStyle::MOST_ADVANCED_BEST_POTENTIAL_FEEFRAC) {
            unsigned adv_a = (all / (std::get<0>(a) | std::get<1>(a))).First();
            unsigned adv_b = (all / (std::get<0>(b) | std::get<1>(b))).First();
            if (adv_a != adv_b) return adv_a < adv_b;
            return std::get<4>(b) > std::get<4>(a);
        } else if constexpr (QS == QueueStyle::LEAST_ADVANCED_BEST_POTENTIAL_FEEFRAC) {
            unsigned adv_a = (all / (std::get<0>(a) | std::get<1>(a))).First();
            unsigned adv_b = (all / (std::get<0>(b) | std::get<1>(b))).First();
            if (adv_a != adv_b) return adv_a > adv_b;
            return std::get<4>(b) > std::get<4>(a);
        } else if constexpr (QS == QueueStyle::MOST_LEFT_BEST_POTENTIAL_FEEFRAC) {
            unsigned left_a = (all / (std::get<0>(a) | std::get<1>(a))).Count();
            unsigned left_b = (all / (std::get<0>(b) | std::get<1>(b))).Count();
            if (left_a != left_b) return left_a < left_b;
            return std::get<4>(b) > std::get<4>(a);
        } else if constexpr (QS == QueueStyle::LEAST_LEFT_BEST_POTENTIAL_FEEFRAC) {
            unsigned left_a = (all / (std::get<0>(a) | std::get<1>(a))).Count();
            unsigned left_b = (all / (std::get<0>(b) | std::get<1>(b))).Count();
            if (left_a != left_b) return left_a > left_b;
            return std::get<4>(b) > std::get<4>(a);
        } else if constexpr (QS == QueueStyle::MOST_INC_BEST_POTENTIAL_FEEFRAC) {
            unsigned inc_a = std::get<0>(a).Count();
            unsigned inc_b = std::get<0>(b).Count();
            if (inc_a != inc_b) return inc_a < inc_b;
            return std::get<4>(b) > std::get<4>(a);
        } else if constexpr (QS == QueueStyle::LEAST_INC_BEST_POTENTIAL_FEEFRAC) {
            unsigned inc_a = std::get<0>(a).Count();
            unsigned inc_b = std::get<0>(b).Count();
            if (inc_a != inc_b) return inc_a > inc_b;
            return std::get<4>(b) > std::get<4>(a);
        } else if constexpr (QS == QueueStyle::LEAST_COVER) {
            auto cover_fn = [&](const S& s) -> unsigned {
                S parents;
                for (unsigned i : s) parents |= cluster[i].second;
                return (s / parents).Count();
            };
            unsigned cov_a = cover_fn(std::get<0>(a) / done);
            unsigned cov_b = cover_fn(std::get<0>(b) / done);
            return cov_a > cov_b;
        } else {
            return false;
        }
    };

    S best_candidate;
    FeeFrac best_feefrac;

    // Internal add function. Arguments:
    // - inc: new included set of transactions
    // - exc: new excluded set of transactions
    // - inc_feefrac: feerate of (inc / done)
    // - inc_may_be_best: whether inc_feerate could be better than best_feerate
    // - pot_known: pointer to the pot of the new item, if known, nullptr otherwise.
    auto add_fn = [&](S inc, S exc, FeeFrac inc_feefrac, bool inc_may_be_best, const S* pot_known) -> bool {
        // In the loop below, we do two things simultaneously:
        // - compute the pot_feefrac for the new queue item.
        // - perform "jump ahead", which may add additional transactions to inc
        /** The new potential feefrac. */
        FeeFrac pot_feefrac = inc_feefrac;
        /** The set of transactions corresponding to that potential feefrac. */
        S pot = inc;
        /** The set of ancestors of everything in pot, combined. */
        S pot_ancestors;
        /** Whether any undecided transactions with higher individual feefrac than inc_feefrac are left. */
        bool explore_further{false};
        if (pot_known == nullptr) {
            // Loop over all undecided transactions (not yet included or excluded), from good to bad feefrac.
            for (unsigned pos : all / (inc | exc)) {
                // Determine if adding transaction pos to pot (ignoring topology) would improve it. If not,
                // we're done updating pot+pot_feefrac (and inc+inc_feefrac).
                if (!pot_feefrac.IsEmpty()) {
                    ++ret.comparisons;
                    if (!(cluster[pos].first >> pot_feefrac)) break;
                }
                // Add the transaction to pot+pot_feefrac.
                pot_feefrac += cluster[pos].first;
                pot.Set(pos);
                // Update the combined ancestors of pot.
                pot_ancestors |= anc[pos];
                // If at this point pot covers all its own ancestors, it means pot is topologically
                // valid. Perform jump ahead (update inc+inc_frac to match pot+pot_feefrac).
                if (pot >> pot_ancestors) {
                    inc = pot;
                    inc_feefrac = pot_feefrac;
                    inc_may_be_best = true;
                    explore_further = false;
                } else {
                    explore_further = true;
                }
            }
        } else {
            // In case we know the new work item's pot ialready, use a simplified loop which skips
            // the feefrac comparisons, and runs until pot_known is hit.
            for (unsigned pos : *pot_known / inc) {
                pot_feefrac += cluster[pos].first;
                pot.Set(pos);
                pot_ancestors |= anc[pos];
                if (pot >> pot_ancestors) {
                    inc = pot;
                    inc_feefrac = pot_feefrac;
                    inc_may_be_best = true;
                    explore_further = false;
                } else {
                    explore_further = true;
                }
            }
        }
        // If the potential feefrac is nothing, this is certainly uninteresting to work on.
        if (pot_feefrac.IsEmpty()) return false;

        // If inc is different from inc of the parent work item that spawned it, consider whether
        // it's the new best we've seen.
        if (inc_may_be_best) {
            ++ret.num_candidate_sets;
            assert(!inc_feefrac.IsEmpty());
            bool new_best = best_feefrac.IsEmpty();
            if (!new_best) {
                ++ret.comparisons;
                new_best = inc_feefrac > best_feefrac;
            }
            if (new_best) {
                best_feefrac = inc_feefrac;
                best_candidate = inc;
                if constexpr (Intermediate) {
                    ret.intermediate.emplace_back(ret.iterations, ret.comparisons, best_feefrac);
                }
            }
        }

        // Only if any transactions with feefrac better than inc_feefrac exist add this entry to the
        // queue. If not, it's not worth exploring further.
        if (!explore_further) return false;

        queue.emplace_back(inc, exc, pot, inc_feefrac, pot_feefrac);
        ret.max_queue_size = std::max(ret.max_queue_size, queue.size());
        if constexpr (QS != QueueStyle::RANDOM && QS != QueueStyle::DFS && QS != QueueStyle::DFS_EXC) {
            std::push_heap(queue.begin(), queue.end(), queue_cmp_fn);
        }
        return true;
    };

    // Find connected components of the cluster, and add queue entries for each which exclude all
    // the other components. This prevents the search further down from considering candidates
    // that span multiple components (as those are necessarily suboptimal).
    auto to_cover = all / done;
    while (true) {
        // Start with one transaction that hasn't been covered with connected components yet.
        S component;
        component.Set(to_cover.First());
        S added = component;
        // Compute the transitive closure of "is ancestor or descendant of but not done".
        while (true) {
            S prev_component = component;
            for (unsigned i : added) {
                component |= anc[i];
                component |= desc[i];
            }
            component /= done;
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
        add_fn(done, desc[best_ancestor_tx] | (all / (done | component)), {}, false, nullptr);
        add_fn(done | anc[best_ancestor_tx], all / (done | component), best_ancestor_feefrac, true, nullptr);
        // Update the set of transactions to cover, and finish if there are none left.
        to_cover /= component;
        if (to_cover.None()) break;
    }

    // Work processing loop.
    while (queue.size()) {
        ++ret.iterations;

        if constexpr (QS == QueueStyle::RANDOM) {
            unsigned pos = ((rng() & 0xffffffff) * queue.size()) >> 32;
            if (pos + 1 != queue.size()) {
                std::swap(queue[pos], queue.back());
            }
        } else if constexpr (QS != QueueStyle::DFS && QS != QueueStyle::DFS_EXC) {
            std::pop_heap(queue.begin(), queue.end(), queue_cmp_fn);
        }

        // Pop the last element of the queue.
        auto [inc, exc, pot, inc_feefrac, pot_feefrac] = queue.back();
        queue.pop_back();

        // If this item's potential feefrac is not better than the best seen so far, drop it.
        assert(pot_feefrac.size > 0);
        if (!best_feefrac.IsEmpty()) {
            ++ret.comparisons;
            if (pot_feefrac <= best_feefrac) continue;
        }

        // Decide which transaction to split on (highest undecided individual feefrac one left).
        // There must be at least one such transaction, because otherwise explore_further would
        // have been false inside add_fn, and the entry would never have been added to the queue.
        auto pos = (all / (inc | exc)).First();

        // Consider adding a work item corresponding to that transaction excluded. As nothing is
        // being added to inc, this new entry cannot be a new best. As desc[pos] always overlaps
        // with pot (in pos, at least), the new work item's potential set will definitely be
        // different from the parent.
        bool added_exc = add_fn(inc, exc | desc[pos], inc_feefrac, false, nullptr);

        // Consider adding a work item corresponding to that transaction included. Since only
        // connected subgraphs can be optimal candidates, if there is no overlap between the
        // parent's included transactions (inc) and the ancestors of the newly added transaction
        // (outside of done), we know it cannot possibly be the new best.
        // One exception to this is the first addition after an empty inc (inc=done). However,
        // due to the preseeding with the best ancestor set, we know that anything better must
        // necessarily consist of the union of at least two ancestor sets, and this is not a
        // concern.
        // In case anc[pos] is a subset of pot, the child potential will be identical to that of
        // the parent.
        auto new_inc = inc | anc[pos];
        auto new_inc_feefrac = inc_feefrac + ComputeSetFeeFrac(cluster, new_inc / inc);
        bool may_be_new_best = !(done >> (inc & anc[pos]));
        bool added_inc = add_fn(new_inc, exc, new_inc_feefrac, may_be_new_best, pot >> anc[pos] ? &pot : nullptr);

        if constexpr (QS == QueueStyle::DFS_EXC) {
            if (added_inc && added_exc) {
                assert(queue.size() >= 2);
                std::swap(queue.back(), *std::next(queue.rbegin()));
            }
        }
    }

    // Return.
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

/** Compute a full linearization of a cluster (vector of cluster indices). */
template<typename S>
LinearizationResult LinearizeCluster(const Cluster<S>& cluster, unsigned optimal_limit)
{
    LinearizationResult ret;
    ret.linearization.reserve(cluster.size());
    S done;
    unsigned left = cluster.size();
    if (left == 0) return ret;

    // Precompute stuff.
    SortedCluster<S> sorted(cluster);
    AncestorSets<S> anc(sorted.cluster);
    DescendantSets<S> desc(anc);
    // Precompute ancestor set sizes, to help with topological sort.
    std::vector<unsigned> anccount(cluster.size(), 0);
    for (unsigned i = 0; i < cluster.size(); ++i) {
        anccount[i] = anc[i].Count();
    }
    AncestorSetFeeFracs anc_feefracs(sorted.cluster, anc, done);

    // Iterate while there are transactions left.
    while (true) {
        // Invoke function to find a good/best candidate.
        CandidateSetAnalysis<S> analysis;
        if (left > optimal_limit) {
            analysis = FindBestAncestorSet(sorted.cluster, anc, anc_feefracs, done);
        } else {
            analysis = FindBestCandidateSetEfficient<QueueStyle::LOWEST_POTENTIAL_SIZE>(sorted.cluster, anc, desc, anc_feefracs, done, nullptr);
        }

        // Sanity checks.
        assert(analysis.best_candidate_set.Any()); // Must be at least one transaction
        assert((analysis.best_candidate_set & done).None()); // Cannot overlap with processed ones.

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

        // Update bookkeeping to reflect newly added transactions.
        left -= analysis.best_candidate_set.Count();
        if (left == 0) break; // Bail out if nothing left.
        done |= analysis.best_candidate_set;
        // Update precomputed ancestor FeeFracs.
        anc_feefracs.Done(sorted.cluster, desc, analysis.best_candidate_set);
#if 0
        // Verify that precomputed ancestor FeeFrac are correct.
        for (unsigned i = 0; i < cluster.size(); ++i) {
            if (!done[i]) {
                assert(anc_feefracs[i] == ComputeSetFeeFrac(sorted.cluster, anc[i] / done));
            }
        }
#endif
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
    while (ret.size() < S::Size()) {
        uint32_t size = DeserializeNumberBase128(data) & 0x3fffff;
        if (size == 0) break;
        uint64_t fee = DeserializeNumberBase128(data) & 0x7ffffffffffff;
        S parents;
        while (true) {
            unsigned read = DeserializeNumberBase128(data);
            if (read == 0) break;
            if (read <= ret.size()) {
                parents.Set(ret.size() - read);
            } else {
                if (read < S::Size()) parents.Set(read);
            }
        }
        ret.emplace_back(FeeFrac{fee, size}, std::move(parents));
    }
    S all = S::Fill(ret.size());
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
        assert(cover == ancs[idx]);
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

} // namespace

} // namespace linearize_cluster

#endif // BITCOIN_CLUSTER_LINEARIZE_H
