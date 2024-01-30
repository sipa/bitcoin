// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <util/strencodings.h>
#include <serialize.h>
#include <streams.h>
#include <clusterlin.h>
#include <algorithm>
#include <vector>
#include <iostream>

using namespace clusterlin;

namespace {

using TestBitSet = BitSet<32>;

/** A formatter for a bespoke serialization for *acyclic* DepGraph objects.
 *
 */
struct DepGraphFormatter
{
    /** Convert x>=0 to 2x (even), x<0 to -2x-1 (odd). */
    static uint64_t SignedToUnsigned(int64_t x) noexcept
    {
        uint64_t ret(x);
        ret <<= 1;
        if (x < 0) ret = ~ret;
        return ret;
    }

    /** Convert even x to x/2 (>=0), odd x to -(x>>1)-1 (<0). */
    static int64_t UnsignedToSigned(uint64_t x) noexcept
    {
        uint64_t ret(x >> 1);
        if (x & 1) ret = ~ret;
        return int64_t(ret);
    }

    template <typename Stream, typename S>
    static void Ser(Stream& s, const DepGraph<S>& depgraph)
    {
        DepGraph<S> rebuild(depgraph.TxCount());
        for (unsigned idx = 0; idx < depgraph.TxCount(); ++idx) {
            // Write size.
            s << VARINT_MODE(depgraph.FeeRate(idx).size, VarIntMode::NONNEGATIVE_SIGNED);
            // Write fee.
            s << VARINT(SignedToUnsigned(depgraph.FeeRate(idx).fee));
            // Write dependency information.
            unsigned counter = 0; //!< How many potential parent/child relations we've iterated over.
            unsigned offset = 0; //!< The counter value at the last actually written relation.
            for (unsigned loop = 0; loop < 2; ++loop) {
                // In loop 0 store parents among tx 0..idx-1; in loop 1 store children among those.
                S towrite = loop ? depgraph.GetReducedChildren(idx) : depgraph.GetReducedParents(idx);
                for (unsigned i = 0; i < idx; ++i) {
                    unsigned parent = loop ? idx : idx - 1 - i;
                    unsigned child = loop ? idx - 1 - i : idx;
                    if (rebuild.CanAddDependency(parent, child)) {
                        ++counter;
                        if (towrite[idx - 1 - i]) {
                            rebuild.AddDependency(parent, child);
                            // The actually emitted values are differentially encoded (one value
                            // per parent/child relation).
                            s << VARINT(counter - offset);
                            offset = counter;
                        }
                    }
                }
            }
            if (counter > offset) s << uint8_t{0};
        }
        // Output a final 0 to denote the end of the graph.
        s << uint8_t{0};
    }

    template <typename Stream, typename S>
    void Unser(Stream& s, DepGraph<S>& depgraph)
    {
        depgraph = {};
        while (true) {
            // Read size. Size 0 signifies the end of the DepGraph.
            int32_t size;
            s >> VARINT_MODE(size, VarIntMode::NONNEGATIVE_SIGNED);
            size &= 0x3FFFFF; // Enough for size up to 4M.
            if (size == 0 || depgraph.TxCount() == S::Size()) break;
            // Read fee, encoded as a signed varint (odd means negative, even means non-negative).
            uint64_t coded_fee;
            s >> VARINT(coded_fee);
            coded_fee &= 0xFFFFFFFFFFFFF; // Enough for fee between -21M...21M BTC.
            auto fee = UnsignedToSigned(coded_fee);
            // Extend resulting graph with new transaction.
            auto idx = depgraph.AddTransaction({fee, size});
            // Read dependency information.
            unsigned offset = 0; //!< The next encoded value.
            unsigned counter = 0; //!< How many potential parent/child relations we've iterated over.
            for (unsigned loop = 0; loop < 2; ++loop) {
                // In loop 0 read parents among tx 0..idx-1; in loop 1 store children among those.
                bool done = false;
                for (unsigned i = 0; i < idx; ++i) {
                    unsigned parent = loop ? idx : idx - 1 - i;
                    unsigned child = loop ? idx - 1 - i : idx;
                    if (depgraph.CanAddDependency(parent, child)) {
                        ++counter;
                        // If counter passes offset, read & decode the next differentially encoded
                        // value. If a 0 is read, this signifies the end of this transaction's
                        // dependency information.
                        if (offset < counter) {
                            uint64_t diff;
                            s >> VARINT(diff);
                            offset += diff;
                            if (diff == 0 || offset < diff) {
                                done = true;
                                break;
                            }
                        }
                        // On a match, actually add the relation.
                        if (offset == counter) depgraph.AddDependency(parent, child);
                    }
                }
                if (done) break;
            }
        }
    }
};

[[maybe_unused]] std::ostream& operator<<(std::ostream& o, const FeeFrac& data)
{
    if (data.IsEmpty()) {
        o << "()";
    } else {
        o << "(" << data.fee << "/" << data.size << "=" << ((double)data.fee / data.size) << ")";
    }
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

[[maybe_unused]] std::ostream& operator<<(std::ostream& o, Span<const unsigned char> data)
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

template<typename S>
std::ostream& operator<<(std::ostream& o, const DepGraph<S>& txgraph)
{
    o << "DepGraph{";
    for (size_t i = 0; i < txgraph.TxCount(); ++i) {
        if (i) o << ",";
        o << i << ":" << txgraph.FeeRate(i);
        S pars = txgraph.Ancestors(i);
        pars.Reset(i);
        for (auto j : pars) {
            if (pars[j]) {
                pars /= txgraph.Ancestors(j);
                pars.Set(j);
            }
        }
        o << pars;
    }
    o << "}";
    return o;
}

/** Convert a Cluster to DepGraph (using the original transaction order the cluster had). */
template<typename BS>
DepGraph<BS> ClusterToDepGraph(const Cluster<BS>& cluster)
{
    std::vector<typename DepGraph<BS>::Entry> entries(cluster.size());
    for (size_t i = 0; i < cluster.size(); ++i) {
        std::tie(entries[i].feerate, entries[i].ancestors) = cluster[i];
    }
    return DepGraph<BS>(std::move(entries));
}

/** Convert a DepGraph back to a Cluster. Omits redundant parents. */
template<typename BS>
Cluster<BS> DepGraphToCluster(const DepGraph<BS>& depgraph)
{
    Cluster<BS> ret(depgraph.TxCount());
    for (unsigned i = 0; i < ret.size(); ++i) {
        ret[i].first = depgraph.FeeRate(i);
        ret[i].second = depgraph.GetReducedParents(i);
    }
    return ret;
}

/** A simpler (and less efficient) equivalent of FindBestCandidate. */
template<typename S>
S FindBestCandidateNaive(const DepGraph<S>& txgraph, const S& todo)
{
    // Queue of work units. Each consists of:
    // - inc: set of transactions definitely included
    // - und: set of transactions that can be added to inc still
    std::vector<std::pair<S, S>> queue;
    queue.emplace_back(S{}, todo);

    // Best solution so far.
    S best = todo;
    auto best_feerate = txgraph.FeeRate(todo);

    // Process the queue.
    while (!queue.empty()) {
        // Pop top element of the queue.
        auto [inc, und] = queue.back();
        queue.pop_back();
        // Look for a transaction to consider adding/removing.
        bool inc_none = inc.None();
        for (auto pivot : und) {
            if (inc_none || (inc && txgraph.Ancestors(pivot))) {
                // Add a queue entry with pivot included.
                auto new_inc = inc | (todo & txgraph.Ancestors(pivot));
                queue.emplace_back(new_inc, und / new_inc);
                // Add a queue entry with pivot excluded.
                queue.emplace_back(inc, und / txgraph.Descendants(pivot));
                // Update statistics to account for the candidate new_inc.
                auto new_inc_feerate = txgraph.FeeRate(new_inc);
                if (new_inc_feerate > best_feerate) {
                    best_feerate = new_inc_feerate;
                    best = new_inc;
                }
                break;
            }
        }
    }

    return best;
}

/** Perform a sanity/consistency check on a DepGraph. */
template<typename BS>
void SanityCheck(const DepGraph<BS>& depgraph)
{
    // Consistency check between ancestors internally.
    for (unsigned i = 0; i < depgraph.TxCount(); ++i) {
        // Transactions include themselves as ancestors.
        assert(depgraph.Ancestors(i)[i]);
        // If a is an ancestor of b, then b's ancestors must include all of a's ancestors.
        for (auto a : depgraph.Ancestors(i)) {
            assert(depgraph.Ancestors(i) >> depgraph.Ancestors(a));
        }
    }
    // Consistency check between ancestors and descendants.
    for (unsigned i = 0; i < depgraph.TxCount(); ++i) {
        for (unsigned j = 0; j < depgraph.TxCount(); ++j) {
            assert(depgraph.Ancestors(i)[j] == depgraph.Descendants(j)[i]);
        }
    }
}

/** Stitch connected components together in a DepGraph, guaranteeing its corresponding cluster is connected. */
template<typename BS>
void MakeConnected(DepGraph<BS>& depgraph)
{
    auto todo = BS::Fill(depgraph.TxCount());
    auto comp = depgraph.FindConnectedComponent(todo);
    todo /= comp;
    while (todo.Any()) {
        auto nextcomp = depgraph.FindConnectedComponent(todo);
        depgraph.AddDependency(comp.Last(), nextcomp.First());
        todo /= nextcomp;
        comp = nextcomp;
    }
}

} // namespace

FUZZ_TARGET(clusterlin_adddependency)
{
    // Verify that computing a DepGraph from a cluster, or building it step by step using AddDependency,
    // have the same effect.

    // Construct a cluster of a certain length, with no dependencies.
    Cluster<TestBitSet> cluster;
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    unsigned num_tx = provider.ConsumeIntegralInRange<unsigned>(2, 32);
    cluster.resize(num_tx);
    // Construct the corresponding DepGraph object (also no dependencies).
    auto depgraph = ClusterToDepGraph(cluster);
    SanityCheck(depgraph);
    // Read (parent, child) pairs, and add them to the cluster and txgraph.
    LIMITED_WHILE(provider.remaining_bytes() > 0, 1024) {
        unsigned parent = provider.ConsumeIntegralInRange<unsigned>(0, num_tx - 1);
        unsigned child = provider.ConsumeIntegralInRange<unsigned>(0, num_tx - 2);
        child += (child >= parent);
        cluster[child].second.Set(parent);
        depgraph.AddDependency(parent, child);
        SanityCheck(depgraph);
    }
    // Verify that the resulting DepGraph matches one recomputed from the cluster.
    assert(ClusterToDepGraph(cluster) == depgraph);
}

FUZZ_TARGET(clusterlin_serialization)
{
    // Verify that any graph of transaction has its ancestry correctly computed by DepGraph, and if
    // it is a DAG, it can be serialized in a way that roundtrips.

    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Construct a cluster in a naive way (using a FuzzedDataProvider-based serialization).
    Cluster<TestBitSet> cluster;
    unsigned num_tx = provider.ConsumeIntegralInRange<unsigned>(1, 32);
    cluster.resize(num_tx);
    for (unsigned i = 0; i < num_tx; ++i) {
        cluster[i].first.size = provider.ConsumeIntegralInRange<int32_t>(1, 0x3fffff);
        cluster[i].first.fee = provider.ConsumeIntegralInRange<int64_t>(-0x8000000000000, 0x7ffffffffffff);
        for (unsigned j = 0; j < num_tx; ++j) {
            if (i == j) continue;
            if (provider.ConsumeBool()) cluster[i].second.Set(j);
        }
    }

    // Verify that ancestry is computed correctly.
    auto depgraph = ClusterToDepGraph(cluster);
    SanityCheck(depgraph);
    for (unsigned i = 0; i < num_tx; ++i) {
        //! Ancestors of transaction i.
        TestBitSet anc;
        // Start with being equal to just i itself.
        anc.Set(i);
        // Loop as long as more ancestors are being added.
        while (true) {
            bool changed{false};
            // For every known ancestor of i, include its parents into anc.
            for (auto i : anc) {
                if (!(cluster[i].second << anc)) {
                    changed = true;
                    anc |= cluster[i].second;
                }
            }
            if (!changed) break;
        }
        // Compare with depgraph.
        assert(depgraph.Ancestors(i) == anc);
    }

    // If the resulting graph is not a DAG, bail out.
    if (!depgraph.IsAcyclic()) return;

    // Check that serializing + deserializing results in an equivalent graph.
    std::vector<unsigned char> ser;
    VectorWriter writer(ser, 0);
    writer << Using<DepGraphFormatter>(depgraph);
    SpanReader reader(ser);
    DepGraph<TestBitSet> decoded_depgraph;
    reader >> Using<DepGraphFormatter>(decoded_depgraph);
    SanityCheck(decoded_depgraph);
    assert(reader.empty());
    assert(depgraph == decoded_depgraph);
}

FUZZ_TARGET(clusterlin_deserialization)
{
    // Verify that any deserialized depgraph is acyclic and roundtrips to an identical depgraph.

    // Construct a graph by deserializing.
    SpanReader reader(buffer);
    DepGraph<TestBitSet> depgraph;
    try {
        reader >> Using<DepGraphFormatter>(depgraph);
    } catch (const std::ios_base::failure&) {
        // Ignore EOF.
    }
    SanityCheck(depgraph);

    // Verify the graph is a DAG.
    assert(depgraph.IsAcyclic());

    // Verify the graph serializes and deserializes back to the same cluster.
    std::vector<unsigned char> ser;
    VectorWriter writer(ser, 0);
    writer << Using<DepGraphFormatter>(depgraph);
    SpanReader rereader(ser);
    DepGraph<TestBitSet> decoded_depgraph;
    rereader >> Using<DepGraphFormatter>(decoded_depgraph);
    SanityCheck(decoded_depgraph);
    assert(rereader.empty());
    assert(depgraph == decoded_depgraph);
}

FUZZ_TARGET(clusterlin_make_connected)
{
    // Verify that MakeConnected makes graphs connected.

    SpanReader reader(buffer);
    DepGraph<TestBitSet> depgraph;
    try {
        reader >> Using<DepGraphFormatter>(depgraph);
    } catch (const std::ios_base::failure&) {
        // Ignore EOF.
    }
    SanityCheck(depgraph);
    MakeConnected(depgraph);
    SanityCheck(depgraph);
    assert(depgraph.IsConnected());
}

FUZZ_TARGET(clusterlin_best_candidate)
{
    // Verify that FindCandidateSet with sufficient iteration_limit finds the optimal candidate
    // set.

    // Retrieve an RNG seed and a cluster/depgraph from the fuzz input.
    SpanReader reader(buffer);
    uint64_t rng_seed = 0;
    DepGraph<TestBitSet> depgraph;
    try {
        reader >> rng_seed >> Using<DepGraphFormatter>(depgraph);
    } catch (const std::ios_base::failure&) {
        // Ignore EOF.
    }
    if (depgraph.TxCount() > 16) return;
    MakeConnected(depgraph);
    SanityCheck(depgraph);
    auto cluster = DepGraphToCluster(depgraph);

    // Construct a linearizer for the cluster.
    Linearizer lin(cluster, rng_seed);

    for (unsigned i = 0; i < cluster.size(); ++i) {
        // Find the best candidate subset of the remaining transactions in the cluster.
        uint64_t iterations = 0x10000;
        auto best = lin.FindCandidateSet(iterations);
        assert(iterations > 0); // we should not run out of iterations with max 15 transactions
        // Do the same using a naive algorithm on depgraph directly.
        auto real_best = FindBestCandidateNaive(depgraph, lin.GetTodo());
        // Compare them. The sets may differ, but they must have the same fee and size.
        assert(depgraph.FeeRate(best) == depgraph.FeeRate(real_best));
        // Remove first transaction from the cluster. This way we test FindCandidateSet also for
        // incompletely remaining clusters.
        lin.RemoveTransactions(TestBitSet::Singleton(i));
    };
}

FUZZ_TARGET(clusterlin_linearize_optimal)
{
    // Verify that the output of Linearize is as good as every topologically-valid permutation
    // of the transactions in a cluster.

    // Retrieve an RNG seed and a cluster/depgraph from the fuzz input.
    SpanReader reader(buffer);
    uint64_t rng_seed = 0;
    DepGraph<TestBitSet> depgraph;
    try {
        reader >> rng_seed >> Using<DepGraphFormatter>(depgraph);
    } catch (const std::ios_base::failure&) {
        // Ignore EOF.
    }
    if (depgraph.TxCount() > 10) return;
    MakeConnected(depgraph);
    SanityCheck(depgraph);
    auto cluster = DepGraphToCluster(depgraph);

    uint64_t iterations = 0x10000;
    auto optimal_lin = Linearize(cluster, iterations, rng_seed);
    assert(iterations > 0);
    auto optimal_chunking = ChunkLinearization(cluster, optimal_lin);

    std::vector<unsigned> linearization;
    linearization.reserve(cluster.size());
    TestBitSet unincluded = TestBitSet::Fill(cluster.size());
    auto permute_fn = [&](auto&& permute_fn) -> void {
        if (unincluded.Any()) {
            bool recursed = false;
            // Iterate over all transactions that can topologically be included next, and recurse.
            for (auto i : unincluded) {
                if ((depgraph.Ancestors(i) & unincluded) == TestBitSet::Singleton(i)) {
                    linearization.push_back(i);
                    unincluded.Reset(i);
                    permute_fn(permute_fn);
                    unincluded.Set(i);
                    linearization.pop_back();
                    recursed = true;
                }
            }
            // There must always be at least one transaction that can be included next.
            assert(recursed);
        } else {
            // Verify the obtained linearization is at least as good as the optimal one.
            auto chunking = ChunkLinearization(cluster, linearization);
            auto cmp = CompareChunkings(optimal_chunking, chunking);
            assert(cmp >= 0);
        }
    };
    permute_fn(permute_fn);
}

/*
FUZZ_TARGET(clusterlin_kernels)
{
    auto depgraph = ReadDepGraph<TestBitSet>(buffer);
    if (depgraph.TxCount() == 0 || depgraph.TxCount() > 10) return;
    MakeConnected(depgraph);
    SanityCheck(depgraph);

    const auto is_kernel = [&](const TestBitSet& kernel) {
        if (kernel.Count() <= 1) return false;
        if (kernel.Count() == depgraph.TxCount()) return false;
        if (depgraph.FindConnectedComponent(kernel) != kernel) return false;
        const auto anc = depgraph.Ancestors(kernel.First()) / kernel;
        const auto desc = depgraph.Descendants(kernel.First()) / kernel;
        for (auto tx : kernel) {
            if (depgraph.Ancestors(tx) / kernel != anc) return false;
            if (depgraph.Descendants(tx) / kernel != desc) return false;
        }

        return true;
    };

    auto kernels = FindKernels<TestBitSet>(depgraph);

    for (uint64_t x = 0; x >> depgraph.TxCount() == 0; ++x) {
        TestBitSet kernel;
        for (unsigned i = 0; i < depgraph.TxCount(); ++i) {
            kernel.Set(i, (x >> i) & 1);
        }
        bool real = is_kernel(kernel);
        bool seen = std::binary_search(kernels.begin(), kernels.end(), kernel);
        if (real != seen) {
            std::cerr << "GRAPH " << depgraph << "\n";
            std::cerr << "KERNEL " << kernel << "\n";
            std::cerr << "REAL " << real << "\n";
            std::cerr << "SEEN " << seen << "\n";
        }
        assert(real == seen);
    }
}
*/