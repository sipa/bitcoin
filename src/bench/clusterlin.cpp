// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <util/bitset.h>
#include <cluster_linearize.h>

using namespace cluster_linearize;

namespace {

// Construct a difficulty graph. These need at least sqrt(2^(n-1)) iterations in the best
// implemented algorithms.
template<typename S>
DepGraph<S> MakeHardGraph(ClusterIndex ntx)
{
    DepGraph<S> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        if (ntx & 1) {
            if (i == 0) {
                depgraph.AddTransaction({1, 2});
            } else if (i == 1) {
                depgraph.AddTransaction({14, 2});
                depgraph.AddDependency(0, 1);
            } else if (i == 2) {
                depgraph.AddTransaction({6, 1});
                depgraph.AddDependency(2, 1);
            } else if (i == 3) {
                depgraph.AddTransaction({5, 1});
                depgraph.AddDependency(2, 3);
            } else if ((i & 1) == 0) {
                depgraph.AddTransaction({7, 1});
                depgraph.AddDependency(i - 1, i);
            } else {
                depgraph.AddTransaction({5, 1});
                depgraph.AddDependency(i, 4);
            }
        } else {
            if (i == 0) {
                depgraph.AddTransaction({1, 1});
            } else if (i == 1) {
                depgraph.AddTransaction({3, 1});
                depgraph.AddDependency(0, 1);
            } else if (i == 2) {
                depgraph.AddTransaction({1, 1});
                depgraph.AddDependency(0, 2);
            } else if (i & 1) {
                depgraph.AddTransaction({4, 1});
                depgraph.AddDependency(i - 1, i);
            } else {
                depgraph.AddTransaction({0, 1});
                depgraph.AddDependency(i, 3);
            }
        }
    }
    return depgraph;
}

template<typename S>
void BenchSearchCandidateBounded(ClusterIndex ntx, benchmark::Bench& bench)
{
    const auto depgraph = MakeHardGraph<S>(ntx);
    uint64_t rng_seed = 0;
    bench.batch(10000).unit("iters").run([&] {
        uint64_t iters = 10000;
        SearchCandidateFinder finder(depgraph, rng_seed++);
        finder.FindCandidateSet(iters, {});
        assert(iters == 0);
    });
}

template<typename S>
void BenchLinearize(ClusterIndex ntx, benchmark::Bench& bench)
{
    const auto depgraph = MakeHardGraph<S>(ntx);
    uint64_t rng_seed = 0;
    std::vector<ClusterIndex> old_lin(ntx);
    for (ClusterIndex i = 0; i < ntx; ++i) old_lin[i] = i;
    bench.batch(1).unit("lins").run([&] {
        uint64_t iters = 10;
        Linearize(depgraph, iters, rng_seed++, old_lin);
        assert(iters == 0);
    });
}

} // namespace

static void SearchCandidateBounded32Tx(benchmark::Bench& bench) { BenchSearchCandidateBounded<BitSet<32>>(32, bench); }
static void SearchCandidateBounded48Tx(benchmark::Bench& bench) { BenchSearchCandidateBounded<BitSet<48>>(48, bench); }
static void SearchCandidateBounded64Tx(benchmark::Bench& bench) { BenchSearchCandidateBounded<BitSet<64>>(64, bench); }
static void SearchCandidateBounded75Tx(benchmark::Bench& bench) { BenchSearchCandidateBounded<BitSet<75>>(75, bench); }
static void SearchCandidateBounded100Tx(benchmark::Bench& bench) { BenchSearchCandidateBounded<BitSet<100>>(100, bench); }

static void Linearize32Tx(benchmark::Bench& bench) { BenchLinearize<BitSet<32>>(32, bench); }
static void Linearize48Tx(benchmark::Bench& bench) { BenchLinearize<BitSet<48>>(48, bench); }
static void Linearize64Tx(benchmark::Bench& bench) { BenchLinearize<BitSet<64>>(64, bench); }
static void Linearize75Tx(benchmark::Bench& bench) { BenchLinearize<BitSet<75>>(75, bench); }
static void Linearize100Tx(benchmark::Bench& bench) { BenchLinearize<BitSet<100>>(100, bench); }

BENCHMARK(SearchCandidateBounded32Tx, benchmark::PriorityLevel::HIGH);
BENCHMARK(SearchCandidateBounded48Tx, benchmark::PriorityLevel::HIGH);
BENCHMARK(SearchCandidateBounded64Tx, benchmark::PriorityLevel::HIGH);
BENCHMARK(SearchCandidateBounded75Tx, benchmark::PriorityLevel::HIGH);
BENCHMARK(SearchCandidateBounded100Tx, benchmark::PriorityLevel::HIGH);

BENCHMARK(Linearize32Tx, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize48Tx, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize64Tx, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize75Tx, benchmark::PriorityLevel::HIGH);
BENCHMARK(Linearize100Tx, benchmark::PriorityLevel::HIGH);
