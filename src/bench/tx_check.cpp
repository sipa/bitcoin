// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <random.h>

// Microbenchmark for performance of CheckTransaction (primarily the duplicate-input check).
static void BenchCheckTransaction(benchmark::Bench& bench, size_t vinsize)
{
    const uint256 dummy_hash = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    CMutableTransaction mtx;
    mtx.vin.resize(vinsize);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;
    FastRandomContext ctx;
    std::set<uint32_t> used;
    for (auto& txin : mtx.vin) {
        txin.prevout.hash = dummy_hash;
        uint32_t n;
        while (true) {
            n = ctx.randbits(24);
            if (used.insert(n).second) break;
        }
        txin.prevout.n = n;
    }
    uint32_t last_n = 0x1000000;
    TxValidationState tx_state;

    // Benchmark.
    bench.run([&] {
        mtx.vin[ctx.randrange(vinsize)].prevout.n = last_n++;
        mtx.vin[ctx.randrange(vinsize)].prevout.n = last_n++;
        bool ret = CheckTransaction(CTransaction(mtx), tx_state);
        assert(ret);
    });
}

static void CheckTransaction0001(benchmark::Bench& bench) { BenchCheckTransaction(bench, 1); }
static void CheckTransaction0002(benchmark::Bench& bench) { BenchCheckTransaction(bench, 2); }
static void CheckTransaction0005(benchmark::Bench& bench) { BenchCheckTransaction(bench, 5); }
static void CheckTransaction0010(benchmark::Bench& bench) { BenchCheckTransaction(bench, 10); }
static void CheckTransaction0020(benchmark::Bench& bench) { BenchCheckTransaction(bench, 20); }
static void CheckTransaction0050(benchmark::Bench& bench) { BenchCheckTransaction(bench, 50); }
static void CheckTransaction0100(benchmark::Bench& bench) { BenchCheckTransaction(bench, 100); }
static void CheckTransaction0200(benchmark::Bench& bench) { BenchCheckTransaction(bench, 200); }
static void CheckTransaction0500(benchmark::Bench& bench) { BenchCheckTransaction(bench, 500); }
static void CheckTransaction1000(benchmark::Bench& bench) { BenchCheckTransaction(bench, 1000); }
static void CheckTransaction2000(benchmark::Bench& bench) { BenchCheckTransaction(bench, 2000); }
static void CheckTransaction5000(benchmark::Bench& bench) { BenchCheckTransaction(bench, 5000); }

BENCHMARK(CheckTransaction0001)
BENCHMARK(CheckTransaction0002)
BENCHMARK(CheckTransaction0005)
BENCHMARK(CheckTransaction0010)
BENCHMARK(CheckTransaction0020)
BENCHMARK(CheckTransaction0050)
BENCHMARK(CheckTransaction0100)
BENCHMARK(CheckTransaction0200)
BENCHMARK(CheckTransaction0500)
BENCHMARK(CheckTransaction1000)
BENCHMARK(CheckTransaction2000)
BENCHMARK(CheckTransaction5000)
