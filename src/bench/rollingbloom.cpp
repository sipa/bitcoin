// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/common.h>
#include <bench/bench.h>
#include <bloom.h>
#include <cuckoofilter.h>

#define WINDOW 5000

namespace {

template<bool TenFails, bool TenSuccess>
static void RollingBloomBench(benchmark::Bench& bench)
{
    CRollingBloomFilter filter(WINDOW, 0.000001);
    std::vector<unsigned char> data(8);
    uint64_t num = 0;
    for (unsigned j = 0; j < WINDOW; ++j) {
        WriteLE64(data.data(), num++);
        filter.insert(data);
    }
    bench.minEpochIterations(1000000).run([&] {
        if (TenFails) {
            for (int k = 0; k < 10; ++k) {
                WriteLE64(data.data(), num + (WINDOW / 12) * (k + 1));
                filter.contains(data);
            }
        }
        if (TenSuccess) {
            for (int k = 0; k < 10; ++k) {
                WriteLE64(data.data(), num - (WINDOW / 12) * (k + 1));
                filter.contains(data);
            }
        }
        WriteLE64(data.data(), num++);
        filter.insert(data);
    });
}

template<int AlphaPct, bool TenFails, bool TenSuccess>
static void RollingCuckooBench(benchmark::Bench& bench)
{
    RollingCuckooFilter filter(WINDOW, 20, 0.01 * AlphaPct, 20);
    std::vector<unsigned char> data(8);
    uint64_t num = 0;
    for (unsigned j = 0; j < WINDOW; ++j) {
        WriteLE64(data.data(), num++);
        filter.Insert(data);
    }
    bench.minEpochIterations(1000000).run([&] {
        if (TenFails) {
            for (int k = 0; k < 10; ++k) {
                WriteLE64(data.data(), num + (WINDOW / 12) * (k + 1));
                filter.Check(data);
            }
        }
        if (TenSuccess) {
            for (int k = 0; k < 10; ++k) {
                WriteLE64(data.data(), num - (WINDOW / 12) * (k + 1));
                filter.Check(data);
            }
        }
        WriteLE64(data.data(), num++);
        filter.Insert(data);
    });
    fprintf(stderr, "Max overflow = %llu\n", (unsigned long long)filter.MaxOverflow());
}

void RollingBloom_Insert(benchmark::Bench& state) { RollingBloomBench<false, false>(state); }
void RollingBloom_Insert10Fail(benchmark::Bench& state) { RollingBloomBench<true, false>(state); }
void RollingBloom_Insert10Success(benchmark::Bench& state) { RollingBloomBench<false, true>(state); }

void RollingCuckoo85_Insert(benchmark::Bench& state) { RollingCuckooBench<85, false, false>(state); }
void RollingCuckoo85_Insert10Fail(benchmark::Bench& state) { RollingCuckooBench<85, true, false>(state); }
void RollingCuckoo85_Insert10Success(benchmark::Bench& state) { RollingCuckooBench<85, false, true>(state); }
void RollingCuckoo90_Insert(benchmark::Bench& state) { RollingCuckooBench<90, false, false>(state); }
void RollingCuckoo90_Insert10Fail(benchmark::Bench& state) { RollingCuckooBench<90, true, false>(state); }
void RollingCuckoo90_Insert10Success(benchmark::Bench& state) { RollingCuckooBench<90, false, true>(state); }
void RollingCuckoo95_Insert(benchmark::Bench& state) { RollingCuckooBench<95, false, false>(state); }
void RollingCuckoo95_Insert10Fail(benchmark::Bench& state) { RollingCuckooBench<95, true, false>(state); }
void RollingCuckoo95_Insert10Success(benchmark::Bench& state) { RollingCuckooBench<95, false, true>(state); }
}

BENCHMARK(RollingBloom_Insert);
BENCHMARK(RollingBloom_Insert10Fail);
BENCHMARK(RollingBloom_Insert10Success);

BENCHMARK(RollingCuckoo85_Insert);
BENCHMARK(RollingCuckoo85_Insert10Fail);
BENCHMARK(RollingCuckoo85_Insert10Success);
BENCHMARK(RollingCuckoo90_Insert);
BENCHMARK(RollingCuckoo90_Insert10Fail);
BENCHMARK(RollingCuckoo90_Insert10Success);
BENCHMARK(RollingCuckoo95_Insert);
BENCHMARK(RollingCuckoo95_Insert10Fail);
BENCHMARK(RollingCuckoo95_Insert10Success);
