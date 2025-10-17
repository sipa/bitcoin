// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <cluster_linearize.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <init/common.h>
#include <interfaces/init.h>
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>
#include <test/util/cluster_linearize.h>
#include <util/bitset.h>
#include <util/frontier.h>
#include <util/time.h>

#include <condition_variable>
#include <mutex>
#include <optional>
#include <thread>
#include <stdio.h>
#include <vector>
#include <cassert>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

using Graph = DepGraph<BitSet<64>>;
using Pool = std::pair<std::chrono::microseconds, std::vector<Graph>>;

std::string PrintTime(const NodeClock::time_point& tp) noexcept
{
    const auto now_seconds{std::chrono::time_point_cast<std::chrono::seconds>(tp)};
    auto time_str = FormatISO8601DateTime(TicksSinceEpoch<std::chrono::seconds>(now_seconds));
    time_str.pop_back();
    time_str += strprintf(".%06dZ", Ticks<std::chrono::microseconds>(tp - now_seconds));
    return time_str;
}

class FeeRateData
{
    // Vector (for each cluster) of pair (chunk_feerates, lin_feerates), sorted by decreasing first chunk feerate.
    std::vector<std::pair<std::vector<FeeFrac>, std::vector<FeeFrac>>> feerates_by_cluster;
    // All chunks: (feerate, cluster_id, chunk_num_in_cluster), sorted by decreasing feerate, increasing cluster_id, increasing chunk_num.
    std::vector<std::tuple<FeeFrac, uint64_t, size_t>> chunk_feerates;
    // Sum of all chunk feerates.
    FeeFrac total_feerate;
public:

    static constexpr uint32_t LIMIT{3992000};
    static constexpr int32_t BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000;
    static constexpr int MAX_CONSECUTIVE_FAILURES = 1000;

    FeeRateData(const Pool& pool)
    {
        std::vector<DepGraphIndex> lin;
        InsecureRandomContext rng(11);
        std::unordered_set<uint64_t> cluster_ids;
        for (const auto& graph : pool.second) {
            uint64_t nonce = 0;
            do {
                nonce = rng.rand64();
            } while (cluster_ids.count(nonce));
            cluster_ids.insert(nonce);
            std::pair<std::vector<FeeFrac>, std::vector<FeeFrac>> cluster_feerates;
            lin.resize(graph.TxCount());
            std::iota(lin.begin(), lin.end(), DepGraphIndex{0});
            auto chunking = ChunkLinearization(graph, lin);
            size_t chunk_num = 0;
            for (const auto& chunk_feerate : chunking) {
                chunk_feerates.emplace_back(chunk_feerate, nonce, chunk_num++);
                total_feerate += chunk_feerate;
                cluster_feerates.first.push_back(chunk_feerate);
            }
            for (auto pos : graph.Positions()) {
                cluster_feerates.second.push_back(graph.FeeRate(pos));
            }
            feerates_by_cluster.push_back(std::move(cluster_feerates));
        }
        std::sort(chunk_feerates.begin(), chunk_feerates.end(), [](auto& a, auto& b) noexcept {
            auto cmp_feerate = FeeRateCompare(std::get<0>(a), std::get<0>(b));
            if (cmp_feerate != 0) return cmp_feerate > 0;
            auto cmp_cluster = std::get<1>(a) <=> std::get<1>(b);
            if (cmp_cluster != 0) return cmp_cluster < 0;
            return std::get<2>(a) < std::get<2>(b);
        });
        std::sort(feerates_by_cluster.begin(), feerates_by_cluster.end(), std::greater{});
    }

    FeeFrac MinChunkFeeRate() const
    {
        if (chunk_feerates.empty()) return {};
        return std::get<0>(chunk_feerates.back());
    }

    FeeFrac MaxChunkFeeRate() const
    {
        if (chunk_feerates.empty()) return {};
        return std::get<0>(chunk_feerates.front());
    }

    FeeFrac TotalFeeRate() const
    {
        return total_feerate;
    }

    FeeFrac LowerBound() const
    {
        uint32_t done{0};
        int64_t ret{0};
        for (const auto& [chunk_feerate, _cluster_id, _chunk_num] : chunk_feerates) {
            if (chunk_feerate.size + done <= LIMIT) {
                done += chunk_feerate.size;
                ret += chunk_feerate.fee;
            } else {
                break;
            }
        }
        return FeeFrac(ret, done);
    }

    FeeFrac UpperBound() const
    {
        uint32_t done{0};
        int64_t ret{0};
        for (const auto& [chunk_feerate, _cluster_id, _chunk_num] : chunk_feerates) {
            if (chunk_feerate.size + done <= LIMIT) {
                done += chunk_feerate.size;
                ret += chunk_feerate.fee;
            } else {
                ret += chunk_feerate.EvaluateFeeDown(LIMIT - done);
                break;
            }
        }
        return FeeFrac(ret, LIMIT);
    }

    FeeFrac MaxFee(bool only_chunks, bool agg) const
    {
        Frontier<int64_t> best(LIMIT, 0);
        Frontier<int64_t> no_effect(LIMIT, 0);
        std::vector<FeeFrac> feerates;
        for (const auto& cluster_data : feerates_by_cluster) {
            feerates = only_chunks ? cluster_data.first : cluster_data.second;
            if (agg) {
                size_t outlen = 0;
                for (size_t inpos = 0; inpos < feerates.size(); ++inpos) {
                    if (inpos == 0 || feerates[inpos] << feerates[inpos - 1]) {
                        feerates[outlen] = feerates[inpos];
                        ++outlen;
                    } else {
                        feerates[outlen - 1] += feerates[inpos];
                    }
                }
                feerates.resize(outlen);
            }
            FeeFrac cluster_so_far;
            for (auto& feerate : feerates) {
                cluster_so_far += feerate;
                feerate = cluster_so_far;
            }
            while (!feerates.empty()) {
                if (!no_effect.Test(feerates.back().size, feerates.back().fee)) break;
                feerates.pop_back();
            }
            if (feerates.empty()) continue;
            bool updated = false;
            auto old = best.Last();
            do {
                for (size_t c = 0; c < feerates.size(); ++c) {
                    const auto& feerate = feerates[c];
                    auto new_size = old.first + feerate.size;
                    if (new_size <= LIMIT) {
                        if (best.Set(new_size, old.second + feerate.fee)) {
                            updated = true;
                        }
                    }
                }
            } while(best.PreviousTick(old));
            if (!updated) {
                for (size_t c = 0; c < feerates.size(); ++c) {
                    const auto& feerate = feerates[c];
                    no_effect.Set(feerate.size, feerate.fee);
                }
            }
        }
        return FeeFrac(best.Last().second, best.Last().first);
    }

    FeeFrac BuildBlock() const
    {
        std::unordered_set<uint64_t> stopped_cluster_ids;
        int64_t fees{0};
        uint32_t weight{0};
        int consecutive_failed = 0;
        for (const auto& [chunk_feerate, cluster_id, _chunk_pos] : chunk_feerates) {
            if (stopped_cluster_ids.count(cluster_id)) continue;
            if (chunk_feerate.size + weight <= LIMIT) {
                fees += chunk_feerate.fee;
                weight += chunk_feerate.size;
                consecutive_failed = 0;
            } else {
                ++consecutive_failed;
                if (consecutive_failed > MAX_CONSECUTIVE_FAILURES && weight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > LIMIT) {
                    break;
                }
                stopped_cluster_ids.insert(cluster_id);
            }
        }
        return FeeFrac(fees, weight);
    }
};

void ProcessPool(const Pool& pool)
{
    auto ts = PrintTime(NodeClock::time_point(pool.first));
    unsigned ntx{0};
    unsigned ndep{0};
    unsigned nchunk{0};
    unsigned ncluster{0};
    std::vector<DepGraphIndex> lin;
    for (const auto& graph : pool.second) {
        lin.resize(graph.TxCount());
        std::iota(lin.begin(), lin.end(), DepGraphIndex{0});
        auto chunking = ChunkLinearization(graph, lin);
        nchunk += chunking.size();
        for (auto pos : graph.Positions()) {
            ndep += graph.GetReducedParents(pos).Count();
            ntx += 1;
        }
        ncluster += 1;
    }

    FeeRateData data(pool);
    auto minrate = data.MinChunkFeeRate();
    auto maxrate = data.MaxChunkFeeRate();
    auto totrate = data.TotalFeeRate();
    auto meta_str = tfm::format("%u META date=%s clusters=%u chunks=%u txn=%u deps=%u mempool_mvb=%f minrate=%f avgrate=%f maxrate=%f\n", pool.first.count(), ts, ncluster, nchunk, ntx, ndep, totrate.size / 4000000.0, minrate.fee * 4.0 / minrate.size, totrate.fee * 4.0 / totrate.size, maxrate.fee * 4.0 / maxrate.size);
    std::cout << meta_str;

    auto lower = data.LowerBound();
    auto lower_str = tfm::format("%u EAGER_CHUNKFEE %u %u\n", pool.first.count(), lower.fee, lower.size);
    std::cout << lower_str;

    auto upper = data.UpperBound();
    auto upper_str = tfm::format("%u OVERESTIMATE_FEE %u %u\n", pool.first.count(), upper.fee, upper.size);
    std::cout << upper_str;

    auto maxfee_chunk = data.MaxFee(true, false);
    auto maxfee_chunk_str = tfm::format("%u MAX_MINCHUNK_FEE %u %u\n", pool.first.count(), maxfee_chunk.fee, maxfee_chunk.size);
    std::cout << maxfee_chunk_str;

    auto maxfee_maxchunk = data.MaxFee(true, true);
    auto maxfee_maxchunk_str = tfm::format("%u MAX_MAXCHUNK_FEE %u %u\n", pool.first.count(), maxfee_maxchunk.fee, maxfee_maxchunk.size);
    std::cout << maxfee_maxchunk_str;

    auto maxfee_lin = data.MaxFee(false, false);
    auto maxfee_lin_str = tfm::format("%u MAX_LIN_FEE %u %u\n", pool.first.count(), maxfee_lin.fee, maxfee_lin.size);
    std::cout << maxfee_lin_str;

    auto block_build = data.BuildBlock();
    auto block_build_str = tfm::format("%u BLOCK_BUILD %u %u\n", pool.first.count(), block_build.fee, block_build.size);
    std::cout << block_build_str;
}

std::optional<Pool> LoadPool(AutoFile& input)
{
    if (input.feof()) return std::nullopt;
    std::vector<Graph> ret;
    uint64_t ts;
    try {
        input >> ts;
    } catch (const std::ios_base::failure&) {
        return std::nullopt;
    }
    while (true) {
        Graph graph;
        input >> Using<DepGraphFormatter>(graph);
        if (graph.TxCount() == 0) break;
        ret.push_back(std::move(graph));
    }
    return Pool(std::chrono::microseconds(ts), std::move(ret));
}

} // namespace

MAIN_FUNCTION
{
    std::cout.setf(std::ios::unitbuf);
    ArgsManager& args = gArgs;
    SetupEnvironment();
    RandomInit();

    std::string error;
    args.AddArg("-threads=<n>", "Number of worker threads to use", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    int threads = args.GetIntArg("-threads", 1);
    size_t queue_max = 3 * threads;

    std::mutex cs;
    VecDeque<Pool> queue;
    std::condition_variable queue_nonfull;
    std::condition_variable queue_nonempty;
    bool done{false};

    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&,i]() {
            while (true) {
                Pool pool;
                {
                    std::unique_lock lock(cs);
                    queue_nonempty.wait(lock, [&]{ return done || queue.size() > 0; });
                    if (done) break;
                    pool = std::move(queue.front());
                    queue.pop_front();
                    queue_nonfull.notify_one();
                }
                ProcessPool(pool);
            }
        });
    }

    AutoFile instream(stdin);
    while (true) {
        auto pool = LoadPool(instream);
        {
            std::unique_lock lock(cs);
            if (!pool.has_value()) {
                done = true;
                queue_nonempty.notify_all();
                break;
            }
            queue_nonfull.wait(lock, [&]{ return queue.size() < queue_max; });
            queue.emplace_front(std::move(*pool));
            queue_nonempty.notify_one();
        }
    }

    for (auto& thread : workers) thread.join();

    return 0;
}
