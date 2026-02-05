// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/args.h>
#include <common/system.h>
#include <clientversion.h>
#include <cluster_linearize.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/cluster_linearize.h>
#include <util/exception.h>
#include <util/fs.h>
#include <util/string.h>
#include <util/translation.h>
#include <util/tdigest.h>
#include <util/splittimer.h>

#include <cstdio>
#include <charconv>
#include <map>
#include <random>
#include <string_view>
#include <utility>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>

using namespace std::literals;

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

using Job = std::pair<DepGraph<BitSet<64>>, uint64_t>;

template<typename T, typename State, typename Func>
class BoundedJobQueue {
    VecDeque<T> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv_not_empty;
    std::condition_variable m_cv_not_full;
    const Func& m_func;
    const size_t m_max_size;
    bool m_done = false;
    std::vector<std::thread> m_threads;
    std::vector<State> m_states;
    size_t m_group_size;

    bool Pop(std::vector<T>& items) {
        std::unique_lock lock(m_mutex);
        m_cv_not_empty.wait(lock, [&] { return m_queue.size() >= m_group_size || m_done; });
        if (m_queue.empty()) return false;
        while (items.size() < m_group_size && !m_queue.empty()) {
            items.push_back(std::move(m_queue.front()));
            m_queue.pop_front();
        }
        m_cv_not_full.notify_one();
        return true;
    }

public:
    explicit BoundedJobQueue(size_t num_threads, const Func& func, size_t group_size) : m_func(func), m_max_size(num_threads ? 5 * num_threads * group_size: 0), m_group_size(group_size)
    {
        m_queue.reserve(m_max_size);
        if (num_threads == 0) {
            m_states.resize(1);
        } else {
            m_threads.reserve(num_threads);
            m_states.resize(num_threads);
            for (size_t i = 0; i < num_threads; ++i) {
                m_threads.emplace_back([&, i]() noexcept {
                    std::vector<T> jobs;
                    while (Pop(jobs)) {
                        for (auto& job : jobs) {
                            m_func(job, m_states[i]);
                        }
                        jobs.clear();
                    }
                });
            }
        }
    }

    void Add(T&& item) noexcept {
        if (m_max_size > 0) {
            std::unique_lock lock(m_mutex);
            m_cv_not_full.wait(lock, [&] { return m_queue.size() < m_max_size; });
            m_queue.push_back(std::move(item));
            if (m_queue.size() >= m_group_size) m_cv_not_empty.notify_one();
        } else {
            m_func(item, m_states[0]);
        }
    }

    std::vector<State> Finish()
    {
        {
            std::lock_guard lock(m_mutex);
            m_done = true;
        }
        m_cv_not_empty.notify_all();
        for (auto& thread : m_threads) thread.join();
        m_threads.clear();
        auto ret = std::move(m_states);
        m_states.clear();
        return ret;
    }

};

using InnerTable = std::map<
    std::pair<uint32_t, uint32_t>,
    TDigest
>;

using Table = std::map<
    std::string_view,
    InnerTable
>;

struct MeasureEvent
{
    std::string_view name;
    uint32_t param1;
    uint32_t param2;
    int64_t duration;

    void LoadInto(Table& table) const noexcept
    {
        auto& inner = table.try_emplace(name).first->second;
        auto& digest = inner.try_emplace(std::make_pair(param1, param2), 16384.0, 65535).first->second;
        digest.Add(duration);
    }
};

class CPUBurner
{
    uint64_t v0, v1, v2, v3;
    static constexpr size_t MEM_SIZE = 0x40000;
    std::vector<uint64_t> mem;

    void SipRound() noexcept
    {
        v0 += v1;
        v1 = std::rotl(v1, 13);
        v1 ^= v0;
        v0 = std::rotl(v0, 32);
        v2 += v3;
        v3 = std::rotl(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = std::rotl(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = std::rotl(v1, 17);
        v1 ^= v2;
        v2 = std::rotl(v2, 32);
    }

public:
    CPUBurner() noexcept
    {
        FastRandomContext rng;
        v0 = rng.rand64();
        v1 = rng.rand64();
        v2 = rng.rand64();
        v3 = rng.rand64();
        mem.resize(MEM_SIZE);
        for (auto& element : mem) element = rng.rand64();
    }

    uint64_t operator()() noexcept
    {
        // A conditional, and interaction with memory.
        if (v1 & 1) {
            mem[v0 % MEM_SIZE] += v1;
            v0 *= 0x3c90430b8a68e831;
            v2 ^= mem[v0 % MEM_SIZE];
            mem[v1 % MEM_SIZE] *= (v2 | 1);
            v1 ^= 0x3e982d4b2b914f8d;
            v3 += mem[v1 % MEM_SIZE];
        } else {
            mem[v1 % MEM_SIZE] ^= v0;
            v1 += 0x517201d19c1180da;
            v3 *= (mem[v1 % MEM_SIZE] | 1);
            mem[v0 % MEM_SIZE] += v3;
            v0 *= 0x5a73f8393e29e71b;
            v2 ^= mem[v0 % MEM_SIZE];
        }
        // One SipHash round.
        SipRound();
        return v0 ^ v1 ^ v2 ^ v3;
    }

    void Add(uint64_t x) noexcept
    {
        v3 ^= x;
        SipRound();
    }

    int64_t ProbablyZero() const noexcept
    {
        return ((v0 % 3) - 1) * ((v1 % 3) - 1) * ((v2 % 3) - 1) * ((v3 % 3) - 1);
    }
};

CPUBurner g_burner;

/** Determine the TSC frequency in GHz. */
double BenchmarkTSC() noexcept
{
    double timings[101];

    SplitTimer<1> timer;
    timer.Reset<0>();
    auto last_time = std::chrono::steady_clock::now();

    for (int q = 0; q < 101; ++q) {
        for (int i = 0; i < 1000000; ++i) g_burner();
        int64_t ticks = timer.Lap<0>() + g_burner.ProbablyZero();
        auto cur_time = std::chrono::steady_clock::now();
        int64_t nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(cur_time - last_time).count();
        last_time = cur_time;
        g_burner.Add(ticks);
        g_burner.Add(nanos);
        timings[q] = (double)ticks / nanos;
    }
    std::ranges::sort(timings);
    return timings[50];
}

struct EventLog
{
    std::vector<MeasureEvent> events;

    EventLog() noexcept
    {
        events.reserve(4096);
    }

    void LoadAllInto(Table& table) noexcept
    {
        for (const auto& event : events) event.LoadInto(table);
        events.clear();
    }
};

class SFLMeasureModel
{
    EventLog& m_eventlog;
    SplitTimer<4> m_timer;

    template<int T>
    inline void Start() noexcept
    {
        m_timer.Reset<T>();
    }

    template<int T>
    inline void Add(std::string_view name, uint32_t param1 = uint32_t(-1), uint32_t param2 = uint32_t(-1)) noexcept
    {
        auto dur = m_timer.Lap<T>();
        m_eventlog.events.emplace_back(name, param1, param2, dur);
    }

public:
    SFLMeasureModel(EventLog& eventlog) noexcept : m_eventlog{eventlog} {}

    // Top level functions
    inline void InitializeBegin() noexcept { Start<0>(); }
    inline void InitializeEnd(int num_txns, int num_deps) noexcept { Add<0>("Initialize"sv, num_txns); }
    inline void GetLinearizationBegin() noexcept { Start<0>(); }
    inline void GetLinearizationEnd(int num_txns, int num_deps) noexcept { Add<0>("GetLinearization"sv, num_txns, num_deps); }
    inline void MakeTopologicalBegin() noexcept { Start<0>(); }
    inline void MakeTopologicalEnd(int num_chunks, int num_steps) noexcept { Add<0>("MakeTopological"sv, num_chunks, num_steps); }
    inline void StartOptimizingBegin() noexcept { Start<0>(); }
    inline void StartOptimizingEnd(int num_chunks) noexcept { Add<0>("StartOptimizing"sv, num_chunks); }
    inline void StartMinimizingBegin() noexcept { Start<0>(); }
    inline void StartMinimizingEnd(int num_chunks) noexcept { Add<0>("StartMinimizing"sv, num_chunks); }
    inline void MinimizeStepBegin() noexcept { Start<0>(); }
    inline void MinimizeStepMid(int num_txns) noexcept { Add<0>("MinimizeStep1"sv, num_txns); }
    inline void MinimizeStepEnd(bool split) noexcept { Add<0>("MinimizeStep2"sv, split); }

    // Mid level functions
    inline void MergeChunksBegin() noexcept { Start<1>(); }
    inline void MergeChunksMid(int num_txns) noexcept { Add<1>("MergeChunks1"sv, num_txns); }
    inline void MergeChunksEnd(int num_steps) noexcept { Add<1>("MergeChunks2"sv, num_steps); }
    inline void PickMergeCandidateBegin() noexcept { Start<1>(); }
    inline void PickMergeCandidateEnd(int num_steps) noexcept { Add<1>("PickMergeCandidate"sv, num_steps); }
    inline void PickChunkToOptimizeBegin() noexcept { Start<1>(); }
    inline void PickChunkToOptimizeEnd(int num_steps) noexcept { Add<1>("PickChunkToOptimize"sv, num_steps); }
    inline void PickDependencyToSplitBegin() noexcept { Start<1>(); }
    inline void PickDependencyToSplitEnd(int num_txns) noexcept { Add<1>("PickDependendencyToSplit"sv, num_txns); }

    // Low level functions. Note that the Model interface uses num_deps, while the digests use num_txns.
    inline void ActivateBegin() noexcept { Start<2>(); }
    inline void ActivateEnd(int num_deps) noexcept { Add<2>("Activate"sv, num_deps + 1); }
    inline void DeactivateBegin() noexcept { Start<2>(); }
    inline void DeactivateEnd(int num_deps) noexcept { Add<2>("Deactivate"sv, num_deps + 1); }

    // Calibration only functions.
    inline void CalibrateStartL0() noexcept { Start<0>(); }
    inline void CalibrateEndL0(bool bottom) noexcept { Add<0>(bottom ? "CalibrateGood"sv : "CalibrateBad"sv); }
    inline void CalibrateStartL1() noexcept { Start<1>(); }
    inline void CalibrateEndL1(bool bottom) noexcept { Add<1>(bottom ? "CalibrateGood"sv : "CalibrateBad"sv); }
    inline void CalibrateStartL2() noexcept { Start<2>(); }
    inline void CalibrateEndL2(bool bottom) noexcept { Add<2>(bottom ? "CalibrateGood"sv : "CalibrateBad"sv); }
    inline void CalibrateStartL3() noexcept { Start<3>(); }
    inline void CalibrateEndL3(bool bottom) noexcept { Add<3>(bottom ? "CalibrateGood"sv : "CalibrateBad"sv); }

    inline uint64_t GetCost() const noexcept { return 0; }

};

void BenchmarkOverhead(SFLMeasureModel& model) noexcept
{
    for (int j = 0; j < 3; ++j) {
        model.CalibrateStartL0(); // L0
        while (true) {
            model.CalibrateStartL1(); // L0- L1
            model.CalibrateEndL1(true); // L0-
            if ((g_burner() % 2) == 0) break;
        }
        model.CalibrateEndL0(false); // []
        model.CalibrateStartL0(); // L0
        g_burner(); // L0-
        model.CalibrateStartL1(); // L0- L1
        model.CalibrateStartL2(); // L0- L1 L2
        int iters = g_burner() % 4; // L0- L1 L2-
        for (int k = 0; k < iters; ++k) {
            model.CalibrateStartL3(); // L0- L1 L2- L3
            model.CalibrateEndL3(true); // L0- L1 L2-
        }
        model.CalibrateEndL2(false); // L0- L1
        model.CalibrateEndL1(true); // L0-
        model.CalibrateEndL0(false); // []
        model.CalibrateStartL0(); // L0
        model.CalibrateStartL1(); // L0 L1
        model.CalibrateStartL2(); // L0 L1 L2
        model.CalibrateStartL3(); // L0 L1 L2 L3
        model.CalibrateEndL3(true); // L0 L1 L2
        model.CalibrateStartL3(); // L0 L1 L2 L3
        g_burner(); // L0 L1 L2 L3-
        model.CalibrateEndL3(false); // L0 L1 L2
        model.CalibrateEndL2(true); // L0 L1
        model.CalibrateStartL2(); // L0 L1 L2
        g_burner(); // L0 L1 L2-
        model.CalibrateEndL2(false); // L0 L1
        model.CalibrateEndL1(true); // L0
        model.CalibrateEndL0(true); // []
    }
}

template<typename SetType, typename ModelType>
std::pair<std::vector<DepGraphIndex>, uint64_t> LinearizeModel(ModelType& model, const DepGraph<SetType>& depgraph, uint64_t rng_seed, std::span<const DepGraphIndex> old_linearization, bool is_topological) noexcept
{
    /** Initialize a spanning forest data structure for this cluster. */
    SpanningForestState forest(depgraph, rng_seed, model);
    if (!old_linearization.empty()) {
        forest.LoadLinearization(old_linearization);
        if (!is_topological) forest.MakeTopological();
    } else {
        forest.MakeTopological();
    }
    // Make improvement steps to it until we hit the max_iterations limit, or an optimal result
    // is found.
    forest.StartOptimizing();
    do {
        if (!forest.OptimizeStep()) break;
    } while (true);
    // Make chunk minimization steps until we hit the max_iterations limit, or all chunks are
    // minimal.
    bool optimal = false;
    forest.StartMinimizing();
    do {
        if (!forest.MinimizeStep()) {
            optimal = true;
            break;
        }
    } while (true);
    return {forest.GetLinearization(IndexTxOrder{}), forest.GetCost()};
}

template<typename Func, typename SetType>
void IterateGraph(const DepGraph<SetType>& depgraph, uint64_t rng_seed, uint64_t iters, const Func& linearize)
{
    InsecureRandomContext rng(rng_seed);

    auto depgraph_neg = NegateDepGraph(depgraph);

    unsigned txn = depgraph.TxCount();
    std::vector<unsigned> lin, lin_input;
    for (auto i : depgraph.Positions()) lin_input.push_back(i);

    for (int i = 0; i < iters; ++i) {
        bool opt{false};
        switch (rng.randrange(4 + 2 * (i > 0))) {
        case 0:
            // Linearize from scratch.
            lin = linearize(depgraph, rng.rand64(), {}, false, /*is_dummy=*/false);
            break;
        case 1:
            // Linearize with a linearization for the negated graph as input (which itself is
            // created from scratch).
            lin_input = linearize(depgraph_neg, rng.rand64(), {}, false, /*is_dummy=*/true);
            lin = linearize(depgraph, rng.rand64(), lin_input, true, /*is_dummy=*/false);
            break;
        case 2:
            // Linearize with a valid but arbitrary linearization as input.
            std::shuffle(lin_input.begin(), lin_input.end(), rng);
            std::sort(lin_input.begin(), lin_input.end(), [&](auto a, auto b) { return depgraph.Ancestors(a).Count() < depgraph.Ancestors(b).Count(); });
            lin = linearize(depgraph, rng.rand64(), lin_input, true, /*is_dummy=*/false);
            break;
        case 3:
            // Linearization with an arbitrary (not necessarily valid) permutation as input.
            std::shuffle(lin_input.begin(), lin_input.end(), rng);
            lin = linearize(depgraph, rng.rand64(), lin_input, false, /*is_dummy=*/false);
            break;
        case 4:
            // Linearize with the previout linearization as input.
            lin_input = lin;
            lin = linearize(depgraph, rng.rand64(), lin_input, true, /*is_dummy=*/false);
            break;
        case 5:
            // Linearize with the previous linearization, PostLinearized, as input.
            lin_input = lin;
            PostLinearize(depgraph, lin_input);
            lin = linearize(depgraph, rng.rand64(), lin_input, true, /*is_dummy=*/false);
        }
    }
}

template<typename JobQueue>
size_t ProcessFile(JobQueue& queue, FILE* file, bool mempool_format)
{
    size_t ret{0};
    AutoFile reader(file);
    if (!mempool_format) {
        while (!reader.feof()) {
            auto build = ReadDepGraphBuilder<BitSet<64>>(reader);
            if (!build) continue;
            ++ret;
            queue.Add(std::move(*build));
        }
    } else {
        uint64_t min_ts = std::numeric_limits<uint64_t>::max();
        uint64_t max_ts = std::numeric_limits<uint64_t>::min();
        while (!reader.feof()) {
            bool good = true;
            uint64_t ts = 0;
            try {
                reader >> ts;
            } catch(const std::ios_base::failure&) {
                good = false;
            }
            if (!good) break;
            min_ts = std::min(min_ts, ts);
            max_ts = std::max(max_ts, ts);
            while (true) {
                DepGraph<BitSet<64>> depgraph;
                reader >> Using<DepGraphFormatter>(depgraph);
                if (depgraph.TxCount() == 0) break;
                Job item(std::move(depgraph), 0);
                ++ret;
                queue.Add(std::move(item));
            }
        }
        std::cerr << "Processed " << ret << " clusters between " << FormatISO8601DateTime(min_ts / 1000000) << " and " << FormatISO8601DateTime(max_ts / 1000000) << "\n";
    }
    return ret;
}

template<typename JobQueue>
void ProcessArgument(JobQueue& queue, const std::string& arg, bool mempool_format)
{
    std::cerr << "Processing " << arg << "\n";
    std::vector<uint8_t> buffer;
    fs::path input_path(arg.c_str());
    if (arg == "-") {
        ProcessFile(queue, stdin, mempool_format);
    } else if (fs::is_directory(input_path)) {
        std::vector<fs::path> files;
        for (fs::directory_iterator it(input_path); it != fs::directory_iterator(); ++it) {
            if (!fs::is_regular_file(it->path())) continue;
            files.emplace_back(it->path());
        }
        std::ranges::shuffle(files, std::mt19937{std::random_device{}()});
        for (const auto& input_path : files) {
            FILE* file = fopen(input_path.c_str(), "rb");
            if (file) ProcessFile(queue, file, mempool_format);
        }
    } else {
        FILE* file = fopen(arg.c_str(), "rb");
        if (file) ProcessFile(queue, file, mempool_format);
    }
}

void SetupToolArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-version", "Print version information", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-iters", "Number of iterations per cluster", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-threads", "Number of computation threads to use (default = 0). Not advisable for `run` action.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-mempool", "Read input in mempool format.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-batchsize", "How many clusters to process per job.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddCommand("run", "Run all clusters in specified files and directories to build a model.");
    argsman.AddCommand("calibrate", "Determine the CPU's TSC frequency.");
    argsman.AddCommand("maxcost", "Run all clusters in specified files and directories with the current model to determine max cost.");
    argsman.AddCommand("costhisto", "Run all clusters in specified files and directories with the current model and output cost histogram per tx count.");
}

std::optional<int> AppInit(ArgsManager& args, int argc, char* argv[])
{
    SetupToolArgs(args);
    std::string error_message;
    if (!args.ParseParameters(argc, argv, error_message)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error_message);
        return EXIT_FAILURE;
    }
    const bool missing_args{argc < 2};
    if (missing_args || HelpRequested(args) || args.GetBoolArg("-version", false)) {
        std::string strUsage = strprintf("%s bitcoin-costmodel utility version", CLIENT_NAME) + " " + FormatFullVersion() + "\n";

        if (args.GetBoolArg("-version", false)) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "Usage: bitcoin-costmodel [options] <command>\n"
                "\n";
            strUsage += "\n" + args.GetHelpMessage();
        }
        tfm::format(std::cout, "%s", strUsage);
        if (missing_args) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    return std::nullopt;
}

} // namespace

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;

    SetupEnvironment();
    RandomInit();

    try {
        if (const auto maybe_exit{AppInit(args, argc, argv)}) return *maybe_exit;
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInit()");
        return EXIT_FAILURE;
    }

    const auto command = args.GetCommand();
    if (!command) {
        tfm::format(std::cerr, "No method provided. Run `bitcoin-costmodel -help` for valid methods.\n");
        return EXIT_FAILURE;
    }

    if (command->command == "run") {
        double tsc_ghz = BenchmarkTSC();
        double inv_tsc_ghz = 1.0 / tsc_ghz;
        std::cout << "# TSC clock: " << tsc_ghz << " GHz\n\n";
        Table table;
        int iters = args.GetIntArg("-iters", 15);
        int threads = args.GetIntArg("-threads", 0);
        int groupsize = args.GetIntArg("-batchsize", 1);
        bool mempool = args.GetBoolArg("-mempool", false);
        auto run_fn = [&](Job& job, Table& table) noexcept {
            IterateGraph(job.first, job.second, iters, [&](const auto& depgraph, uint64_t rng_seed, std::span<const DepGraphIndex> input, bool is_topo, bool is_dummy) noexcept {
                EventLog log;
                SFLMeasureModel model(log);
                auto [lin, _cost] = LinearizeModel(model, depgraph, rng_seed, input, is_topo);
                BenchmarkOverhead(model);
                log.LoadAllInto(table);
                return lin;
            });
        };
        BoundedJobQueue<Job, Table, decltype(run_fn)> queue(threads, run_fn, groupsize);
        for (const auto& arg : command->args) {
            ProcessArgument(queue, arg, mempool);
        }
        auto tables = queue.Finish();
        auto combined_table = std::move(tables.back());
        tables.pop_back();
        for (auto& table : tables) {
            for (auto& [key, inner] : table) {
                auto& combined_inner = combined_table[key];
                for (auto& [params, tdigest] : inner) {
                    auto it = combined_inner.find(params);
                    if (it != combined_inner.end()) {
                        it->second.Absorb(std::move(tdigest));
                    } else {
                        combined_inner.emplace(params, std::move(tdigest));
                    }
                }
            }
        }
        for (auto& [key, inner] : combined_table) {
            for (auto& [params, tdigest] : inner) {
                for (auto [avg, weight] : tdigest.Dump()) {
                    std::cout << key << " ";
                    if (params.first == uint32_t(-1)) {
                        std::cout << "- ";
                    } else {
                        std::cout << params.first << " ";
                    }
                    if (params.second == uint32_t(-1)) {
                        std::cout << "- ";
                    } else {
                        std::cout << params.second << " ";
                    }
                    char out[32];
                    auto out_result = std::to_chars(std::begin(out), std::end(out), avg * inv_tsc_ghz);
                    std::cout << std::string_view(std::begin(out), out_result.ptr) << " ";
                    out_result = std::to_chars(std::begin(out), std::end(out), weight);
                    std::cout << std::string_view(std::begin(out), out_result.ptr) << "\n";
                }
            }
        }
    } else if (command->command == "maxcost") {
        int iters = args.GetIntArg("-iters", 15);
        int threads = args.GetIntArg("-threads", 0);
        bool mempool = args.GetBoolArg("-mempool", false);
        int groupsize = args.GetIntArg("-batchsize", 1);
        auto run_fn = [&](Job& job, std::map<unsigned, uint64_t>& max_cost) noexcept {
            IterateGraph(job.first, job.second, iters, [&](const auto& depgraph, uint64_t rng_seed, std::span<const DepGraphIndex> input, bool is_topo, bool is_dummy) noexcept {
                auto [lin, opt, cost] = Linearize(depgraph, 1000000000000, rng_seed, IndexTxOrder{}, input, is_topo);
                assert(opt);
                auto ntx = depgraph.TxCount();
                max_cost[ntx] = std::max(max_cost[ntx], cost);
                return lin;
            });
        };
        BoundedJobQueue<Job, std::map<unsigned, uint64_t>, decltype(run_fn)> queue(threads, run_fn, groupsize);
        for (const auto& arg : command->args) {
            ProcessArgument(queue, arg, mempool);
        }
        auto max_costs = queue.Finish();
        auto combined_max_cost = std::move(max_costs.back());
        max_costs.pop_back();
        for (auto& max_cost : max_costs) {
            for (auto& [ntx, cost] : max_cost) {
                auto& combined_cost = combined_max_cost[ntx];
                combined_cost = std::max(combined_cost, cost);
            }
        }
        std::cout << "    static constexpr uint64_t ITERS[65] = {\n";
        std::cout << "        " << combined_max_cost[0] << ",\n";
        for (int i = 0; i < 8; ++i) {
            std::cout << "        ";
            for (int j = 1 + 8 * i; j <= 8 + 8 * i; ++j) {
                std::cout << combined_max_cost[j];
                if (j != 64) std::cout << ", ";
            }
            std::cout << "\n";
        }
        std::cout << "    };\n";
    } else if (command->command == "costhisto") {
        int iters = args.GetIntArg("-iters", 15);
        int threads = args.GetIntArg("-threads", 0);
        bool mempool = args.GetBoolArg("-mempool", false);
        int groupsize = args.GetIntArg("-batchsize", 1);
        auto run_fn = [&](Job& job, std::map<unsigned, TDigest>& digests) noexcept {
            IterateGraph(job.first, job.second, iters, [&](const auto& depgraph, uint64_t rng_seed, std::span<const DepGraphIndex> input, bool is_topo, bool is_dummy) noexcept {
                auto [lin, opt, cost] = Linearize(depgraph, 1000000000000, rng_seed, IndexTxOrder{}, input, is_topo);
                assert(opt);
                if (!is_dummy) {
                    auto ntx = depgraph.TxCount();
                    auto [it, _inserted] = digests.try_emplace(ntx, 4096.0, 65536);
                    it->second.Add(cost);
                }
                return lin;
            });
        };
        BoundedJobQueue<Job, std::map<unsigned, TDigest>, decltype(run_fn)> queue(threads, run_fn, groupsize);
        for (const auto& arg : command->args) {
            ProcessArgument(queue, arg, mempool);
        }
        auto all_digests = queue.Finish();
        auto combined_digests = std::move(all_digests.back());
        all_digests.pop_back();
        for (auto& digests : all_digests) {
            for (auto& [ntx, digest] : digests) {
                auto [it, _inserted] = combined_digests.try_emplace(ntx, 16384.0, 1048576);
                it->second.Absorb(std::move(digest));
            }
        }
        for (auto& [ntx, combined_digest] : combined_digests) {
            combined_digest.Shrink();
            auto dump = combined_digest.Dump();
            char out[32];
            for (auto [avg, weight] : dump) {
                std::cout << ntx << " ";
                auto out_result = std::to_chars(std::begin(out), std::end(out), avg);
                std::cout << std::string_view(std::begin(out), out_result.ptr) << " ";
                out_result = std::to_chars(std::begin(out), std::end(out), weight);
                std::cout << std::string_view(std::begin(out), out_result.ptr) << "\n";
            }
        }
    } else if (command->command == "calibrate") {
        double tsc_ghz = BenchmarkTSC();
        std::cout << "TSC clock: " << tsc_ghz << " GHz\n";
    } else {
        tfm::format(std::cerr, "Error: unknown command `%s`. Please refer to `-help`.\n", command->command);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
