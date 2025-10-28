// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <arith_uint256.h>
#include <util/bitset.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <cluster_linearize.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <core_io.h>
#include <random.h>
#include <streams.h>
#include <test/util/cluster_linearize.h>
#include <util/exception.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <thread>
#include <atomic>
#include <fstream>
#include <cstdio>
#include <functional>
#include <cmath>
#include <memory>
#include <thread>

using namespace cluster_linearize;

template<typename SetType>
static DepGraph<SetType> GenRandomCluster(int ntx, int ndeps, int nlevels, int group_threshold, FastRandomContext& rng)
{
    DepGraph<SetType> ret;
    assert(ntx >= nlevels);
    assert(ndeps >= ntx - 1);
    assert(ndeps <= ((ntx + 1) >> 1) * (ntx >> 1));
    std::vector<std::pair<DepGraphIndex, DepGraphIndex>> candidate_deps;
    std::vector<std::pair<DepGraphIndex, DepGraphIndex>> active_deps;
    std::vector<uint32_t> order;
    order.resize(ntx);
    std::vector<SetType> component_map;
    component_map.resize(ntx);
    for (int i = 0; i < ntx; ++i) {
        order[i] = i;
        component_map[i] = SetType::Singleton(i);
        int32_t size = rng.randrange<int32_t>(1000) + 100;
        int32_t ran = sqrt(size * size * (double)ntx);
        int32_t fee = int32_t(rng.randrange<uint32_t>(2 * ran + 1)) - ran;
        auto tx = ret.AddTransaction(FeeFrac{fee, size});
        assert(tx == (unsigned)i);
    }
    std::shuffle(order.begin(), order.end(), rng);
    if (nlevels == 0) {
        for (int p = 0; p < ntx; ++p) {
            for (int c = 0; c < ntx; ++c) {
                if (p != c) candidate_deps.emplace_back(p, c);
            }
        }
    } else {
        std::vector<std::vector<uint32_t>> by_level;
        by_level.resize(nlevels);
        for (int i = 0; i < nlevels; ++i) {
            by_level[i].push_back(order[i]);
        }
        for (int p = nlevels; p < ntx; ++p) {
            by_level[rng.randrange(nlevels)].push_back(order[p]);
        }
        for (int l = 1; l < nlevels; ++l) {
            for (auto p : by_level[l - 1]) {
                for (auto c : by_level[l]) {
                    candidate_deps.emplace_back(p, c);
                }
            }
        }
    }
    int max_size_sum = group_threshold + 2;
    while (active_deps.size() + 1 < (size_t)ntx) {
        bool found = false;
        bool avail = false;
        for (size_t pos = 0; pos < candidate_deps.size(); ++pos) {
            size_t pick = rng.randrange(candidate_deps.size() - pos) + pos;
            if (pick != pos) std::swap(candidate_deps[pos], candidate_deps[pick]);
            auto [p, c] = candidate_deps[pos];
            auto p_comp = component_map[p];
            auto c_comp = component_map[c];
            if (p_comp == c_comp) continue;
            avail = true;
            if (p_comp.Count() + c_comp.Count() > (unsigned)max_size_sum) continue;
            ret.AddDependencies(SetType::Singleton(p), c);
            active_deps.emplace_back(p, c);
            SetType comp = p_comp | c_comp;
            for (auto i : p_comp) {
                component_map[i] = comp;
            }
            for (auto i : c_comp) {
                component_map[i] = comp;
            }
            found = true;
        }
        assert(avail);
        if (!found) ++max_size_sum;
    }
    while (active_deps.size() < (size_t)ndeps && !candidate_deps.empty()) {
        size_t pick = rng.randrange(candidate_deps.size());
        if (pick != candidate_deps.size() - 1) std::swap(candidate_deps[pick], candidate_deps.back());
        auto [p, c] = candidate_deps.back();
        candidate_deps.pop_back();
        if (ret.Ancestors(c)[p]) continue;
        if (ret.Descendants(c)[p]) continue;
        bool bad = false;
        for (auto [ap, ac] : active_deps) {
            if (ret.Ancestors(p)[ap] && ret.Descendants(c)[ac]) {
                bad = true;
                break;
            }
        }
        if (bad) continue;
        ret.AddDependencies(SetType::Singleton(p), c);
        active_deps.emplace_back(p, c);
    }
    return ret;
}

static const int CONTINUE_EXECUTION=-1;

const TranslateFn G_TRANSLATION_FUN{nullptr};

static void SetupBitcoinUtilArgs(ArgsManager &argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddCommand("grind", "Perform proof of work on hex header string");
    argsman.AddCommand("gengraph", "Generate hard graphs");
    argsman.AddCommand("rungraph", "Linearize graphs read from stdin");

    SetupChainParamsBaseOptions(argsman);
}

// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
static int AppInitUtil(ArgsManager& args, int argc, char* argv[])
{
    SetupBitcoinUtilArgs(args);
    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    if (HelpRequested(args) || args.GetBoolArg("-version", false)) {
        // First part of help message is specific to this utility
        std::string strUsage = CLIENT_NAME " bitcoin-util utility version " + FormatFullVersion() + "\n";

        if (args.GetBoolArg("-version", false)) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "The bitcoin-util tool provides bitcoin related functionality that does not rely on the ability to access a running node. Available [commands] are listed below.\n"
                "\n"
                "Usage:  bitcoin-util [options] [command]\n"
                "or:     bitcoin-util [options] grind <hex-block-header>\n";
            strUsage += "\n" + args.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);

        if (argc < 2) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // Check for chain settings (Params() calls are only valid after this clause)
    try {
        SelectParams(args.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return CONTINUE_EXECUTION;
}

static void grind_task(uint32_t nBits, CBlockHeader header, uint32_t offset, uint32_t step, std::atomic<bool>& found, uint32_t& proposed_nonce)
{
    arith_uint256 target;
    bool neg, over;
    target.SetCompact(nBits, &neg, &over);
    if (target == 0 || neg || over) return;
    header.nNonce = offset;

    uint32_t finish = std::numeric_limits<uint32_t>::max() - step;
    finish = finish - (finish % step) + offset;

    while (!found && header.nNonce < finish) {
        const uint32_t next = (finish - header.nNonce < 5000*step) ? finish : header.nNonce + 5000*step;
        do {
            if (UintToArith256(header.GetHash()) <= target) {
                if (!found.exchange(true)) {
                    proposed_nonce = header.nNonce;
                }
                return;
            }
            header.nNonce += step;
        } while(header.nNonce != next);
    }
}

static int Grind(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() != 1) {
        strPrint = "Must specify block header to grind";
        return EXIT_FAILURE;
    }

    CBlockHeader header;
    if (!DecodeHexBlockHeader(header, args[0])) {
        strPrint = "Could not decode block header";
        return EXIT_FAILURE;
    }

    uint32_t nBits = header.nBits;
    std::atomic<bool> found{false};
    uint32_t proposed_nonce{};

    std::vector<std::thread> threads;
    int n_tasks = std::max(1u, std::thread::hardware_concurrency());
    threads.reserve(n_tasks);
    for (int i = 0; i < n_tasks; ++i) {
        threads.emplace_back(grind_task, nBits, header, i, n_tasks, std::ref(found), std::ref(proposed_nonce));
    }
    for (auto& t : threads) {
        t.join();
    }
    if (found) {
        header.nNonce = proposed_nonce;
    } else {
        strPrint = "Could not satisfy difficulty target";
        return EXIT_FAILURE;
    }

    DataStream ss{};
    ss << header;
    strPrint = HexStr(ss);
    return EXIT_SUCCESS;
}

static constexpr int NUM_THREADS = 124;
static constexpr int KEEP_PER_NTX = 1000;
static constexpr int NUM_SEEDS = 100;

static int RunGraph(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() != 1) {
        strPrint = "Must specify iterations per graph";
        return EXIT_FAILURE;
    }

    unsigned iter_per_graph = 1;
    std::from_chars(args[0].data(), args[0].data() + args[0].size(), iter_per_graph);
    unsigned graphs_per_batch = 1 + (100000 / iter_per_graph);

    std::map<unsigned, uint64_t> results;
    std::mutex in_cs;
    std::mutex out_cs;
    bool done = false;
    uint64_t num_lines = 0;
    auto thread_fn = [&, iter_per_graph, graphs_per_batch](int thn) {
        std::vector<std::string> lines;
        while (true) {
            lines.clear();
            {
                std::unique_lock lock(in_cs);
                if (done) return;
                for (unsigned i = 0; i < graphs_per_batch; ++i) {
                    std::string line;
                    if (!std::getline(std::cin, line)) {
                        done = true;
                        break;
                    }
                    lines.emplace_back(std::move(line));
                }
            }
            std::map<unsigned, uint64_t> local_res;
            for (auto& line : lines) {
                while (!line.empty()) {
                    auto fnd = line.find(' ');
                    std::string now;
                    if (fnd == line.npos) {
                        now = line;
                        line = "";
                    } else {
                        now = line.substr(0, fnd);
                        line = line.substr(fnd + 1);
                    }
                    auto eq = now.find("hex=");
                    if (eq != now.npos) {
                        auto data = ParseHex<uint8_t>(now.substr(eq + 4));
                        SpanReader reader(data);
                        DepGraph<BitSet<64>> depgraph;
                        reader >> Using<DepGraphFormatter>(depgraph);
                        uint64_t out = 0;
                        for (unsigned iter = 0; iter < iter_per_graph; ++iter) {
                            auto [lin, _opt, cost] = Linearize(depgraph, 1000000000, iter, {});
                            out = std::max(out, cost);
                        }
                        uint64_t& outr = local_res[depgraph.TxCount()];
                        outr = std::max(outr, out);
                    }
                }
            }
            {
                std::unique_lock lock(out_cs);
                for (const auto& [ntx, nout] : local_res) {
                    uint64_t& outr = results[ntx];
                    outr = std::max(outr, nout);
                }
                auto new_lines = num_lines + lines.size();
                if ((new_lines * iter_per_graph) / 50000 != (num_lines * iter_per_graph) / 50000) {
                    std::cerr << "# " << new_lines << " lines done\n";
                    std::cerr << "{";
                    for (unsigned i = 0; i <= 64; ++i) {
                        if (i) std::cerr << ", ";
                        if (results.count(i)) {
                            std::cerr << results[i];
                        } else {
                            std::cerr << 0;
                        }
                    }
                    std::cerr << "};\n";
                }
                num_lines = new_lines;
            }
        }
    };
    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; ++i) {
        threads.emplace_back(thread_fn, i);
    }
    for (auto& thread : threads) thread.join();
    {
        std::unique_lock lock(out_cs);
        std::cerr << "{";
        for (unsigned i = 0; i <= 64; ++i) {
            if (i) std::cerr << ", ";
            if (results.count(i)) {
                std::cerr << results[i];
            } else {
                std::cerr << 0;
            }
        }
        std::cerr << "};\n";
    }
    return 0;
}

static int GenGraph()
{
    RandomInit();
    std::atomic<int> merger{0};
    uint64_t glob_tot_tot_cost = 0;
    uint64_t glob_num_merges = 0;
    uint64_t glob_params = 0;
    uint64_t glob_clusters = 0;
    std::map<unsigned, std::vector<std::pair<uint64_t, std::vector<unsigned char>>>> db;
    auto thread_fn = [&](int threadnum) {
        FastRandomContext rng;
        std::map<unsigned, std::vector<std::pair<uint64_t, std::vector<unsigned char>>>> local_db;
        uint64_t tot_tot_cost = 0;
        uint64_t params = 0;
        uint64_t clusters = 0;
        while (true) {
            unsigned ntx = rng.randrange(63) + 2;
            unsigned mindep = ntx - 1;
            unsigned maxdep = ((ntx + 1) >> 1) * (ntx >> 1);
            unsigned ndeps = rng.randrange(maxdep - mindep + 1) + mindep;
            uint64_t tot_cost = 0;
            params += 1;
            while (true) {
                clusters += 1;
                int levels = rng.randbool() ? 0 : rng.randrange(ntx - 1) + 2;
                int thresh = rng.randrange(ntx);
                auto depgraph = GenRandomCluster<BitSet<64>>(ntx, ndeps, levels, thresh, rng);
                uint64_t max_cost = 0;
                for (int i = 0; i < NUM_SEEDS; ++i) {
                    auto [lin, opt, cost] = Linearize(depgraph, 1000000000, i, {});
                    assert(opt);
                    tot_cost += cost;
                    max_cost = std::max(cost, max_cost);
                }
                auto& vec = local_db[ntx];
                std::vector<unsigned char> ser;
                {
                    VectorWriter writer(ser, 0);
                    writer << Using<DepGraphFormatter>(depgraph);
                }
                vec.emplace_back(max_cost, std::move(ser));
                std::push_heap(vec.begin(), vec.end(), std::greater{});
                if (vec.size() > KEEP_PER_NTX) {
                    std::pop_heap(vec.begin(), vec.end(), std::greater{});
                    vec.pop_back();
                }
                if (tot_cost > 3000000) break;
            }
            tot_tot_cost += tot_cost;
            int lmerger = merger.load();
            if (lmerger == threadnum) {
                for (auto& [key, value] : local_db) {
                    auto& gvec = db[key];
                    gvec.insert(gvec.end(), value.begin(), value.end());
                    std::sort(gvec.begin(), gvec.end(), std::greater{});
                    if (gvec.size() > KEEP_PER_NTX) gvec.resize(KEEP_PER_NTX);
                }
                local_db.clear();
                glob_num_merges += 1;
                glob_params += params;
                params = 0;
                glob_clusters += clusters;
                clusters = 0;
                if (glob_tot_tot_cost / 100000000000 != (glob_tot_tot_cost + tot_tot_cost) / 100000000000) {
                    std::cerr << "DUMP merges=" << glob_num_merges << " params=" << glob_params << " clusters=" << glob_clusters << "\n";
                    std::ofstream osf("dump.txt.tmp");
                    for (auto& [key, value] : db) {
                        for (auto& [iter, ser] : value) {
                            osf << "tx=" << key << " iter=" << iter << " hex=" << HexStr(ser) << "\n";
                        }
                    }
                    std::rename("dump.txt.tmp", "dump.txt");
                }
                glob_tot_tot_cost += tot_tot_cost;
                tot_tot_cost = 0;

                lmerger += 1;
                if (lmerger == NUM_THREADS) lmerger = 0;
                merger.store(lmerger);
            }
        }
    };
    std::vector<std::thread> threads;
    for (int th = 0; th < NUM_THREADS; ++th) {
        threads.emplace_back(thread_fn, th);
    }
    for (int th = 0; th < NUM_THREADS; ++th) {
        threads[th].join();
    }
    return 0;
}

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    SetupEnvironment();

    try {
        int ret = AppInitUtil(args, argc, argv);
        if (ret != CONTINUE_EXECUTION) {
            return ret;
        }
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitUtil()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitUtil()");
        return EXIT_FAILURE;
    }

    const auto cmd = args.GetCommand();
    if (!cmd) {
        tfm::format(std::cerr, "Error: must specify a command\n");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    std::string strPrint;
    try {
        if (cmd->command == "grind") {
            ret = Grind(cmd->args, strPrint);
        } else if (cmd->command == "gengraph") {
            ret = GenGraph();
        } else if (cmd->command == "rungraph") {
            ret = RunGraph(cmd->args, strPrint);
        } else {
            assert(false); // unknown command should be caught earlier
        }
    } catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
    } catch (...) {
        strPrint = "unknown error";
    }

    if (strPrint != "") {
        tfm::format(ret == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }

    return ret;
}
