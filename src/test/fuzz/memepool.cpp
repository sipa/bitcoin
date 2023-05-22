// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <time.h>
#include <cmath>

#include <bitset>
#include <vector>
#include <queue>

#include <test/util/xoroshiro128plusplus.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>

#include <assert.h>

#include <iostream>

//#define DO_LOG

namespace {

const constexpr size_t MAX_LINEARIZATION_CLUSTER = 32;

template<size_t Size>
using BitMatrix = std::array<std::bitset<Size>, Size>;

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

inline uint64_t RdSeed() noexcept
{
    uint8_t ok;
    uint64_t r1;
    do {
        __asm__ volatile (".byte 0x48, 0x0f, 0xc7, 0xf8; setc %1" : "=a"(r1), "=q"(ok) :: "cc"); // rdseed %rax
        if (ok) break;
        __asm__ volatile ("pause");
    } while(true);
    return r1;
}

class RNG
{
    uint64_t v0 = RdSeed(), v1 = RdSeed(), v2 = RdSeed(), v3 = RdSeed();

public:
    uint64_t operator()()
    {
        const uint64_t result = ROTL(v0 + v3, 23) + v0;
        const uint64_t t = v1 << 17;
        v2 ^= v0;
        v3 ^= v1;
        v1 ^= v2;
        v0 ^= v3;
        v2 ^= t;
        v3 = ROTL(v3, 45);
        return result;
    }
};

RNG GLOBAL_RNG;

template<typename SizeType, SizeType Size>
class UnionFind
{
    SizeType m_ref[Size];
    SizeType m_size;

public:
    void Init(SizeType size)
    {
        m_size = size;
        for (SizeType i = 0; i < m_size; ++i) {
            m_ref[i] = i;
        }
    }

    explicit UnionFind(SizeType size)
    {
        Init(size);
    }

    SizeType Find(SizeType idx)
    {
        SizeType start = idx;
        while (m_ref[idx] != idx) {
            idx = m_ref[idx];
        }
        while (m_ref[start] != idx) {
            SizeType prev = start;
            start = m_ref[start];
            m_ref[prev] = idx;
        }
        return idx;
    }

    void Union(SizeType a, SizeType b)
    {
        m_ref[Find(a)] = Find(b);
    }
};

enum class FeeRateOperator
{
    HIGHER,
    LOWER,
    DIFFERENT
};

enum class EqualFeeRate
{
    ALLOWED,
    NOT_ALLOWED,
    IF_SIZE_SMALLER,
    IF_SIZE_NOT_LARGER
};

struct ChunkData
{
    uint64_t sats;
    uint32_t bytes;

    ChunkData() : sats{0}, bytes{0} {}

    ChunkData(uint64_t s, uint32_t b) : sats{s}, bytes{b}
    {
        assert(bytes != 0 || sats == 0);
    }

    ChunkData(const ChunkData&) = default;
    ChunkData& operator=(const ChunkData&) = default;

    explicit ChunkData(FuzzedDataProvider& provider, bool size_is_one = false)
    {
        sats = provider.ConsumeIntegralInRange<uint32_t>(0, 0xFFFF);
        if (size_is_one) {
            bytes = 1;
        } else {
            bytes = provider.ConsumeIntegralInRange<uint32_t>(1, 0x10000);
        }
    }

    bool IsEmpty() const {
        return bytes == 0;
    }

    void operator+=(const ChunkData& other)
    {
        sats += other.sats;
        bytes += other.bytes;
    }

    void operator-=(const ChunkData& other)
    {
        sats -= other.sats;
        bytes -= other.bytes;
    }

    friend ChunkData operator+(const ChunkData& a, const ChunkData& b)
    {
        return ChunkData{a.sats + b.sats, a.bytes + b.bytes};
    }

    friend std::ostream& operator<<(std::ostream& o, const ChunkData& data)
    {
        o << "(" << data.sats << "/" << data.bytes << "=" << ((double)data.sats / data.bytes) << ")";
        return o;
    }
};

template<FeeRateOperator DIR, EqualFeeRate EQ>
bool FeeRateCompare(const ChunkData& a, const ChunkData& b)
{
    if (__builtin_expect(((a.sats | b.sats) >> 32) != 0, false)) {
        unsigned __int128 v1 = (unsigned __int128)(a.sats) * b.bytes;
        unsigned __int128 v2 = (unsigned __int128)(b.sats) * a.bytes;
        if (v1 != v2) {
            if constexpr (DIR == FeeRateOperator::LOWER) {
                return v1 < v2;
            } else if constexpr (DIR == FeeRateOperator::HIGHER) {
                return v1 > v2;
            } else {
                static_assert(DIR == FeeRateOperator::DIFFERENT);
                return true;
            }
        }
    } else {
        uint64_t v1 = uint64_t{(uint32_t)a.sats} * b.bytes;
        uint64_t v2 = uint64_t{(uint32_t)b.sats} * a.bytes;
        if (v1 != v2) {
            if constexpr (DIR == FeeRateOperator::LOWER) {
                return v1 < v2;
            } else if constexpr (DIR == FeeRateOperator::HIGHER) {
                return v1 > v2;
            } else {
                static_assert(DIR == FeeRateOperator::DIFFERENT);
                return true;
            }
        }
    }
    if constexpr (EQ == EqualFeeRate::NOT_ALLOWED) {
        return false;
    } else if constexpr (EQ == EqualFeeRate::ALLOWED) {
        return true;
    } else if constexpr (EQ == EqualFeeRate::IF_SIZE_SMALLER) {
        return a.bytes < b.bytes;
    } else {
        static_assert(EQ == EqualFeeRate::IF_SIZE_NOT_LARGER);
        return a.bytes <= b.bytes;
    }
}

template<EqualFeeRate EQ>
bool FeeRateLower(const ChunkData& a, const ChunkData& b)
{
    return FeeRateCompare<FeeRateOperator::LOWER, EQ>(a, b);
}

template<EqualFeeRate EQ>
bool FeeRateHigher(const ChunkData& a, const ChunkData& b)
{
    return FeeRateCompare<FeeRateOperator::HIGHER, EQ>(a, b);
}

bool FeeRateDiffers(const ChunkData& a, const ChunkData& b)
{
    return FeeRateCompare<FeeRateOperator::DIFFERENT, EqualFeeRate::NOT_ALLOWED>(a, b);
}

template<size_t Size>
bool IsConnected(const BitMatrix<Size>& deps, unsigned size)
{
    assert(size <= Size);
    if (size == 0) return true;

    UnionFind<unsigned, Size> uf(size);
    for (unsigned i = 0; i < size; ++i) {
        for (unsigned j = 0; j < size; ++j) {
            if (deps[i][j]) {
                uf.Union(i, j);
            }
        }
    }

    unsigned idx = uf.Find(0);
    for (unsigned i = 1; i < size; ++i) {
        if (uf.Find(i) != idx) return false;
    }
    return true;
}

template<size_t Size>
bool IsConnectedSubset(const BitMatrix<Size>& deps, std::bitset<Size>& select, unsigned size)
{
    assert(size <= Size);

    UnionFind<unsigned, Size> uf(size);
    for (unsigned i = 0; i < size; ++i) {
        for (unsigned j = 0; j < size; ++j) {
            if (select[i] && select[j] && deps[i][j]) {
                uf.Union(i, j);
            }
        }
    }

    bool found = false;
    unsigned idx = -1;
    for (unsigned i = 0; i < size; ++i) {
        if (select[i]) {
            if (!found) {
                idx = uf.Find(i);
            } else {
                if (uf.Find(i) != idx) return false;
            }
        }
    }
    return true;
}


template<size_t Size>
uint64_t CountCandidates(const BitMatrix<Size>& deps, unsigned size, uint64_t limit)
{
    assert(size <= Size);

    std::bitset<Size> select;
    uint64_t count{0};
    bool done{false};

    auto rec = [&](size_t pos, auto& recfn) {
        if (done) return;
        if (pos == size) {
            if (!select.none() && IsConnectedSubset(deps, select, size)) {
                ++count;
                if (count == limit) {
                    done = true;
                }
            }
        } else {
            recfn(pos + 1, recfn);
            if ((deps[pos] & ~select).none()) {
                select[pos] = true;
                recfn(pos + 1, recfn);
                select[pos] = false;
            }
        }
    };
    rec(0, rec);

    return count;
}

template<size_t Size>
std::tuple<std::bitset<Size>, ChunkData, uint64_t> FindBestCandidates(const std::array<ChunkData, Size>& txdata, const BitMatrix<Size>& deps, unsigned size, uint64_t limit, const std::bitset<Size>& exclude = {})
{
    assert(size <= Size);

    std::bitset<Size> best_select;
    std::bitset<Size> select = exclude;
    ChunkData acc;
    ChunkData best_acc;
    uint64_t count{0};
    bool done{false};

    auto rec = [&](size_t pos, auto& recfn) {
        if (done) return;
        ++count;
        if (count == limit) {
            done = true;
            return;
        }
        if (pos == size) {
            if (select != exclude && (best_acc.bytes == 0 || FeeRateHigher<EqualFeeRate::IF_SIZE_SMALLER>(acc, best_acc))) {
                best_acc = acc;
                best_select = select;
            }
        } else {
            recfn(pos + 1, recfn);
            if (!select[pos] && (deps[pos] & ~select).none()) {
                select[pos] = true;
                acc += txdata[pos];
                recfn(pos + 1, recfn);
                acc -= txdata[pos];
                select[pos] = false;
            }
        }
    };
    rec(0, rec);

    return {best_select, best_acc, count};
}


#define SIPROUND do { \
    v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; \
    v0 = ROTL(v0, 32); \
    v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; \
    v2 = ROTL(v2, 32); \
} while (0)

template<size_t Size>
struct LinearClusterWithDeps
{
    size_t cluster_size{0};
    std::array<ChunkData, Size> txdata;
    BitMatrix<Size> deps;

    LinearClusterWithDeps(FuzzedDataProvider& provider)
    {
        cluster_size = 0;
        while (cluster_size < Size && provider.remaining_bytes()) {
            txdata[cluster_size] = ChunkData(provider);
            for (size_t i = 0; i < cluster_size; ++i) {
                if (provider.ConsumeBool()) {
                    deps[cluster_size][i] = true;
                }
            }
            ++cluster_size;
        }
    }

    size_t SerSize() const
    {
        return (cluster_size * (cluster_size + 7)) / 2U;
    }

    uint64_t hash(uint64_t init) const 
    {
        uint64_t v0 = 0x736f6d6570736575ULL ^ init;
        uint64_t v1 = 0x646f72616e646f6dULL ^ init;
        uint64_t v2 = 0x6c7967656e657261ULL ^ init;
        uint64_t v3 = 0x7465646279746573ULL ^ init;
        v3 ^= cluster_size;
        SIPROUND;
        v0 ^= cluster_size;
        for (size_t i = 0; i < cluster_size; ++i) {
            v3 ^= txdata[i].sats;
            SIPROUND;
            v0 ^= txdata[i].sats;
            v3 ^= txdata[i].bytes;
            SIPROUND;
            v0 ^= txdata[i].bytes;
            for (size_t j = 0; j < cluster_size; j += 64) {
                uint64_t v{0};
                for (size_t j0 = 0; j0 < 64 && j+j0 < cluster_size; ++j0) {
                    v |= uint64_t{deps[i][j+j0]} << j0;
                }
                v3 ^= v;
                SIPROUND;
                v0 ^= v;
            }
        }
        v2 ^= 0xFF;
        SIPROUND;
        SIPROUND;
        return v0 ^ v1 ^ v2 ^ v3;
    }

    bool IsConnected() const { return ::IsConnected(deps, cluster_size); }

    friend std::ostream& operator<<(std::ostream& o, const LinearClusterWithDeps& data)
    {
        o << "{";
        for (size_t i = 0; i < data.cluster_size; ++i) {
            if (i) o << ";";
            o << i;
            bool anydep{false};
            for (size_t j = 0; j < data.cluster_size; ++j) {
                if (data.deps[i][j]) {
                    if (anydep) {
                        o << ",";
                    } else {
                        o << "[";
                        anydep = true;
                    }
                    o << j;
                }
            }
            if (anydep) o << "]";
            o << ":";
            o << data.txdata[i];
        }
        o << "}";
        return o;
    }

    uint64_t CountCandidates() const
    {
        return ::CountCandidates(deps, cluster_size, 0xFFFFFFFF);
    }
};

template<size_t Size>
BitMatrix<Size> ComputeAncestors(const BitMatrix<Size>& deps, size_t size)
{
    BitMatrix<Size> ret;
    for (size_t i = 0; i < size; ++i) {
        ret[i][i] = true;
    }
    bool changed;
    do {
        changed = false;
        for (size_t i = 0; i < size; ++i) {
            for (size_t j = 0; j < size; ++j) {
                if (i != j && deps[i][j]) { // j is ancestor of i
                    auto next = ret[i] | ret[j];
                    if (next != ret[i]) {
                        ret[i] = next;
                        changed = true;
                    }
                }
            }
        }
    } while (changed);
    return ret;
}

template<size_t Size>
BitMatrix<Size> ComputeDirectParents(const BitMatrix<Size>& ancestors, size_t size)
{
    auto ret = ancestors;
    for (size_t i = 0; i < size; ++i) {
        ret[i][i] = false;
        for (size_t j = 0; j < size; ++j) {
            if (ret[i][j]) {
                ret[i] &= ~ancestors[j];
                ret[i][j] = true;
            }
        }
    }
    return ret;
}

template<size_t Size>
BitMatrix<Size> ComputeDescendants(const BitMatrix<Size>& deps, size_t size)
{
    BitMatrix<Size> ret;
    for (size_t i = 0; i < size; ++i) {
        ret[i][i] = true;
    }
    bool changed;
    do {
        changed = false;
        for (size_t i = 0; i < size; ++i) {
            for (size_t j = 0; j < size; ++j) {
                if (i != j && deps[j][i]) { // j is descendant of i
                    auto next = ret[i] | ret[j];
                    if (next != ret[i]) {
                        ret[i] = next;
                        changed = true;
                    }
                }
            }
        }
    } while (changed);
    return ret;
}

template<size_t Size>
struct ChunkingResult
{
    std::bitset<Size> selection;
    ChunkData feerate;
    size_t iterations;
    size_t comparisons;

    ChunkingResult(const std::bitset<Size> s, ChunkData f, size_t i, size_t c) : selection(s), feerate(f), iterations(i), comparisons(c) {}
};

template<size_t Size>
bool EquivalentChunking(const std::vector<ChunkingResult<Size>>& a, const std::vector<ChunkingResult<Size>>& b)
{
    size_t idx_a{0}, idx_b{0};
    while (idx_a != a.size() || idx_b != b.size()) {
        if (idx_a == a.size() || idx_b == b.size()) return false;
        ChunkData cumul_a{a[idx_a].feerate}, cumul_b{b[idx_b].feerate};
        if (FeeRateDiffers(cumul_a, cumul_b)) return false;
        ++idx_a;
        ++idx_b;
        while (idx_a != a.size() && !FeeRateDiffers(cumul_a, a[idx_a].feerate)) {
            cumul_a += a[idx_a].feerate;
            ++idx_a;
        }
        while (idx_b != b.size() && !FeeRateDiffers(cumul_b, b[idx_b].feerate)) {
            cumul_b += b[idx_b].feerate;
            ++idx_b;
        }
        if (idx_a != idx_b) return false;
        if (cumul_a.bytes != cumul_b.bytes) return false;
        assert(cumul_a.sats == cumul_b.sats);
    }
    return true;
}

template<size_t Size>
std::vector<ChunkingResult<Size>> FindOptimalChunks(const LinearClusterWithDeps<Size>& cluster)
{
    auto ancestors = ComputeAncestors(cluster.deps, cluster.cluster_size);

    if (cluster.cluster_size == 0) return {};

    std::vector<ChunkingResult<Size>> ret;
    std::bitset<Size> done, all;

    struct Sol
    {
        std::bitset<Size> select;
        ChunkData achieved;
        size_t expanded;

        Sol() = default;
        Sol(const std::bitset<Size>& sel, const ChunkData& ach, size_t exp) : select(sel), achieved(ach), expanded(exp) {}
    };

    for (size_t i = 0; i < cluster.cluster_size; ++i) all[i] = true;
    while (done != all) {
        size_t iterations{0}, comparisons{0};
        ChunkData best;
        std::bitset<Size> best_select;
        std::vector<Sol> sols;
        sols.emplace_back(done, ChunkData{}, 0);
        while (!sols.empty()) {
            ++iterations;
            Sol& ent = sols.back();
            assert(ent.expanded <= cluster.cluster_size);
            while (ent.expanded < cluster.cluster_size && done[ent.expanded]) ++ent.expanded;
            assert(ent.expanded <= cluster.cluster_size);
            if (ent.expanded == cluster.cluster_size) {
                sols.pop_back();
            } else {
                ChunkData next = ent.achieved;
                std::bitset<Size> next_select = ent.select | ancestors[ent.expanded];
                std::bitset<Size> to_add = next_select & ~ent.select;
                assert(!to_add.none());
                for (size_t j = 0; j < cluster.cluster_size; ++j) {
                    if (to_add[j]) next += cluster.txdata[j];
                }
                ++comparisons;
                assert(next.bytes > 0);
                if (best_select.none() || FeeRateHigher<EqualFeeRate::IF_SIZE_SMALLER>(next, best)) {
                    best = next;
                    best_select = next_select;
                }
                ++ent.expanded;
                sols.emplace_back(next_select, next, ent.expanded);
            }
        }

        ret.emplace_back(best_select & ~done, best, iterations, comparisons);
        done = best_select;
    }

    return ret;
}

template<size_t Size>
struct IncExcSolution
{
    std::bitset<Size> inc;
    std::bitset<Size> exc;
    ChunkData achieved;
    ChunkData potential;

    IncExcSolution() = default;
};

template<size_t Size>
struct IncExcStats
{
    size_t iterations{0};
    size_t queue_size{0};
    std::bitset<Size> select;
    ChunkData achieved;
};

template<size_t Size>
IncExcStats<Size> AnalyzeMurch(const LinearClusterWithDeps<Size>& cluster)
{
    if (!cluster.IsConnected()) return {};

    std::bitset<Size> remaining_cluster;
    for (size_t i = 0; i < cluster.cluster_size; ++i) {
        remaining_cluster[i] = true;
    }

    auto ancestors = ComputeAncestors(cluster.deps, cluster.cluster_size);
    auto descendants = ComputeDescendants(cluster.deps, cluster.cluster_size);
/*    auto parents = ComputeDirectParents(ancestors, cluster.cluster_size);*/

    std::array<ChunkData, Size> ancestor_data;
    for (size_t i = 0; i < cluster.cluster_size; ++i) {
        for (size_t j = 0; j < cluster.cluster_size; ++j) {
            if (ancestors[i][j]) {
                ancestor_data[i] += cluster.txdata[j];
            }
        }
    }

    std::array<size_t, Size> direct_order;
    std::iota(direct_order.begin(), direct_order.begin() + cluster.cluster_size, size_t{0});
    std::sort(direct_order.begin(), direct_order.begin() + cluster.cluster_size, [&](size_t a, size_t b) {
        return FeeRateHigher<EqualFeeRate::IF_SIZE_SMALLER>(cluster.txdata[a], cluster.txdata[b]);
    });

    std::bitset<Size> best_select;
    ChunkData best_feerate;

    std::unordered_set<std::bitset<Size>> added;

    using search_list_entry = std::pair<ChunkData, std::bitset<Size>>;
    auto compare = [&](const search_list_entry& x, const search_list_entry& y) { return !FeeRateHigher<EqualFeeRate::IF_SIZE_SMALLER>(x.first, y.first); };
    std::priority_queue<search_list_entry, std::vector<search_list_entry>, decltype(compare)> search_list(compare);

    auto compute_feerate = [&](const std::bitset<Size>& select) {
        ChunkData ret;
        for (size_t i = 0; i < cluster.cluster_size; ++i) {
            if (select[i]) {
                assert(remaining_cluster[i]);
                ret += cluster.txdata[i];
            }
        }
        return ret;
    };

    size_t last_best_updated = 0;

    auto add_to_searchlist = [&](const std::bitset<Size>& select) {
        auto feerate = compute_feerate(select);
        search_list.emplace(feerate, select);

        if (FeeRateHigher<EqualFeeRate::IF_SIZE_SMALLER>(feerate, best_feerate)) {
            best_feerate = feerate;
            best_select = select;
            last_best_updated = added.size();

            bool updated;
            do {
                updated = false;
                for (size_t i = 0; i < cluster.cluster_size; ++i) {
                    if (remaining_cluster[i] && (descendants[i] & remaining_cluster).count() == 1) { /* that's a leaf! */
                        bool worse = !FeeRateHigher<EqualFeeRate::IF_SIZE_SMALLER>(cluster.txdata[i], best_feerate);
                        if (worse) {
                            remaining_cluster[i] = false;
                            updated = true;
                        }
                    }
                }
            } while(updated);
        }
    };


    for (size_t i = 0; i < cluster.cluster_size; ++i) {
        if (remaining_cluster[i]) {
            added.emplace(ancestors[i]);
            add_to_searchlist(ancestors[i]);
        }
    }

    while (!search_list.empty()) {
        auto next = search_list.top();
        search_list.pop();
        if ((next.second & ~remaining_cluster).any()) continue;

        for (size_t i = 0; i < cluster.cluster_size; ++i) {
            size_t idx = direct_order[i];
            if (remaining_cluster[idx] && !next.second[idx]/* && (parents[idx] & next.second).any()*/) {
                auto next_select = next.second | ancestors[idx];
                if (!added.count(next_select)) {
                    added.emplace(next_select);
                    add_to_searchlist(next_select);
                    if ((next.second & ~remaining_cluster).any()) break;
                }
            }
        }
    }

    return {.iterations = last_best_updated, .queue_size = 0, .select = best_select, .achieved = best_feerate};
}

template<size_t Size>
struct FullStats
{
    size_t comparisons;
    std::vector<ChunkingResult<Size>> chunks;
    double duration;
};

template<typename Stream, size_t Size>
Stream& operator<<(Stream& s, const std::vector<ChunkingResult<Size>>& arg)
{
    s << "{";
    for (size_t i = 0; i < arg.size(); ++i) {
        if (i) s << ",";
        s << arg[i].selection << arg[i].feerate << "[iter=" << arg[i].iterations << ",comp=" << arg[i].comparisons << "]";
    }
    s << "}";
    return s;
}

int inline StripBit(uint64_t& x)
{
    int pos;
    constexpr auto digits = std::numeric_limits<uint64_t>::digits;
    constexpr auto digits_u = std::numeric_limits<unsigned>::digits;
    constexpr auto digits_ul = std::numeric_limits<unsigned long>::digits;
    constexpr auto digits_ull = std::numeric_limits<unsigned long long>::digits;

    if constexpr (digits >= digits_u) {
        pos = __builtin_ctz(x);
    } else if constexpr (digits >= digits_ul) {
        pos = __builtin_ctzl(x);
    } else {
        static_assert(digits >= digits_ull);
        pos = __builtin_ctzll(x);
    }
    x &= x - uint64_t{1};
    return pos;
}

template<typename Iter, typename Fn>
Iter Filter(Iter begin, Iter end, Fn fn)
{
    while (true) {
        while (begin != end && !fn(*begin)) ++begin;
        if (begin == end) break;
        --end;
        while (begin != end && fn(*end)) --end;
        if (begin == end) break;
        std::iter_swap(begin, end);
        ++begin;
    }
    return end;
}

template<unsigned Size>
FullStats<Size> AnalyzeIncExcOpt(const LinearClusterWithDeps<Size>& cluster)
{
    static_assert(Size <= 64);

    if (!cluster.IsConnected()) return {};
    if (cluster.cluster_size == 0) return {};

    struct timespec measure_start, measure_stop;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_start);

    size_t comparisons{0};

    unsigned sorted_to_idx[Size];
    std::iota(sorted_to_idx, sorted_to_idx + cluster.cluster_size, unsigned{0});
    std::sort(sorted_to_idx, sorted_to_idx + cluster.cluster_size, [&](unsigned a, unsigned b) {
        return FeeRateHigher<EqualFeeRate::IF_SIZE_SMALLER>(cluster.txdata[a], cluster.txdata[b]);
    });
    unsigned idx_to_sorted[Size];
    ChunkData sorted_data[Size];
    for (unsigned i = 0; i < cluster.cluster_size; ++i) {
        idx_to_sorted[sorted_to_idx[i]] = i;
        sorted_data[i] = cluster.txdata[sorted_to_idx[i]];
    }

    auto sum_fn = [&](uint64_t mask) {
        ChunkData ret;
        while (mask) {
            int pos = StripBit(mask);
            ret += sorted_data[pos];
        }
        return ret;
    };

    uint64_t ancdes[2][Size] = {{0},{0}};
    for (unsigned i = 0; i < cluster.cluster_size; ++i) ancdes[0][i] = uint64_t{1} << i;
    bool changed;
    do {
        changed = false;
        for (unsigned i = 0; i < cluster.cluster_size; ++i) {
            unsigned sorted_i = idx_to_sorted[i];
            uint64_t deps = cluster.deps[i].to_ullong();
            while (deps) {
                int pos = StripBit(deps);
                uint64_t next = ancdes[0][sorted_i] | ancdes[0][idx_to_sorted[pos]];
                if (next != ancdes[0][sorted_i]) {
                    ancdes[0][sorted_i] = next;
                    changed = true;
                }
            }
        }
    } while(changed);

    for (unsigned i = 0; i < cluster.cluster_size; ++i) {
        uint64_t deps = ancdes[0][i];
        while (deps) {
            int pos = StripBit(deps);
            ancdes[1][pos] |= uint64_t{1} << i;
        }
    }

    struct Sol
    {
        uint64_t inc, exc;
        ChunkData potential, achieved;

        Sol(uint64_t inc_, uint64_t exc_, const ChunkData& pot_, const ChunkData& ach_) : inc(inc_), exc(exc_), potential(pot_), achieved(ach_) {}
    };

    uint64_t done{0};
    uint64_t all = (~uint64_t{0}) >> (64 - cluster.cluster_size);

    static const auto compare_fn = [](const Sol& a, const Sol& b) {
        return a.achieved.bytes > b.achieved.bytes;
    };

    std::vector<ChunkingResult<Size>> chunks;
    std::vector<Sol> queue;

    while (done != all) {
        const size_t start_comparisons = comparisons;
        size_t iterations{0};
        uint64_t best{0};
        ChunkData best_achieved;

        auto add_fn = [&](ChunkData prev, uint64_t prevmask, uint64_t inc, uint64_t exc) {
            ChunkData potential = prev + sum_fn(inc & ~prevmask);
            ChunkData achieved = potential;

            uint64_t satisfied = inc;
            uint64_t required{0};
            uint64_t undecided = all & ~(inc | exc);
            while (undecided) {
                int pos = StripBit(undecided);
                assert(!sorted_data[pos].IsEmpty());
                bool should_add = potential.IsEmpty();
                if (!should_add) {
                    ++comparisons;
                    should_add = FeeRateHigher<EqualFeeRate::NOT_ALLOWED>(sorted_data[pos], potential);
                }
                if (should_add) {
                    potential += sorted_data[pos];
                    satisfied |= uint64_t{1} << pos;
                    required |= ancdes[0][pos];
                    if (!(required & ~satisfied)) {
                        inc = satisfied;
                        achieved = potential;
                    }
                } else {
                    break;
                }
            }

            if (best_achieved.IsEmpty()) {
                best_achieved = achieved;
                best = inc;
            } else {
                if (potential.IsEmpty()) return;
                ++comparisons;
                if (FeeRateHigher<EqualFeeRate::IF_SIZE_NOT_LARGER>(best_achieved, potential)) return;
                if (!achieved.IsEmpty()) {
                    ++comparisons;
                    if (FeeRateHigher<EqualFeeRate::IF_SIZE_SMALLER>(achieved, best_achieved)) {
                        best_achieved = achieved;
                        best = inc;
                    }
                }
            }

            queue.emplace_back(inc, exc, potential, achieved);
            std::push_heap(queue.begin(), queue.end(), compare_fn);
        };

        queue.clear();
        add_fn({}, done, done, 0);

        while (!queue.empty()) {
            std::pop_heap(queue.begin(), queue.end(), compare_fn);
            Sol elem = queue.back();
            queue.pop_back();

            uint64_t undecided = all & ~(elem.inc | elem.exc);
            if (undecided) {
                ++iterations;
                int idx = StripBit(undecided);
                add_fn(elem.achieved, elem.inc, elem.inc | ancdes[0][idx], elem.exc);
                add_fn(elem.achieved, elem.inc, elem.inc, elem.exc | ancdes[1][idx]);
            }
        }

        uint64_t new_select = best & ~done;
        uint64_t new_select_idx{0};
        while (new_select) {
            int idx = StripBit(new_select);
            new_select_idx |= uint64_t{1} << sorted_to_idx[idx];
        }
        chunks.emplace_back(new_select_idx, best_achieved, iterations, comparisons - start_comparisons);
        done |= best;
    }

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_stop);

    double duration = (double)((int64_t)measure_stop.tv_sec - (int64_t)measure_start.tv_sec) + 0.000000001*(double)((int64_t)measure_stop.tv_nsec - (int64_t)measure_start.tv_nsec);

    return {.comparisons = comparisons, .chunks = std::move(chunks), .duration = duration};
}

} // namespace

FUZZ_TARGET(memepool_filter)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    std::vector<uint64_t> vec;
    while (vec.size() != 20 && provider.ConsumeBool()) {
        vec.push_back(provider.ConsumeIntegral<uint64_t>());
    }

    std::vector<uint64_t> tmp = vec;

    static constexpr auto is_bad = [](uint64_t x) -> bool { return (((uint32_t)x) >> 23) & 1; };

    auto limit = Filter(tmp.begin(), tmp.end(), is_bad);

    for (auto it = tmp.begin(); it != limit; ++it) {
        assert(!is_bad(*it));
    }
    for (auto it = limit; it != tmp.end(); ++it) {
        assert(is_bad(*it));
    }

    std::sort(vec.begin(), vec.end());
    std::sort(tmp.begin(), tmp.end());
    assert(vec == tmp);
}

FUZZ_TARGET(memepool_incexc_auto)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    LinearClusterWithDeps<MAX_LINEARIZATION_CLUSTER> cluster(provider);

    if (!cluster.IsConnected()) return;

    const auto& [comparisons, chunks, duration] = AnalyzeIncExcOpt<MAX_LINEARIZATION_CLUSTER>(cluster);

    if (cluster.cluster_size <= 10 || (cluster.cluster_size <= 22 && GLOBAL_RNG() >> (74 - cluster.cluster_size) == 0)) {
        auto best_chunks = FindOptimalChunks(cluster);
        bool eq = EquivalentChunking(chunks, best_chunks);
        if (!eq) std::cerr << "DIFF " << cluster << " optimal=" << best_chunks << " found=" << chunks << std::endl;
        assert(eq);
    }

    static std::map<std::pair<int, unsigned long>, std::pair<uint64_t, uint64_t>> COUNTS;

    std::pair<int, unsigned long> key{cluster.cluster_size, (unsigned long)std::floor(1000.0 * ::log(comparisons))};
    std::pair<uint64_t, uint64_t>& val = COUNTS[key];
    ++val.first;
    if (val.first > val.second) {
        std::cerr << "COMP " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur/comp=" << (duration / comparisons) << " count=" << val.first << std::endl;
        if (!FuzzSave(buffer.first(cluster.SerSize()))) {
            val.first = ((val.first * 17) >> 4) + 1;
        }
    }
    while (val.second >= val.first) {
        val.second = (val.second * 2) + 1;
    }

    static std::array<size_t, MAX_LINEARIZATION_CLUSTER+1> MAX_COMPS;
    if (comparisons > MAX_COMPS[cluster.cluster_size]) {
        MAX_COMPS[cluster.cluster_size] = comparisons;
        std::cerr << "COMPS:";
        for (size_t i = 0; i <= MAX_LINEARIZATION_CLUSTER; ++i) {
            std::cerr << " " << i << ":" << MAX_COMPS[i];
        }
        std::cerr << std::endl;
    }
}

FUZZ_TARGET(memepool_analyze_murch)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    LinearClusterWithDeps<MAX_LINEARIZATION_CLUSTER> cluster(provider);

    if (!cluster.IsConnected()) return;

/*    std::cerr << "PROC: " << cluster << std::endl;*/

    const auto& [best_selects, best_chunkdata, iters] = FindBestCandidates(cluster.txdata, cluster.deps, cluster.cluster_size, 100000);
    std::vector<std::bitset<MAX_LINEARIZATION_CLUSTER>> empty;
    auto incexc_stats = AnalyzeMurch(cluster);

/*  size_t tot_candidates = CountCandidates(cluster.deps, cluster.cluster_size, 100000);
    std::cerr << "STATS: best=" << best_chunkdata << " achieved=" << incexc_stats.achieved << " sol=" << incexc_stats.select << " iters=" << incexc_stats.iterations << " cands=" << tot_candidates << std::endl;*/

    assert(FeeRateHigher<EqualFeeRate::IF_SIZE_NOT_LARGER>(incexc_stats.achieved, best_chunkdata));
    if (iters < 100000) {
        assert(incexc_stats.achieved.sats == best_chunkdata.sats);
        assert(incexc_stats.achieved.bytes == best_chunkdata.bytes);
    }

    static std::array<size_t, MAX_LINEARIZATION_CLUSTER+1> MAX_ITERS;
    if (incexc_stats.iterations > MAX_ITERS[cluster.cluster_size]) {
        MAX_ITERS[cluster.cluster_size] = incexc_stats.iterations;
        std::cerr << "ITERS:";
        for (size_t i = 0; i <= MAX_LINEARIZATION_CLUSTER; ++i) {
            std::cerr << " " << i << ":" << MAX_ITERS[i];
        }
        std::cerr << std::endl;

    }

    /*                                          0   1   2   3   4   5   6   7   8    9   10   11   12   13   14   15   16 */

/*  static constexpr size_t KNOWN_LIMITS[] =   {0,  0,  0,  4,  8, 14, 24, 46, 87, 164, 308, 583, 1112,   0,   0,   0,   0};  // only trying direct children of candidates */
    static constexpr size_t KNOWN_LIMITS[] =   {0,  1,  2,  4,  7, 13, 23, 49, 95,  90, 263, 574,  963,   0,   0,   0,   0};
    /*                                          0   4   9  15  22  30  39  49  60   72   85   99   114  130  147  165  184 */

    if (cluster.cluster_size == 3 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 4 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 5 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 6 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 7 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 8 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 9 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 10 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 11 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 12 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 13 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 14 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 15 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 16 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;

    return;
}

FUZZ_TARGET(memepool_analyze_incexc_opt)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    LinearClusterWithDeps<MAX_LINEARIZATION_CLUSTER> cluster(provider);

    if (!cluster.IsConnected()) return;

    const auto& [comparisons, chunks, duration] = AnalyzeIncExcOpt<MAX_LINEARIZATION_CLUSTER>(cluster);

    if (cluster.cluster_size <= 10 || (cluster.cluster_size <= 22 && GLOBAL_RNG() >> (74 - cluster.cluster_size) == 0)) {
        auto best_chunks = FindOptimalChunks(cluster);
        bool eq = EquivalentChunking(chunks, best_chunks);
        if (!eq) std::cerr << "DIFF " << cluster << " optimal=" << best_chunks << " found=" << chunks << std::endl;
        assert(eq);
    }

/*
    if (cluster.cluster_size >= 16) {
        std::cerr << "STAT: size " << cluster.cluster_size << " comptime " << (duration_opt / comparisons_opt) << " comptime_old " << (duration / comparisons) << " comparisons " << comparisons_opt << " cluster " << cluster <<  " result " << chunks_opt << std::endl;
    }
*/

    static std::array<size_t, MAX_LINEARIZATION_CLUSTER+1> MAX_COMPS;

    if (comparisons > MAX_COMPS[cluster.cluster_size]) {
        MAX_COMPS[cluster.cluster_size] = comparisons;
        std::cerr << "COMPS:";
        for (size_t i = 0; i <= MAX_LINEARIZATION_CLUSTER; ++i) {
            std::cerr << " " << i << ":" << MAX_COMPS[i];
        }
        std::cerr << std::endl;

    }

/*    static constexpr size_t KNOWN_LIMITS[27] = {0};*/
    static constexpr size_t KNOWN_LIMITS[] = {0,  0,  3, 12, 28,  53,  87, 130, 214, 360,  569,  930, 1488, 2346, 3690,  5730,  9064, 13838, 21183, 31857, 49014, 75352, 116443, 178166, 268465, 403395, 609550};
    /*                                        0   1   2   3   4    5    6    7    8    9    10    11    12    13    14     15     16     17     18     19     20     21      22      23      24      25      26 */
    /*                                        0   4   9  15  22   30   39   49   60   72    85    99   114   130   147    165    184    204    225    247    270    294     319     345     372     400     429 */

/*    if (cluster.cluster_size == 3 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 4 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 5 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 6 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 7 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 8 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 9 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;*/

    if (cluster.cluster_size == 10 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 11 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 12 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 13 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 14 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 15 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 16 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 17 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 18 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 19 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 20 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 21 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 22 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 23 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 24 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 25 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;
    if (cluster.cluster_size == 26 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << " cps=" << (duration / comparisons) << std::endl;

    if (cluster.cluster_size >= 0 && cluster.cluster_size <= 26) assert(comparisons <= KNOWN_LIMITS[cluster.cluster_size]);
}
