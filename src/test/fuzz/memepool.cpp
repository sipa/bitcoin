// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <time.h>

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

struct ChunkData
{
    uint32_t sats;
    uint32_t bytes;

    ChunkData() : sats{0}, bytes{0} {}

    ChunkData(uint32_t s, uint32_t b) : sats{s}, bytes{b} {}

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

    int CompareJustFeerate(const ChunkData& other) const
    {
        if (bytes == 0) {
            assert(sats == 0);
            if (other.bytes == 0) return 0;
            return -1;
        }
        if (other.bytes == 0) return 1;
        uint64_t v1 = uint64_t{sats} * other.bytes;
        uint64_t v2 = uint64_t{other.sats} * bytes;
        if (v1 < v2) return -1;
        if (v1 > v2) return 1;
        return 0;
    }

    int Compare(const ChunkData& other) const
    {
        if (bytes == 0) {
            assert(sats == 0);
            if (other.bytes == 0) return 0;
            return -1;
        }
        if (other.bytes == 0) return 1;
        uint64_t v1 = uint64_t{sats} * other.bytes;
        uint64_t v2 = uint64_t{other.sats} * bytes;
        if (v1 < v2) return -1;
        if (v1 > v2) return 1;
        if (bytes < other.bytes) return 1;
        if (bytes > other.bytes) return -1;
        return 0;
    }

    bool operator==(const ChunkData& other) const { return sats == other.sats && bytes == other.bytes; }
    bool operator!=(const ChunkData& other) const { return sats != other.sats || bytes != other.bytes; }
    bool operator>(const ChunkData& other) const { return Compare(other) > 0; }
    bool operator<(const ChunkData& other) const { return Compare(other) < 0; }
    bool operator>=(const ChunkData& other) const { return Compare(other) >= 0; }
    bool operator<=(const ChunkData& other) const { return Compare(other) <= 0; }

    friend std::ostream& operator<<(std::ostream& o, const ChunkData& data)
    {
        o << "(" << data.sats << "/" << data.bytes << "=" << ((double)data.sats / data.bytes) << ")";
        return o;
    }
};

struct Chunking
{
    std::array<ChunkData, MAX_LINEARIZATION_CLUSTER> data;
    size_t chunks{0};

    void Add(const ChunkData& txdata)
    {
        assert(chunks < MAX_LINEARIZATION_CLUSTER);
        data[chunks++] = txdata;
        while (chunks >= 2 && data[chunks - 1] > data[chunks - 2]) {
            data[chunks - 2] += data[chunks - 1];
            --chunks;
        }
    }

    bool operator==(const Chunking& other) const
    {
        if (chunks != other.chunks) return false;
        return std::equal(data.begin(), data.begin() + chunks, other.data.begin());
    }

    void GetDiagram(std::vector<ChunkData>& ret) const
    {
        ret.clear();
        ret.emplace_back(0, 0);
        for (size_t i = 0; i < chunks; ++i) {
            ret.emplace_back(ret.back() + data[i]);
        }
    }
};

int DiagramCompare(const std::vector<ChunkData>& diagram, const ChunkData& value)
{
    assert(value.bytes <= diagram.back().bytes);

    size_t min = 0, max = diagram.size() - 1;
    while (max > min + 1) {
        size_t mid = (max + min) >> 1;
        if (value.bytes <= diagram[mid].bytes) max = mid;
        if (value.bytes >= diagram[mid].bytes) min = mid;
        assert(value.bytes >= diagram[min].bytes);
        assert(value.bytes <= diagram[max].bytes);
    }

    if (value.bytes == diagram[min].bytes) {
        if (value.sats > diagram[min].sats) return 1;
        if (value.sats < diagram[min].sats) return -1;
        return 0;
    }
    if (value.bytes == diagram[max].bytes) {
        if (value.sats > diagram[max].sats) return 1;
        if (value.sats < diagram[max].sats) return -1;
        return 0;
    }
    int64_t left = (int64_t{value.sats} - int64_t{diagram[min].sats}) * (int64_t{diagram[max].bytes} - int64_t{diagram[min].bytes});
    int64_t right = (int64_t{value.bytes} - int64_t{diagram[min].bytes}) * (int64_t{diagram[max].sats} - int64_t{diagram[min].sats});
    if (left > right) return 1;
    if (left < right) return -1;
    return 0;
}

/**
 * Result:
 * - 0: diagram1 == diagram2
 * - 1: diagram1 > diagram2
 * - 2: diagram2 > diagram1
 * - 3: inconsistent
 */
int DiagramFullCompare(const std::vector<ChunkData>& diagram1, const std::vector<ChunkData>& diagram2)
{
    bool sometimes_1_better = false;
    bool sometimes_2_better = false;

    for (const auto& value : diagram1) {
        int ret = DiagramCompare(diagram2, value);
        if (ret < 0) sometimes_2_better = true;
        if (ret > 0) sometimes_1_better = true;
    }
    for (const auto& value : diagram2) {
        int ret = DiagramCompare(diagram1, value);
        if (ret < 0) sometimes_1_better = true;
        if (ret > 0) sometimes_2_better = true;
    }

    return (sometimes_1_better ? 1 : 0) + (sometimes_2_better ? 2 : 0);
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
            if (select != exclude && (best_acc.bytes == 0 || acc >= best_acc)) {
                if (acc > best_acc) {
                    best_acc = acc;
                    best_select = select;
                }
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
    if (a.size() != b.size()) return false;
    size_t idx{0};
    while (idx != a.size()) {
        ChunkData cumul_a{a[idx].feerate}, cumul_b{b[idx].feerate};
        if (cumul_a.CompareJustFeerate(cumul_b) != 0) return false;
        ++idx;
        size_t idx_a{idx}, idx_b{idx};
        while (idx_a != a.size() && cumul_a.CompareJustFeerate(a[idx_a].feerate) == 0) {
            cumul_a += a[idx_a].feerate;
            ++idx_a;
        }
        while (idx_b != b.size() && cumul_b.CompareJustFeerate(b[idx_b].feerate) == 0) {
            cumul_b += b[idx_b].feerate;
            ++idx_b;
        }
        if (idx_a != idx_b) return false;
        if (cumul_a.bytes != cumul_b.bytes) return false;
        assert(cumul_a == cumul_b);
        idx = idx_a;
    }
    return true;
}

template<size_t Size>
std::vector<ChunkingResult<Size>> FindOptimalChunks(const LinearClusterWithDeps<Size>& cluster)
{
    auto ancestors = ComputeAncestors(cluster.deps, cluster.cluster_size);

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
                if (next > best) {
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

template<typename MoreTxFn, typename TxFeeFn, typename DepFn>
void TargetImproveLinearizationUnconvexedSizeOne(MoreTxFn moretxfn, TxFeeFn txfeefn, DepFn depfn)
{
    size_t cluster_size{0};
    std::array<ChunkData, MAX_LINEARIZATION_CLUSTER> txdata;
    BitMatrix<MAX_LINEARIZATION_CLUSTER> deps;

    while (cluster_size < MAX_LINEARIZATION_CLUSTER && moretxfn(cluster_size)) {
        txdata[cluster_size].sats = txfeefn(cluster_size);
        txdata[cluster_size].bytes = 1;
        for (size_t i = 0; i < cluster_size; ++i) {
            if (depfn(cluster_size, i)) {
                deps[cluster_size][i] = true;
            }
        }
        ++cluster_size;
    }

    ChunkData best_chunkdata;
    ChunkData chunkdata;
    std::bitset<MAX_LINEARIZATION_CLUSTER> best_select;
    std::bitset<MAX_LINEARIZATION_CLUSTER> select;
    size_t iterations{0};
    bool limit{false};

    auto rec = [&](size_t pos, auto& recfn) {
        if (limit) return;
        if (pos == cluster_size) {
            if (++iterations > 100000) {
                limit = true;
                return;
            }
            if (select.any() && (best_select.none() || chunkdata > best_chunkdata)) {
                best_chunkdata = chunkdata;
                best_select = select;
            }
        } else {
            assert(select[pos] == false);
            recfn(pos + 1, recfn);
            if ((deps[pos] & ~select).none()) {
                select[pos] = true;
                chunkdata += txdata[pos];
                recfn(pos + 1, recfn);
                chunkdata -= txdata[pos];
                select[pos] = false;
            }
        }
    };
    rec(0, rec);

    if (limit) return;

    ChunkData acc_old, acc_new;
    size_t cnt{0};
    for (size_t i = 0; i < cluster_size; ++i) {
        if (best_select[i]) {
            acc_old += txdata[cnt];
            acc_new += txdata[i];
            ++cnt;
        }
    }
    assert(cnt == best_select.count());
    for (size_t i = 0; i < cluster_size; ++i) {
        if (!best_select[i]) {
            acc_old += txdata[cnt];
            acc_new += txdata[i];
            ++cnt;
            assert(acc_new >= acc_old);
        }
    }
    assert(cnt == cluster_size);
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
        return cluster.txdata[a] > cluster.txdata[b];
    });

    std::bitset<Size> best_select;
    ChunkData best_feerate;

    std::unordered_set<std::bitset<Size>> added;

    using search_list_entry = std::pair<ChunkData, std::bitset<Size>>;
    auto compare = [&](const search_list_entry& x, const search_list_entry& y) { return x.first < y.first; };
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

        if (feerate > best_feerate) {
            best_feerate = feerate;
            best_select = select;
            last_best_updated = added.size();

            bool updated;
            do {
                updated = false;
                for (size_t i = 0; i < cluster.cluster_size; ++i) {
                    if (remaining_cluster[i] && (descendants[i] & remaining_cluster).count() == 1) { /* that's a leaf! */
                        int cmp = cluster.txdata[i].CompareJustFeerate(best_feerate);
                        bool worse = cmp < 0;
                        if (cmp == 0) {
                            if (ancestor_data[i].bytes > best_feerate.bytes) worse = true;
                        }
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
IncExcStats<Size> AnalyzeIncExc(const LinearClusterWithDeps<Size>& cluster)
{
    if (!cluster.IsConnected()) return {};

/*    std::cerr << "INCEXC start (cluster_size=" << cluster.cluster_size << ")" << std::endl;*/

    auto ancestors = ComputeAncestors(cluster.deps, cluster.cluster_size);
    auto descendants = ComputeDescendants(cluster.deps, cluster.cluster_size);

/*    uint64_t seed{0xa04adcad1f4b95e};*/
    std::array<ChunkData, Size> ancestor_data;
    std::array<size_t, Size> ancestor_order;
    std::iota(ancestor_order.begin(), ancestor_order.begin() + cluster.cluster_size, size_t{0});

    auto update_ancestors = [&](const std::bitset<Size>& decided) {
        for (size_t i = 0; i < cluster.cluster_size; ++i) {
            ancestor_data[i] = {};
            if (!decided[i]) {
                for (size_t j = 0; j < cluster.cluster_size; ++j) {
                    if (!decided[j] && ancestors[i][j]) {
                        ancestor_data[i] += cluster.txdata[j];
                    }
                }
            }
        }
        std::sort(ancestor_order.begin(), ancestor_order.begin() + cluster.cluster_size, [&](size_t a, size_t b) {
            return ancestor_data[a] > ancestor_data[b];
        });
    };

    update_ancestors({});

    std::array<size_t, Size> direct_order;
    std::iota(direct_order.begin(), direct_order.begin() + cluster.cluster_size, size_t{0});
    std::sort(direct_order.begin(), direct_order.begin() + cluster.cluster_size, [&](size_t a, size_t b) {
        return cluster.txdata[a] > cluster.txdata[b];
    });


    IncExcSolution<Size> best;

    auto compare_fn = [](const auto& a, const auto& b) {
        if (a.potential < b.potential) return true;
        if (a.potential > b.potential) return false;
        if (a.achieved < b.achieved) return true;
        if (a.achieved > b.achieved) return false;
        return false;
    };

    std::priority_queue<IncExcSolution<Size>, std::vector<IncExcSolution<Size>>, decltype(compare_fn)> queue{compare_fn};

/*    std::vector<IncExcSolution<Size>> queue;*/

    size_t adds{0};

    auto add_fn = [&](std::bitset<Size> inc, const std::bitset<Size>& exc) {
        ChunkData acc;
        ++adds;
        for (size_t i = 0; i < cluster.cluster_size; ++i) {
            if (inc[i]) acc += cluster.txdata[i];
        }
        ChunkData achieved = acc;
        std::bitset<Size> satisfied = inc;
        std::bitset<Size> required;
        std::bitset<Size> decided = inc | exc;
        for (size_t i = 0; i < cluster.cluster_size; ++i) {
            size_t idx = direct_order[i];
            if (!decided[idx]) {
                auto next = acc + cluster.txdata[idx];
                if (next > acc) {
                    acc = next;
                    satisfied[idx] = true;
                    required |= ancestors[idx];
                    if ((required & ~satisfied).none()) {
                        inc = satisfied;
                        achieved = acc;
                    }
                } else {
                    break;
                }
            }
        }
        if (acc < best.achieved) return;
        IncExcSolution<Size> sol{.inc = inc, .exc = exc, .achieved = achieved, .potential = acc};
        if (sol.achieved > best.achieved) {
            best = sol;
        }
        queue.emplace(sol);
/*      queue.emplace_back(sol);*/
    };

    add_fn({}, {});
/*    assert(best.achieved.bytes == 0);
    assert(queue.size() == 1);*/

    size_t max_queue{0};

    while (!queue.empty()) {
/*        size_t pos = ((unsigned __int128)rng() * queue.size()) >> 64;
        if (pos != queue.size() - 1) std::swap(queue[pos], queue.back());
        auto elem = queue.back();
        queue.pop_back();*/
        auto elem = queue.top();
        bool first = elem.inc.none();
        queue.pop();
/*        std::cerr << "PROC inc=" << elem.inc << " exc=" << elem.exc << std::endl;*/
        if (elem.potential <= best.achieved) continue;

        bool have_branch{false};
        size_t branch_idx{0};
/*        update_ancestors(elem.inc | elem.exc);*/
        for (size_t i = 0; i < cluster.cluster_size; ++i) {
            size_t idx = first ? ancestor_order[i] : direct_order[i];
            if (!elem.inc[idx] && !elem.exc[idx]) {
                branch_idx = idx;
                have_branch = true;
                break;
            }
        }
        if (have_branch) {
            add_fn(elem.inc | ancestors[branch_idx], elem.exc);
            add_fn(elem.inc, elem.exc | descendants[branch_idx]);
            max_queue = std::max(max_queue, queue.size());
        }
    }

/*    std::cerr << "INCEXC best (cluster_size=" << cluster.cluster_size << "): " << best.inc << std::endl;*/

    return {.iterations = adds, .queue_size = max_queue, .select = best.inc, .achieved = best.achieved};
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
        ++comparisons;
        return cluster.txdata[a].Compare(cluster.txdata[b]) > 0;
    });
    unsigned idx_to_sorted[Size];
    ChunkData sorted_data[Size];
    for (unsigned i = 0; i < cluster.cluster_size; ++i) {
        idx_to_sorted[sorted_to_idx[i]] = i;
        sorted_data[i] = cluster.txdata[sorted_to_idx[i]];
    }

    uint64_t ancestors[Size] = {0};
    for (unsigned i = 0; i < cluster.cluster_size; ++i) ancestors[i] = uint64_t{1} << i;
    bool changed;
    do {
        changed = false;
        for (unsigned i = 0; i < cluster.cluster_size; ++i) {
            unsigned sorted_i = idx_to_sorted[i];
            uint64_t deps = cluster.deps[i].to_ullong();
            while (deps) {
                int pos = StripBit(deps);
                uint64_t next = ancestors[sorted_i] | ancestors[idx_to_sorted[pos]];
                if (next != ancestors[sorted_i]) {
                    ancestors[sorted_i] = next;
                    changed = true;
                }
            }
        }
    } while(changed);

    uint64_t descendants[Size] = {0};
    for (unsigned i = 0; i < cluster.cluster_size; ++i) {
        uint64_t deps = ancestors[i];
        while (deps) {
            int pos = StripBit(deps);
            descendants[pos] |= uint64_t{1} << i;
        }
    }

    struct Sol
    {
        uint64_t inc, exc;
        ChunkData potential, achieved;
    };

    uint64_t done{0};
    uint64_t all = (~uint64_t{0}) >> (64 - cluster.cluster_size);

    auto compare_fn = [&](const Sol& a, const Sol& b) {
        ++comparisons;
        return a.potential.Compare(b.potential) < 0;
    };

    std::vector<ChunkingResult<Size>> chunks;

    while (done != all) {
        const size_t start_comparisons = comparisons;
        size_t iterations{0};
        uint64_t best{0};
        ChunkData best_achieved;

        std::priority_queue<Sol, std::vector<Sol>, decltype(compare_fn)> queue{compare_fn};

        auto add_fn = [&](ChunkData prev, uint64_t prevmask, uint64_t inc, uint64_t exc) {
            ChunkData acc = prev;
            uint64_t to_add = inc & ~prevmask;
            while (to_add) {
                int pos = StripBit(to_add);
                acc += sorted_data[pos];
            }
            ChunkData achieved = acc;
            uint64_t satisfied = inc;
            uint64_t required{0};
            uint64_t undecided = all & ~(inc | exc);
            while (undecided) {
                int pos = StripBit(undecided);
                ++comparisons;
                if (sorted_data[pos].CompareJustFeerate(acc) > 0) {
                    acc += sorted_data[pos];
                    satisfied |= uint64_t{1} << pos;
                    required |= ancestors[pos];
                    if (!(required & ~satisfied)) {
                        inc = satisfied;
                        achieved = acc;
                    }
                } else {
                    break;
                }
            }
            ++comparisons;
            if (acc.Compare(best_achieved) <= 0) return;
            ++comparisons;
            if (achieved.Compare(best_achieved) > 0) {
                best_achieved = achieved;
                best = inc;
            }
            Sol sol;
            sol.inc = inc;
            sol.exc = exc;
            sol.potential = acc;
            sol.achieved = achieved;
            queue.emplace(sol);
        };

        add_fn({}, done, done, 0);

        while (!queue.empty()) {
            Sol elem = queue.top();
            ++comparisons;
            if (elem.potential.Compare(best_achieved) <= 0) break;
            queue.pop();
            ++iterations;

            uint64_t undecided = all & ~(elem.inc | elem.exc);
            if (undecided) {
                int idx = StripBit(undecided);
                add_fn(elem.achieved, elem.inc, elem.inc | ancestors[idx], elem.exc);
                add_fn(elem.achieved, elem.inc, elem.inc, elem.exc | descendants[idx]);
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

template<size_t Size>
FullStats<Size> AnalyzeIncExcFull(const LinearClusterWithDeps<Size>& cluster)
{
    if (!cluster.IsConnected()) return {};

    struct timespec measure_start, measure_stop;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_start);

    auto ancestors = ComputeAncestors(cluster.deps, cluster.cluster_size);
    auto descendants = ComputeDescendants(cluster.deps, cluster.cluster_size);
    std::bitset<Size> done;


    std::array<size_t, Size> direct_order;
    std::iota(direct_order.begin(), direct_order.begin() + cluster.cluster_size, size_t{0});
    std::sort(direct_order.begin(), direct_order.begin() + cluster.cluster_size, [&](size_t a, size_t b) {
        // Don't count comparisons in here; they can always be maximized to O(n log n) by presenting
        // input in a pessimal order.
        return cluster.txdata[a] > cluster.txdata[b];
    });

    size_t comparisons{0};

    auto compare_fn = [&](const IncExcSolution<Size>& a, const IncExcSolution<Size>& b) {
        int cmp_pot = a.potential.Compare(b.potential);
        ++comparisons;
/*        if (cmp_pot) return cmp_pot < 0;
        int cmp_ach = a.achieved.Compare(a.achieved);
        ++comparisons;
        if (cmp_ach) return cmp_ach < 0;
        return false;*/
        return cmp_pot < 0;
    };

/*    std::cerr << "CLUSTER: " << cluster << std::endl;*/

    std::vector<ChunkingResult<Size>> chunks;

    while (done.count() != cluster.cluster_size) {

        const size_t start_comparisons{comparisons};
        size_t iterations{0};
        IncExcSolution<Size> best;

        std::priority_queue<IncExcSolution<Size>, std::vector<IncExcSolution<Size>>, decltype(compare_fn)> queue{compare_fn};

        auto add_fn = [&](std::bitset<Size> inc, const std::bitset<Size>& exc) {
            ChunkData acc;
            for (size_t i = 0; i < cluster.cluster_size; ++i) {
                if ((inc & ~done)[i]) acc += cluster.txdata[i];
            }
            ChunkData achieved = acc;
            std::bitset<Size> satisfied = inc;
            std::bitset<Size> required;
            std::bitset<Size> undecided = ~(inc | exc);
            for (size_t i = 0; i < cluster.cluster_size; ++i) {
                size_t idx = direct_order[i];
                if (undecided[idx]) {
                    auto next = acc + cluster.txdata[idx];
                    ++comparisons;
                    if (next > acc) {
                        acc = next;
                        satisfied[idx] = true;
                        required |= ancestors[idx];
                        if ((required & ~satisfied).none()) {
                            inc = satisfied;
                            achieved = acc;
                        }
                    } else {
                        break;
                    }
                }
            }
            ++comparisons;
            if (acc < best.achieved) return;
            IncExcSolution<Size> sol{.inc = inc, .exc = exc, .achieved = achieved, .potential = acc};
            ++comparisons;
            if (sol.achieved > best.achieved) {
                best = sol;
            }
            queue.emplace(sol);
        };

        add_fn(done, {});

        while (!queue.empty()) {
            auto elem = queue.top();
            ++comparisons;
            if (elem.potential <= best.achieved) break;
            queue.pop();
            ++iterations;

            bool have_branch{false};
            size_t branch_idx{0};
            for (size_t i = 0; i < cluster.cluster_size; ++i) {
                size_t idx = direct_order[i];
                if (~(elem.inc | elem.exc)[idx]) {
                    branch_idx = idx;
                    have_branch = true;
                    break;
                }
            }

            if (have_branch) {
                add_fn(elem.inc | ancestors[branch_idx], elem.exc);
                add_fn(elem.inc, elem.exc | descendants[branch_idx]);
            }
        }

/*
        const auto& [best_select, best_chunkdata, iters] = FindBestCandidates(cluster.txdata, cluster.deps, cluster.cluster_size, 9000000, done);
        assert(best.achieved >= best_chunkdata);
        if (iters <= 9000000) assert(best.achieved == best_chunkdata);
*/

        chunks.emplace_back(best.inc & ~done, best.achieved, iterations, comparisons - start_comparisons);
        done |= best.inc;
    }

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &measure_stop);

    double duration = (double)((int64_t)measure_stop.tv_sec - (int64_t)measure_start.tv_sec) + 0.000000001*(double)((int64_t)measure_stop.tv_nsec - (int64_t)measure_start.tv_nsec);

/*    std::cerr << "BENCH clustersize=" << cluster.cluster_size << " comparisons=" << comparisons << " chunks=" << chunks.size() << " duration=" << duration << " timepercomp=" << (duration / comparisons) << std::endl;*/

    return {.comparisons = comparisons, .chunks = std::move(chunks), .duration = duration};
}

} // namespace

FUZZ_TARGET(memepool_chunk_converge)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    XoRoShiRo128PlusPlus rng(provider.ConsumeIntegral<uint64_t>());

    std::vector<ChunkData> chunks;

    LIMITED_WHILE(provider.remaining_bytes(), 64) {
        chunks.emplace_back(ChunkData(provider));
    }

    std::vector<ChunkData> solution;

    for (int attempt = 0; attempt < 16; ++attempt) {
        std::vector<ChunkData> current_chunks = chunks;
        std::vector<int> merge_pos;

        while (true) {
            merge_pos.clear();
            for (size_t i = 1; i < current_chunks.size(); ++i) {
                if (current_chunks[i] > current_chunks[i - 1]) {
                    merge_pos.emplace_back(i - 1);
                }
            }
            if (merge_pos.empty()) break;

            size_t merge;
            if (merge_pos.size() == 1 || attempt == 0) {
                merge = merge_pos[0];
            } else {
                merge = merge_pos[rng() % merge_pos.size()];
            }

            assert(merge + 1 < current_chunks.size());
            assert(current_chunks[merge + 1] > current_chunks[merge]);
            current_chunks[merge] += current_chunks[merge + 1];
            current_chunks.erase(current_chunks.begin() + merge + 1);
        }

        if (attempt == 0) {
            solution = std::move(current_chunks);
        } else {
            assert(solution == current_chunks);
        }
    }
}


FUZZ_TARGET(memepool_optimal_linearization)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    size_t cluster_size{0};
    std::array<ChunkData, MAX_LINEARIZATION_CLUSTER> txdata;
    std::array<size_t, MAX_LINEARIZATION_CLUSTER> order[2];

    LIMITED_WHILE(provider.remaining_bytes(), MAX_LINEARIZATION_CLUSTER) {
        assert(cluster_size < MAX_LINEARIZATION_CLUSTER);
        txdata[cluster_size] = ChunkData(provider);
        order[0][cluster_size] = cluster_size;
        order[1][cluster_size] = cluster_size;
        size_t perm = cluster_size ? provider.ConsumeIntegralInRange<uint16_t>(0, cluster_size) : 0;
        if (perm != cluster_size) std::swap(order[1][cluster_size], order[1][perm]);
        ++cluster_size;
    }

#ifdef DO_LOG
    fprintf(stderr, "INFO: lin1=[");
    for (size_t i = 0; i < cluster_size; ++i) {
        fprintf(stderr, "%lu(%lu,%lu) ", (unsigned long)order[0][i], (unsigned long)txdata[order[0][i]].bytes, (unsigned long)txdata[order[0][i]].sats);
    }
    fprintf(stderr, "] lin2=[");
    for (size_t i = 0; i < cluster_size; ++i) {
        fprintf(stderr, "%lu(%lu,%lu) ", (unsigned long)order[1][i], (unsigned long)txdata[order[1][i]].bytes, (unsigned long)txdata[order[1][i]].sats);
    }
    fprintf(stderr, "] ");
#endif

    // If both orders are identical, there is nothing to check.
    if (order[0] == order[1]) {
#ifdef DO_LOG
        fprintf(stderr, "\n");
        fprintf(stderr, "DROP: equal order\n");
#endif
        return;
    }

    Chunking chunkings[3];
    for (size_t i = 0; i < cluster_size; ++i) {
        chunkings[0].Add(txdata[order[0][i]]);
        chunkings[1].Add(txdata[order[1][i]]);
    }
    if (chunkings[0] == chunkings[1]) {
#ifdef DO_LOG
        fprintf(stderr, "DROP: chunkings equal\n");
#endif
        return;
    }

    std::vector<ChunkData> diagram1, diagram2;
    chunkings[0].GetDiagram(diagram1);
    chunkings[1].GetDiagram(diagram2);

#ifdef DO_LOG
    fprintf(stderr, "graph1=[");
    for (size_t i = 0; i < diagram1.size(); ++i) {
        fprintf(stderr, "(%lu,%lu) ", (unsigned long)diagram1[i].bytes, (unsigned long)diagram1[i].sats);
    }
    fprintf(stderr, "] graph2=[");
    for (size_t i = 0; i < diagram2.size(); ++i) {
        fprintf(stderr, "(%lu,%lu) ", (unsigned long)diagram2[i].bytes, (unsigned long)diagram2[i].sats);
    }
#endif
    int vs_1_2 = DiagramFullCompare(diagram1, diagram2);
#ifdef DO_LOG
    fprintf(stderr, "] (1:2)=%i ", vs_1_2);
#endif

    if (vs_1_2 != 3) {
#ifdef DO_LOG
        fprintf(stderr, "\n");
        fprintf(stderr, "DROP: consistent quality comparison\n");
#endif
        return;
    }

    /* Compute implied dependency graph. */
    std::bitset<MAX_LINEARIZATION_CLUSTER> deps[3][MAX_LINEARIZATION_CLUSTER];
    for (int side = 0; side < 2; ++side) {
        std::bitset<MAX_LINEARIZATION_CLUSTER> comb;
        for (size_t i = 0; i < cluster_size; ++i) {
            deps[side][order[side][i]] = comb;
            comb[order[side][i]] = true;
        }
    }
    for (size_t i = 0; i < cluster_size; ++i) {
        deps[2][i] = deps[0][i] & deps[1][i];
    }

    std::array<size_t, MAX_LINEARIZATION_CLUSTER> new_order;
    std::bitset<MAX_LINEARIZATION_CLUSTER> new_selected;
    std::vector<ChunkData> new_diagram, best_diagram;
    bool done = false;
    bool ok = false;
    bool limit = false;
    size_t permutations = 0;

    auto rec = [&](size_t pos, auto& recfn) {
        if (done) return;
        if (pos == cluster_size) {
            Chunking new_chunking;
            for (size_t i = 0; i < cluster_size; ++i) {
                new_chunking.Add(txdata[new_order[i]]);
            }
            new_chunking.GetDiagram(new_diagram);
            int cmp1 = DiagramFullCompare(new_diagram, diagram1);
            int cmp2 = DiagramFullCompare(new_diagram, diagram2);
            if (cmp1 <= 1 && cmp2 <= 1) {
                done = true;
                ok = true;
            }
            if (++permutations > 1000000) {
                done = true;
                limit = true;
            }
        } else {
            for (size_t i = 0; i < cluster_size; ++i) {
                if (!new_selected[i]) {
                    if ((deps[2][i] & ~new_selected).none()) {
                        new_selected[i] = true;
                        new_order[pos] = i;
                        recfn(pos + 1, recfn);
                        new_selected[i] = false;
                    }
                }
            }
        }
    };


    rec(0, rec);

    assert(limit || ok);

#ifdef DO_LOG
    if (ok) {
        fprintf(stderr, "OK\n");
    } else if (limit) {
        fprintf(stderr, "LIMIT\n");
    }
#endif
}

FUZZ_TARGET(memepool_improve_linearization)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    size_t cluster_size{0};
    std::array<ChunkData, MAX_LINEARIZATION_CLUSTER> txdata;
    BitMatrix<MAX_LINEARIZATION_CLUSTER> deps;

    LIMITED_WHILE(provider.remaining_bytes(), MAX_LINEARIZATION_CLUSTER) {
        assert(cluster_size < MAX_LINEARIZATION_CLUSTER);
        txdata[cluster_size] = ChunkData(provider);
        for (size_t i = 0; i < cluster_size; ++i) {
            if (provider.ConsumeBool()) {
                deps[cluster_size][i] = true;
            }
        }
        ++cluster_size;
    }

    ChunkData best_chunkdata;
    ChunkData chunkdata;
    std::bitset<MAX_LINEARIZATION_CLUSTER> best_select;
    std::bitset<MAX_LINEARIZATION_CLUSTER> select;
    size_t iterations{0};
    bool limit{false};

    auto rec = [&](size_t pos, auto& recfn) {
        if (limit) return;
        if (pos == cluster_size) {
            if (++iterations > 100000) {
                limit = true;
                return;
            }
            if (select.any() && (best_select.none() || chunkdata > best_chunkdata)) {
                best_chunkdata = chunkdata;
                best_select = select;
            }
        } else {
            recfn(pos + 1, recfn);
            if ((deps[pos] & ~select).none()) {
                select[pos] = true;
                chunkdata += txdata[pos];
                recfn(pos + 1, recfn);
                chunkdata -= txdata[pos];
                select[pos] = false;
            }
        }
    };
    rec(0, rec);

    if (limit) return;

    Chunking chunk_old, chunk_new;

    for (size_t i = 0; i < cluster_size; ++i) {
        chunk_old.Add(txdata[i]);
        if (best_select[i]) {
            chunk_new.Add(txdata[i]);
        }
    }
    for (size_t i = 0; i < cluster_size; ++i) {
        if (!best_select[i]) {
            chunk_new.Add(txdata[i]);
        }
    }

    std::vector<ChunkData> diagram_old, diagram_new;
    chunk_old.GetDiagram(diagram_old);
    chunk_new.GetDiagram(diagram_new);

    int cmp = DiagramFullCompare(diagram_new, diagram_old);
    assert(cmp <= 1);
}

FUZZ_TARGET(memepool_improve_linearization_strict_size_one)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    auto moretxfn = [&](size_t) -> bool { return provider.remaining_bytes(); };
    auto txfeefn = [&](size_t) -> uint32_t { return provider.ConsumeIntegralInRange<uint32_t>(0, 0xFFFF); };
    auto depfn = [&](size_t, size_t) -> bool { return provider.ConsumeBool(); };

    TargetImproveLinearizationUnconvexedSizeOne(moretxfn, txfeefn, depfn);
}

FUZZ_TARGET(memepool_improve_linearization_strict_size_one_example)
{
    std::array fees{0, 2, 2, 0, 3};

    auto moretxfn = [&](size_t s) -> bool { return s < 5; };
    auto txfeefn = [&](size_t i) -> uint32_t { return fees[i]; };
    auto depfn = [&](size_t a, size_t b) -> bool { return (a==1 && b==0) || (a==2 && b==1) || (a == 4 && b==3); };

    TargetImproveLinearizationUnconvexedSizeOne(moretxfn, txfeefn, depfn);
}


FUZZ_TARGET(memepool_max_connected_candidates)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    size_t cluster_size{0};
    BitMatrix<MAX_LINEARIZATION_CLUSTER> deps;

    while (cluster_size < MAX_LINEARIZATION_CLUSTER && provider.remaining_bytes()) {
        for (size_t i = 0; i < cluster_size; ++i) {
            deps[cluster_size][i] = provider.ConsumeBool();
        }
        ++cluster_size;
    }

    if (!IsConnected(deps, cluster_size)) return;

    uint64_t candidates = CountCandidates(deps, cluster_size, 100000);

    assert(cluster_size > 0 || candidates <= 0);
    assert(cluster_size == 0 || candidates <= ((uint64_t)1) << (cluster_size - 1));
}

FUZZ_TARGET(memepool_analyze_incexc)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    LinearClusterWithDeps<MAX_LINEARIZATION_CLUSTER> cluster(provider);

    if (!cluster.IsConnected()) return;

/*    std::cerr << "PROC: " << cluster << std::endl;*/

    const auto& [best_select, best_chunkdata, iters] = FindBestCandidates(cluster.txdata, cluster.deps, cluster.cluster_size, 100000);
    std::vector<std::bitset<MAX_LINEARIZATION_CLUSTER>> empty;
    auto incexc_stats = AnalyzeIncExc(cluster);

/*    std::cerr << "STATS: best=" << best_chunkdata << " achieved=" << incexc_stats.achieved << std::endl;*/

    assert(incexc_stats.achieved >= best_chunkdata);
    if (iters < 100000) {
        assert(incexc_stats.achieved == best_chunkdata);
    }

    static std::array<size_t, MAX_LINEARIZATION_CLUSTER+1> MAX_ITERS;
    static std::array<size_t, MAX_LINEARIZATION_CLUSTER+1> MAX_QUEUE;
    static std::array<size_t, MAX_LINEARIZATION_CLUSTER+1> TOT_COUNT;

    TOT_COUNT[cluster.cluster_size] += 1;

    if (incexc_stats.iterations > MAX_ITERS[cluster.cluster_size]) {
        MAX_ITERS[cluster.cluster_size] = incexc_stats.iterations;
        std::cerr << "ITERS:";
        for (size_t i = 0; i <= MAX_LINEARIZATION_CLUSTER; ++i) {
            std::cerr << " " << i << ":" << MAX_ITERS[i];
        }
        std::cerr << std::endl;

    }

/*  static constexpr size_t KNOWN_LIMITS[] = {0,  0,  1,  2,  4,  6,  9, 15, 23,  35,  53,  83,  127, 189, 289, 429,  429};*/ /* always branch on direct feerate; iters; last change */
/*  static constexpr size_t KNOWN_LIMITS[] = {0,  1,  2,  2,  8, 14, 22, 36, 55,  81,   0,   0,    0,   0,   0,   0,    0};*/ /* first branch by ancestor feerate; adds; dir 2; last change */
    static constexpr size_t KNOWN_LIMITS[] = {1,  1,  3,  5,  9, 15, 25, 39, 57,  87, 135, 201,  293, 453,   0,   0,    0};   /* first branch by ancestor feerate; adds; dir 2; total count */
/*  static constexpr size_t KNOWN_LIMITS[] = {0,  1,  2,  2,  8, 14, 22, 36, 50,  79, 121, 183,  257, 417, 603, 799, 1107};*/ /* first branch by ancestor feerate; adds; last change */
/*  static constexpr size_t KNOWN_LIMITS[] = {0,  0,  1,  1,  2,  6, 13, 29, 61, 125, 253, 509, 1017,   0,   0,   0,    0};*/ /* always branch by ancestor feerate; iters; last change */
    /*                                        0   1   2   3   4   5   6   7   8    9   10   11    12   13   14   15    16 */
    /*                                        0   4   9  15  22  30  39  49  60   72   85   99   114  130  147  165   184 */

/*    if (cluster.cluster_size == 3 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 4 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 5 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;*/
    if (cluster.cluster_size == 6 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 7 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 8 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 9 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 10 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 11 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 12 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 13 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 14 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 15 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;
    if (cluster.cluster_size == 16 && incexc_stats.iterations >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "ITER " << (incexc_stats.iterations > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": [" << TOT_COUNT[cluster.cluster_size] << "]: " << incexc_stats.iterations << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << "] SEL:" << incexc_stats.select << std::endl;

    if (cluster.cluster_size <= 12) assert(incexc_stats.iterations <= KNOWN_LIMITS[cluster.cluster_size]);

    if (incexc_stats.queue_size > MAX_QUEUE[cluster.cluster_size]) {
        MAX_QUEUE[cluster.cluster_size] = incexc_stats.queue_size;
        std::cerr << "QUEUE:";
        for (size_t i = 0; i <= MAX_LINEARIZATION_CLUSTER; ++i) {
            std::cerr << " " << i << ":" << MAX_QUEUE[i];
        }
        std::cerr << std::endl;
    }
}

FUZZ_TARGET(memepool_analyze_incexc_full)
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

    static constexpr size_t KNOWN_LIMITS[] = {0,  4, 17, 39, 72, 118, 178, 251, 423, 713, 1146, 1865, 3149, 5017, 8008, 12738, 20390, 33634, 53619, 81236, 138000, 217939, 348463, 559652, 844640, 1310447, 1990701}; /* highest individual feerate first; num comparisons; full chunking */
    /*                                        0   1   2   3   4    5    6    7    8    9    10    11    12    13    14     15     16     17     18     19      20      21      22      23      24       25       26 */
    /*                                        0   4   9  15  22   30   39   49   60   72    85    99   114   130   147    165    184    204    225    247     270     294     319     345     372      400      429 */

/*    if (cluster.cluster_size == 3 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 4 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 5 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 6 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 7 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 8 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 9 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;*/

    if (cluster.cluster_size == 10 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 11 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 12 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 13 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 14 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 15 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 16 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 17 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 18 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 19 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 20 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 21 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 22 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 23 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 24 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 25 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;
    if (cluster.cluster_size == 26 && comparisons >= KNOWN_LIMITS[cluster.cluster_size]) std::cerr << "COMP " << (comparisons > KNOWN_LIMITS[cluster.cluster_size] ? "EXCEED" : "LIMIT") << " " << cluster.cluster_size << ": " << comparisons << ": CLUSTER " << cluster << " [SUBS=" << cluster.CountCandidates() << ",CHUNKS=" << chunks << "] dur=" << duration << std::endl;

/*    if (cluster.cluster_size >= 0 && cluster.cluster_size <= 26) assert(comparisons <= KNOWN_LIMITS[cluster.cluster_size]);*/
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

    assert(incexc_stats.achieved >= best_chunkdata);
    if (iters < 100000) {
        assert(incexc_stats.achieved == best_chunkdata);
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
