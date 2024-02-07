// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <span.h>
#include <test/fuzz/util.h>
#include <util/ringbuffer.h>

#include <iostream>
#include <deque>
#include <stdint.h>

namespace {

/** The maximum number of simultaneous buffers kept by the test. */
static constexpr size_t MAX_BUFFERS{3};
/** How many elements are kept in a buffer at most. */
static constexpr size_t MAX_BUFFER_SIZE{48};
/** How many operations are performed at most on the buffers in one test. */
static constexpr size_t MAX_OPERATIONS{1024};

/** Perform a simulation fuzz test on RingBuffer type T.
 *
 * T must be constructible from a uint64_t seed, comparable to other T, copyable, and movable.
 */
template<typename T, bool CheckNoneLeft>
void TestType(Span<const uint8_t> buffer, uint64_t rng_tweak)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    // Local RNG, only used for the seeds to initialize T objects with.
    InsecureRandomContext rng(provider.ConsumeIntegral<uint64_t>() ^ rng_tweak);

    // Real circular buffers.
    std::vector<RingBuffer<T>> real;
    real.reserve(MAX_BUFFERS);
    // Simulated circular buffers.
    std::vector<std::deque<T>> sim;
    sim.reserve(MAX_BUFFERS);
    // Temporary object of type T.
    std::optional<T> tmp;

    // Compare a real and a simulated buffer.
    auto compare_fn = [](const RingBuffer<T>& r, const std::deque<T>& s) {
        assert(r.size() == s.size());
        assert(r.empty() == s.empty());
        assert(r.capacity() >= r.size());
        if (s.size() == 0) return;
        assert(r.front() == s.front());
        assert(r.back() == s.back());
        for (size_t i = 0; i < s.size(); ++i) {
            assert(r[i] == s[i]);
        }
    };

    LIMITED_WHILE(provider.remaining_bytes(), MAX_OPERATIONS) {
        auto cmd_byte = provider.ConsumeIntegral<uint8_t>();
        unsigned idx = real.empty() ? 0 : (unsigned{cmd_byte} * real.size()) >> 8;
        uint32_t command = cmd_byte % 32;
        const size_t num_buffers = sim.size();
        // Loop until command reaches 0 (not all commands are always applicable, and this approach
        // avoids the need to compute the number of applicable commands ahead of time).
        while (true) {
            if (num_buffers < MAX_BUFFERS && command-- == 0) {
                /* Default construct. */
                real.emplace_back();
                sim.emplace_back();
                break;
            }
            if (num_buffers != 0 && command-- == 0) {
                /* resize() */
                size_t new_size = provider.ConsumeIntegralInRange<size_t>(0, MAX_BUFFER_SIZE);
                real[idx].resize(new_size);
                sim[idx].resize(new_size);
                assert(real[idx].size() == new_size);
                break;
            }
            if (num_buffers != 0 && command-- == 0) {
                /* clear() */
                real[idx].clear();
                sim[idx].clear();
                assert(real[idx].empty());
                break;
            }
            if (num_buffers != 0 && command-- == 0) {
                /* Copy construct default. */
                real[idx] = RingBuffer<T>();
                sim[idx].clear();
                assert(real[idx].size() == 0);
                break;
            }
            if (num_buffers != 0 && command-- == 0) {
                /* Destruct. */
                compare_fn(real.back(), sim.back());
                real.pop_back();
                sim.pop_back();
                break;
            }
            if (num_buffers > 0 && num_buffers < MAX_BUFFERS && command-- == 0) {
                /* Copy construct. */
                real.emplace_back(real[idx]);
                sim.emplace_back(sim[idx]);
                break;
            }
            if (num_buffers > 0 && num_buffers < MAX_BUFFERS && command-- == 0) {
                /* Move construct. */
                RingBuffer<T> copy(real[idx]);
                real.emplace_back(std::move(copy));
                sim.emplace_back(sim[idx]);
                break;
            }
            if (num_buffers > 1 && command-- == 0) {
                /* swap() */
                swap(real[idx], real[(idx + 1) % num_buffers]);
                swap(sim[idx], sim[(idx + 1) % sim.size()]);
                break;
            }
            if (num_buffers > 1 && command-- == 0) {
                /* Copy assign. */
                compare_fn(real[idx], sim[idx]);
                real[idx] = real[(idx + 1) % num_buffers];
                sim[idx] = sim[(idx + 1) % sim.size()];
                break;
            }
            if (num_buffers > 1 && command-- == 0) {
                /* Move assign. */
                RingBuffer<T> copy(real[(idx + 1) % num_buffers]);
                compare_fn(real[idx], sim[idx]);
                real[idx] = std::move(copy);
                sim[idx] = sim[(idx + 1) % sim.size()];
                break;
            }
            if (num_buffers != 0 && command-- == 0) {
                /* reserve() */
                size_t res_size = provider.ConsumeIntegralInRange<size_t>(0, MAX_BUFFER_SIZE);
                size_t old_cap = real[idx].capacity();
                size_t old_size = real[idx].size();
                real[idx].reserve(res_size);
                assert(real[idx].size() == old_size);
                assert(real[idx].capacity() == std::max(old_cap, res_size));
                break;
            }
            if (num_buffers != 0 && sim[idx].size() < MAX_BUFFER_SIZE && command-- == 0) {
                /* shrink_to_fit() */
                size_t old_size = real[idx].size();
                real[idx].shrink_to_fit();
                assert(real[idx].size() == old_size);
                assert(real[idx].capacity() == old_size);
                break;
            }
            if (num_buffers != 0 && sim[idx].size() < MAX_BUFFER_SIZE && command-- == 0) {
                /* push_back() (copying) */
                tmp = T(rng.rand64());
                size_t old_size = real[idx].size();
                size_t old_cap = real[idx].capacity();
                real[idx].push_back(*tmp);
                sim[idx].push_back(*tmp);
                assert(real[idx].size() == old_size + 1);
                if (old_cap > old_size) assert(real[idx].capacity() == old_cap);
                break;
            }
            if (num_buffers != 0 && sim[idx].size() < MAX_BUFFER_SIZE && command-- == 0) {
                /* push_back() (moving) */
                tmp = T(rng.rand64());
                size_t old_size = real[idx].size();
                size_t old_cap = real[idx].capacity();
                sim[idx].push_back(*tmp);
                real[idx].push_back(std::move(*tmp));
                assert(real[idx].size() == old_size + 1);
                if (old_cap > old_size) assert(real[idx].capacity() == old_cap);
                break;
            }
            if (num_buffers != 0 && sim[idx].size() < MAX_BUFFER_SIZE && command-- == 0) {
                /* emplace_back() */
                uint64_t seed{rng.rand64()};
                size_t old_size = real[idx].size();
                size_t old_cap = real[idx].capacity();
                sim[idx].emplace_back(seed);
                real[idx].emplace_back(seed);
                assert(real[idx].size() == old_size + 1);
                if (old_cap > old_size) assert(real[idx].capacity() == old_cap);
                break;
            }
            if (num_buffers != 0 && sim[idx].size() < MAX_BUFFER_SIZE && command-- == 0) {
                /* push_front() (copying) */
                tmp = T(rng.rand64());
                size_t old_size = real[idx].size();
                size_t old_cap = real[idx].capacity();
                real[idx].push_front(*tmp);
                sim[idx].push_front(*tmp);
                assert(real[idx].size() == old_size + 1);
                if (old_cap > old_size) assert(real[idx].capacity() == old_cap);
                break;
            }
            if (num_buffers != 0 && sim[idx].size() < MAX_BUFFER_SIZE && command-- == 0) {
                /* push_front() (moving) */
                tmp = T(rng.rand64());
                size_t old_size = real[idx].size();
                size_t old_cap = real[idx].capacity();
                sim[idx].push_front(*tmp);
                real[idx].push_front(std::move(*tmp));
                assert(real[idx].size() == old_size + 1);
                if (old_cap > old_size) assert(real[idx].capacity() == old_cap);
                break;
            }
            if (num_buffers != 0 && sim[idx].size() < MAX_BUFFER_SIZE && command-- == 0) {
                /* emplace_front() */
                uint64_t seed{rng.rand64()};
                size_t old_size = real[idx].size();
                size_t old_cap = real[idx].capacity();
                sim[idx].emplace_front(seed);
                real[idx].emplace_front(seed);
                assert(real[idx].size() == old_size + 1);
                if (old_cap > old_size) assert(real[idx].capacity() == old_cap);
                break;
            }
            if (num_buffers != 0 && !sim[idx].empty() && command-- == 0) {
                /* front() [modifying] */
                tmp = T(rng.rand64());
                size_t old_size = real[idx].size();
                assert(sim[idx].front() == real[idx].front());
                sim[idx].front() = *tmp;
                real[idx].front() = std::move(*tmp);
                assert(real[idx].size() == old_size);
                break;
            }
            if (num_buffers != 0 && !sim[idx].empty() && command-- == 0) {
                /* back() [modifying] */
                tmp = T(rng.rand64());
                size_t old_size = real[idx].size();
                assert(sim[idx].back() == real[idx].back());
                sim[idx].back() = *tmp;
                real[idx].back() = *tmp;
                assert(real[idx].size() == old_size);
                break;
            }
            if (num_buffers != 0 && !sim[idx].empty() && command-- == 0) {
                /* operator[] [modifying] */
                tmp = T(rng.rand64());
                size_t pos = provider.ConsumeIntegralInRange<size_t>(0, sim[idx].size() - 1);
                size_t old_size = real[idx].size();
                assert(sim[idx][pos] == real[idx][pos]);
                sim[idx][pos] = *tmp;
                real[idx][pos] = std::move(*tmp);
                assert(real[idx].size() == old_size);
                break;
            }
        }
    }

    /* Fully compare the final state. */
    for (unsigned i = 0; i < sim.size(); ++i) {
        // Make sure const getters work.
        const RingBuffer<T>& realbuf = real[i];
        const std::deque<T>& simbuf = sim[i];
        compare_fn(realbuf, simbuf);
        for (unsigned j = 0; j < sim.size(); ++j) {
            assert((realbuf == real[j]) == (simbuf == sim[j]));
            assert((real[j] <=> realbuf) == (sim[j] <=> simbuf));
        }
        // Clear out the buffers so we can check below that no objects exist anymore.
        sim[i].clear();
        real[i].clear();
    }

    if constexpr (CheckNoneLeft) {
        tmp = std::nullopt;
        T::CheckNoneExist();
    }
}

/** Data structure with built-in tracking of all existing objects. */
template<size_t Size>
class TrackedObj
{
    static_assert(Size > 0);

    /* Data type for map that actually stores the object data.
     *
     * The key is a pointer to the TrackedObj, the value is the uint64_t it was initialized with.
     * Default-constructed and moved-from objects hold an std::nullopt.
     */
    using track_map_type = std::map<const TrackedObj<Size>*, std::optional<uint64_t>>;

private:

    /** Actual map. */
    static inline track_map_type g_tracker;

    /** Iterators into the tracker map for this object.
     *
     * This is an array of size Size, all holding the same value, to give the object configurable
     * size. The value is g_tracker.end() if this object is not fully initialized. */
    track_map_type::iterator m_track_entry[Size];

    void Check() const
    {
        auto it = g_tracker.find(this);
        for (size_t i = 0; i < Size; ++i) {
            assert(m_track_entry[i] == it);
        }
    }

    void Register()
    {
        auto [it, inserted] = g_tracker.emplace(this, std::nullopt);
        assert(inserted);
        for (size_t i = 0; i < Size; ++i) {
            m_track_entry[i] = it;
        }
    }

    void Deregister()
    {
        Check();
        assert(m_track_entry[0] != g_tracker.end());
        g_tracker.erase(m_track_entry[0]);
        for (size_t i = 0; i < Size; ++i) {
            m_track_entry[i] = g_tracker.end();
        }
    }

    std::optional<uint64_t>& Deref()
    {
        Check();
        assert(m_track_entry[0] != g_tracker.end());
        return m_track_entry[0]->second;
    }

    const std::optional<uint64_t>& Deref() const
    {
        Check();
        assert(m_track_entry[0] != g_tracker.end());
        return m_track_entry[0]->second;
    }

public:
    ~TrackedObj() { Deregister(); }
    TrackedObj() { Register(); }

    TrackedObj(uint64_t value)
    {
        Register();
        Deref() = value;
    }

    TrackedObj(const TrackedObj& other)
    {
        Register();
        Deref() = other.Deref();
    }

    TrackedObj(TrackedObj&& other)
    {
        Register();
        Deref() = other.Deref();
        other.Deref() = std::nullopt;
    }

    TrackedObj& operator=(const TrackedObj& other)
    {
        Deref() = other.Deref();
        return *this;
    }

    TrackedObj& operator=(TrackedObj&& other)
    {
        Deref() = other.Deref();
        other.Deref() = std::nullopt;
        return *this;
    }

    friend bool operator==(const TrackedObj& a, const TrackedObj& b)
    {
        return a.Deref() == b.Deref();
    }

    friend std::strong_ordering operator<=>(const TrackedObj& a, const TrackedObj& b)
    {
        return a.Deref() <=> b.Deref();
    }

    static void CheckNoneExist()
    {
        assert(g_tracker.empty());
    }
};

} // namespace

FUZZ_TARGET(ringbuffer)
{
    // Run the test with simple uints (which are std::is_trivially_copyable_v).
    TestType<uint8_t, false>(buffer, 1);
    TestType<uint16_t, false>(buffer, 2);
    TestType<uint32_t, false>(buffer, 3);
    TestType<uint64_t, false>(buffer, 4);
    // Run the test with TrackedObjs (which are not).
    TestType<TrackedObj<1>, true>(buffer, 5);
    TestType<TrackedObj<3>, true>(buffer, 6);
    TestType<TrackedObj<17>, true>(buffer, 7);
}
