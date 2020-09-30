// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <random.h>
#include <txrequest.h>
#include <test/fuzz/fuzz.h>
#include <crypto/common.h>
#include <crypto/siphash.h>

#include <bitset>
#include <cstdint>
#include <queue>
#include <vector>

namespace {

constexpr int MAX_TXHASHES = 16;
constexpr int MAX_PEERS = 16;

//! Randomly generated GenTxids used in this test (length is MAX_TX).
uint256 TXHASHES[MAX_TXHASHES];

/** Precomputed random durations (positive and negative, each ~exponentially distributed). */
std::chrono::microseconds DELAYS[256];

struct Initializer
{
    Initializer()
    {
        // Use deterministic RNG to fill in txids and delays.
        // Non-determinism hurts fuzzing.
        FastRandomContext rng(true);
        for (int txhash = 0; txhash < MAX_TXHASHES; txhash += 1) {
            do {
                TXHASHES[txhash] = rng.rand256();
            } while (*(TXHASHES[txhash].begin() + 31) != txhash || *(TXHASHES[txhash].begin()) != txhash);
        }
        for (int i = 0; i < 16; ++i) {
            DELAYS[i] = std::chrono::microseconds{i};
        }
        for (int i = 16; i < 128; ++i) {
            DELAYS[i] = DELAYS[i - 1] + std::chrono::microseconds{1 + rng.randbits(((i - 10) * 2) / 9)};
        }
        for (int i = 128; i < 256; ++i) {
            DELAYS[i] = -DELAYS[255 - i];
        }
    }
} g_initializer;

/** Tester class for TxRequestTracker
 *
 * It includes a naive reimplementation of its behavior, for a limited set
 * of MAX_TXHASHES distinct txids, and MAX_PEERS peer identifiers.
 *
 * All of the public member functions perform the same operation on
 * an actual TxRequestTracker and on the state of the reimplementation.
 * The output of GetRequestable is compared with the expected value
 * as well.
 *
 * Check() calls the TxRequestTracker's sanity check, plus compares the
 * output of the constant accessors (Size(), CountLoad(), CountTracked())
 * with expected values.
 */
class Tester
{
    //! TxRequestTracker object being tested.
    TxRequestTracker m_tracker;

    //! States for txid/peer combinations in the naive data structure.
    enum class State {
        NOTHING, //!< Absence of this txid/peer combination

        // Note that this implementation does not distinguish between BEST/NEW/OTHER variants of CANDIDATE.
        CANDIDATE,
        REQUESTED,
        COMPLETED,
    };

    //! Sequence numbers, incremented whenever a new CANDIDATE is added.
    uint64_t m_sequence{0};

    //! List of future 'events' (all inserted reqtimes/exptimes). This is used to implement AdvanceToEvent.
    std::priority_queue<std::chrono::microseconds, std::vector<std::chrono::microseconds>, std::greater<std::chrono::microseconds>> m_events;

    //! Information about a txhash/peer combination.
    struct Entry
    {
        std::chrono::microseconds m_time;
        uint64_t m_sequence;
        State m_state{State::NOTHING};
        bool m_preferred;
        bool m_first;
        bool m_is_wtxid;
        uint64_t m_priority; //!< Precomputed priority.
    };

    struct PerTxHash
    {
        bool m_ever_requested = false;
        bool m_ever_first_preferred = false;
        bool m_ever_first_nonpreferred = false;
    };

    //! Information about all txhash/peer combination.
    Entry m_entries[MAX_TXHASHES][MAX_PEERS];

    //! Information about every txhash.
    PerTxHash m_pertxhash[MAX_TXHASHES];

    //! The current time; can move forward and backward.
    std::chrono::microseconds m_now{112223333};

    //! The last peer we've called GetRequestable for, or -1 if none.
    //! Also reset to -1 whenever an operation is performed that removes the ability to call RequestedTx.
    int m_get_requestable_last_peer = -1;

    //! The txidnums returned by the last GetRequestable, which ForgetTxHash or RequestedTx haven't been called on
    //! yet.
    std::bitset<MAX_TXHASHES> m_get_requestable_last_result;

    //! Check if a new entry for txhash can be marked first.
    bool PermitFirst(int txhash, bool preferred)
    {
        return !(m_pertxhash[txhash].m_ever_requested ||
            (preferred ?
                m_pertxhash[txhash].m_ever_first_preferred :
                m_pertxhash[txhash].m_ever_first_nonpreferred
            ));
    }

    //! Delete txhashes whose only entries are COMPLETED.
    void Cleanup(int txhash)
    {
        bool all_nothing = true;
        for (int peer = 0; peer < MAX_PEERS; ++peer) {
            const Entry& entry = m_entries[txhash][peer];
            if (entry.m_state == State::CANDIDATE || entry.m_state == State::REQUESTED) return;
            if (entry.m_state != State::NOTHING) all_nothing = false;
        }
        m_pertxhash[txhash].m_ever_requested = false;
        m_pertxhash[txhash].m_ever_first_preferred = false;
        m_pertxhash[txhash].m_ever_first_nonpreferred = false;
        if (all_nothing) return;
        for (int peer = 0; peer < MAX_PEERS; ++peer) {
            m_entries[txhash][peer].m_state = State::NOTHING;
        }
    }

    //! Find the current best peer to request from for a txhash (or -1 if none).
    int GetSelected(int txhash) const
    {
        int ret = -1;
        uint64_t ret_priority = 0;
        for (int peer = 0; peer < MAX_PEERS; ++peer) {
            const auto& entry = m_entries[txhash][peer];
            // Return -1 if there already is a (non-expired) in-flight request.
            if (entry.m_state == State::REQUESTED) return -1;
            // If it's a viable candidate, see if it has lower priority than the best one so far.
            if (entry.m_state == State::CANDIDATE && entry.m_time <= m_now) {
                if (ret == -1 || entry.m_priority < ret_priority) {
                    std::tie(ret, ret_priority) = std::tie(peer, entry.m_priority);
                }
            }
        }
        return ret;
    }

public:
    Tester() : m_tracker(true) {}

    std::chrono::microseconds Now() const { return m_now; }

    void AdvanceTime(std::chrono::microseconds offset)
    {
        m_now += offset;
        while (!m_events.empty() && m_events.top() <= m_now) m_events.pop();
    }

    void AdvanceToEvent()
    {
        while (!m_events.empty() && m_events.top() <= m_now) m_events.pop();
        if (!m_events.empty()) {
            m_now = m_events.top();
            m_events.pop();
        }
    }

    void DisconnectedPeer(int peer)
    {
        // Removes the ability to call RequestedTx until the next GetRequestable.
        m_get_requestable_last_peer = -1;

        // Apply to naive structure: all entries for that peer are wiped.
        for (int txhash = 0; txhash < MAX_TXHASHES; ++txhash) {
            if (m_entries[txhash][peer].m_state != State::NOTHING) {
                m_entries[txhash][peer].m_state = State::NOTHING;
                Cleanup(txhash);
            }
        }

        // Call TxRequestTracker's implementation.
        m_tracker.DisconnectedPeer(peer);
    }

    void ForgetTxHash(int txhash)
    {
        // RequestedTx cannot be called on this txidnum anymore.
        m_get_requestable_last_result.reset(txhash);

        // Apply to naive structure: all entries for that txhash are wiped.
        for (int peer = 0; peer < MAX_PEERS; ++peer) {
            m_entries[txhash][peer].m_state = State::NOTHING;
        }
        Cleanup(txhash);

        // Call TxRequestTracker's implementation.
        m_tracker.ForgetTxHash(TXHASHES[txhash]);
    }

    void ReceivedInv(int peer, int txhash, bool is_wtxid, bool preferred, bool overloaded,
        std::chrono::microseconds reqtime)
    {
        // Removes the ability to call RequestedTx until the next GetRequestable.
        m_get_requestable_last_peer = -1;

        // Apply to naive structure: if no entry for txidnum/peer combination
        // already, create a new CANDIDATE; otherwise do nothing.
        Entry& entry = m_entries[txhash][peer];
        if (entry.m_state == State::NOTHING) {
            entry.m_first = !overloaded && PermitFirst(txhash, preferred);
            entry.m_preferred = preferred;
            entry.m_state = State::CANDIDATE;
            entry.m_time = reqtime;
            entry.m_is_wtxid = is_wtxid;
            entry.m_sequence = m_sequence++;
            entry.m_priority = m_tracker.ComputePriority(TXHASHES[txhash], peer, entry.m_preferred, entry.m_first);
            if (entry.m_first && entry.m_preferred) m_pertxhash[txhash].m_ever_first_preferred = true;
            if (entry.m_first && !entry.m_preferred) m_pertxhash[txhash].m_ever_first_nonpreferred = true;

            // Add event so that AdvanceToEvent can quickly jump to the point where its reqtime passes.
            if (reqtime > m_now) m_events.push(reqtime);
        }

        // Call TxRequestTracker's implementation.
        m_tracker.ReceivedInv(peer, GenTxid{is_wtxid, TXHASHES[txhash]}, preferred, overloaded, reqtime);
    }

    void RequestedTx(int txhash, bool is_wtxid, std::chrono::microseconds exptime)
    {
        // Must be called with a txid that was returned by GetRequestable
        int peer = m_get_requestable_last_peer;
        if (peer == -1) return;
        if (!m_get_requestable_last_result[txhash]) return;
        m_get_requestable_last_result.reset(txhash);

        // Apply to naive structure: convert CANDIDATE to REQUESTED.
        assert(m_entries[txhash][peer].m_state == State::CANDIDATE);
        m_entries[txhash][peer].m_state = State::REQUESTED;
        m_entries[txhash][peer].m_time = exptime;
        m_pertxhash[txhash].m_ever_requested = true;

        // Add event so that AdvanceToEvent can quickly jump to the point where its exptime passes.
        if (exptime > m_now) m_events.push(exptime);

        // Call TxRequestTracker's implementation.
        m_tracker.RequestedTx(peer, GenTxid{is_wtxid, TXHASHES[txhash]}, exptime);
    }

    void ReceivedResponse(int peer, int txhash, bool is_wtxid)
    {
        // Removes the ability to call RequestedTx until the next GetRequestable.
        m_get_requestable_last_peer = -1;

        // Apply to naive structure: convert anything to COMPLETED.
        if (m_entries[txhash][peer].m_state != State::NOTHING) {
            m_entries[txhash][peer].m_state = State::COMPLETED;
            Cleanup(txhash);
        }

        // Call TxRequestTracker's implementation.
        m_tracker.ReceivedResponse(peer, GenTxid{is_wtxid, TXHASHES[txhash]});
    }

    void GetRequestable(int peer)
    {
        // Enables future calls to RequestedTx for this peer, and the call's response as txids.
        m_get_requestable_last_peer = peer;
        m_get_requestable_last_result.reset();

        // Implement using naive structure:
        std::vector<std::tuple<uint64_t, int, bool>> result; //!< list of (sequence number, txhash, is_wtxid) pairs.
        for (int txhash = 0; txhash < MAX_TXHASHES; ++txhash) {
            // Mark any expired REQUESTED entries as COMPLETED.
            for (int peer2 = 0; peer2 < MAX_PEERS; ++peer2) {
                auto& entry2 = m_entries[txhash][peer2];
                if (entry2.m_state == State::REQUESTED && entry2.m_time <= m_now) {
                    entry2.m_state = State::COMPLETED;
                    break;
                }
            }
            // And delete txids with only COMPLETED entries left.
            Cleanup(txhash);
            // CANDIDATEs for which this entry has the lowest priority get returned.
            const auto& entry = m_entries[txhash][peer];
            if (entry.m_state == State::CANDIDATE && GetSelected(txhash) == peer) {
                m_get_requestable_last_result.set(txhash);
                result.emplace_back(entry.m_sequence, txhash, entry.m_is_wtxid);
            }
        }
        // Sort the results by sequence number.
        std::sort(result.begin(), result.end());

        // Compare with TxRequestTracker's implementation.
        const auto actual = m_tracker.GetRequestable(peer, m_now);

        m_tracker.PostGetRequestableSanityCheck(m_now);
        assert(result.size() == actual.size());
        for (size_t pos = 0; pos < actual.size(); ++pos) {
            assert(TXHASHES[std::get<1>(result[pos])] == actual[pos].GetHash());
            assert(std::get<2>(result[pos]) == actual[pos].IsWtxid());
        }
    }

    void Check()
    {
        // Compare CountTracked and CountLoad with naive structure.
        size_t total = 0;
        for (int peer = 0; peer < MAX_PEERS; ++peer) {
            size_t tracked = 0;
            size_t inflight = 0;
            size_t candidates = 0;
            for (int txhash = 0; txhash < MAX_TXHASHES; ++txhash) {
                tracked += m_entries[txhash][peer].m_state != State::NOTHING;
                inflight += m_entries[txhash][peer].m_state == State::REQUESTED;
                candidates += m_entries[txhash][peer].m_state == State::CANDIDATE;
            }
            assert(m_tracker.Count(peer) == tracked);
            assert(m_tracker.CountInFlight(peer) == inflight);
            assert(m_tracker.CountCandidates(peer) == candidates);
            total += tracked;
        }
        // Compare Size.
        assert(m_tracker.Size() == total);

        // Invoke internal consistency check of TxRequestTracker object.
        m_tracker.SanityCheck();
    }
};
} // namespace

void test_one_input(const std::vector<uint8_t>& buffer)
{
    // Tester object (which encapsulates a TxRequestTracker).
    Tester tester;

    // Decode the input as a sequence of instructions with parameters
    auto it = buffer.begin();
    while (it != buffer.end()) {
        int cmd = *(it++) % 15;
        int peer, txidnum, delaynum;
        switch (cmd) {
        case 0: // Make time jump to the next event (m_time of PENDING or REQUESTED)
            tester.AdvanceToEvent();
            break;
        case 1: // Change time
            delaynum = it == buffer.end() ? 0 : *(it++);
            tester.AdvanceTime(DELAYS[delaynum]);
            break;
        case 2: // Query for requestable txs
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            tester.GetRequestable(peer);
            break;
        case 3: // Peer went offline
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            tester.DisconnectedPeer(peer);
            break;
        case 4: // No longer need tx
            txidnum = it == buffer.end() ? 0 : *(it++);
            tester.ForgetTxHash(txidnum % MAX_TXHASHES);
            break;
        case 5: // Received immediate preferred non-overloaded inv
        case 6: // Same, but non-preferred overloaded.
        case 7: // Same, but preferred overloaded.
        case 8: // Same, but non-preferred non-overloaded.
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            txidnum = it == buffer.end() ? 0 : *(it++);
            tester.ReceivedInv(peer, txidnum % MAX_TXHASHES, (txidnum / MAX_TXHASHES) & 1, cmd & 1, cmd & 2,
                std::chrono::microseconds::min());
            break;
        case 9: // Received delayed preferred non-overloaded inv
        case 10: // Same, but non-preferred overloaded.
        case 11: // Same, but preferred overloaded.
        case 12: // Same, but non-preferred non-overloaded.
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            txidnum = it == buffer.end() ? 0 : *(it++);
            delaynum = it == buffer.end() ? 0 : *(it++);
            tester.ReceivedInv(peer, txidnum % MAX_TXHASHES, (txidnum / MAX_TXHASHES) & 1, cmd & 1, cmd & 2,
                tester.Now() + DELAYS[delaynum]);
            break;
        case 13: // Requested tx from peer
            txidnum = it == buffer.end() ? 0 : *(it++);
            delaynum = it == buffer.end() ? 0 : *(it++);
            tester.RequestedTx(txidnum % MAX_TXHASHES, (txidnum / MAX_TXHASHES) & 1,
                tester.Now() + DELAYS[delaynum]);
            break;
        case 14: // Received response
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            txidnum = it == buffer.end() ? 0 : *(it++);
            tester.ReceivedResponse(peer, txidnum % MAX_TXHASHES, (txidnum / MAX_TXHASHES) & 1);
            break;
        default:
            assert(false);
        }
    }
    tester.Check();
}
