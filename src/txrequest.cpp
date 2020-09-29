// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txrequest.h>

#include <crypto/siphash.h>
#include <net.h>
#include <primitives/transaction.h>
#include <random.h>
#include <uint256.h>
#include <util/memory.h>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>

#include <chrono>
#include <unordered_map>
#include <utility>

#include <assert.h>

namespace {

/** The various states a (txhash,peer) pair can be in.
 *
 * Note that CANDIDATE is split up into 3 substates (DELAYED, BEST, READY), allowing more efficient implementation.
 * Also note that the sorting order of EntryTxHash relies on the specific order of values in this enum.
 *
 * Expected behaviour is:
 *   - When first announced by a peer, the state is CANDIDATE_DELAYED until reqtime is reached.
 *   - Announcemnets that have reached their reqtime but not been requested will be either CANDIDATE_READY or
 *     CANDIDATE_BEST
 *   - When requested, an announcement will be in state REQUESTED until expiry is reached.
 *   - If expiry is reached, or the peer replies to the request (either with NOTFOUND or the tx), the state becomes
 *     COMPLETED
 */
enum class State : uint8_t {
    /** A CANDIDATE entry whose reqtime is in the future. */
    CANDIDATE_DELAYED,
    /** The best CANDIDATE for a given txhash; only if there is no REQUESTED entry already for that txhash.
     *  The CANDIDATE_BEST is the lowest-priority entry among all CANDIDATE_READY (and _BEST) ones for that txhash. */
    CANDIDATE_BEST,
    /** A REQUESTED entry. */
    REQUESTED,
    /** A CANDIDATE entry that's not CANDIDATE_DELAYED or CANDIDATE_BEST. */
    CANDIDATE_READY,
    /** A COMPLETED entry. */
    COMPLETED,

    /** An invalid State value that's larger than all valid ones. */
    TOO_LARGE,
};

/** An announcement entry. This is the data we track for each txid or wtxid that is announced to us. */
struct Entry {
    /** Txid or wtxid that was announced. */
    const uint256 m_txhash;
    /** For CANDIDATE_{DELAYED,BEST,READY} the reqtime; for REQUESTED the expiry. */
    std::chrono::microseconds m_time;
    /** What peer the request was from. */
    const uint64_t m_peer;
    /** What sequence number this announcement has. */
    const uint64_t m_sequence : 59;
    /** Whether the request is preferred (giving it priority higher than non-preferred ones). */
    const bool m_preferred : 1;
    /** Whether this is a wtxid request. */
    const bool m_is_wtxid : 1;

    /** What state this announcement is in. This is a uint8_t instead of a State to silence a GCC warning. */
    uint8_t m_state : 3;

    // The two flags below are _per txhash_, and not per announcement. They're part of the Entry
    // data structure because having a separate per-txhash map would consume much more memory.
    // Only the flags of the last Entry for a given txhash (ByTxHash order) are relevant;
    // the other ones are ignored.

    /** Convert the m_state variable to a State enum. */
    State GetState() const { return State(m_state); }
    /** Convert a State to a uint8_t and store it in m_state. */
    void SetState(State state) { m_state = uint8_t(state); }

    /** Whether this entry is selected. There can be at most 1 selected peer per txhash. */
    bool IsSelected() const
    {
        return GetState() == State::CANDIDATE_BEST || GetState() == State::REQUESTED;
    }

    /** Whether this entry is waiting for a certain time to pass. */
    bool IsWaiting() const
    {
        return GetState() == State::REQUESTED || GetState() == State::CANDIDATE_DELAYED;
    }

    /** Whether this entry can feasibly be selected if the current IsSelected() one disappears. */
    bool IsSelectable() const
    {
        return GetState() == State::CANDIDATE_READY || GetState() == State::CANDIDATE_BEST;
    }

    /** Construct a new entry from scratch, initially in CANDIDATE_DELAYED state. */
    Entry(const GenTxid& gtxid, uint64_t peer, bool preferred, std::chrono::microseconds reqtime,
        uint64_t sequence) :
        m_txhash(gtxid.GetHash()), m_time(reqtime), m_peer(peer), m_sequence(sequence), m_preferred(preferred),
        m_is_wtxid(gtxid.IsWtxid()), m_state(uint8_t(State::CANDIDATE_DELAYED)) {}
};

/** A functor with embedded salt that computes priority of an announcement.
 *
 * Lower priorities are selected first.
 */
class PriorityComputer {
    const uint64_t m_k0, m_k1;
public:
    explicit PriorityComputer(bool deterministic) :
        m_k0{deterministic ? 0 : GetRand(0xFFFFFFFFFFFFFFFF)},
        m_k1{deterministic ? 0 : GetRand(0xFFFFFFFFFFFFFFFF)} {}

    uint64_t operator()(const uint256& txhash, uint64_t peer, bool preferred) const
    {
        uint64_t low_bits = CSipHasher(m_k0, m_k1).Write(txhash.begin(), txhash.size()).Write(peer).Finalize() >> 1;
        return low_bits | uint64_t{!preferred} << 63;
    }

    uint64_t operator()(const Entry& entry) const
    {
        return operator()(entry.m_txhash, entry.m_peer, entry.m_preferred);
    }
};

// Definitions for the 3 indexes used in the main data structure.
//
// Each index has a By* type to identify it, a Entry* data type to represent the view of Entry it is sorted by,
// and an Entry*Extractor type to convert an Entry into the Entry* view type.
// See https://www.boost.org/doc/libs/1_54_0/libs/multi_index/doc/reference/key_extraction.html#key_extractors
// for more information about the key extraction concept.

// The ByPeer index is sorted by (peer, state == CANDIDATE_BEST, txhash)
//
// Uses:
// * Looking up existing entries by peer/txhash, by checking both (peer, false, txhash) and (peer, true, txhash).
// * Finding all CANDIDATE_BEST for a given peer in GetRequestable.
struct ByPeer {};
using EntryPeer = std::tuple<uint64_t, bool, const uint256&>;
struct EntryPeerExtractor
{
    using result_type = EntryPeer;
    result_type operator()(const Entry& entry) const
    {
        return EntryPeer{entry.m_peer, entry.GetState() == State::CANDIDATE_BEST, entry.m_txhash};
    }
};

// The ByTxHash index is sorted by (txhash, state, priority [CANDIDATE_READY]; 0 [otherwise])
//
// Uses:
// * Deleting all Entrys with a given txhash in ForgetTxHash.
// * Finding the best CANDIDATE_READY to convert to CANDIDATE_READY, when no other CANDIDATE_READY or REQUESTED
//   Entry exists for that txhash.
// * Finding the Entry to store per-txhash flags in.
// * Determining when no more non-COMPLETED Entrys for a given txhash exist, so the COMPLETED ones can be deleted.
struct ByTxHash {};
using EntryTxHash = std::tuple<const uint256&, State, uint64_t>;
class EntryTxHashExtractor {
    const PriorityComputer& m_computer;
public:
    EntryTxHashExtractor(const PriorityComputer& computer) : m_computer(computer) {}
    using result_type = EntryTxHash;
    result_type operator()(const Entry& entry) const
    {
        const State state = entry.GetState();
        const uint64_t prio = (state == State::CANDIDATE_READY) ? m_computer(entry) : 0;
        return EntryTxHash{entry.m_txhash, state, prio};
    }
};

// The ByTime index is sorted by (0 [CANDIDATE_DELAYED,REQUESTED]; 1 [COMPLETED];
// 2 [CANDIDATE_READY,CANDIDATE_BEST], time)
//
// Uses:
// * Finding CANDIDATE_DELAYED entries whose reqtime has passed, and REQUESTED entries whose expiry has passed.
// * Finding CANDIDATE_READY/BEST entries whose reqtime is in the future (when the clock time when backwards).
struct ByTime {};
using EntryTime = std::pair<int, std::chrono::microseconds>;
struct EntryTimeExtractor
{
    using result_type = EntryTime;
    result_type operator()(const Entry& entry) const
    {
        return EntryTime{entry.IsWaiting() ? 0 : entry.IsSelectable() ? 2 : 1, entry.m_time};
    }
};

/** Data type for the main data structure (Entry objects with ByPeer/ByTxHash/ByTime indexes). */
using Index = boost::multi_index_container<
    Entry,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByPeer>, EntryPeerExtractor>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByTxHash>, EntryTxHashExtractor>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByTime>, EntryTimeExtractor>
    >
>;

/** Helper type to simplify syntax of iterator types. */
template<typename Tag>
using Iter = typename Index::index<Tag>::type::iterator;

/** Per-peer statistics object. */
struct PeerInfo {
    size_t m_total = 0; //!< Total number of entries for this peer.
    size_t m_completed = 0; //!< Number of COMPLETED entries for this peer.
    size_t m_requested = 0; //!< Number of REQUESTED entries for this peer.

    friend bool operator==(const PeerInfo& a, const PeerInfo& b)
    {
        return std::tie(a.m_total, a.m_completed, a.m_requested) ==
               std::tie(b.m_total, b.m_completed, b.m_requested);
    }
};

/** Per-txhash statistics object. Only used for sanity checking. */
struct TxHashInfo
{
    //! Number of CANDIDATE_DELAYED entries for this txhash.
    size_t m_candidate_delayed = 0;
    //! Number of CANDIDATE_READY entries for this txhash.
    size_t m_candidate_ready = 0;
    //! Number of CANDIDATE_BEST entries for this txhash (at most one).
    size_t m_candidate_best = 0;
    //! Number of REQUESTED entries for this txhash.
    size_t m_requested = 0;
    //! The priority of the CANDIDATE_BEST entry if one exists, or 0 otherwise.
    uint64_t m_priority_candidate_best = 0;
    //! The lowest priority of all CANDIDATE_READY entries (or max() if none exist).
    uint64_t m_priority_best_candidate_ready = std::numeric_limits<uint64_t>::max();
    //! All peers we have an entry for this txhash for.
    std::vector<uint64_t> m_peers;
};

/** (Re)compute the PeerInfo map from the index. Only used for sanity checking. */
std::unordered_map<uint64_t, PeerInfo> RecomputePeerInfo(const Index& index)
{
    std::unordered_map<uint64_t, PeerInfo> ret;
    for (const Entry& entry : index) {
        PeerInfo& info = ret[entry.m_peer];
        ++info.m_total;
        info.m_requested += (entry.GetState() == State::REQUESTED);
        info.m_completed += (entry.GetState() == State::COMPLETED);
    }
    return ret;
}

/** Compute the TxHashInfo map. Only used for sanity checking. */
std::map<uint256, TxHashInfo> ComputeTxHashInfo(const Index& index, const PriorityComputer& computer)
{
    std::map<uint256, TxHashInfo> ret;
    for (const Entry& entry : index) {
        TxHashInfo& info = ret[entry.m_txhash];
        // Classify how many Entrys of each state we have for this txhash.
        info.m_candidate_delayed += (entry.GetState() == State::CANDIDATE_DELAYED);
        info.m_candidate_ready += (entry.GetState() == State::CANDIDATE_READY);
        info.m_candidate_best += (entry.GetState() == State::CANDIDATE_BEST);
        info.m_requested += (entry.GetState() == State::REQUESTED);
        // And track the priority of the best CANDIDATE_READY/CANDIDATE_BEST entries.
        if (entry.GetState() == State::CANDIDATE_BEST) {
            info.m_priority_candidate_best = computer(entry);
        }
        if (entry.GetState() == State::CANDIDATE_READY) {
            info.m_priority_best_candidate_ready = std::min(info.m_priority_best_candidate_ready, computer(entry));
        }
        // Also keep track of which peers this txhash has a Entry for (so we can detect duplicates).
        info.m_peers.push_back(entry.m_peer);
        // Track preferred/first.
    }
    return ret;
}

const uint256 UINT256_ZERO;

}  // namespace

/** Actual implementation for TxRequestTracker's data structure. */
class TxRequestTracker::Impl {
    //! The current sequence number. Increases for every announcement. This is used to sort txhashes returned by
    //! GetRequestable in announcement order.
    uint64_t m_sequence{0};

    //! This tracker's priority computer.
    const PriorityComputer m_computer;

    //! This tracker's main data structure.
    Index m_index;

    //! Map with this tracker's per-peer statistics.
    std::unordered_map<uint64_t, PeerInfo> m_peerinfo;

public:
    void SanityCheck() const
    {
        // Recompute m_peerdata from m_index. This verifies the data in it as it should just be caching statistics
        // on m_index. It also verifies the invariant that no PeerInfo entries exist with m_total==0 exist.
        assert(m_peerinfo == RecomputePeerInfo(m_index));

        // Calculate per-txhash statistics from m_index, and validate invariants.
        for (auto& item : ComputeTxHashInfo(m_index, m_computer)) {
            TxHashInfo& info = item.second;

            // Cannot have only COMPLETED peer (txhash should have been forgotten already)
            assert(info.m_candidate_delayed + info.m_candidate_ready + info.m_candidate_best + info.m_requested > 0);

            // Can have at most 1 CANDIDATE_BEST/REQUESTED peer
            assert(info.m_candidate_best + info.m_requested <= 1);

            // If there are any CANDIDATE_READY entries, there must be exactly one CANDIDATE_BEST or REQUESTED
            // entry.
            if (info.m_candidate_ready > 0) {
                assert(info.m_candidate_best + info.m_requested == 1);
            }

            // If there is both a CANDIDATE_READY and a CANDIDATE_BEST entry, the CANDIDATE_BEST one must be at
            // least as good (equal or lower priority) as the best CANDIDATE_READY.
            if (info.m_candidate_ready && info.m_candidate_best) {
                assert(info.m_priority_candidate_best <= info.m_priority_best_candidate_ready);
            }

            // No txhash can have been announced by the same peer twice.
            std::sort(info.m_peers.begin(), info.m_peers.end());
            assert(std::adjacent_find(info.m_peers.begin(), info.m_peers.end()) == info.m_peers.end());

            // Looking up the last ByTxHash entry with the given txhash must return an Entry with that txhash or the
            // multi_index is very bad.
            auto it_last = std::prev(m_index.get<ByTxHash>().lower_bound(
                EntryTxHash{item.first, State::TOO_LARGE, 0}));
            assert(it_last != m_index.get<ByTxHash>().end() && it_last->m_txhash == item.first);
        }
    }

    void PostGetRequestableSanityCheck(std::chrono::microseconds now) const
    {
        for (const auto& entry : m_index) {
            if (entry.IsWaiting()) {
                // REQUESTED and CANDIDATE_DELAYED must have a time in the future (they should have been converted
                // to COMPLETED/CANDIDATE_READY respectively).
                assert(entry.m_time > now);
            } else if (entry.IsSelectable()) {
                // CANDIDATE_READY and CANDIDATE_BEST cannot have a time in the future (they should have remained
                // CANDIDATE_DELAYED, or should have been converted back to it if time went backwards).
                assert(entry.m_time <= now);
            }
        }
    }

private:
    //! Wrapper around Index::...::erase that keeps m_peerinfo and per-txhash flags up to date.
    template<typename Tag>
    Iter<Tag> Erase(Iter<Tag> it)
    {
        auto peerit = m_peerinfo.find(it->m_peer);
        peerit->second.m_completed -= it->GetState() == State::COMPLETED;
        peerit->second.m_requested -= it->GetState() == State::REQUESTED;
        if (--peerit->second.m_total == 0) m_peerinfo.erase(peerit);
        return m_index.get<Tag>().erase(it);
    }

    //! Wrapper around Index::...::modify that keeps m_peerinfo and per-txhash flags up to date.
    template<typename Tag, typename Modifier>
    void Modify(Iter<Tag> it, Modifier modifier)
    {
        auto peerit = m_peerinfo.find(it->m_peer);
        peerit->second.m_completed -= it->GetState() == State::COMPLETED;
        peerit->second.m_requested -= it->GetState() == State::REQUESTED;
        m_index.get<Tag>().modify(it, std::move(modifier));
        peerit->second.m_completed += it->GetState() == State::COMPLETED;
        peerit->second.m_requested += it->GetState() == State::REQUESTED;
    }

    //! Convert a CANDIDATE_DELAYED entry into a CANDIDATE_READY. If this makes it the new best CANDIDATE_READY
    //! (and no REQUESTED exists) and better than the CANDIDATE_BEST (if any), it becomes the new CANDIDATE_BEST.
    void PromoteCandidateReady(Iter<ByTxHash> it)
    {
        assert(it->GetState() == State::CANDIDATE_DELAYED);
        // Convert CANDIDATE_DELAYED to CANDIDATE_READY first.
        Modify<ByTxHash>(it, [](Entry& entry){ entry.SetState(State::CANDIDATE_READY); });
        // The following code relies on the fact that the ByTxHash is sorted by txhash, and then by state (first
        // _DELAYED, then _BEST/REQUESTED, then _READY). Within the _READY entries, the best one (lowest priority)
        // comes first. Thus, if an existing _BEST exists for the same txhash that this entry may be preferred over,
        // it must immediately precede the newly created _READY.
        if (it == m_index.get<ByTxHash>().begin() || std::prev(it)->m_txhash != it->m_txhash ||
            std::prev(it)->GetState() == State::CANDIDATE_DELAYED) {
            // This is the new best CANDIDATE_READY, and there is no IsSelected() entry for this txhash already.
            Modify<ByTxHash>(it, [](Entry& entry){ entry.SetState(State::CANDIDATE_BEST); });
        } else if (std::prev(it)->GetState() == State::CANDIDATE_BEST) {
            uint64_t priority_old = m_computer(*std::prev(it));
            uint64_t priority_new = m_computer(*it);
            if (priority_new < priority_old) {
                // There is a CANDIDATE_BEST entry already, but this one is better.
                auto new_ready_it = std::prev(it);
                Modify<ByTxHash>(new_ready_it, [](Entry& entry){ entry.SetState(State::CANDIDATE_READY); });
                Modify<ByTxHash>(it, [](Entry& entry){ entry.SetState(State::CANDIDATE_BEST); });
            }
        }
    }

    //! Change the state of an entry to something non-IsSelected(). If it was IsSelected(), the next best entry will
    //! be marked CANDIDATE_BEST.
    void ChangeAndReselect(Iter<ByTxHash> it, State new_state)
    {
        if (it->IsSelected()) {
            auto it_next = std::next(it);
            // The next best CANDIDATE_READY, if any, immediately follows the REQUESTED or CANDIDATE_BEST entry in
            // the ByTxHash index.
            if (it_next != m_index.get<ByTxHash>().end() && it_next->m_txhash == it->m_txhash &&
                it_next->GetState() == State::CANDIDATE_READY) {
                // If one such CANDIDATE_READY exists (for this txhash), convert it to CANDIDATE_BEST.
                Modify<ByTxHash>(it_next, [](Entry& entry){ entry.SetState(State::CANDIDATE_BEST); });
            }
        }
        Modify<ByTxHash>(it, [new_state](Entry& entry){ entry.SetState(new_state); });
        assert(!it->IsSelected());
    }

    //! Check if 'it' is the only Entry for a given txhash that isn't COMPLETED.
    bool IsOnlyNonCompleted(Iter<ByTxHash> it)
    {
        assert(it->GetState() != State::COMPLETED); // Not allowed to call this on COMPLETED entries.

        // If this Entry's predecessor exists, and belongs to the same txhash, it can't be COMPLETED either.
        if (it != m_index.get<ByTxHash>().begin() && std::prev(it)->m_txhash == it->m_txhash) return false;

        // If this Entry's successor exists, belongs to the same txhash, and isn't COMPLETED, fail.
        if (std::next(it) != m_index.get<ByTxHash>().end() && std::next(it)->m_txhash == it->m_txhash &&
            std::next(it)->GetState() != State::COMPLETED) return false;

        return true;
    }

    /** Convert any entry to a COMPLETED one. If there are no non-COMPLETED entries left for this txhash, they are
     *  deleted. If this was a REQUESTED entry, and there are other CANDIDATEs left, the best one is made
     *  CANDIDATE_BEST. Returns whether the Entry still exists. */
    bool MakeCompleted(Iter<ByTxHash> it)
    {
        // Nothing to be done if it's already COMPLETED.
        if (it->GetState() == State::COMPLETED) return true;

        if (IsOnlyNonCompleted(it)) {
            // This is the last non-COMPLETED entry for this txhash. Delete all.
            uint256 txhash = it->m_txhash;
            do {
                it = Erase<ByTxHash>(it);
            } while (it != m_index.get<ByTxHash>().end() && it->m_txhash == txhash);
            return false;
        }

        // Mark the entry COMPLETED, and select the next best entry (the first CANDIDATE_READY) if needed.
        ChangeAndReselect(it, State::COMPLETED);

        return true;
    }

    //! Make the data structure consistent with a given point in time:
    //! - REQUESTED entries with expiry <= now are turned into COMPLETED.
    //! - CANDIDATE_DELAYED entries with reqtime <= now are turned into CANDIDATE_{READY,BEST}.
    //! - CANDIDATE_{READY,BEST} entries with reqtime > now are turned into CANDIDATE_DELAYED.
    void SetTimePoint(std::chrono::microseconds now)
    {
        // Iterate over all CANDIDATE_DELAYED and REQUESTED from old to new, as long as they're in the past,
        // and convert them to CANDIDATE_READY and COMPLETED respectively.
        while (!m_index.empty()) {
            auto it = m_index.get<ByTime>().begin();
            if (it->GetState() == State::CANDIDATE_DELAYED && it->m_time <= now) {
                PromoteCandidateReady(m_index.project<ByTxHash>(it));
            } else if (it->GetState() == State::REQUESTED && it->m_time <= now) {
                MakeCompleted(m_index.project<ByTxHash>(it));
            } else {
                break;
            }
        }

        while (!m_index.empty()) {
            // If time went backwards, we may need to demote CANDIDATE_BEST and CANDIDATE_READY entries back
            // to CANDIDATE_DELAYED. This is an unusual edge case, and unlikely to matter in production. However,
            // it makes it much easier to specify and test TxRequestTracker::Impl's behaviour.
            auto it = std::prev(m_index.get<ByTime>().end());
            if (it->IsSelectable() && it->m_time > now) {
                ChangeAndReselect(m_index.project<ByTxHash>(it), State::CANDIDATE_DELAYED);
            } else {
                break;
            }
        }
    }

public:
    Impl(bool deterministic) :
        m_computer(deterministic),
        // Explicitly initialize m_index as we need to pass a reference to m_computer to EntryTxHashExtractor.
        m_index(boost::make_tuple(
            boost::make_tuple(EntryPeerExtractor(), std::less<EntryPeer>()),
            boost::make_tuple(EntryTxHashExtractor(m_computer), std::less<EntryTxHash>()),
            boost::make_tuple(EntryTimeExtractor(), std::less<EntryTime>())
        )) {}

    // Disable copying and assigning (a default copy won't work due the stateful EntryTxHashExtractor).
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    void DisconnectedPeer(uint64_t peer)
    {
        auto& index = m_index.get<ByPeer>();
        auto it = index.lower_bound(EntryPeer{peer, false, UINT256_ZERO});
        while (it != index.end() && it->m_peer == peer) {
            // Check what to continue with after this iteration. Note that 'it' may change position, and
            // std::next(it) may be deleted in the process, so this needs to be decided beforehand.
            auto it_next = (std::next(it) == index.end() || std::next(it)->m_peer != peer) ?
                index.end() : std::next(it);
            // If the entry isn't already COMPLETED, first make it COMPLETED (which will mark other CANDIDATEs as
            // CANDIDATE_BEST, or delete all of a txhash's entries if no non-COMPLETED ones are left).
            if (MakeCompleted(m_index.project<ByTxHash>(it))) {
                // Then actually delete the entry (unless it was already deleted by MakeCompleted).
                Erase<ByPeer>(it);
            }
            it = it_next;
        }
    }

    void ForgetTxHash(const uint256& txhash)
    {
        auto it = m_index.get<ByTxHash>().lower_bound(EntryTxHash{txhash, State::CANDIDATE_DELAYED, 0});
        while (it != m_index.get<ByTxHash>().end() && it->m_txhash == txhash) {
            it = Erase<ByTxHash>(it);
        }
    }

    void ReceivedInv(uint64_t peer, const GenTxid& gtxid, bool preferred,
        std::chrono::microseconds reqtime)
    {
        // Bail out if we already have a CANDIDATE_BEST entry for this (txhash, peer) combination. The case where
        // there is a non-CANDIDATE_BEST entry already will be caught by the uniqueness property of the ByPeer index
        // automatically.
        if (m_index.get<ByPeer>().count(EntryPeer{peer, true, gtxid.GetHash()})) return;

        // Find last entry for this txhash, and extract per-txhash information from it.
        Iter<ByTxHash> it_last = m_index.get<ByTxHash>().end();
        // First find the first entry past this txhash.
        it_last = m_index.get<ByTxHash>().lower_bound(EntryTxHash{gtxid.GetHash(), State::TOO_LARGE, 0});
        if (it_last != m_index.get<ByTxHash>().begin() && std::prev(it_last)->m_txhash == gtxid.GetHash()) {
            it_last--;
        } else {
            // No entry for this txhash exists yet.
            it_last = m_index.get<ByTxHash>().end();
        }

        // Try creating the entry with CANDIDATE_DELAYED state (which will fail due to the uniqueness
        // of the ByPeer index if a non-CANDIDATE_BEST entry already exists with the same txhash and peer).
        // Bail out in that case.
        auto ret = m_index.get<ByPeer>().emplace(gtxid, peer, preferred, reqtime, m_sequence);
        if (!ret.second) return;

        // Update accounting metadata.
        ++m_peerinfo[peer].m_total;
        ++m_sequence;
    }

    //! Find the GenTxids to request now from peer.
    std::vector<GenTxid> GetRequestable(uint64_t peer, std::chrono::microseconds now)
    {
        // Move time.
        SetTimePoint(now);

        // Find all CANDIDATE_BEST entries for this peer.
        std::vector<std::pair<uint64_t, const Entry*>> selected;
        auto it_peer = m_index.get<ByPeer>().lower_bound(EntryPeer{peer, true, UINT256_ZERO});
        while (it_peer != m_index.get<ByPeer>().end() && it_peer->m_peer == peer &&
            it_peer->GetState() == State::CANDIDATE_BEST) {
            selected.emplace_back(it_peer->m_sequence, &*it_peer);
            ++it_peer;
        }

        // Return them, sorted by sequence number.
        std::sort(selected.begin(), selected.end());
        std::vector<GenTxid> ret;
        for (const auto& item : selected) {
            ret.emplace_back(item.second->m_is_wtxid, item.second->m_txhash);
        }
        return ret;
    }

    void RequestedTx(uint64_t peer, const GenTxid& gtxid, std::chrono::microseconds expiry)
    {
        auto it = m_index.get<ByPeer>().find(EntryPeer{peer, true, gtxid.GetHash()});
        // RequestedTx can only be called on CANDIDATE_BEST entries (this is implied by its condition that it can
        // only be called on GenTxids returned by GetRequestable (and only AlreadyHave and RequestedTx can be called
        // in between, which preserve the state of other GenTxids).
        assert(it != m_index.get<ByPeer>().end());
        assert(it->GetState() == State::CANDIDATE_BEST);
        Modify<ByPeer>(it, [expiry](Entry& entry) {
            entry.SetState(State::REQUESTED);
            entry.m_time = expiry;
        });

        // Update the per-txhash data (of the last Entry for this txhash) to reflect that new ones are no longer
        // eligible for the "first" marker.
        auto it_last = std::prev(m_index.get<ByTxHash>().lower_bound(EntryTxHash{gtxid.GetHash(), State::TOO_LARGE, 0}));
        assert(it_last->m_txhash == gtxid.GetHash());
    }

    void ReceivedResponse(uint64_t peer, const GenTxid& gtxid)
    {
        // We need to search the ByPeer index for both (peer, false, txhash) and (peer, true, txhash).
        auto it = m_index.get<ByPeer>().find(EntryPeer{peer, false, gtxid.GetHash()});
        if (it == m_index.get<ByPeer>().end()) {
            it = m_index.get<ByPeer>().find(EntryPeer{peer, true, gtxid.GetHash()});
        }
        if (it != m_index.get<ByPeer>().end()) MakeCompleted(m_index.project<ByTxHash>(it));
    }

    size_t CountInFlight(uint64_t peer) const
    {
        auto it = m_peerinfo.find(peer);
        if (it != m_peerinfo.end()) return it->second.m_requested;
        return 0;
    }

    size_t CountCandidates(uint64_t peer) const
    {
        auto it = m_peerinfo.find(peer);
        if (it != m_peerinfo.end()) return it->second.m_total - it->second.m_requested - it->second.m_completed;
        return 0;
    }

    size_t Count(uint64_t peer) const
    {
        auto it = m_peerinfo.find(peer);
        if (it != m_peerinfo.end()) return it->second.m_total;
        return 0;
    }

    //! Count how many announcements are being tracked in total across all peers and transactions.
    size_t Size() const { return m_index.size(); }

    uint64_t ComputePriority(const uint256& txhash, uint64_t peer, bool preferred) const
    {
        return m_computer(txhash, peer, preferred);
    }

};

TxRequestTracker::TxRequestTracker(bool deterministic) :
    m_impl{MakeUnique<TxRequestTracker::Impl>(deterministic)} {}

TxRequestTracker::~TxRequestTracker() = default;

void TxRequestTracker::ForgetTxHash(const uint256& txhash) { m_impl->ForgetTxHash(txhash); }
void TxRequestTracker::DisconnectedPeer(uint64_t peer) { m_impl->DisconnectedPeer(peer); }
size_t TxRequestTracker::CountInFlight(uint64_t peer) const { return m_impl->CountInFlight(peer); }
size_t TxRequestTracker::CountCandidates(uint64_t peer) const { return m_impl->CountCandidates(peer); }
size_t TxRequestTracker::Count(uint64_t peer) const { return m_impl->Count(peer); }
size_t TxRequestTracker::Size() const { return m_impl->Size(); }
void TxRequestTracker::SanityCheck() const { m_impl->SanityCheck(); }

void TxRequestTracker::PostGetRequestableSanityCheck(std::chrono::microseconds now) const
{
    m_impl->PostGetRequestableSanityCheck(now);
}

void TxRequestTracker::ReceivedInv(uint64_t peer, const GenTxid& gtxid, bool preferred,
    std::chrono::microseconds reqtime)
{
    m_impl->ReceivedInv(peer, gtxid, preferred, reqtime);
}

void TxRequestTracker::RequestedTx(uint64_t peer, const GenTxid& gtxid, std::chrono::microseconds expiry)
{
    m_impl->RequestedTx(peer, gtxid, expiry);
}

void TxRequestTracker::ReceivedResponse(uint64_t peer, const GenTxid& gtxid)
{
    m_impl->ReceivedResponse(peer, gtxid);
}

std::vector<GenTxid> TxRequestTracker::GetRequestable(uint64_t peer, std::chrono::microseconds now)
{
    return m_impl->GetRequestable(peer, now);
}

uint64_t TxRequestTracker::ComputePriority(const uint256& txhash, uint64_t peer, bool preferred) const
{
    return m_impl->ComputePriority(txhash, peer, preferred);
}
