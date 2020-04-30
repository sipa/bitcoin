// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txrequest.h>

#include <crypto/siphash.h>
#include <net.h>
#include <random.h>
#include <uint256.h>

#include <chrono>
#include <utility>

#include <assert.h>

TxRequestTracker::AnnouncementKeyHasher::AnnouncementKeyHasher(bool det) :
    k0(det ? 0 : GetRand(std::numeric_limits<uint64_t>::max())),
    k1(det ? 0 : GetRand(std::numeric_limits<uint64_t>::max())) {}

size_t TxRequestTracker::AnnouncementKeyHasher::operator()(const AnnouncementKey& key) const
{
    return CSipHasher(k0, k1)
        .Write(key.m_txid.GetUint64(0))
        .Write(key.m_txid.GetUint64(1))
        .Write(key.m_txid.GetUint64(2))
        .Write(key.m_txid.GetUint64(3))
        .Write(key.m_node)
        .Finalize();
}

TxRequestTracker::TxRequestTracker(std::chrono::microseconds inbound_delay, std::chrono::microseconds timeout, size_t max_in_flight, bool deterministic) :
    m_inbound_delay(inbound_delay), m_timeout(timeout), m_max_in_flight(max_in_flight),
    m_index(boost::make_tuple(
        // Construct the first index explicitly (because we want to pass deterministic to the AnnouncementKeyHasher)
        boost::make_tuple(
            size_t(0),
            boost::multi_index::member<Announcement, AnnouncementKey, &Announcement::m_key>(),
            AnnouncementKeyHasher(deterministic),
            std::equal_to<AnnouncementKey>()
        ),
        // Default construct the second index
        Index::index<ByTxid>::type::ctor_args(),
        // Default construct the third index
        Index::index<ByPeer>::type::ctor_args()
    )) {}

TxRequestTracker::Index::index<TxRequestTracker::ByTxid>::type::iterator TxRequestTracker::GetSelectedForTxid(const uint256& txid) const
{
    Announcement an{0, txid, std::chrono::microseconds::min(), AnnounceType::FIRST_SELECTED};
    auto it = m_index_txid.lower_bound(an);
    if (it == m_index_txid.end() || it->m_key.m_txid != txid || !it->IsSelected()) return m_index_txid.end();
    return it;
}

TxRequestTracker::Index::index<TxRequestTracker::ByTxid>::type::iterator TxRequestTracker::FirstCandidateforTxid(const uint256& txid) const
{
    Announcement an{0, txid, std::chrono::microseconds::min(), AnnounceType::FIRST_CANDIDATE};
    auto it = m_index_txid.lower_bound(an);
    if (it == m_index_txid.end() || it->m_key.m_txid != txid || !it->IsCandidate()) return m_index_txid.end();
    return it;
}

TxRequestTracker::Index::index<TxRequestTracker::ByTxid>::type::iterator TxRequestTracker::NextCandidateforTxid(Index::index<ByTxid>::type::iterator it) const
{
    auto it_next = std::next(it);
    if (it_next == m_index_txid.end() || it_next->m_key.m_txid != it->m_key.m_txid || !it_next->IsCandidate()) return m_index_txid.end();
    return it_next;
}

void TxRequestTracker::ChangeSelected(Index::index<ByTxid>::type::iterator it_old, Index::index<ByTxid>::type::iterator it_new)
{
    if (it_old == it_new) return;

    // Unplan the current planned announcement (convert it back to CANDIDATE)
    NodeId old_node = -1;
    bool reeval = false;
    if (it_old != m_index_txid.end()) {
        assert(it_old->IsPlanned());
        old_node = it_old->m_key.m_node;
        AnnounceType new_type = it_old->IsOutbound() ? AnnounceType::CANDIDATE_OUT : AnnounceType::CANDIDATE_IN;
        m_index_txid.modify(it_old, [new_type](Announcement& a) {a.m_type = new_type;});
        auto peer_it = m_peerdata.find(it_old->m_key.m_node);
        assert(peer_it != m_peerdata.end());
        reeval = (peer_it->second.m_in_flight-- == m_max_in_flight); // Reevaluate if this brings in flight below limit
    }

    // Plan the new announcement (convert from CANDIDATE to PLANNED)
    assert(it_new != m_index_txid.end());
    assert(it_new->IsCandidate());
    AnnounceType new_type = it_new->IsOutbound() ? AnnounceType::PLANNED_OUT : AnnounceType::PLANNED_IN;
    m_index_txid.modify(it_new, [new_type](Announcement& a) {a.m_type = new_type; });
    auto peer_it = m_peerdata.find(it_new->m_key.m_node);
    assert(peer_it != m_peerdata.end());
    ++peer_it->second.m_in_flight;

    // If this took the old peer from being at max-in-flight to below, try to find other transactions to plan for it.
    if (reeval) ReevaluatePeer(old_node);
}

bool TxRequestTracker::UpdateSelectedForTxid(const uint256& txid)
{
    // First find the currently selected announcement
    auto selected = GetSelectedForTxid(txid);
    // If it's one we've already requested from, don't change it (it needs to receive a response or time out first).
    // Also, if the currently selected peer is already an outbound one, don't change it (we prefer outbound).
    if (selected != m_index_txid.end() && (selected->IsWaiting() || selected->IsOutbound())) return true;

    bool skipped_full_peer = false;
    // No peer is selected yet, or it's a not-yet requested inbound peer, see if maybe a better candidate exists.
    auto candidate = FirstCandidateforTxid(txid);
    while (candidate != m_index_txid.end()) {
        assert(candidate->IsCandidate());
        if (selected != m_index_txid.end()) {
            assert(selected->IsPlanned() && !selected->IsOutbound());
            if (!candidate->IsOutbound()) return true; // If the candidate is inbound, so are all following ones. Give up.
        }
        // If this peer has in-flight slots available, switch to it
        auto peer_it = m_peerdata.find(candidate->m_key.m_node);
        assert(peer_it != m_peerdata.end());
        if (peer_it->second.m_in_flight < m_max_in_flight) {
            ChangeSelected(selected, candidate);
            return true;
        }
        skipped_full_peer = true;
        // Otherwise, move on to the next candidate peer:
        candidate = NextCandidateforTxid(candidate);
    }

    return skipped_full_peer || selected != m_index_txid.end();
}

void TxRequestTracker::ReevaluatePeer(NodeId node)
{
    auto peer_it = m_peerdata.find(node);
    if (peer_it == m_peerdata.end()) return;

    Announcement an{node, {}, std::chrono::microseconds::min(), AnnounceType::FIRST_CANDIDATE};
    auto it = m_index_peer.lower_bound(an);
    while (peer_it->second.m_in_flight < m_max_in_flight && it != m_index_peer.end() && it->m_key.m_node == node && it->IsCandidate()) {
        uint256 txid = it->m_key.m_txid;
        ++it;
        // Only reconsider txids with no currently selected peer; this is not optimal
        // but reconsidering everything could set off a cycle of peer-txid reassignments.
        if (GetSelectedForTxid(txid) == m_index_txid.end()) UpdateSelectedForTxid(txid);
    }
}

void TxRequestTracker::DeleteTxid(const uint256& txid)
{
    // Find the first entry for txid.
    Announcement an{0, txid, std::chrono::microseconds::min(), AnnounceType(0)};
    auto it = m_index_txid.lower_bound(an);
    // Iterate over the entries of that txid and delete them.
    while (it != m_index_txid.end() && it->m_key.m_txid == txid) {
        NodeId node = it->m_key.m_node;
        auto peers_it = m_peerdata.find(node);
        assert(peers_it != m_peerdata.end());
        bool reeval = false;
        if (--peers_it->second.m_total_announcements == 0) {
            m_peerdata.erase(peers_it);
        } else if (it->IsSelected()) {
            // If we delete a selected announcement for a peer (and it isn't the last announcement
            // by that peer), reevaluate it.
            reeval = (peers_it->second.m_in_flight-- == m_max_in_flight);
        }
        it = m_index_txid.erase(it);
        if (reeval) ReevaluatePeer(node);
    }
}

void TxRequestTracker::ProcessTimeouts(NodeId node, std::chrono::microseconds now)
{
    auto peer_it = m_peerdata.find(node);
    if (peer_it == m_peerdata.end()) return;

    // Find the first timed-out announcement
    Announcement an{node, {}, std::chrono::microseconds::min(), AnnounceType::WAITING};
    auto it = m_index_peer.lower_bound(an);
    bool was_at_limit = peer_it->second.m_in_flight == m_max_in_flight;
    // Delete entries as long as they're expired WAITING entries for the right node
    while (it != m_index_peer.end() && it->m_key.m_node == node && it->IsWaiting() && it->m_time <= now) {
        uint256 txid = it->m_key.m_txid;
        m_index_peer.modify(it, [](Announcement& a){ a.m_type = AnnounceType::FINISHED; });
        --peer_it->second.m_in_flight;
        ++it;
        if (!UpdateSelectedForTxid(txid)) {
            DeleteTxid(txid);
            // Deleting a transaction may invalidate "it".
            it = m_index_peer.lower_bound(an);
        }
    }
    // If this peer was at the in-flight limit, still exists, and is no longer at the limit, reevaluate its transactions
    if (was_at_limit && m_peerdata.count(node) && peer_it->second.m_in_flight < m_max_in_flight) ReevaluatePeer(node);
}

void TxRequestTracker::DeletedNode(NodeId node)
{
    // Find the first entry for this peer
    Announcement an{node, {}, std::chrono::microseconds::min(), AnnounceType(0)};
    auto it = m_index_peer.lower_bound(an);
    // Delete entries as long as they belong to that peer
    while (it != m_index_peer.end() && it->m_key.m_node == node) {
        uint256 txid = it->m_key.m_txid;
        // No need to update m_peerdata.m_total_announcements; we're going to delete its entry anyway.
        it = m_index_peer.erase(it);
        if (!UpdateSelectedForTxid(txid)) {
            DeleteTxid(txid);
            // If a transaction was deleted, "it" may be invalidated.
            it = m_index_peer.lower_bound(an);
        }
    }
    m_peerdata.erase(node);
}

void TxRequestTracker::AlreadyHaveTx(const uint256& txid)
{
    DeleteTxid(txid);
}

bool TxRequestTracker::ReceivedInv(NodeId node, bool outbound, const uint256& txid, std::chrono::microseconds now)
{
    auto ret = m_index.emplace(node, txid, outbound ? now : now + m_inbound_delay, outbound ? AnnounceType::CANDIDATE_OUT : AnnounceType::CANDIDATE_IN);

    if (ret.second) {
        ++m_peerdata[node].m_total_announcements;
        // Consider making the new entry selected for this txid
        UpdateSelectedForTxid(txid);
    }
    return ret.second;
}

void TxRequestTracker::RequestedTx(NodeId node, const uint256& txid, std::chrono::microseconds now)
{
    auto it = m_index_key.find(AnnouncementKey{node, txid});
    if (it == m_index_key.end()) return;
    if (!it->IsSelected()) return;
    m_index_key.modify(it, [&](Announcement& a){ a.m_type = AnnounceType::WAITING; a.m_time = now + m_timeout; });
}

void TxRequestTracker::ReceivedResponse(NodeId node, const uint256& txid)
{
    auto it = m_index_key.find(AnnouncementKey{node, txid});
    if (it == m_index_key.end() || it->IsFinished()) return;
    bool reeval = false;
    if (it->IsSelected()) {
        auto peer_it = m_peerdata.find(node);
        assert(peer_it != m_peerdata.end());
        if (peer_it->second.m_in_flight-- == m_max_in_flight) reeval = true;
    }
    m_index_key.modify(it, [&](Announcement& a){ a.m_type = AnnounceType::FINISHED; });
    if (!UpdateSelectedForTxid(txid)) DeleteTxid(txid);
    if (reeval) ReevaluatePeer(node);
}

size_t TxRequestTracker::CountInFlight(NodeId node) const
{
    auto it = m_peerdata.find(node);
    if (it == m_peerdata.end()) return 0;
    return it->second.m_in_flight;
}

size_t TxRequestTracker::CountTracked(NodeId node) const
{
    auto it = m_peerdata.find(node);
    if (it == m_peerdata.end()) return 0;
    return it->second.m_total_announcements;
}

std::vector<uint256> TxRequestTracker::GetRequestable(NodeId node, std::chrono::microseconds now)
{
    ProcessTimeouts(node, now);

    std::vector<uint256> ret;
    Announcement an{node, {}, std::chrono::microseconds::min(), AnnounceType::FIRST_PLANNED};
    auto it = m_index_peer.lower_bound(an);
    while (it != m_index_peer.end() && it->IsPlanned() && it->m_key.m_node == node && it->m_time <= now) {
        ret.push_back(it->m_key.m_txid);
        ++it;
    }
    return ret;
}

void TxRequestTracker::SanityCheck() const
{
    // Recompute m_peerdata.
    // This verifies the data in it, including the invariant
    // that no entries with m_total_announcements==0 exist.
    std::unordered_map<NodeId, PeerData> peerdata;
    for (const auto& a : m_index) {
        auto& entry = peerdata[a.m_key.m_node];
        ++entry.m_total_announcements;
        if (a.IsSelected()) {
            ++entry.m_in_flight;
            assert(entry.m_in_flight <= m_max_in_flight);
        }
    }
    assert(m_peerdata == peerdata);

    // Classify how many types peers we have for each txid
    std::map<uint256, std::tuple<int, int, int>> table;
    for (const auto& a : m_index) {
        auto& entry = table[a.m_key.m_txid];
        bool peer_busy = peerdata[a.m_key.m_node].m_in_flight >= m_max_in_flight;
        std::get<0>(entry) += a.IsCandidate() && !peer_busy;
        std::get<1>(entry) += a.IsCandidate() && peer_busy;
        std::get<2>(entry) += a.IsSelected();
    }
    for (const auto& entry : table) {
        // Cannot have only finished peers (txid should have been deleted)
        assert(std::get<0>(entry.second) + std::get<1>(entry.second) + std::get<2>(entry.second) > 0);
        // Cannot have more than 1 selected announcement (the older one should have been unselected first)
        assert(std::get<2>(entry.second) <= 1);
        // Must have exactly 1 selected announcement, unless all candidate peers are busy (one should have been selected)
        assert(std::get<2>(entry.second) == 1 || std::get<0>(entry.second) == 0);
    }
}
