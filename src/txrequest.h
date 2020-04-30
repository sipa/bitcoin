// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXREQUEST_H
#define BITCOIN_TXREQUEST_H

#include <net.h> // For NodeId
#include <uint256.h>

#include <chrono>
#include <functional>
#include <unordered_map>
#include <vector>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>

#include <stdint.h>

/** Data structure to keep track of and schedule transaction downloads from peers.
 *
 * High level overview:
 * - Transactions are generally requested in order of announcement, first from
 *   outbound peers, then from inbound ones.
 * - There is a delay before fetching from inbound peers, to give time for
 *   outbound to peers to announce.
 * - Once a transaction is requested from a peer, it is not requested again
 *   until either:
 *     - a NOTFOUND response is received from that peer
 *     - the request times out (after a preset delay)
 *     - the peer we requested from goes offline
 * - Re-requests occur as soon as possible after any of the above conditions,
 *   subject to the same delay for inbound peers, and using the same preference
 *   for earliest (remaining) outbound peers if possible and earliest inbound
 *   otherwise.
 * - A transaction is only forgotten about when it is correctly received, or
 *   when all requests from available peers have failed (NOTFOUND or timed out).
 * - A transaction is never requested twice from the same peer, unless it was
 *   forgotten in between.
 * - There is a limit on the number of outstanding requests per peer. When that
 *   limit is reached for a peer, that peer is skipped and the next best peer is
 *   used instead.
 *
 * Implementation details:
 * - The data structure is conceptually a (node, txid) -> (state, timestamp)
 *   map, with various indexes to accelerate lookups and modifications.
 *   - The state consists of inbound/outbound info, plus one of the following:
 *     - CANDIDATE: an announcement from a peer for a transaction that we have
 *                  not requested, and aren't planning to request.
 *     - PLANNED: an announcement from a peer for a transaction that we plan
 *                to request when its time comes, unless a better announcement
 *                for that transaction still appears (=from outbound).
 *     - WAITING: an announcement from a peer for a transaction that we have
 *                requested and are currently waiting for.
 *     - FINISHED: an announcement from a peer for a transaction that we have
 *                 requested, but are no longer waiting for (it timed out or
 *                 we received a NOTFOUND for it).
 *   - The timestamp for CANDIDATE and PLANNED entries is when the transaction
 *     becomes requestable (=equal to the time the announcement was received
 *     for outbound peers, and m_inbound_delay later for inbound).
 *   - The timestamp for WAITING entries is when the request times out.
 *   - The timestamp for FINISHED entries is unused.
 * - Invariants and how they are maintained:
 *   - Among all announcements for any given txid there can be at most one
 *     PLANNED or WAITING one (which is called the selected one). Generally
 *     there will be exactly one, except when all CANDIDATE announcements are
 *     from peers which are at their in-flight limit. If the peer with a PLANNED
 *     or WAITING announcement goes offline, the next best CANDIDATE is
 *     converted to PLANNED. When all announcements for a txid are FINISHED,
 *     the entire txid and all its announcements are forgotten.
 *   - Among all announcements for any given peer there can be at most
 *     m_max_in_flight PLANNED + WAITING ones. When that limit is reached, the
 *     remaining CANDIDATE ones cannot be selected for becoming PLANNED anymore,
 *     and the next best announcement for that txid will be chosen.
 */
class TxRequestTracker
{
    //! Configuration parameter: delay before considering requesting from an inbound peer
    const std::chrono::microseconds m_inbound_delay;
    //! Configuration parameter: delay after which we consider a requested transaction timed out
    const std::chrono::microseconds m_timeout;
    //! Configuration parameter: how many transactions can be in flight per peer
    const size_t m_max_in_flight;

    //! A (node, txid) pair
    struct AnnouncementKey
    {
        NodeId m_node;
        uint256 m_txid;

        friend bool operator==(const AnnouncementKey& a, const AnnouncementKey& b) { return a.m_node == b.m_node && a.m_txid == b.m_txid; }
        friend class AnnouncementKeyHasher;
    };

    //! A hasher class for AnnouncementKeys
    class AnnouncementKeyHasher
    {
    private:
        const uint64_t k0, k1;
    public:
        explicit AnnouncementKeyHasher(bool deterministic);
        size_t operator()(const AnnouncementKey&) const;
    };

    //! An enum for the different states an announcement can be in
    enum class AnnounceType {
        // Candidate types: announcements to be considered for requesting from
        CANDIDATE_OUT, //!< An outbound peer we haven't requested from and are not planning to
        CANDIDATE_IN, //!< An inbound peer we haven't requested from and are not planning to

        // Selected types: announcements we have requested or are planning to request from
        PLANNED_OUT, //!< An outbound peer we've selected to request from
        PLANNED_IN, //!< An inbound peer we've selected to request from (may change when an outbound peer announces)
        WAITING, //!< An announcement we've requested and are waiting for

        // Finish types: announcements we're done with
        FINISHED, //!< An announcement we've requested that has finished (we received a NOTFOUND, or it timed out)

        FIRST_CANDIDATE = CANDIDATE_OUT,
        FIRST_SELECTED = PLANNED_OUT,
        FIRST_PLANNED = PLANNED_OUT,
        LAST = FINISHED,
    };

    //! An announcement, contains node, txid, time, and type.
    struct Announcement
    {
        //! The node and txid; encapsulated for hashing efficiency
        AnnouncementKey m_key;
        //! Time of entry (when the tx is ready to be requested for CANDIDATE/PLANNED; when the request times out for WAITING)
        std::chrono::microseconds m_time;
        //! The state this announcement is in
        AnnounceType m_type;

        Announcement(NodeId node, const uint256& txid, std::chrono::microseconds time, AnnounceType type) : m_key{node, txid}, m_time(time), m_type(type) {}

        bool IsOutbound() const { return m_type == AnnounceType::CANDIDATE_OUT || m_type == AnnounceType::PLANNED_OUT; }
        bool IsCandidate() const { return m_type == AnnounceType::CANDIDATE_OUT || m_type == AnnounceType::CANDIDATE_IN; }
        bool IsPlanned() const { return m_type == AnnounceType::PLANNED_OUT || m_type == AnnounceType::PLANNED_IN; }
        bool IsWaiting() const { return m_type == AnnounceType::WAITING; }
        bool IsSelected() const { return IsPlanned() || IsWaiting(); }
        bool IsFinished() const { return m_type == AnnounceType::FINISHED; }
    };

    //! Comparator that sorts Announcements by txid, then by type, then by time.
    struct OrderAnnouncementByTxidTypeTime
    {
        bool operator()(const Announcement& a, const Announcement& b) const
        {
            return std::tie(a.m_key.m_txid, a.m_type, a.m_time) < std::tie(b.m_key.m_txid, b.m_type, b.m_time);
        }
    };

    //! Comparator that sorts Announcements by node, then by type, then by time.
    struct OrderAnnouncementByPeerTypeTime
    {
        bool operator()(const Announcement& a, const Announcement& b) const
        {
            return std::tie(a.m_key.m_node, a.m_type, a.m_time) < std::tie(b.m_key.m_node, b.m_type, b.m_time);
        }
    };

    // Tag names
    struct ByKey {};
    struct ByTxid {};
    struct ByPeer {};

    // Index type definition
    typedef boost::multi_index_container<
        Announcement,
        boost::multi_index::indexed_by<
            boost::multi_index::hashed_unique<
                boost::multi_index::tag<ByKey>,
                boost::multi_index::member<Announcement, AnnouncementKey, &Announcement::m_key>,
                AnnouncementKeyHasher
            >,
            boost::multi_index::ordered_non_unique<
                boost::multi_index::tag<ByTxid>,
                boost::multi_index::identity<Announcement>,
                OrderAnnouncementByTxidTypeTime
            >,
            boost::multi_index::ordered_non_unique<
                boost::multi_index::tag<ByPeer>,
                boost::multi_index::identity<Announcement>,
                OrderAnnouncementByPeerTypeTime
            >
        >
    > Index;

    // Main data structure
    Index m_index;
    // Short names for the individual indexes
    Index::index<ByKey>::type& m_index_key = m_index.get<ByKey>(); //!< Hashed index by node/txid
    Index::index<ByPeer>::type& m_index_peer = m_index.get<ByPeer>(); //!< Ordered index by node, type, time
    Index::index<ByTxid>::type& m_index_txid = m_index.get<ByTxid>(); //!< Ordered index by txid, type, time

    // Additional per-peer information
    struct PeerData
    {
        size_t m_total_announcements = 0;
        size_t m_in_flight = 0;

        friend bool operator==(const PeerData& a, const PeerData& b)
        {
            return a.m_total_announcements == b.m_total_announcements && a.m_in_flight == b.m_in_flight;
        }
    };

    std::unordered_map<NodeId, PeerData> m_peerdata;

    //! Find the currently selected announcement for a txid, or end() if there is none.
    Index::index<ByTxid>::type::iterator GetSelectedForTxid(const uint256& txid) const;

    //! Find the best candidate to download, or end() if there are none.
    Index::index<ByTxid>::type::iterator FirstCandidateforTxid(const uint256& txid) const;

    //! Find the next candidate to download, or end() if there are none left.
    Index::index<ByTxid>::type::iterator NextCandidateforTxid(Index::index<ByTxid>::type::iterator it) const;

    //! Change the currently selected announcement (it_old if any) to it_new.
    void ChangeSelected(Index::index<ByTxid>::type::iterator it_old, Index::index<ByTxid>::type::iterator it_new);

    //! Delete information regarding txid. May invalidate iterators.
    void DeleteTxid(const uint256& txid);

    //! Re-evaluate transactions without planned announcement.
    void ReevaluatePeer(NodeId node);

    //! Update the selected announcement, if needed. Return whether we need to still keep track of txid.
    bool UpdateSelectedForTxid(const uint256& txid);

    //! Mark any expired transaction requests from this peer as timed out.
    void ProcessTimeouts(NodeId node, std::chrono::microseconds now);

public:
    //! Construct a TxRequestTracker with the specified parameters.
    TxRequestTracker(std::chrono::microseconds inbound_delay, std::chrono::microseconds timeout, size_t max_in_flight, bool deterministic = false);

    // Other constructors/assignments are disabled (they'd need to reassign m_index_*)
    TxRequestTracker() = delete;
    TxRequestTracker(const TxRequestTracker&) = delete;
    TxRequestTracker& operator=(const TxRequestTracker&) = delete;

    //! A node went offline, delete any data related to it.
    void DeletedNode(NodeId nodeid);

    //! For whatever reason, we no longer need this txid. Delete any data related to it.
    void AlreadyHaveTx(const uint256& txid);

    //! We received a new inv, enter it into the data structure.
    //! Returns whether this (node,txid) pair was new.
    //! All invs by the same peer must have the same outbound value.
    bool ReceivedInv(NodeId node, bool outbound, const uint256& txid, std::chrono::microseconds now);

    //! We sent a request for txid at time now, mark it as requested. It is a no-op if called for
    //! anything but a planned request (which is always the case for txids returned by GetRequestable).
    void RequestedTx(NodeId node, const uint256& txid, std::chrono::microseconds now);

    //! We received a response (a tx, or a NOTFOUND) for txid from node. This txid will not be
    //! returned anymore by GetRequestable for this node, unless the txid is forgotten (or was
    //! never known or already forgotten prior to this call) and announced again.
    //! Note that if a good tx is received (such that we don't need it anymore), AlreadyHaveTx should
    //! be called instead of, or in addition to ReceivedResponse.
    void ReceivedResponse(NodeId node, const uint256& txid);

    //! Count how many in-flight transactions a peer has (this includes transactions we plan to request
    //! from this peer, but have not yet)
    size_t CountInFlight(NodeId node) const;

    //! Count how many transactions are being tracked for a peer (including timed out ones and in-flight ones)
    size_t CountTracked(NodeId node) const;

    //! Count how many announcements are being tracked in total across all peers and transactions.
    size_t Size() const { return m_index.size(); }

    //! Find the txids to request now from node. This also marks expired requests as timed out.
    std::vector<uint256> GetRequestable(NodeId node, std::chrono::microseconds now);

    //! Perform a sanity check on the data structure (for testing)
    void SanityCheck() const;
};

#endif
