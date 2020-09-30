// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXREQUEST_H
#define BITCOIN_TXREQUEST_H

#include <primitives/transaction.h>
#include <uint256.h>

#include <chrono>
#include <vector>

#include <stdint.h>

/** Data structure to keep track of, and schedule, transaction downloads from peers.
 *
 * === Specification ===
 *
 * We keep track of which peers have announced which transactions, and use that to determine which requests
 * should go to which peer, when, and in what order.
 *
 * The following information is tracked per peer/tx combination ("announcement"):
 * - Which peer announced it (through their NodeId)
 * - The txid or wtxid of the transaction (collectively called "txhash" in what follows)
 * - Whether it was a tx or wtx announcement (see BIP339).
 * - What the earliest permitted time is that that transaction can be requested from that peer (called "reqtime").
 * - Whether it's from a "preferred" peer or not. Which announcements get this flag is determined by the caller, but
 *   this is designed for outbound peers, or other peers that we have a higher level of trust in). Even when the
 *   peers' preferredness changes, the preferred flag of existing announcements from that peer won't change.
 * - Whether the peer was the "first" to announce this txhash within its class (see '"First" marker rules').
 * - Whether or not the transaction was requested already, and if so, when it times out (called "expiry").
 * - Whether or not the transaction request failed already (timed out, or NOTFOUND was received).
 *
 * Transaction requests are then assigned to peers, following these rules:
 *
 * - No transaction is requested as long as another request for the same txhash is outstanding (it needs to fail
 *   first by passing expiry, or a NOTFOUND or invalid transaction has to be received for it).
 *
 *   Rationale: to avoid wasting bandwidth on multiple copies of the same transaction.
 *
 * - The same transaction is never requested twice from the same peer, unless the transaction was forgotten in
 *   between (see next point), and re-announced.
 *
 *   Rationale: giving a peer multiple chances to announce a transaction would allow them to bias requests in their
 *              favor, worsening invblock attacks. The flip side is that as long as an attacker manages to prevent
 *              us from receiving a transaction, failed announcements (including those from honest peers) will
 *              linger longer, increasing memory usage somewhat. The impact of this is limited by imposing a cap on
 *              the number of tracked announcements per peer.
 *              Invblocking is the practice of announcing transactions but not answer requests for them, in order
 *              to delay (or prevent) a target learning the transaction. See
 *              https://allquantor.at/blockchainbib/pdf/miller2015topology.pdf for more information.
 *
 * - Announcements are only forgotten about when the peer that announced them went offline, when the transaction
 *   was received successfully, or when no candidates for a transaction remain that haven't been tried already.
 *
 *   Rationale: we need to eventually forget announcements to keep memory bounded, but as long as viable
 *              candidate peers remain, we prefer to avoid fetching from failed ones. As every request has a finite
 *              timeout and we schedule new request as soon a previous one expired, there is always progress being
 *              made towards forgetting a transaction - either successfully or unsuccessfully.
 *
 * - Transactions are not requested from a peer until its reqtime has passed.
 *
 *   Rationale: enable net_processing code to define a delay for less-than-ideal peers, so that (presumed) better
 *              peers have a chance to give their announcement first.
 *
 * - If multiple viable candidate peers exist according to the above rules, pick a peer as follows:
 *
 *   - If any preferred peers are available, non-preferred peers are not considered for what follows.
 *
 *     Rationale: preferred peers (outbound, whitelisted) are chosen by us, so are less likely to be under attacker
 *                control.
 *
 *   - Among the remaining candidates, choose the first (non-overloaded) peer to have announced the transaction,
 *     if that one is still a candidate. This is done using a "first" marker that is added to announcements, which
 *     prioritizes an announcement over all others (within the class of preferred or non-preferred announcements).
 *     The "first" marker is given to announcements at the time they are received, provided:
 *     - No requests for its txhash have ever been attempted (or since it was forgotten about).
 *     - The peer that announced them was not overloaded.
 *     - No announcement for the same txhash from another peer within the same preferred/nonpreferred class has been
 *       given a "first" marker already.
 *
 *     Rationale: in non-attack scenarios we want to give one chance to request from the fastest peer to reduce
 *                latency, and reduce risk of fetching chains of dependent transactions out of order. An attacker
 *                who races the network can exploit this to delay us learning about a transaction, but it is
 *                available only once per txhash. The restrictions on the eligibility to get the "first" marker
 *                avoid giving the speed benefit to honest but overloaded peers, and also reduce the extent to which
 *                attackers that race the network in announcing large swaths of transactions can disarrange chains
 *                of transactions.
 *
 *   - If no remaining candidates have the "first" marker, pick a uniformly random peer among the candidates.
 *
 *     Rationale: if the "first" mechanism failed, random assignments are hard to influence for attackers.
 *
 * Together these rules strike a balance between being fast in non-adverserial conditions and minimizing
 * susceptibility to invblock attacks. An attacker that races the network:
 * - Will be unsuccessful if all preferred connections are honest (and there is at least one).
 * - If there are P preferred connections of which Ph>=1 are honest, the attacker can delay us from learning
 *   about a transaction by k expiration periods, where k ~ 1 + NHG(N=P-1,K=P-Ph-1,r=1), which has mean
 *   P/(Ph+1) (where NHG stands for Negative Hypergeometric distribution). The "1 +" is due to the fact that the
 *   attacker can be the first to announce through a preferred connection in this scenario, meaning they will get the
 *   "first" marker and thus the first request.
 * - If all P preferred connections are to the attacker, and there are NP non-preferred connections of which NPh are
 *   honest, k ~ P + 1 + NHG(N=NP-1,K=NP-NPh-1,r=1), with mean P + NP/(NPh+1).
 *
 * Complexity:
 * - Memory usage is proportional to the total number of tracked announcements (Size()) plus the number of
 *   peers with a nonzero number of tracked announcements.
 * - CPU usage is generally logarithmic in the total number of tracked announcements, plus the number of
 *   announcements affected by an operation (amortized O(1) per announcement).
 */
class TxRequestTracker {
    // Avoid littering this header file with implementation details.
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    //! Construct a TxRequestTracker.
    TxRequestTracker(bool deterministic = false);
    ~TxRequestTracker();

    // Conceptually, the data structure consists of a collection of entries, one for each peer/txhash combination
    // (an "announcement"):
    //
    // - CANDIDATE entries represent transactions that were announced by a peer, and that become available for
    //   download after their reqtime has passed.
    //
    // - REQUESTED entries represent transactions that have been requested, and which we're awaiting a response for
    //   from that peer. Their expiry value determines when the request times out.
    //
    // - COMPLETED entries represent transactions that have been requested from a peer, and a NOTFOUND or a
    //   transaction was received in response (valid or not), or they timed out. They're only kept around to
    //   prevent requesting them again. If only COMPLETED entries for a given txhash remain (so no CANDIDATE or
    //   REQUESTED ones), all of them are deleted (this is an invariant, and maintained by all operations below).
    //
    // The operations below manipulate the data structure.

    /** Deletes all entries for a given peer.
     *
     * It should be called when a peer goes offline.
     */
    void DisconnectedPeer(uint64_t peer);

    /** Deletes all entries for a given txhash (both txid and wtxid ones).
     *
     * This should be called when a transaction is successfully added to the mempool, seen in a block, or for
     * whatever reason we no longer care about it.
     */
    void ForgetTxHash(const uint256& txhash);

    /** Adds a new CANDIDATE entry.
     *
     * Does nothing if one already exists for that (txhash, peer) combination (whether it's CANDIDATE, REQUESTED, or
     * COMPLETED). Note that this means a second INV with the same txhash from the same peer will be ignored, even
     * if one is a txid and the other is wtxid (but that shouldn't happen, as BIP339 requires that all announced
     * inventory is exclusively using MSG_WTX). The new entry is given the specified preferred and reqtime values,
     * and takes it is_wtxid from the specified gtxid. It is eligible to get a first marker if overloaded is false
     * (but also subject to the other rules regarding the first marker).
     */
    void ReceivedInv(uint64_t peer, const GenTxid& gtxid, bool preferred, bool overloaded,
        std::chrono::microseconds reqtime);

    /** Converts the CANDIDATE entry for the provided peer and gtxid into a REQUESTED one.
     *
     * Expiry is set to the specified value. This can ONLY be called immediately after GetRequestable was called
     * (for the same peer), with only ForgetTx and other RequestedTx calls (both for other txhashes) in
     * between. Any other non-const operation removes the ability to call RequestedTx.
     */
    void RequestedTx(uint64_t peer, const GenTxid& gtxid, std::chrono::microseconds expiry);

    /** Converts any CANDIDATE or REQUESTED entry to a COMPLETED one, if one exists.
     *
     * It should be called whenever a transaction or NOTFOUND was received from a peer. When a good transaction is
     * received, ForgetTx should be called instead of (or in addition to) this operation.
     */
    void ReceivedResponse(uint64_t peer, const GenTxid& gtxid);

    // The operations below inspect the data structure.

    /** Find the txids to request now from peer.
     *
     * It does the following:
     *  - Convert all REQUESTED entries (for all txhashes/peers) with (expiry <= now) to COMPLETED entries.
     *  - Requestable entries are selected: CANDIDATE entries from the specified peer with (reqtime <= now) for
     *    which the specified peer is the best choice among all such CANDIDATE entries with the same txhash (subject
     *    to preference/first rules, and tiebreaking using a deterministic salted hash of peer and txhash).
     *  - The selected entries are sorted in order of announcement (even if multiple were added at the same time, or
     *    even when the clock went backwards while they were being added), converted to GenTxids using their
     *    is_wtxid flag, and returned.
     */
    std::vector<GenTxid> GetRequestable(uint64_t peer, std::chrono::microseconds now);

    /** Count how many REQUESTED entries a peer has. */
    size_t CountInFlight(uint64_t peer) const;

    /** Count how many CANDIDATE entries a peer has. */
    size_t CountCandidates(uint64_t peer) const;

    /** Count how many entries a peer has (REQUESTED, CANDIDATE, and COMPLETED combined). */
    size_t Count(uint64_t peer) const;

    /** Count how many announcements are being tracked in total across all peers and transaction hashes. */
    size_t Size() const;

    /** Access to the internal priority computation (testing only) */
    uint64_t ComputePriority(const uint256& txhash, uint64_t peer, bool preferred, bool first) const;

    /** Run internal consistency check (testing only). */
    void SanityCheck() const;

    /** Run a time-dependent internal consistency check (testing only).
     *
     * This can only be called immediately after GetRequestable, with the same 'now' parameter.
     */
    void PostGetRequestableSanityCheck(std::chrono::microseconds now) const;
};

#endif // BITCOIN_TXREQUEST_H
