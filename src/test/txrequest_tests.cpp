// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txrequest.h>

#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <tuple>
#include <vector>


BOOST_FIXTURE_TEST_SUITE(txrequest_tests, TestingSetup)

namespace
{
/** Check the state of tracker at time now against exp.
 *
 * Exp is a vector of tuples consisting of:
 * - NodeId: node which we're making a state about
 * - in_flight: number of txids that should have been requested + planned to be requested from that node
 * - other: number of other txids we should be tracking for that node
 * - txids: the txids that should be requested from that peer now
 *
 * One entry should be present in the vector per peer that has a non-zero number of txids tracked.
 */
void Check(TxRequestTracker& tracker, std::chrono::microseconds now, const std::vector<std::tuple<NodeId, size_t, size_t, std::vector<uint256>>>& exp)
{
    // Test the tracker's internal consistency.
    tracker.SanityCheck();
    size_t global_count_total = 0;

    // Process all timeouts, which may change observations for other nodes
    for (const auto& entry : exp) {
        NodeId node = std::get<0>(entry);
        (void)tracker.GetRequestable(node, now);
    }

    // Verify the provided exp vector against the observable state of tracker
    for (const auto& entry : exp) {
        NodeId node = std::get<0>(entry);
        size_t count_in_flight = std::get<1>(entry);
        size_t count_total = count_in_flight + std::get<2>(entry);
        const std::vector<uint256>& req = std::get<3>(entry);
        BOOST_CHECK_EQUAL(tracker.CountTracked(node), count_total);
        BOOST_CHECK_EQUAL(tracker.CountInFlight(node), count_in_flight);
        BOOST_CHECK(tracker.GetRequestable(node, now) == req);
        global_count_total += count_total;
    }
    // Verify that no entries exist in tracker that weren't listed in exp
    BOOST_CHECK_EQUAL(tracker.Size(), global_count_total);
}

}

BOOST_AUTO_TEST_CASE(test_scenario)
{
    // Five names for peers.
    constexpr NodeId ALICE = 1; // outbound
    constexpr NodeId BOB = 2; // inbound
    constexpr NodeId CAROL = 3; // outbound
    constexpr NodeId DAN = 4; // inbound
    constexpr NodeId ERIN = 5; // outbound

    //! Current time
    std::chrono::microseconds now{0x5A51C1CF07BE9};

    //! Tracker object. Note that it has an unusually low limit of 3 in-flight requests per peer.
    constexpr auto delay = std::chrono::seconds{2};
    constexpr auto timeout = std::chrono::minutes{2};
    TxRequestTracker tracker{delay, timeout, 3};

    // Nothing has happened yet
    Check(tracker, now, {});

    // TEST 1

    // Generate a transaction
    const uint256 alpha = InsecureRand256();

    // Alice submits alpha
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(ALICE, true, alpha, now), true);
    Check(tracker, now, {{ALICE, 1, 0, {alpha}}});

    // Alice resubmits alpha
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(ALICE, true, alpha, now), false);
    Check(tracker, now, {{ALICE, 1, 0, {alpha}}});

    // And again, but a bit later
    now += std::chrono::microseconds{1};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(ALICE, true, alpha, now), false);
    Check(tracker, now, {{ALICE, 1, 0, {alpha}}});

    // We request from Alice
    now += std::chrono::microseconds{1000};
    tracker.RequestedTx(ALICE, alpha, now);
    Check(tracker, now, {{ALICE, 1, 0, {}}});

    // And the transaction arrives
    now += std::chrono::microseconds{1000};
    tracker.AlreadyHaveTx(alpha);
    Check(tracker, now, {});

    // TEST 2

    // Generate a new transaction
    const uint256 beta = InsecureRand256();

    // Bob, an inbound peer, submits beta
    now += std::chrono::microseconds{1000};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(BOB, false, beta, now), true);
    Check(tracker, now, {{BOB, 1, 0, {}}});

    // 1.999999s later, we still wouldn't request it
    now += delay - std::chrono::microseconds{1};
    Check(tracker, now, {{BOB, 1, 0, {}}});

    // But after 2s, we would
    now += std::chrono::microseconds{1};
    Check(tracker, now, {{BOB, 1, 0, {beta}}});

    // Yet, even now, if an outbound shows up, we reconsider
    now += std::chrono::microseconds{1000};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(CAROL, true, beta, now), true);
    Check(tracker, now, {{BOB, 0, 1, {}}, {CAROL, 1, 0, {beta}}});

    // If yet another outbound shows up at the same time, we don't reconsider again
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(ERIN, true, beta, now), true);
    Check(tracker, now, {{BOB, 0, 1, {}}, {CAROL, 1, 0, {beta}}, {ERIN, 0, 1, {}}});

    // We request from Carol
    now += std::chrono::microseconds{1000};
    tracker.RequestedTx(CAROL, beta, now);
    Check(tracker, now, {{BOB, 0, 1, {}}, {CAROL, 1, 0, {}}, {ERIN, 0, 1, {}}});

    // If a NOTFOUND arrives from Bob, nothing changes (wasn't requested)
    now += std::chrono::microseconds{1000};
    tracker.ReceivedResponse(BOB, beta);
    Check(tracker, now, {{BOB, 0, 1, {}}, {CAROL, 1, 0, {}}, {ERIN, 0, 1, {}}});

    // But a NOTFOUND from Carol does. We would fetch from the second best, Erin.
    now += std::chrono::microseconds{1000};
    tracker.ReceivedResponse(CAROL, beta);
    Check(tracker, now, {{BOB, 0, 1, {}}, {CAROL, 0, 1, {}}, {ERIN, 1, 0, {beta}}});

    // Now an announcement from inbound Dan comes in, which doesn't matter as we
    // have selected an outbound peer already.
    now += std::chrono::microseconds{1000};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(DAN, false, beta, now), true);
    Check(tracker, now, {{BOB, 0, 1, {}}, {CAROL, 0, 1, {}}, {DAN, 0, 1, {}}, {ERIN, 1, 0, {beta}}});

    // If we request from Erin, and a NOTFOUND comes back, we will finally choose Dan
    // after a delay. Bob isn't selected because we already received a NOTFOUND from him (unsollicited).
    now += std::chrono::microseconds{1000};
    tracker.RequestedTx(ERIN, beta, now);
    Check(tracker, now, {{BOB, 0, 1, {}}, {CAROL, 0, 1, {}}, {DAN, 0, 1, {}}, {ERIN, 1, 0, {}}});
    now += std::chrono::microseconds{1000};
    tracker.ReceivedResponse(ERIN, beta);
    Check(tracker, now, {{BOB, 0, 1, {}}, {CAROL, 0, 1, {}}, {DAN, 1, 0, {}}, {ERIN, 0, 1, {}}});
    now += std::chrono::microseconds{2000000};
    Check(tracker, now, {{BOB, 0, 1, {}}, {CAROL, 0, 1, {}}, {DAN, 1, 0, {beta}}, {ERIN, 0, 1, {}}});

    // If a NOTFOUND arrived from Dan too, we have no candidates left and forget about beta.
    now += std::chrono::microseconds{1000};
    tracker.ReceivedResponse(DAN, beta);
    Check(tracker, now, {});

    // TEST 3

    // Generate 6 transactions

    const uint256 gamma = InsecureRand256();
    const uint256 delta = InsecureRand256();
    const uint256 epsilon = InsecureRand256();
    const uint256 zeta = InsecureRand256();
    const uint256 eta = InsecureRand256();
    const uint256 theta = InsecureRand256();

    // Bob announces gamma,delta,epsilon (all of which become selected for him)
    now += std::chrono::microseconds{1000};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(BOB, false, gamma, now), true);
    now += std::chrono::microseconds{1};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(BOB, false, delta, now), true);
    now += std::chrono::microseconds{1};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(BOB, false, epsilon, now), true);
    Check(tracker, now, {{BOB, 3, 0, {}}});

    // Dan announces delta,epsilon,zeta (only zeta gets selected)
    now += std::chrono::microseconds{1000};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(DAN, false, delta, now), true);
    now += std::chrono::microseconds{1};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(DAN, false, epsilon, now), true);
    now += std::chrono::microseconds{1};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(DAN, false, zeta, now), true);
    Check(tracker, now, {{BOB, 3, 0, {}}, {DAN, 1, 2, {}}});

    // Alice announces epsilon,zeta,gamma (as Alice is outbound, all 3 get selected)
    // Bob still has delta left.
    now += std::chrono::microseconds{1000};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(ALICE, true, epsilon, now), true);
    now += std::chrono::microseconds{1};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(ALICE, true, zeta, now), true);
    now += std::chrono::microseconds{1};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(ALICE, true, gamma, now), true);
    Check(tracker, now, {{ALICE, 3, 0, {epsilon, zeta, gamma}}, {BOB, 1, 2, {}}, {DAN, 0, 3, {}}});

    // If enough time passes, delta will become requestable from Bob as well.
    now += std::chrono::microseconds{2000000};
    Check(tracker, now, {{ALICE, 3, 0, {epsilon, zeta, gamma}}, {BOB, 1, 2, {delta}}, {DAN, 0, 3, {}}});

    // If we request epsilon and zeta from Alice, in order, the requestable txids change
    now += std::chrono::microseconds{1000};
    tracker.RequestedTx(ALICE, epsilon, now);
    Check(tracker, now, {{ALICE, 3, 0, {zeta, gamma}}, {BOB, 1, 2, {delta}}, {DAN, 0, 3, {}}});
    now += std::chrono::microseconds{1000};
    tracker.RequestedTx(ALICE, zeta, now);
    Check(tracker, now, {{ALICE, 3, 0, {gamma}}, {BOB, 1, 2, {delta}}, {DAN, 0, 3, {}}});

    // Dan now announces new transaction eta, which gets selected for him.
    now += std::chrono::microseconds{1000};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(DAN, false, eta, now), true);
    Check(tracker, now, {{ALICE, 3, 0, {gamma}}, {BOB, 1, 2, {delta}}, {DAN, 1, 3, {}}});

    // If Alice now announces delta, eta, and a new transaction theta, nothing changes, because she
    // is already at her in-flight maximum (which includes the planned but unrequested gamma).
    now += std::chrono::microseconds{1000};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(ALICE, true, delta, now), true);
    now += std::chrono::microseconds{1};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(ALICE, true, eta, now), true);
    now += std::chrono::microseconds{1};
    BOOST_CHECK_EQUAL(tracker.ReceivedInv(ALICE, true, theta, now), true);
    Check(tracker, now, {{ALICE, 3, 3, {gamma}}, {BOB, 1, 2, {delta}}, {DAN, 1, 3, {}}});

    // If NOTFOUNDs for epsilon and zeta arrive from Alice, the formerly tx with no planned
    // requests theta gets selected. Delta and eta do not get moved to Alice, despite her
    // having in-flight slots available. This is not exactly desirable behavior, but only
    // currently-no-planned-requests txids get reconsidered when a peer drops below its
    // max-in-flight for complexity reasons.
    now += std::chrono::microseconds{1000};
    tracker.ReceivedResponse(ALICE, zeta);
    Check(tracker, now, {{ALICE, 3, 3, {gamma, theta}}, {BOB, 1, 2, {delta}}, {DAN, 2, 2, {zeta}}});
    now += std::chrono::microseconds{1};
    tracker.ReceivedResponse(ALICE, epsilon);
    Check(tracker, now, {{ALICE, 2, 4, {gamma, theta}}, {BOB, 2, 1, {delta, epsilon}}, {DAN, 2, 2, {zeta}}});

    // This remains the case even when transactions epsilon and zeta actually arrive.
    now += std::chrono::microseconds{1000};
    tracker.AlreadyHaveTx(zeta);
    Check(tracker, now, {{ALICE, 2, 3, {gamma, theta}}, {BOB, 2, 1, {delta, epsilon}}, {DAN, 1, 2, {}}});
    now += std::chrono::microseconds{1};
    tracker.AlreadyHaveTx(epsilon);
    Check(tracker, now, {{ALICE, 2, 2, {gamma, theta}}, {BOB, 1, 1, {delta}}, {DAN, 1, 1, {}}});

    // If enough time passes, eta becomes requestable from Dan.
    now += std::chrono::seconds{2};
    Check(tracker, now, {{ALICE, 2, 2, {gamma, theta}}, {BOB, 1, 1, {delta}}, {DAN, 1, 1, {eta}}});

    // So we request eta from Dan.
    now += std::chrono::microseconds{1000};
    tracker.RequestedTx(DAN, eta, now);
    Check(tracker, now, {{ALICE, 2, 2, {gamma, theta}}, {BOB, 1, 1, {delta}}, {DAN, 1, 1, {}}});

    // And request gamma from Alice.
    now += std::chrono::microseconds{1000};
    tracker.RequestedTx(ALICE, gamma, now);
    Check(tracker, now, {{ALICE, 2, 2, {theta}}, {BOB, 1, 1, {delta}}, {DAN, 1, 1, {}}});

    // 1m59.999999s seconds later eta would not expire
    now += timeout - std::chrono::microseconds{1001};
    Check(tracker, now, {{ALICE, 2, 2, {theta}}, {BOB, 1, 1, {delta}}, {DAN, 1, 1, {}}});

    // Even if we no longer need theta.
    tracker.AlreadyHaveTx(theta);
    Check(tracker, now, {{ALICE, 1, 2, {}}, {BOB, 1, 1, {delta}}, {DAN, 1, 1, {}}});

    // But after 2m it would, and Alice will immediatelly be selected for eta instead.
    now += std::chrono::microseconds{1};
    Check(tracker, now, {{ALICE, 2, 1, {eta}}, {BOB, 1, 1, {delta}}, {DAN, 0, 2, {}}});

    // Let's request eta.
    now += std::chrono::microseconds{500};
    tracker.RequestedTx(ALICE, eta, now);
    Check(tracker, now, {{ALICE, 2, 1, {}}, {BOB, 1, 1, {delta}}, {DAN, 0, 2, {}}});

    // Now Alice's gamma request expires as well, which moves to Bob.
    now += std::chrono::microseconds{500};
    Check(tracker, now, {{ALICE, 1, 2, {}}, {BOB, 2, 0, {gamma, delta}}, {DAN, 0, 2, {}}});

    // When Bob goes offline, we will immediately reassign its selected delta to Alice.
    now += std::chrono::microseconds{1000};
    tracker.DeletedNode(BOB);
    Check(tracker, now, {{ALICE, 2, 0, {delta}}, {DAN, 0, 2, {}}});

    // And if Alice goes offline, the last non-finished announcements for eta
    // disappears, removing those transactions entirely, including from
    // Dan. As Alice was waiting for delta, and enough time has passed, that
    // is reassigned to Dan.
    now += std::chrono::microseconds{1000};
    tracker.DeletedNode(ALICE);
    Check(tracker, now, {{DAN, 1, 0, {delta}}});

    // A NOTFOUND from Dan will make us forget delta too.
    now += std::chrono::microseconds{1000};
    tracker.ReceivedResponse(DAN, {delta});
    Check(tracker, now, {});
}

BOOST_AUTO_TEST_SUITE_END()
