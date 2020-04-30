// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <txrequest.h>
#include <test/fuzz/fuzz.h>

#include <cstdint>
#include <vector>

std::pair<std::vector<uint256>, std::vector<NodeId>> Precompute()
{
    FastRandomContext rng(true);
    std::pair<std::vector<uint256>, std::vector<NodeId>> ret;
    for (int i = 0; i < 256; ++i) {
        ret.first.emplace_back(rng.randbytes(32));
        ret.second.emplace_back(rng.rand64());
    }
    return ret;
}

//! Precomputed list of 256 NodeIds and 256 txids to use in tests.
static const auto PRE = Precompute();

void test_one_input(const std::vector<uint8_t>& buffer)
{
    // The first 3 bytes are configuration of TxRequestTracker:
    // - the inbound delay
    // - the timeout (minus inbound delay)
    // - the max tx in flight per peer
    if (buffer.size() < 3) return;
    std::chrono::microseconds inbound_delay{buffer[0]};
    std::chrono::microseconds timeout = std::chrono::microseconds{buffer[1]} + inbound_delay;
    size_t max_in_flight = buffer[2];

    // Quick input parsing check so the fuzzer doesn't waste time exploring invalid inputs.
    auto it = buffer.begin() + 3;
    static constexpr int CMDSIZE[] = {1, 1, 1, 1, 2, 2, 2, 3, 3, 3};
    while (it != buffer.end()) {
        int cmd = *it;
        if (cmd > 9) return;
        if (buffer.end() - it < CMDSIZE[cmd]) return;
        it += CMDSIZE[cmd];
    }

    TxRequestTracker tracker(inbound_delay, timeout, max_in_flight, true);

    // Current clock
    std::chrono::microseconds now{1122333};

    // Decode the input as a sequence of instructions with parameters
    it = buffer.begin() + 3;
    while (it != buffer.end()) {
        int cmd = *(it++);
        int nodenum;
        int txidnum;
        switch (cmd) {
        case 0: // Advance time by 1
            now += std::chrono::microseconds{1};
            break;
        case 1: // Advance time by inbound_delay
            now += inbound_delay;
            break;
        case 2: // Advance time by timeout
            now += timeout;
            break;
        case 3: // Decrease time by 1 (simulate clock jitter or whatever)
            now -= std::chrono::microseconds{1};
            break;
        case 4: // Query for requestable txids (1 byte param: nodenum)
            nodenum = *(it++);
            (void)tracker.GetRequestable(PRE.second[nodenum], now);
            break;
        case 5: // Node went offline (1 byte param: nodenum)
            nodenum = *(it++);
            tracker.DeletedNode(PRE.second[nodenum]);
            break;
        case 6: // No longer need txid (1 byte param: txidnum)
            txidnum = *(it++);
            tracker.AlreadyHaveTx(PRE.first[txidnum]);
            break;
        case 7: // Received inv from peer (2 byte param: nodenum, txidnum; nodenum < 128 are outbound, others are inbound)
            nodenum = *(it++);
            txidnum = *(it++);
            tracker.ReceivedInv(PRE.second[nodenum], nodenum < 0x80, PRE.first[txidnum], now);
            break;
        case 8: // Requested tx from peer (2 byte param: nodenum, txidnum)
            nodenum = *(it++);
            txidnum = *(it++);
            tracker.RequestedTx(PRE.second[nodenum], PRE.first[txidnum], now);
            break;
        case 9: // Received response (2 byte param: nodenum, txidnum)
            nodenum = *(it++);
            txidnum = *(it++);
            tracker.ReceivedResponse(PRE.second[nodenum], PRE.first[txidnum]);
            break;
        default:
            assert(false);
        }
    }

    tracker.SanityCheck();
}
