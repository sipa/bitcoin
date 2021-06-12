// Copyright (c) 2014-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#include <cuckoofilter.h>
#include <bloom.h>

#include <crypto/common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(cuckoofilter_tests, BasicTestingSetup)

#define WINDOW 512
#define RANGE ((WINDOW)*3)

//#define Insert insert
//#define Check contains

BOOST_AUTO_TEST_CASE(cuckoofilter_test) {
    RollingCuckooFilter rcf{WINDOW, 8, 0.95};
//    CRollingBloomFilter rcf{WINDOW, 0.000001};

    std::vector<bool> bitset(RANGE);
    std::deque<uint32_t> window;

    std::vector<unsigned char> data(8);
    unsigned char* ptr = data.data();

    uint64_t checks = 0;
    uint64_t fps = 0;

    for (int i = 0; i < WINDOW * 1000; ++i) {
        for (int j = 0; j < 10; ++j) {
            uint32_t r = InsecureRandRange(RANGE);
            if (bitset[r]) {
                WriteLE64(ptr, r);
                BOOST_CHECK(rcf.Check(data));
            }
            r += RANGE;
            WriteLE64(ptr, r);
            ++checks;
            fps += rcf.Check(data);
        }

        uint32_t r = InsecureRandRange(RANGE);
        WriteLE64(ptr, r);
        rcf.Insert(data);
        bitset[r] = true;
        window.push_back(r);
        if (window.size() > WINDOW) {
            bitset[window[0]] = false;
            window.pop_front();
        }
        WriteLE64(ptr, window.front());
        BOOST_CHECK(rcf.Check(data));
        WriteLE64(ptr, window.back());
        BOOST_CHECK(rcf.Check(data));
        if (window.size() > 1) {
            WriteLE64(ptr, *(window.begin() + 1));
            BOOST_CHECK(rcf.Check(data));
            WriteLE64(ptr, *(window.end() - 2));
            BOOST_CHECK(rcf.Check(data));
        }
    }

    printf("FP: %lu/%lu = %g\n", (unsigned long)fps, (unsigned long)checks, (double)fps / checks);
}

BOOST_AUTO_TEST_SUITE_END()
