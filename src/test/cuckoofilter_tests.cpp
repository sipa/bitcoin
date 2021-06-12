// Copyright (c) 2014-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#include <cuckoofilter.h>
#include <bloom.h>

#include <crypto/common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(cuckoofilter_tests, BasicTestingSetup)

#define WINDOW 500000

//#define Insert insert
//#define Check contains

BOOST_AUTO_TEST_CASE(cuckoofilter_test) {
    RollingCuckooFilter rcf{WINDOW, 27, 0.95};
//    CRollingBloomFilter rcf{WINDOW, 0.000001};

    std::vector<unsigned char> data(8);
    unsigned char* ptr = data.data();

    for (uint64_t c = 0; c < WINDOW; ++c) {
        WriteLE64(ptr, c);
        rcf.Insert(data);
    }

    uint64_t checks = 0;
    uint64_t fps = 0;

    for (uint64_t c = WINDOW; c < 10*WINDOW; ++c) {
        for (int j = 0; j < 10; ++j) {
            WriteLE64(ptr, c - (j + 1) * (WINDOW / 12));
            BOOST_CHECK(rcf.Check(data));
        }
        for (int j = 0; j < 10; ++j) {
            WriteLE64(ptr, c + (j + 1) * (WINDOW / 12));
            checks += 1;
            fps += rcf.Check(data);
        }

        WriteLE64(ptr, c);
        rcf.Insert(data);
    }

    printf("FP: %lu/%lu = %g\n", (unsigned long)fps, (unsigned long)checks, (double)fps / checks);
}

BOOST_AUTO_TEST_SUITE_END()
