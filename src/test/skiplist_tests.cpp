// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <bit>
#include <cstdint>
#include <iterator>
#include <vector>

#include <boost/test/unit_test.hpp>

#define SKIPLIST_LENGTH 300000

namespace {

/**
 * A reference implementation of the heights that skip pointers point to. It is written directly
 * from the description in chain.cpp of how heights are arranged into trees, rather than from the
 * way they are computed there.
 */

/** The number of heights in a subtree of the given level. */
uint32_t RefTreeSize(int level) { return (uint32_t{1} << level) - 1; }

/** The level of a height, which is that of the subtree it is the root of. */
int RefLevel(uint32_t height)
{
    // Go down from the root of the smallest tree starting at height 0 that the height is in,
    // towards the height. pos is its position in the tree that is being looked at, counting from
    // 1 for the lowest height of that tree.
    uint32_t pos{height + 1};
    int level{std::bit_width(pos)};
    // The highest height of a tree is its root.
    while (pos != RefTreeSize(level)) {
        // Otherwise the height is in one of the halves of the tree, which are trees one level
        // lower. The right half comes after the heights of the left half.
        --level;
        if (pos > RefTreeSize(level)) pos -= RefTreeSize(level);
    }
    return level;
}

/** The height that the skip pointer of an entry at a positive height points to. */
uint32_t RefSkipHeight(uint32_t height)
{
    const int level{RefLevel(height)};
    // Not a leaf: its left child, which is the root of the left half of its subtree. That is the
    // height just below the right half.
    if (level >= 2) return height - 1 - RefTreeSize(level - 1);
    // A leaf, which is the right one of its pair if the height below it is a leaf too.
    const uint32_t left{RefLevel(height - 1) == 1 ? height - 1 : height};
    // The lowest pair has nothing below it. Its right leaf points to its left leaf, the genesis
    // block.
    if (left == 0) return 0;
    // The lowest height of the subtree whose root is just below the pair.
    return left - RefTreeSize(RefLevel(left - 1));
}

/** Build a chain of block index entries at heights 0 through length - 1, with skip pointers. */
std::vector<CBlockIndex> BuildChain(uint32_t length)
{
    std::vector<CBlockIndex> index(length);
    for (uint32_t height = 0; height < length; ++height) {
        index[height].nHeight = height;
        index[height].pprev = (height == 0) ? nullptr : &index[height - 1];
        index[height].BuildSkip();
    }
    return index;
}

/** The height of a block index entry. */
uint32_t Height(const CBlockIndex* index) { return static_cast<uint32_t>(index->nHeight); }

} // namespace

BOOST_FIXTURE_TEST_SUITE(skiplist_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(skiplist_test)
{
    std::vector<CBlockIndex> vIndex(SKIPLIST_LENGTH);

    for (int i=0; i<SKIPLIST_LENGTH; i++) {
        vIndex[i].nHeight = i;
        vIndex[i].pprev = (i == 0) ? nullptr : &vIndex[i - 1];
        vIndex[i].BuildSkip();
    }

    for (int i=0; i<SKIPLIST_LENGTH; i++) {
        if (i > 0) {
            BOOST_CHECK(vIndex[i].pskip == &vIndex[vIndex[i].pskip->nHeight]);
            BOOST_CHECK(vIndex[i].pskip->nHeight < i);
        } else {
            BOOST_CHECK(vIndex[i].pskip == nullptr);
        }
    }

    for (int i=0; i < 1000; i++) {
        int from = m_rng.randrange(SKIPLIST_LENGTH - 1);
        int to = m_rng.randrange(from + 1);

        BOOST_CHECK(vIndex[SKIPLIST_LENGTH - 1].GetAncestor(from) == &vIndex[from]);
        BOOST_CHECK(vIndex[from].GetAncestor(to) == &vIndex[to]);
        BOOST_CHECK(vIndex[from].GetAncestor(0) == vIndex.data());
    }
}

BOOST_AUTO_TEST_CASE(missing_skip_test)
{
    // GetAncestor must also work when BuildSkip was not called on all entries (or on none at all),
    // in which case it has to fall back to following pprev.
    static constexpr uint32_t LENGTH{2000};
    for (const int skip_percentage : {0, 10, 50, 90}) {
        std::vector<CBlockIndex> index(LENGTH);
        for (uint32_t height = 0; height < LENGTH; ++height) {
            index[height].nHeight = height;
            index[height].pprev = (height == 0) ? nullptr : &index[height - 1];
            if (m_rng.randrange(100) < skip_percentage) index[height].BuildSkip();
        }
        for (int i = 0; i < 1000; ++i) {
            const uint32_t from{m_rng.randrange(LENGTH)};
            const uint32_t to{m_rng.randrange(from + 1)};
            BOOST_CHECK(index[from].GetAncestor(to) == &index[to]);
        }
        BOOST_CHECK(index[LENGTH - 1].GetAncestor(0) == &index[0]);
        BOOST_CHECK(index[LENGTH - 1].GetAncestor(LENGTH) == nullptr);
        BOOST_CHECK(index[LENGTH - 1].GetAncestor(-1) == nullptr);
    }
}

BOOST_AUTO_TEST_CASE(getlocator_test)
{
    // Build a main chain 100000 blocks long.
    std::vector<uint256> vHashMain(100000);
    std::vector<CBlockIndex> vBlocksMain(100000);
    for (unsigned int i=0; i<vBlocksMain.size(); i++) {
        vHashMain[i] = ArithToUint256(i); // Set the hash equal to the height, so we can quickly check the distances.
        vBlocksMain[i].nHeight = i;
        vBlocksMain[i].pprev = i ? &vBlocksMain[i - 1] : nullptr;
        vBlocksMain[i].phashBlock = &vHashMain[i];
        vBlocksMain[i].BuildSkip();
        BOOST_CHECK_EQUAL((int)UintToArith256(vBlocksMain[i].GetBlockHash()).GetLow64(), vBlocksMain[i].nHeight);
        BOOST_CHECK(vBlocksMain[i].pprev == nullptr || vBlocksMain[i].nHeight == vBlocksMain[i].pprev->nHeight + 1);
    }

    // Build a branch that splits off at block 49999, 50000 blocks long.
    std::vector<uint256> vHashSide(50000);
    std::vector<CBlockIndex> vBlocksSide(50000);
    for (unsigned int i=0; i<vBlocksSide.size(); i++) {
        vHashSide[i] = ArithToUint256(i + 50000 + (arith_uint256(1) << 128)); // Add 1<<128 to the hashes, so GetLow64() still returns the height.
        vBlocksSide[i].nHeight = i + 50000;
        vBlocksSide[i].pprev = i ? &vBlocksSide[i - 1] : (vBlocksMain.data()+49999);
        vBlocksSide[i].phashBlock = &vHashSide[i];
        vBlocksSide[i].BuildSkip();
        BOOST_CHECK_EQUAL((int)UintToArith256(vBlocksSide[i].GetBlockHash()).GetLow64(), vBlocksSide[i].nHeight);
        BOOST_CHECK(vBlocksSide[i].pprev == nullptr || vBlocksSide[i].nHeight == vBlocksSide[i].pprev->nHeight + 1);
    }

    // Build a CChain for the main branch.
    CChain chain;
    chain.SetTip(vBlocksMain.back());

    // Test 100 random starting points for locators.
    for (int n=0; n<100; n++) {
        int r = m_rng.randrange(150000);
        CBlockIndex* tip = (r < 100000) ? &vBlocksMain[r] : &vBlocksSide[r - 100000];
        CBlockLocator locator = GetLocator(tip);

        // The first result must be the block itself, the last one must be genesis.
        BOOST_CHECK(locator.vHave.front() == tip->GetBlockHash());
        BOOST_CHECK(locator.vHave.back() == vBlocksMain[0].GetBlockHash());

        // Entries 1 through 11 (inclusive) go back one step each.
        for (unsigned int i = 1; i < 12 && i < locator.vHave.size() - 1; i++) {
            BOOST_CHECK_EQUAL(UintToArith256(locator.vHave[i]).GetLow64(), tip->nHeight - i);
        }

        // The further ones (excluding the last one) go back with exponential steps.
        unsigned int dist = 2;
        for (unsigned int i = 12; i < locator.vHave.size() - 1; i++) {
            BOOST_CHECK_EQUAL(UintToArith256(locator.vHave[i - 1]).GetLow64() - UintToArith256(locator.vHave[i]).GetLow64(), dist);
            dist *= 2;
        }
    }
}

BOOST_AUTO_TEST_CASE(findearliestatleast_test)
{
    std::vector<uint256> vHashMain(100000);
    std::vector<CBlockIndex> vBlocksMain(100000);
    for (unsigned int i=0; i<vBlocksMain.size(); i++) {
        vHashMain[i] = ArithToUint256(i); // Set the hash equal to the height
        vBlocksMain[i].nHeight = i;
        vBlocksMain[i].pprev = i ? &vBlocksMain[i - 1] : nullptr;
        vBlocksMain[i].phashBlock = &vHashMain[i];
        vBlocksMain[i].BuildSkip();
        if (i < 10) {
            vBlocksMain[i].nTime = i;
            vBlocksMain[i].nTimeMax = i;
        } else {
            // randomly choose something in the range [MTP, MTP*2]
            int64_t medianTimePast = vBlocksMain[i].GetMedianTimePast();
            int r{int(m_rng.randrange(medianTimePast))};
            vBlocksMain[i].nTime = uint32_t(r + medianTimePast);
            vBlocksMain[i].nTimeMax = std::max(vBlocksMain[i].nTime, vBlocksMain[i-1].nTimeMax);
        }
    }
    // Check that we set nTimeMax up correctly.
    unsigned int curTimeMax = 0;
    for (unsigned int i=0; i<vBlocksMain.size(); ++i) {
        curTimeMax = std::max(curTimeMax, vBlocksMain[i].nTime);
        BOOST_CHECK(curTimeMax == vBlocksMain[i].nTimeMax);
    }

    // Build a CChain for the main branch.
    CChain chain;
    chain.SetTip(vBlocksMain.back());

    // Verify that FindEarliestAtLeast is correct.
    for (unsigned int i=0; i<10000; ++i) {
        // Pick a random element in vBlocksMain.
        int r = m_rng.randrange(vBlocksMain.size());
        int64_t test_time = vBlocksMain[r].nTime;
        CBlockIndex* ret = chain.FindEarliestAtLeast(test_time, 0);
        BOOST_CHECK(ret->nTimeMax >= test_time);
        BOOST_CHECK((ret->pprev==nullptr) || ret->pprev->nTimeMax < test_time);
        BOOST_CHECK(vBlocksMain[r].GetAncestor(ret->nHeight) == ret);
    }
}

BOOST_AUTO_TEST_CASE(findearliestatleast_edge_test)
{
    std::list<CBlockIndex> blocks;
    for (const unsigned int timeMax : {100, 100, 100, 200, 200, 200, 300, 300, 300}) {
        CBlockIndex* prev = blocks.empty() ? nullptr : &blocks.back();
        blocks.emplace_back();
        blocks.back().nHeight = prev ? prev->nHeight + 1 : 0;
        blocks.back().pprev = prev;
        blocks.back().BuildSkip();
        blocks.back().nTimeMax = timeMax;
    }

    CChain chain;
    chain.SetTip(blocks.back());

    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(50, 0)->nHeight, 0);
    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(100, 0)->nHeight, 0);
    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(150, 0)->nHeight, 3);
    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(200, 0)->nHeight, 3);
    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(250, 0)->nHeight, 6);
    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(300, 0)->nHeight, 6);
    BOOST_CHECK(!chain.FindEarliestAtLeast(350, 0));

    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(0, 0)->nHeight, 0);
    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(-1, 0)->nHeight, 0);

    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(std::numeric_limits<int64_t>::min(), 0)->nHeight, 0);
    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(-int64_t(std::numeric_limits<unsigned int>::max()) - 1, 0)->nHeight, 0);
    BOOST_CHECK(!chain.FindEarliestAtLeast(std::numeric_limits<int64_t>::max(), 0));
    BOOST_CHECK(!chain.FindEarliestAtLeast(std::numeric_limits<unsigned int>::max(), 0));
    BOOST_CHECK(!chain.FindEarliestAtLeast(int64_t(std::numeric_limits<unsigned int>::max()) + 1, 0));

    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(0, -1)->nHeight, 0);
    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(0, 0)->nHeight, 0);
    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(0, 3)->nHeight, 3);
    BOOST_CHECK_EQUAL(chain.FindEarliestAtLeast(0, 8)->nHeight, 8);
    BOOST_CHECK(!chain.FindEarliestAtLeast(0, 9));

    CBlockIndex* ret1 = chain.FindEarliestAtLeast(100, 2);
    BOOST_CHECK(ret1->nTimeMax >= 100);
    BOOST_CHECK(ret1->nHeight == 2);
    BOOST_CHECK(!chain.FindEarliestAtLeast(300, 9));
    CBlockIndex* ret2 = chain.FindEarliestAtLeast(200, 4);
    BOOST_CHECK(ret2->nTimeMax >= 200);
    BOOST_CHECK(ret2->nHeight == 4);
}

BOOST_AUTO_TEST_CASE(skip_height_test)
{
    // The heights that the skip pointers of the entries at heights 1 through 30 point to. With
    // the genesis block, those are the heights of the tree in the picture in chain.cpp.
    static constexpr uint32_t EXPECTED[]{0, 0, 0, 0, 3, 2, 0, 0, 7, 7, 7, 10, 9, 6, 0,
                                         0, 15, 15, 15, 18, 17, 15, 15, 22, 22, 22, 25, 24, 21, 14};

    const auto index{BuildChain(SKIPLIST_LENGTH)};

    // The genesis block has no skip pointer.
    BOOST_CHECK(index[0].pskip == nullptr);
    for (uint32_t height = 1; height < index.size(); ++height) {
        BOOST_REQUIRE(index[height].pskip != nullptr);
        const uint32_t skip_height{Height(index[height].pskip)};
        BOOST_CHECK(index[height].pskip == &index[skip_height]);
        BOOST_CHECK_EQUAL(skip_height, RefSkipHeight(height));
        if (height <= std::size(EXPECTED)) BOOST_CHECK_EQUAL(skip_height, EXPECTED[height - 1]);
        // Above height 1, the skip pointer never points to the same entry as pprev.
        if (height >= 2) BOOST_CHECK_LE(skip_height, height - 2);
    }
}

BOOST_AUTO_TEST_SUITE_END()
