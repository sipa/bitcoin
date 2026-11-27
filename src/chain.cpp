// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <tinyformat.h>
#include <util/check.h>

#include <bit>
#include <cassert>
#include <cstdint>

std::string CBlockIndex::ToString() const
{
    return strprintf("CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
                     pprev, nHeight, hashMerkleRoot.ToString(), GetBlockHash().ToString());
}

void CChain::SetTip(CBlockIndex& block)
{
    CBlockIndex* pindex = &block;
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
}

std::vector<uint256> LocatorEntries(const CBlockIndex* index)
{
    int step = 1;
    std::vector<uint256> have;
    if (index == nullptr) return have;

    have.reserve(32);
    while (index) {
        have.emplace_back(index->GetBlockHash());
        if (index->nHeight == 0) break;
        // Exponentially larger steps back, plus the genesis block.
        int height = std::max(index->nHeight - step, 0);
        // Use skiplist.
        index = index->GetAncestor(height);
        if (have.size() > 10) step *= 2;
    }
    return have;
}

CBlockLocator GetLocator(const CBlockIndex* index)
{
    return CBlockLocator{LocatorEntries(index)};
}

const CBlockIndex* CChain::FindFork(const CBlockIndex& index) const
{
    const auto* pindex{&index};
    if (pindex->nHeight > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(*pindex))
        pindex = pindex->pprev;
    return pindex;
}

CBlockIndex* CChain::FindEarliestAtLeast(int64_t nTime, int height) const
{
    std::pair<int64_t, int> blockparams = std::make_pair(nTime, height);
    std::vector<CBlockIndex*>::const_iterator lower = std::lower_bound(vChain.begin(), vChain.end(), blockparams,
        [](CBlockIndex* pBlock, const std::pair<int64_t, int>& blockparams) -> bool { return pBlock->GetBlockTimeMax() < blockparams.first || pBlock->nHeight < blockparams.second; });
    return (lower == vChain.end() ? nullptr : *lower);
}

namespace {

/*
 * Skip pointers
 * =============
 *
 * Besides a pointer to its parent (pprev), every block index entry has a pointer to one further
 * ancestor (pskip). Which ancestor that is depends only on the height of the entry. It is chosen
 * such that any ancestor can be reached by following few pointers (see CBlockIndex::GetAncestor):
 * at most 2*floor(log2(h + 1)) - 1 of them from an entry at height h.
 *
 * Arranging the heights into trees
 * --------------------------------
 *
 * Where pskip leads is defined by arranging the heights 0, 1, 2, ... into binary trees. A tree
 * consists of consecutive heights, and there are many trees of every level k >= 1:
 * - A tree of level 1 is a single height.
 * - A tree of level k + 1 consists of two trees of level k and one more height. The tree with
 *   the lower heights is its left half, the tree right above that one is its right half, and
 *   the height right above both is its root. The roots of the two halves are the left and the
 *   right child of that root.
 *
 * So a tree of level k has 2^k - 1 heights, the highest of which is its root. For every k, the
 * heights 0 through 2^k - 2 are a tree of level k. This is the one of level 5 (the numbers in
 * parentheses are explained further down):
 *
 *                                   30
 *                   .---------------'---------------.
 *                   14                              29
 *           .-------'-------.               .-------'-------.
 *           6               13              21              28
 *       .---'---.       .---'---.       .---'---.       .---'---.
 *       2       5       9       12      17      20      24      27
 *     .-'-.   .-'-.   .-'-.   .-'-.   .-'-.   .-'-.   .-'-.   .-'-.
 *     0   1   3   4   7   8   10  11  15  16  18  19  22  23  25  26
 *      (0)     (0)     (0)     (7)     (0)     (15)    (15)    (22)
 *
 * Its two halves are the trees of level 4 with the heights 0 through 14, and 15 through 29. Each
 * of those has two trees of level 3 as its halves, and so on, down to the 16 trees of level 1
 * at the bottom, the leaves. The picture as a whole is the left half of the tree of level 6 with
 * the heights 0 through 62, and so on, so every height has its place.
 *
 * Some terms:
 * - The subtree of a height is the tree that it is the root of: the height itself, and
 *   everything under it in the picture. Every height is the root of exactly one tree. That tree
 *   ends with the height itself, and starts with the leftmost leaf under it. For example, the
 *   subtree of 28 consists of the heights 22 through 28.
 * - The level of a height is the level of its subtree. In the picture, 30 has level 5, 14 and 29
 *   have level 4, and so on down to the leaves, which have level 1. A large height can have a
 *   small level: 21 has level 3, just like 6.
 * - The leaves come in pairs of consecutive heights: the left and the right leaf under a height
 *   of level 2. The genesis block is the left leaf of the lowest pair.
 *
 * The right child of a height is always the height just below it, and its left child is the
 * height just below the subtree of the right child.
 *
 * The heights 0 through h always form a stack of entire subtrees: the subtree of h on top, below
 * it the subtree whose root is the next height down, and so on until the genesis block. For
 * example, the heights 0 through 26 are the subtrees of 26 (only 26 itself), 25 (only 25
 * itself), 24 (heights 22 through 24), 21 (heights 15 through 21) and 14 (heights 0 through 14).
 * Their levels are 1, 1, 2, 3 and 4. Going down such a stack, every subtree is larger than the
 * one above it, except that the second one can be as large as the first (the sizes form what is
 * known as the skew binary representation of h + 1).
 *
 * Where the pointers lead
 * -----------------------
 *
 * For a height that is not a leaf, pskip leads to its left child, and pprev to its right child.
 * For example, the pskip of 29 leads to 21, and its pprev to 28.
 *
 * A leaf has no children. Its pprev leads to the height just below it, like every pprev: that is
 * the left leaf of the pair for a right leaf, and the root of the subtree below the pair for a
 * left leaf. The pskip of both leaves of a pair jumps over that entire subtree, to its lowest
 * height. Those are the numbers in parentheses in the picture. For example:
 * - Below the pair 25 and 26 is the subtree of 24 (heights 22 through 24), so the pskip of both
 *   leads to 22.
 * - Below the pair 15 and 16 is the subtree of 14, the entire left half of the picture, so their
 *   pskip leads to 0, the genesis block.
 * - Below the lowest pair, 0 and 1, there is nothing. The genesis block has no pointers at all,
 *   and the pskip of 1 leads to the genesis block, like its pprev.
 *
 * As a result, pskip never leads to the same entry as pprev, except at height 1.
 *
 * Finding an ancestor
 * -------------------
 *
 * To get from an entry at height h to its ancestor at a lower height t, follow pskip whenever
 * that does not lead below t, and pprev otherwise.
 *
 * If t is in the subtree of h, this works like a lookup in a binary search tree: every step goes
 * to the child whose subtree t is in. For example, from 29 to 19:
 *
 *     29 -> 21   pskip. 19 is in the subtree of the left child (heights 15 through 21).
 *     21 -> 20   pprev, as pskip leads to 17, which is below 19. 19 is in the subtree of the
 *                right child (heights 18 through 20).
 *     20 -> 19   pprev, as pskip leads to 18. 19 is the right child.
 *
 * If t is below the subtree of h, the walk has three parts:
 * 1. Down to the lowest height of the subtree of h, by following pskip to the left child until
 *    a leaf is reached.
 * 2. Over the subtrees between the subtree of h and the one that t is in. The pskip of a leaf
 *    jumps over the subtree below its pair, and lands on the lowest height of that subtree,
 *    which is a left leaf again. That is repeated for as long as it does not lead below t.
 * 3. Into the subtree that t is in, unless part 2 ended at t. The root of that subtree is the
 *    height just below, so pprev leads to it. The rest is a lookup in a binary search tree
 *    again.
 *
 * For example, from 12 to 1:
 *
 *     12 -> 10   pskip, to the left child, the lowest height of the subtree of 12.   (part 1)
 *     10 -> 7    pskip, over the subtree of 9 (heights 7 through 9).                 (part 2)
 *     7 -> 6     pprev, as pskip leads to 0, which is below 1. 6 is the root of      (part 3)
 *                the subtree that 1 is in.
 *     6 -> 2     pskip. 1 is in the subtree of the left child (heights 0 through 2).
 *     2 -> 1     pprev, as pskip leads to 0. 1 is the right child.
 *
 * From 26 to 2 there is no part 1, as 26 is a leaf:
 *
 *     26 -> 22   pskip, over the left leaf of its pair (25) and the subtree of 24    (part 2)
 *                (heights 22 through 24).
 *     22 -> 15   pskip, over the subtree of 21 (heights 15 through 21).
 *     15 -> 14   pprev, as pskip leads to 0, which is below 2. 14 is the root of     (part 3)
 *                the subtree that 2 is in.
 *     14 -> 6    pskip. 2 is in the subtree of the left child (heights 0 through 6).
 *     6 -> 2     pskip. 2 is the left child.
 *
 * As the first step of that walk shows, the pskip of a right leaf also jumps over the left leaf
 * of its pair. If a walk starts at a right leaf and that jump leads below t, it follows pprev to
 * the left leaf first, as part 2, and continues from there. For example, from 23 to 17:
 *
 *     23 -> 22   pprev, as pskip leads to 15, which is below 17.                     (part 2)
 *     22 -> 21   pprev, as pskip leads to 15 here too. 21 is the root of the         (part 3)
 *                subtree that 17 is in.
 *     21 -> 17   pskip. 17 is the left child.
 *
 * The number of steps
 * -------------------
 *
 * Getting from height h to any lower height takes at most 2*floor(log2(h + 1)) - 1 steps.
 *
 * To see why, let k = floor(log2(h + 1)). A subtree whose heights are all below h has at most h
 * heights, so its level is at most k. A walk to a height t below the subtree of h has two
 * halves:
 * - Getting to the subtree that t is in (parts 1 and 2 above). No two steps of this half are
 *   about the same level: the walk first goes down through the levels of the subtree of h, and
 *   then jumps over subtrees that are at least as large as that one, and larger every time. All
 *   those levels are below the level of the subtree that t is in, so this takes at most k - 1
 *   steps.
 * - Getting to t inside that subtree (part 3). That is one step onto its root, and then at most
 *   k - 1 steps down, one per level.
 *
 * Together that is at most 2*k - 1 steps. If t is in the subtree of h itself, the walk only goes
 * down, which takes at most k steps.
 *
 * The walk from 29 to 1 uses all of that: k is 4, and the walk takes three steps down the
 * subtree of 29 (to 21, 17 and 15), one onto the root of the subtree that 1 is in (14), and
 * three more down inside it (to 6, 2 and 1). A tighter bound, which also depends on t, is
 * checked by the unit tests.
 */

/** The number of heights in a subtree of the given level. */
constexpr uint32_t TreeSize(int level) { return (uint32_t{1} << level) - 1; }

/** The bit that stands for a level, in a set of levels. */
constexpr uint32_t LevelBit(int level) { return uint32_t{1} << level; }

/**
 * Information about the subtree of a height, in the arrangement of heights into trees described
 * above.
 *
 * Besides the root and the level of the subtree, this holds the levels of the subtrees below it,
 * in the stack of subtrees that the heights 0 through its root form. For example, the subtree of
 * 28 (heights 22 through 28) has level 3, and the subtrees below it have levels 3 and 4. The
 * subtree of 26 (only 26 itself) has level 1, and the subtrees below it have levels 1, 2, 3 and
 * 4.
 *
 * That is all that is needed to find the subtrees of the heights that the pskip and pprev of an
 * entry at the root lead to. So during a walk, only the subtree of the height it starts at has
 * to be found from the height itself, which is what the constructor does.
 */
struct SubtreeInfo {
    //! The height of the root of the subtree, which is its highest height.
    uint32_t root;
    //! The level of the subtree.
    int level{0};
    //! The levels of the subtrees below this one, as a set of bits (see LevelBit). That is
    //! 0b11000 for the subtree of 28, and 0b11110 for the subtree of 26.
    uint32_t levels_below{0};

    /** Find the subtree of a height. */
    explicit SubtreeInfo(uint32_t height) : root{height}
    {
        // Find the stack of subtrees that the heights 0 through height form, from the bottom up.
        // At the bottom is the largest tree starting at height 0 that fits: the heights 0 through
        // 2^k - 2. That tree is the left half of a larger one, so the heights above it are the
        // first heights of another tree of level k. All trees of a level are built up in the same
        // way, so those heights form the same subtrees as that many heights starting at height 0
        // do. The next subtree is thus found in the same way from the number of heights that are
        // left, and so on.
        uint32_t remaining{height + 1};
        while (true) {
            // The highest level for which TreeSize(level) <= remaining.
            level = std::bit_width(remaining + 1) - 1;
            remaining -= TreeSize(level);
            // If no heights are left, this is the top of the stack: the subtree of height itself.
            if (remaining == 0) break;
            levels_below |= LevelBit(level);
        }
    }

    /** The number of heights in this subtree. */
    uint32_t Size() const { return TreeSize(level); }

    /** The left half of this subtree, whose root is the left child. Not for leaves. */
    SubtreeInfo LeftChild() const
    {
        // The left child is below the root and the 2^(level-1) - 1 heights of the right half. The
        // left half has the same subtrees below it as this subtree has.
        return {root - LevelBit(level - 1), level - 1, levels_below};
    }

    /** The right half of this subtree, whose root is the right child. Not for leaves. */
    SubtreeInfo RightChild() const
    {
        // The right child is the height just below the root. The right half also has the left
        // half below it.
        return {root - 1, level - 1, levels_below | LevelBit(level - 1)};
    }

    /** The subtree just below this one. Not for the lowest subtree, which has nothing below it. */
    SubtreeInfo Below() const
    {
        // Its root is the height just below the lowest height of this subtree. It is the smallest
        // one of the subtrees below this one, and has the other ones below it.
        return {root - Size(), std::countr_zero(levels_below), levels_below & (levels_below - 1)};
    }

    /** The leftmost leaf of this subtree, which is its lowest height. */
    SubtreeInfo LeftmostLeaf() const { return {root - Size() + 1, 1, levels_below}; }

    /** Whether this subtree, which must be a leaf, is the right leaf of its pair. */
    bool IsRightLeaf() const
    {
        // That is the case if the subtree below it is a leaf too: the left leaf of the pair.
        return (levels_below & LevelBit(1)) != 0;
    }

    /**
     * The subtree of the height that the pprev of an entry at the root leads to. Not for the
     * genesis block, which has no pprev.
     */
    SubtreeInfo Prev() const
    {
        // That is the height just below the root: its right child if it has children, and the
        // root of the subtree below it if it is a leaf.
        return level > 1 ? RightChild() : Below();
    }

    /** The subtree of the height that the pskip of an entry at the root leads to. */
    SubtreeInfo Skip() const
    {
        // If the root has children, its left child.
        if (level > 1) return LeftChild();
        // A leaf. Both leaves of a pair lead to the same height, so start from the left leaf.
        const SubtreeInfo left_leaf{IsRightLeaf() ? Below() : *this};
        // The lowest pair has nothing below it. The pskip of its right leaf leads to its left
        // leaf, the genesis block, which has no pskip itself.
        if (left_leaf.levels_below == 0) return left_leaf;
        // Otherwise, jump over the subtree below the pair, to its lowest height.
        return left_leaf.Below().LeftmostLeaf();
    }

private:
    SubtreeInfo(uint32_t root_in, int level_in, uint32_t levels_below_in)
        : root{root_in}, level{level_in}, levels_below{levels_below_in} {}
};

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
uint32_t GetSkipHeight(uint32_t height) { return SubtreeInfo{height}.Skip().root; }

} // namespace

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    if (height > nHeight || height < 0) {
        return nullptr;
    }
    if (height == nHeight) return this;

    // Walk down from this entry, following pskip whenever that does not lead below the requested
    // height, and pprev otherwise. See the explanation of skip pointers above.
    const CBlockIndex* walk{this};
    const uint32_t target{static_cast<uint32_t>(height)};
    // Keep track of the subtree of the height that the walk is at. It tells where pskip leads
    // without looking at the entry that pskip points to, which would mean accessing the memory of
    // entries that the walk never goes through.
    SubtreeInfo subtree{static_cast<uint32_t>(nHeight)};
    while (subtree.root > target) {
        const SubtreeInfo skip{subtree.Skip()};
        // Entries on which BuildSkip was not called have no pskip. Always follow pprev for those.
        if (skip.root >= target && walk->pskip != nullptr) {
            walk = walk->pskip;
            subtree = skip;
        } else {
            assert(walk->pprev);
            walk = walk->pprev;
            subtree = subtree.Prev();
        }
    }
    return walk;
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    return const_cast<CBlockIndex*>(static_cast<const CBlockIndex*>(this)->GetAncestor(height));
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

arith_uint256 GetBitsProof(uint32_t bits)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(bits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for an arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (bnTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * int64_t(r.GetLow64());
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-nullptr. */
const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb) {
    // First rewind to the last common height (the forking point cannot be past one of the two).
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }
    while (pa != pb) {
        // Jump back until pa and pb have a common "skip" ancestor.
        while (pa->pskip != pb->pskip) {
            // This logic relies on the property that equal-height blocks have equal-height skip
            // pointers.
            Assume(pa->nHeight == pb->nHeight);
            Assume(pa->pskip->nHeight == pb->pskip->nHeight);
            pa = pa->pskip;
            pb = pb->pskip;
        }
        // At this point, pa and pb are different, but have equal pskip. The forking point lies in
        // between pa/pb on the one end, and pa->pskip/pb->pskip on the other end.
        pa = pa->pprev;
        pb = pb->pprev;
    }
    return pa;
}
