// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    return s.str();
}

size_t GetBlockCost(const CBlock& block)
{
    // witness data is 4 times less costly than core data, because we can prune it
    size_t coreCost = ::GetSerializeSize(block, SER_NETWORK, 0);
    size_t witCost = ::GetSerializeSize(block, SER_NETWORK, SERIALIZE_TRANSACTION_WITNESS) - coreCost;
    return witCost + 4 * coreCost;
}
