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

size_t GetVirtualBlockSize(const CBlock& block)
{
    // The formula is: vsize = base_size + witness_size / 4.
    // We can only serialize base or totalbase+witness, however, so the formula
    // becomes: vsize = base_size + (total_size - base_size) / 4 or
    // vsize = (total_size + 3 * base_size) / 4.
    return (::GetSerializeSize(block, SER_NETWORK, 0) * 3 + ::GetSerializeSize(block, SER_NETWORK, SERIALIZE_TRANSACTION_WITNESS) + 3) / 4;
}
