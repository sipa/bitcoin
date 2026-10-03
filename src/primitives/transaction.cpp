// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <core_memusage.h>

#include <consensus/amount.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <primitives/transaction_identifier.h>
#include <script/script.h>
#include <serialize.h>
#include <tinyformat.h>

#include <algorithm>
#include <cassert>
#include <span>
#include <stdexcept>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(Txid hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : version{Transaction::CURRENT_VERSION}, nLockTime{0} {}
CMutableTransaction::CMutableTransaction(const Transaction& tx) : version{tx.GetVersion()}, nLockTime{tx.GetLockTime()}
{
    vin.reserve(tx.GetNumInputs());
    for (const CTxInView txin : tx.Inputs()) vin.push_back(txin.ToTxIn());
    vout.reserve(tx.GetNumOutputs());
    for (const CTxOutView txout : tx.Outputs()) vout.push_back(txout.ToTxOut());
}

size_t WitnessView::GetSerializeSize() const noexcept
{
    return ::GetSerializeSize(*m_stack);
}

CTxIn CTxInView::ToTxIn() const
{
    // Fill in the fields directly, as CTxIn's constructor would copy the scriptSig once more.
    CTxIn ret;
    ret.prevout = GetPrevout();
    const auto script_sig{GetScriptSig()};
    ret.scriptSig.assign(script_sig.begin(), script_sig.end());
    ret.nSequence = GetSequence();
    ret.scriptWitness.stack = GetWitness().ToStack();
    return ret;
}

CTxOut CTxOutView::ToTxOut() const
{
    // Fill in the fields directly, as CTxOut's constructor would copy the scriptPubKey once more.
    CTxOut ret;
    ret.nValue = GetValue();
    const auto script_pub_key{GetScriptPubKey()};
    ret.scriptPubKey.assign(script_pub_key.begin(), script_pub_key.end());
    return ret;
}

size_t Transaction::DynamicMemoryUsage() const
{
    size_t mem = memusage::DynamicUsage(vin) + memusage::DynamicUsage(vout);
    for (const CTxIn& txin : vin) mem += RecursiveDynamicUsage(txin);
    for (const CTxOut& txout : vout) mem += RecursiveDynamicUsage(txout);
    return mem;
}

uint32_t Transaction::GetStrippedSize() const
{
    return ::GetSerializeSize(TX_NO_WITNESS(*this));
}

Txid CMutableTransaction::GetHash() const
{
    return Txid::FromUint256((HashWriter{} << TX_NO_WITNESS(*this)).GetHash());
}

bool Transaction::ComputeHasWitness() const
{
    return std::any_of(vin.begin(), vin.end(), [](const auto& input) {
        return !input.scriptWitness.IsNull();
    });
}

Txid Transaction::ComputeHash() const
{
    return Txid::FromUint256((HashWriter{} << TX_NO_WITNESS(*this)).GetHash());
}

Wtxid Transaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return Wtxid::FromUint256(hash.ToUint256());
    }

    return Wtxid::FromUint256((HashWriter{} << TX_WITH_WITNESS(*this)).GetHash());
}

Transaction::Transaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), version{tx.version}, nLockTime{tx.nLockTime}, m_has_witness{ComputeHasWitness()}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
Transaction::Transaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), version{tx.version}, nLockTime{tx.nLockTime}, m_has_witness{ComputeHasWitness()}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount Transaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut + tx_out.nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += tx_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

unsigned int Transaction::ComputeTotalSize() const
{
    return ::GetSerializeSize(TX_WITH_WITNESS(*this));
}

std::string Transaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%u, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        version,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}
