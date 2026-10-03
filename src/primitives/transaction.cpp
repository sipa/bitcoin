// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <consensus/amount.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <memusage.h>
#include <primitives/transaction_identifier.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
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

std::vector<std::span<const unsigned char>> WitnessView::ToSpans() const
{
    std::vector<std::span<const unsigned char>> ret;
    ret.reserve(size());
    for (const auto element : *this) ret.push_back(element);
    return ret;
}

std::vector<std::vector<unsigned char>> WitnessView::ToStack() const
{
    std::vector<std::vector<unsigned char>> ret;
    ret.reserve(size());
    for (const auto element : *this) ret.emplace_back(element.begin(), element.end());
    return ret;
}

CTxIn CTxInView::ToTxIn() const
{
    const auto script_sig{GetScriptSig()};
    CTxIn ret{GetPrevout(), CScript(script_sig.begin(), script_sig.end()), GetSequence()};
    ret.scriptWitness.stack = GetWitness().ToStack();
    return ret;
}

CTxOut CTxOutView::ToTxOut() const
{
    const auto script_pub_key{GetScriptPubKey()};
    return CTxOut{GetValue(), CScript(script_pub_key.begin(), script_pub_key.end())};
}

size_t Transaction::DynamicMemoryUsage() const
{
    return memusage::DynamicUsage(m_data) + memusage::DynamicUsage(m_offsets);
}

Txid CMutableTransaction::GetHash() const
{
    return Txid::FromUint256((HashWriter{} << TX_NO_WITNESS(*this)).GetHash());
}

void Transaction::Finalize()
{
    m_data.shrink_to_fit();
    m_offsets.shrink_to_fit();
    assert(m_offsets.size() == 2 * size_t{m_num_inputs} + m_num_outputs);

    HashWriter txid_hasher{};
    SerializeWithoutWitness(txid_hasher);
    m_txid = Txid::FromUint256(txid_hasher.GetHash());
    if (HasWitness()) {
        HashWriter wtxid_hasher{};
        wtxid_hasher.write(std::as_bytes(GetSerialization()));
        m_wtxid = Wtxid::FromUint256(wtxid_hasher.GetHash());
    } else {
        m_wtxid = Wtxid::FromUint256(m_txid.ToUint256());
    }
}

Transaction::Transaction(const CMutableTransaction& tx)
{
    m_data.reserve(::GetSerializeSize(TX_WITH_WITNESS(tx)));
    m_offsets.reserve(2 * tx.vin.size() + tx.vout.size());
    VectorWriter writer{m_data, 0};
    const bool witness{tx.HasWitness()};
    writer << tx.version;
    if (witness) writer << uint8_t{0} << uint8_t{1}; // Extended format marker and flags.
    writer << COMPACTSIZE(tx.vin.size());
    for (const CTxIn& txin : tx.vin) {
        m_offsets.push_back(CurrentOffset());
        m_offsets.push_back(0);
        writer << txin.prevout << txin.scriptSig << txin.nSequence;
    }
    writer << COMPACTSIZE(tx.vout.size());
    for (const CTxOut& txout : tx.vout) {
        m_offsets.push_back(CurrentOffset());
        writer << txout.nValue << txout.scriptPubKey;
    }
    if (witness) {
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            m_offsets[2 * i + 1] = CurrentOffset();
            writer << tx.vin[i].scriptWitness.stack;
        }
    }
    writer << tx.nLockTime;
    CurrentOffset();
    m_num_inputs = tx.vin.size();
    m_num_outputs = tx.vout.size();
    Finalize();
}

CAmount Transaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const CTxOutView tx_out : Outputs()) {
        const CAmount value{tx_out.GetValue()};
        if (!MoneyRange(value) || !MoneyRange(nValueOut + value))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += value;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

bool Transaction::Equals(const Transaction& other, const EqualsOptions opts) const
{
    if (GetLockTime() != other.GetLockTime() || GetVersion() != other.GetVersion()) return false;
    if (GetNumInputs() != other.GetNumInputs() || GetNumOutputs() != other.GetNumOutputs()) return false;
    for (uint32_t i = 0; i < GetNumOutputs(); ++i) {
        if (!std::ranges::equal(GetOutputSerialization(i), other.GetOutputSerialization(i))) return false;
    }
    for (uint32_t i = 0; i < GetNumInputs(); ++i) {
        if (!std::ranges::equal(GetInputPrevoutSerialization(i), other.GetInputPrevoutSerialization(i))) return false;
        if (GetInputSequence(i) != other.GetInputSequence(i)) return false;
        if (opts.include_script_sig && !std::ranges::equal(GetInputScriptSig(i), other.GetInputScriptSig(i))) return false;
        if (opts.include_witness_data && !std::ranges::equal(GetInputWitness(i).Serialized(), other.GetInputWitness(i).Serialized())) return false;
    }
    return true;
}

std::string Transaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%u, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        GetVersion(),
        GetNumInputs(),
        GetNumOutputs(),
        GetLockTime());
    for (const CTxInView tx_in : Inputs())
        str += "    " + tx_in.ToTxIn().ToString() + "\n";
    for (const CTxInView tx_in : Inputs())
        str += "    " + tx_in.ToTxIn().scriptWitness.ToString() + "\n";
    for (const CTxOutView tx_out : Outputs())
        str += "    " + tx_out.ToTxOut().ToString() + "\n";
    return str;
}
