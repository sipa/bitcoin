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

Transaction::Scratch& Transaction::GetScratch()
{
    static thread_local Scratch scratch;
    return scratch;
}

void Transaction::UseScratchBuffers()
{
    Scratch& scratch{GetScratch()};
    m_data.swap(scratch.data);
    m_data.clear();
    m_offsets.swap(scratch.offsets);
    m_offsets.clear();
}

void Transaction::Finalize()
{
    // Copy the data and offsets into exactly-sized vectors, and hand the scratch buffers back (unless very large).
    std::vector<uint8_t> data(m_data.begin(), m_data.end());
    std::vector<uint32_t> offsets(m_offsets.begin(), m_offsets.end());
    m_data.swap(data);
    m_offsets.swap(offsets);
    Scratch& scratch{GetScratch()};
    if (data.capacity() <= (1 << 20)) scratch.data.swap(data);
    if (offsets.capacity() <= (1 << 18)) scratch.offsets.swap(offsets);

    assert(m_offsets.size() == 2 * size_t{m_num_inputs} + m_num_outputs);
    // The serialized sizes: the data, plus the framing that is left out of it.
    uint64_t stripped_size{4 + GetSizeOfCompactSize(m_num_inputs) + GetSizeOfCompactSize(m_num_outputs) + OutputsEnd() + 4};
    for (uint32_t i = 0; i < m_num_inputs; ++i) stripped_size += GetSizeOfCompactSize(GetInputScriptSig(i).size());
    for (uint32_t i = 0; i < m_num_outputs; ++i) stripped_size += GetSizeOfCompactSize(GetOutputScriptPubKey(i).size());
    uint64_t total_size{stripped_size};
    if (HasWitness()) {
        total_size += 2 + (m_data.size() - OutputsEnd());
        for (uint32_t i = 0; i < m_num_inputs; ++i) total_size += GetSizeOfCompactSize(GetInputWitness(i).size());
    }
    if (total_size > std::numeric_limits<uint32_t>::max()) throw std::ios_base::failure("Transaction too large");
    m_stripped_size = stripped_size;
    m_total_size = total_size;
    HashWriter txid_hasher{};
    SerializeImpl(txid_hasher, /*with_witness=*/false);
    m_txid = Txid::FromUint256(txid_hasher.GetHash());
    if (HasWitness()) {
        HashWriter wtxid_hasher{};
        SerializeImpl(wtxid_hasher, /*with_witness=*/true);
        m_wtxid = Wtxid::FromUint256(wtxid_hasher.GetHash());
    } else {
        m_wtxid = Wtxid::FromUint256(m_txid.ToUint256());
    }
}

Transaction::Transaction(const CMutableTransaction& tx)
    : m_version{tx.version}, m_lock_time{tx.nLockTime}, m_num_inputs(tx.vin.size()), m_num_outputs(tx.vout.size())
{
    UseScratchBuffers();
    VectorWriter writer{m_data, 0};
    for (const CTxIn& txin : tx.vin) {
        writer << txin.prevout;
        writer.write(std::as_bytes(std::span{txin.scriptSig}));
        writer << txin.nSequence;
        m_offsets.push_back(CurrentOffset());
        m_offsets.push_back(0); // end of the witness stack (filled in below)
    }
    for (const CTxOut& txout : tx.vout) {
        writer << txout.nValue;
        writer.write(std::as_bytes(std::span{txout.scriptPubKey}));
        m_offsets.push_back(CurrentOffset());
    }
    const bool witness{tx.HasWitness()};
    const uint32_t outputs_end{CurrentOffset()};
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (witness) {
            for (const auto& element : tx.vin[i].scriptWitness.stack) writer << element;
        }
        m_offsets[2 * i + 1] = witness ? CurrentOffset() : outputs_end;
    }
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
        if (GetOutputValue(i) != other.GetOutputValue(i)) return false;
        if (!std::ranges::equal(GetOutputScriptPubKey(i), other.GetOutputScriptPubKey(i))) return false;
    }
    for (uint32_t i = 0; i < GetNumInputs(); ++i) {
        if (!std::ranges::equal(GetInputPrevoutSerialization(i), other.GetInputPrevoutSerialization(i))) return false;
        if (GetInputSequence(i) != other.GetInputSequence(i)) return false;
        if (opts.include_script_sig && !std::ranges::equal(GetInputScriptSig(i), other.GetInputScriptSig(i))) return false;
        if (opts.include_witness_data && !std::ranges::equal(GetInputWitness(i).Elements(), other.GetInputWitness(i).Elements())) return false;
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
