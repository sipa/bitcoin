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
#include <ios>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

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
    return memusage::MallocUsage(m_data_size) + memusage::MallocUsage(m_witness_data_size) +
           memusage::MallocUsage(NumOffsets() * sizeof(uint32_t));
}

Txid CMutableTransaction::GetHash() const
{
    return Txid::FromUint256((HashWriter{} << TX_NO_WITNESS(*this)).GetHash());
}

namespace {
/** Clear a scratch buffer, releasing its memory if it is very large. */
template <typename T>
void ClearScratch(std::vector<T>& vec)
{
    if (vec.capacity() * sizeof(T) > (1 << 20)) {
        vec = {};
    } else {
        vec.clear();
    }
}

/** Copy size elements starting at data into a new array (nullptr if size is 0). */
template <typename T>
std::unique_ptr<T[]> CopyArray(const T* data, size_t size)
{
    if (size == 0) return nullptr;
    auto ret{std::make_unique_for_overwrite<T[]>(size)};
    std::copy(data, data + size, ret.get());
    return ret;
}

/** Copy the contents of a scratch buffer into an exactly-sized array (nullptr if empty), and clear it. */
template <typename T>
std::unique_ptr<T[]> CopyScratch(std::vector<T>& vec)
{
    auto ret{CopyArray(vec.data(), vec.size())};
    ClearScratch(vec);
    return ret;
}
} // namespace

Transaction::Scratch& Transaction::GetScratch()
{
    static thread_local Scratch scratch;
    // Clear the buffers, as a previous construction may have been interrupted by an exception.
    ClearScratch(scratch.data);
    ClearScratch(scratch.offsets);
    return scratch;
}

Transaction::Transaction(const Transaction& other)
    : m_version{other.m_version}, m_lock_time{other.m_lock_time}, m_num_inputs{other.m_num_inputs},
      m_num_outputs{other.m_num_outputs}, m_txid{other.m_txid}, m_wtxid{other.m_wtxid},
      m_data_size{other.m_data_size}, m_witness_data_size{other.m_witness_data_size},
      m_data{CopyArray(other.m_data.get(), other.m_data_size)},
      m_witness_data{CopyArray(other.m_witness_data.get(), other.m_witness_data_size)},
      m_offsets{CopyArray(other.m_offsets.get(), other.NumOffsets())}
{
}

void Transaction::SetData(std::vector<uint8_t>& data)
{
    if (data.size() > std::numeric_limits<uint32_t>::max() - 8) throw std::ios_base::failure("Transaction too large");
    m_data_size = data.size();
    m_data = CopyScratch(data);
}

void Transaction::SetWitnessData(std::vector<uint8_t>& data)
{
    if (data.size() > std::numeric_limits<uint32_t>::max() - 10 - m_data_size) {
        throw std::ios_base::failure("Transaction too large");
    }
    m_witness_data_size = data.size();
    m_witness_data = CopyScratch(data);
}

void Transaction::Finalize(std::vector<uint32_t>& offsets)
{
    assert(offsets.size() == NumOffsets());
    m_offsets = CopyScratch(offsets);

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
    Scratch& scratch{GetScratch()};
    std::vector<uint8_t>& data{scratch.data};
    std::vector<uint32_t>& offsets{scratch.offsets};
    VectorWriter writer{data, 0};
    writer << COMPACTSIZE(tx.vin.size());
    for (const CTxIn& txin : tx.vin) {
        offsets.push_back(CurrentOffset(data));
        writer << txin.prevout << txin.scriptSig << txin.nSequence;
    }
    writer << COMPACTSIZE(tx.vout.size());
    for (const CTxOut& txout : tx.vout) {
        offsets.push_back(CurrentOffset(data));
        writer << txout.nValue << txout.scriptPubKey;
    }
    SetData(data);
    if (tx.HasWitness()) {
        VectorWriter witness_writer{data, 0};
        for (const CTxIn& txin : tx.vin) {
            offsets.push_back(CurrentOffset(data));
            witness_writer << txin.scriptWitness.stack;
        }
        SetWitnessData(data);
    }
    Finalize(offsets);
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
