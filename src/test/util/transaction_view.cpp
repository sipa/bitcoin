// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/transaction_view.h>

#include <consensus/amount.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <vector>

namespace {

template <typename T>
std::vector<unsigned char> Ser(const T& obj)
{
    std::vector<unsigned char> ret;
    VectorWriter{ret, 0} << obj;
    return ret;
}

std::optional<CAmount> TryGetValueOut(const Transaction& tx)
{
    try {
        return tx.GetValueOut();
    } catch (const std::runtime_error&) {
        return std::nullopt;
    }
}

/** The output value sum (and whether it is in range), computed independently of Transaction. */
std::optional<CAmount> ExpectedValueOut(const CMutableTransaction& mtx)
{
    CAmount sum{0};
    for (const CTxOut& txout : mtx.vout) {
        if (!MoneyRange(txout.nValue) || !MoneyRange(sum + txout.nValue)) return std::nullopt;
        sum += txout.nValue;
    }
    return sum;
}

} // namespace

std::string CompareTransaction(const Transaction& tx, const CMutableTransaction& mtx)
{
    const auto ser_witness{Ser(TX_WITH_WITNESS(mtx))};
    const auto ser_no_witness{Ser(TX_NO_WITNESS(mtx))};

    if (tx.GetNumInputs() != mtx.vin.size()) return "input count";
    if (tx.GetNumOutputs() != mtx.vout.size()) return "output count";
    if (tx.GetVersion() != mtx.version) return "version";
    if (tx.GetLockTime() != mtx.nLockTime) return "lock time";
    if (tx.GetHash() != mtx.GetHash()) return "txid";
    if (tx.GetWitnessHash().ToUint256() != (HashWriter{} << TX_WITH_WITNESS(mtx)).GetHash()) return "wtxid";
    if (tx.HasWitness() != mtx.HasWitness()) return "HasWitness";
    if (tx.IsNull() != (mtx.vin.empty() && mtx.vout.empty())) return "IsNull";
    if (tx.IsCoinBase() != (mtx.vin.size() == 1 && mtx.vin[0].prevout.IsNull())) return "IsCoinBase";
    if (TryGetValueOut(tx) != ExpectedValueOut(mtx)) return "GetValueOut";

    for (uint32_t i = 0; i < mtx.vin.size(); ++i) {
        const CTxIn& txin{mtx.vin[i]};
        if (tx.GetInputPrevout(i) != txin.prevout) return strprintf("input %u prevout", i);
        if (!std::ranges::equal(tx.GetInputScriptSig(i), txin.scriptSig)) return strprintf("input %u scriptSig", i);
        if (tx.GetInputSequence(i) != txin.nSequence) return strprintf("input %u sequence", i);
        const auto& stack{txin.scriptWitness.stack};
        const WitnessView witness{tx.GetInputWitness(i)};
        if (witness.size() != stack.size()) return strprintf("input %u witness size", i);
        if (witness.empty() != stack.empty() || witness.IsNull() != txin.scriptWitness.IsNull()) return strprintf("input %u witness IsNull", i);
        if (witness.GetSerializeSize() != Ser(stack).size()) return strprintf("input %u witness serialized size", i);
        if (Ser(witness) != Ser(stack)) return strprintf("input %u witness serialization", i);
        if (!std::ranges::equal(witness, stack, std::ranges::equal)) return strprintf("input %u witness iteration", i);
        if (!stack.empty() && !std::ranges::equal(witness.front(), stack.front())) return strprintf("input %u witness front", i);
        if (!std::ranges::equal(witness.ToSpans(), stack, std::ranges::equal)) return strprintf("input %u witness ToSpans", i);
        if (witness.ToStack() != stack) return strprintf("input %u witness ToStack", i);
        const CTxInView view{tx.Inputs()[i]};
        if (view.GetIndex() != i || &view.GetTransaction() != &tx) return strprintf("input %u view identity", i);
        if (view.GetPrevout() != txin.prevout || !std::ranges::equal(view.GetScriptSig(), txin.scriptSig) ||
            view.GetSequence() != txin.nSequence || view.GetWitness().ToStack() != stack) {
            return strprintf("input %u view", i);
        }
        const CTxIn converted{tx.GetInput(i).ToTxIn()};
        if (converted != txin || converted.scriptWitness.stack != stack) return strprintf("input %u ToTxIn", i);
    }
    uint32_t count{0};
    for (const CTxInView view : tx.Inputs()) {
        if (view.GetIndex() != count++) return "input range iteration";
    }
    if (count != mtx.vin.size() || tx.Inputs().size() != mtx.vin.size()) return "input range size";

    for (uint32_t i = 0; i < mtx.vout.size(); ++i) {
        const CTxOut& txout{mtx.vout[i]};
        if (tx.GetOutputValue(i) != txout.nValue) return strprintf("output %u value", i);
        if (!std::ranges::equal(tx.GetOutputScriptPubKey(i), txout.scriptPubKey)) return strprintf("output %u scriptPubKey", i);
        const CTxOutView view{tx.GetOutput(i)};
        if (view.GetValue() != txout.nValue || !std::ranges::equal(view.GetScriptPubKey(), txout.scriptPubKey)) return strprintf("output %u view", i);
        if (!(view == txout)) return strprintf("output %u equality", i);
        if (view.ToTxOut() != txout) return strprintf("output %u ToTxOut", i);
        if (Ser(view) != Ser(txout)) return strprintf("output %u serialization", i);
    }
    count = 0;
    for (const CTxOutView view : tx.Outputs()) {
        if (view.GetIndex() != count++) return "output range iteration";
    }
    if (count != mtx.vout.size() || tx.Outputs().size() != mtx.vout.size()) return "output range size";

    if (Ser(TX_WITH_WITNESS(tx)) != ser_witness) return "serialization with witness";
    if (Ser(TX_NO_WITNESS(tx)) != ser_no_witness) return "serialization without witness";
    if (tx.GetTotalSize() != ser_witness.size() || tx.ComputeTotalSize() != ser_witness.size()) return "total size";
    if (tx.GetStrippedSize() != ser_no_witness.size()) return "stripped size";

    if (Ser(TX_WITH_WITNESS(CMutableTransaction{tx})) != ser_witness) return "conversion to CMutableTransaction";
    if (Ser(TX_WITH_WITNESS(Transaction{mtx})) != ser_witness) return "conversion from CMutableTransaction";

    // Deserializing the serialization must give the same object, except where the witness serialization is
    // ambiguous (no inputs, but outputs, which looks like the extended format's marker and flags).
    if (!mtx.vin.empty() || mtx.vout.empty()) {
        SpanReader reader{ser_witness};
        const Transaction deser{deserialize, TX_WITH_WITNESS, reader};
        if (Ser(TX_WITH_WITNESS(deser)) != ser_witness || deser.GetWitnessHash() != tx.GetWitnessHash() || !reader.empty()) return "deserialization with witness";
    }
    if (!mtx.HasWitness()) {
        SpanReader reader{ser_no_witness};
        const Transaction deser{deserialize, TX_NO_WITNESS, reader};
        if (Ser(TX_WITH_WITNESS(deser)) != ser_witness || !reader.empty()) return "deserialization without witness";
    }
    return {};
}
