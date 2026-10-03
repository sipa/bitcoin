// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/transaction_view.h>

#include <cassert>
#include <cstdio>
#include <ios>
#include <optional>
#include <string>

namespace {

void CheckEquivalent(const Transaction& tx, const CMutableTransaction& mtx)
{
    const std::string err{CompareTransaction(tx, mtx)};
    if (!err.empty()) {
        std::fprintf(stderr, "Transaction mismatch: %s\n", err.c_str());
        assert(false);
    }
}

} // namespace

/** Deserialize the input as both a CMutableTransaction and a Transaction, and compare them. */
FUZZ_TARGET(transaction_view_deserialize)
{
    if (buffer.empty()) return;
    const TransactionSerParams params{buffer[0] & 1 ? TX_WITH_WITNESS : TX_NO_WITNESS};
    const auto data{buffer.subspan(1)};
    std::optional<CMutableTransaction> mtx;
    std::optional<Transaction> tx;
    SpanReader mtx_reader{data}, tx_reader{data};
    try {
        mtx.emplace(deserialize, params, mtx_reader);
    } catch (const std::ios_base::failure&) {
    }
    try {
        tx.emplace(deserialize, params, tx_reader);
    } catch (const std::ios_base::failure&) {
    }
    assert(mtx.has_value() == tx.has_value());
    if (!mtx) return;
    assert(mtx_reader.size() == tx_reader.size());
    CheckEquivalent(*tx, *mtx);
}

/** Construct a Transaction from a fuzzer-generated CMutableTransaction, and compare them. */
FUZZ_TARGET(transaction_view_convert)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const CMutableTransaction mtx{ConsumeTransaction(provider, std::nullopt)};
    CheckEquivalent(Transaction{mtx}, mtx);
}

/** Compare Transaction::Equals with an implementation on CMutableTransactions. */
FUZZ_TARGET(transaction_view_equals)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const CMutableTransaction mtx1{ConsumeTransaction(provider, std::nullopt)};
    CMutableTransaction mtx2{provider.ConsumeBool() ? ConsumeTransaction(provider, std::nullopt) : mtx1};
    // Make some (small) modifications, to exercise every field.
    LIMITED_WHILE(provider.ConsumeBool(), 4) {
        const auto pick_input = [&]() -> CTxIn& { return mtx2.vin[provider.ConsumeIntegralInRange<size_t>(0, mtx2.vin.size() - 1)]; };
        switch (provider.ConsumeIntegralInRange(0, 7)) {
        case 0: mtx2.version ^= 1; break;
        case 1: mtx2.nLockTime ^= 1; break;
        case 2: if (!mtx2.vin.empty()) pick_input().prevout.n ^= 1; break;
        case 3: if (!mtx2.vin.empty()) pick_input().nSequence ^= 1; break;
        case 4: if (!mtx2.vin.empty()) pick_input().scriptSig << OP_1; break;
        case 5: if (!mtx2.vin.empty()) pick_input().scriptWitness.stack.emplace_back(); break;
        case 6: if (!mtx2.vout.empty()) mtx2.vout.back().nValue ^= 1; break;
        case 7: if (!mtx2.vout.empty()) mtx2.vout.back().scriptPubKey << OP_1; break;
        }
    }
    const Transaction tx1{mtx1}, tx2{mtx2};
    for (const bool include_script_sig : {false, true}) {
        for (const bool include_witness_data : {false, true}) {
            const EqualsOptions opts{.include_script_sig = include_script_sig, .include_witness_data = include_witness_data};
            assert(tx1.Equals(tx2, opts) == ExpectedEquals(mtx1, mtx2, opts));
            assert(tx2.Equals(tx1, opts) == ExpectedEquals(mtx2, mtx1, opts));
        }
    }
}
