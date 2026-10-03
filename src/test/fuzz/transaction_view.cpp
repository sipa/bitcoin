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
