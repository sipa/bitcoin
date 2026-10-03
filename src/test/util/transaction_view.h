// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_TRANSACTION_VIEW_H
#define BITCOIN_TEST_UTIL_TRANSACTION_VIEW_H

#include <string>

class Transaction;
struct CMutableTransaction;
struct EqualsOptions;

/** Compare every accessor, view, size, serialization (with and without witness), hash, and conversion of a
 *  Transaction with the CMutableTransaction it should be equivalent to. Returns an empty string if they are
 *  equivalent, and a description of the first difference otherwise. */
std::string CompareTransaction(const Transaction& tx, const CMutableTransaction& mtx);

/** What Transaction::Equals should return for the Transactions corresponding to a and b. */
bool ExpectedEquals(const CMutableTransaction& a, const CMutableTransaction& b, EqualsOptions opts);

#endif // BITCOIN_TEST_UTIL_TRANSACTION_VIEW_H
