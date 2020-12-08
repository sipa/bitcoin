// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <test/fuzz/fuzz.h>

#include <vector>
#include <cassert>

#include <stdint.h>

static bool Weird(const CMutableTransaction& mtx)
{
    if (mtx.vin.size() == 0 || mtx.vout.size() == 0) {
        for (size_t i = 0; i < mtx.vin.size(); ++i) {
            // A transaction with missing inputs and/or outputs, but with witnesses/scriptsigs.
            if (mtx.vin[i].scriptSig.size() || mtx.vin[i].scriptWitness.stack.size()) return true;
        }
    }
    for (size_t i = 0; i < mtx.vin.size(); ++i) {
        // A transaction input with both scriptSig and witness must have a P2SH-compatible scriptSig.
        if (mtx.vin[i].scriptSig.size() && mtx.vin[i].scriptWitness.stack.size()) {
            if (!mtx.vin[i].scriptSig.IsPushOnly()) return true;
            std::vector<std::vector<unsigned char>> stack;
            if (!EvalScript(stack, mtx.vin[i].scriptSig, 0, BaseSignatureChecker{}, SigVersion::BASE, nullptr)) return true;
            if (stack.size() == 0) return true;
            CScript redeemScript{stack.back().begin(), stack.back().end()};
            int version;
            std::vector<unsigned char> program;
            if (!redeemScript.IsWitnessProgram(version, program)) return true;
        }
    }
    return false;
}

void test_one_input(const std::vector<uint8_t>& buffer)
{
    CMutableTransaction tx_both, tx_legacy, tx_extended;
    bool ok_both = DecodeTx(tx_both, buffer, true, true);
    bool ok_legacy = DecodeTx(tx_legacy, buffer, true, false);
    bool ok_extended = DecodeTx(tx_extended, buffer, false, true);

    assert(ok_both == (ok_legacy | ok_extended));
    if (ok_legacy && !Weird(tx_legacy)) assert(tx_both == tx_legacy);
    if (ok_extended && !Weird(tx_extended)) assert(tx_both == tx_extended);
}
