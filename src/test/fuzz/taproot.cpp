// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>

#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/algorithm/string.hpp>
#include <cstdint>
#include <string>
#include <vector>

#include <assert.h>

static CScript ScriptFromHex(const std::string& str)
{
    std::vector<unsigned char> data = ParseHex(str);
    return CScript(data.begin(), data.end());
}

static CMutableTransaction TxFromHex(const std::string& str)
{
    CMutableTransaction tx;
    VectorReader(SER_DISK, SERIALIZE_TRANSACTION_NO_WITNESS, ParseHex(str), 0) >> tx;
    return tx;
}

static std::vector<CTxOut> TxOutsFromJSON(const UniValue& univalue)
{
    assert(univalue.isArray());
    std::vector<CTxOut> prevouts;
    for (size_t i = 0; i < univalue.size(); ++i) {
        CTxOut txout;
        VectorReader(SER_DISK, 0, ParseHex(univalue[i].get_str()), 0) >> txout;
        prevouts.push_back(std::move(txout));
    }
    return prevouts;
}

static CScriptWitness ScriptWitnessFromJSON(const UniValue& univalue)
{
    assert(univalue.isArray());
    CScriptWitness scriptwitness;
    for (size_t i = 0; i < univalue.size(); ++i) {
        auto bytes = ParseHex(univalue[i].get_str());
        scriptwitness.stack.push_back(std::move(bytes));
    }
    return scriptwitness;
}

static std::map<std::string, unsigned int> mapFlagNames = {
    {std::string("P2SH"), (unsigned int)SCRIPT_VERIFY_P2SH},
    {std::string("NULLDUMMY"), (unsigned int)SCRIPT_VERIFY_NULLDUMMY},
    {std::string("CHECKLOCKTIMEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY},
    {std::string("CHECKSEQUENCEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKSEQUENCEVERIFY},
    {std::string("WITNESS"), (unsigned int)SCRIPT_VERIFY_WITNESS},
    {std::string("TAPROOT"), (unsigned int)SCRIPT_VERIFY_TAPROOT},
};

static std::vector<unsigned int> AllFlags()
{
    std::vector<unsigned int> ret;

    for (unsigned int i = 0; i < 64; ++i) {
        unsigned int flag = 0;
        if (i & 1) flag |= SCRIPT_VERIFY_P2SH;
        if (i & 2) flag |= SCRIPT_VERIFY_NULLDUMMY;
        if (i & 4) flag |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
        if (i & 8) flag |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        if (i & 16) flag |= SCRIPT_VERIFY_WITNESS;
        if (i & 32) flag |= SCRIPT_VERIFY_TAPROOT;

        if (flag & SCRIPT_VERIFY_WITNESS && !(flag & SCRIPT_VERIFY_P2SH)) continue;
        if (flag & SCRIPT_VERIFY_TAPROOT && !(flag & SCRIPT_VERIFY_WITNESS)) continue;

        ret.push_back(flag);
    }

    return ret;
}

static const std::vector<unsigned int> ALL_FLAGS = AllFlags();

unsigned int ParseScriptFlags(const std::string& strFlags)
{
    if (strFlags.empty()) {
        return 0;
    }
    unsigned int flags = 0;
    std::vector<std::string> words;
    boost::algorithm::split(words, strFlags, boost::algorithm::is_any_of(","));

    for (const std::string& word : words)
    {
        assert(mapFlagNames.count(word));
        flags |= mapFlagNames[word];
    }

    return flags;
}

static void Test(const std::string& str)
{
    UniValue test;
    bool ok = test.read(str) && test.isObject();
    assert(ok);

    CMutableTransaction tx = TxFromHex(test["tx"].get_str());
    const std::vector<CTxOut> prevouts = TxOutsFromJSON(test["prevouts"]);
    assert(prevouts.size() == tx.vin.size());
    size_t idx = test["index"].get_int64();
    unsigned int test_flags = ParseScriptFlags(test["flags"].get_str());
    bool final = test.exists("final") && test["final"].get_bool();

    if (test.exists("success")) {
        tx.vin[idx].scriptSig = ScriptFromHex(test["success"]["scriptSig"].get_str());
        tx.vin[idx].scriptWitness = ScriptWitnessFromJSON(test["success"]["witness"]);
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>(prevouts));
        MutableTransactionSignatureChecker txcheck(&tx, idx, prevouts[idx].nValue, txdata);
        for (const auto flags : ALL_FLAGS) {
            // "final": true tests are valid for all flags. Others are only valid with flags that are
            // a subset of test_flags.
            if (final || ((flags & test_flags) == flags)) {
                bool ret = VerifyScript(tx.vin[idx].scriptSig, prevouts[idx].scriptPubKey, &tx.vin[idx].scriptWitness, flags, txcheck, nullptr);
                assert(ret);
            }
        }
    }

    if (test.exists("failure")) {
        tx.vin[idx].scriptSig = ScriptFromHex(test["failure"]["scriptSig"].get_str());
        tx.vin[idx].scriptWitness = ScriptWitnessFromJSON(test["failure"]["witness"]);
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>(prevouts));
        MutableTransactionSignatureChecker txcheck(&tx, idx, prevouts[idx].nValue, txdata);
        for (const auto flags : ALL_FLAGS) {
            // If a test is supposed to fail with test_flags, it should also fail with any superset thereof.
            if ((flags & test_flags) == test_flags) {
                bool ret = VerifyScript(tx.vin[idx].scriptSig, prevouts[idx].scriptPubKey, &tx.vin[idx].scriptWitness, flags, txcheck, nullptr);
                assert(!ret);
            }
        }
    }
}

static ECCVerifyHandle handle;

void test_one_input(const std::vector<uint8_t>& buffer)
{
    const std::string str((const char*)buffer.data(), buffer.size() - 2);
    Test(str);
}
