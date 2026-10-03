// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <streams.h>
#include <test/data/tx_invalid.json.h>
#include <test/data/tx_valid.json.h>
#include <test/util/common.h>
#include <test/util/json.h>
#include <test/util/transaction_view.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <ios>
#include <optional>
#include <vector>

namespace {

/** Deserialize with the given parameters as both a CMutableTransaction and a Transaction, check that
 *  they agree on success/failure and on the number of bytes consumed, and compare them if successful. */
void CheckDeserialization(const std::vector<unsigned char>& bytes, const TransactionSerParams& params)
{
    std::optional<CMutableTransaction> mtx;
    std::optional<Transaction> tx;
    SpanReader mtx_reader{bytes}, tx_reader{bytes};
    try {
        mtx.emplace(deserialize, params, mtx_reader);
    } catch (const std::ios_base::failure&) {
    }
    try {
        tx.emplace(deserialize, params, tx_reader);
    } catch (const std::ios_base::failure&) {
    }
    BOOST_REQUIRE_EQUAL(mtx.has_value(), tx.has_value());
    if (!mtx) return;
    BOOST_CHECK_EQUAL(mtx_reader.size(), tx_reader.size());
    const std::string err{CompareTransaction(*tx, *mtx)};
    BOOST_CHECK_MESSAGE(err.empty(), "mismatch: " << err);
}

void CheckJsonTransactions(const UniValue& tests)
{
    int count{0};
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        if (!test[0].isArray()) continue; // Comment.
        const auto bytes{ParseHex(test[1].get_str())};
        CheckDeserialization(bytes, TX_WITH_WITNESS);
        CheckDeserialization(bytes, TX_NO_WITNESS);
        ++count;
    }
    BOOST_CHECK(count > 10);
}

std::vector<unsigned char> RandomBytes(FastRandomContext& rng)
{
    size_t len;
    switch (rng.randrange(8)) {
    case 0: len = 0; break;
    case 1: len = 250 + rng.randrange(10); break; // Around the 1-byte CompactSize boundary.
    case 2: len = 65530 + rng.randrange(10); break; // Around the 3-byte CompactSize boundary.
    default: len = rng.randrange(80); break;
    }
    return rng.randbytes<unsigned char>(len);
}

CMutableTransaction RandomTransaction(FastRandomContext& rng)
{
    CMutableTransaction mtx;
    mtx.version = rng.rand32();
    mtx.nLockTime = rng.rand32();
    const bool witness{rng.randbool()};
    const int num_inputs = rng.randrange(5);
    for (int i = 0; i < num_inputs; ++i) {
        CTxIn txin;
        txin.prevout = rng.randrange(8) ? COutPoint{Txid::FromUint256(rng.rand256()), rng.rand32()} : COutPoint{};
        const auto script_sig{RandomBytes(rng)};
        txin.scriptSig = CScript(script_sig.begin(), script_sig.end());
        txin.nSequence = rng.rand32();
        if (witness) {
            const int num_elements = rng.randrange(4) ? rng.randrange(5) : 0;
            for (int j = 0; j < num_elements; ++j) txin.scriptWitness.stack.push_back(RandomBytes(rng));
        }
        mtx.vin.push_back(std::move(txin));
    }
    const int num_outputs = rng.randrange(5);
    for (int i = 0; i < num_outputs; ++i) {
        const auto script_pub_key{RandomBytes(rng)};
        mtx.vout.emplace_back(rng.randrange(4) ? int64_t(rng.randrange(MAX_MONEY)) : int64_t(rng.rand64()), CScript(script_pub_key.begin(), script_pub_key.end()));
    }
    return mtx;
}

std::vector<unsigned char> Serialize(const auto& obj)
{
    std::vector<unsigned char> ret;
    VectorWriter{ret, 0} << obj;
    return ret;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(transaction_view_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(transaction_view_json)
{
    CheckJsonTransactions(read_json(json_tests::tx_valid));
    CheckJsonTransactions(read_json(json_tests::tx_invalid));
}

BOOST_AUTO_TEST_CASE(transaction_view_random)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    for (int i = 0; i < 1000; ++i) {
        const CMutableTransaction mtx{RandomTransaction(rng)};
        const Transaction tx{mtx};
        const std::string err{CompareTransaction(tx, mtx)};
        BOOST_REQUIRE_MESSAGE(err.empty(), "mismatch: " << err);
        const auto bytes{Serialize(TX_WITH_WITNESS(mtx))};
        CheckDeserialization(bytes, TX_WITH_WITNESS);
        CheckDeserialization(bytes, TX_NO_WITNESS);
        const auto bytes_no_witness{Serialize(TX_NO_WITNESS(mtx))};
        CheckDeserialization(bytes_no_witness, TX_WITH_WITNESS);
        CheckDeserialization(bytes_no_witness, TX_NO_WITNESS);
    }
}

BOOST_AUTO_TEST_CASE(transaction_view_edge_cases)
{
    // A Transaction converted from a default-constructed CMutableTransaction.
    BOOST_CHECK(CompareTransaction(Transaction{CMutableTransaction{}}, CMutableTransaction{}).empty());

    // No inputs and no outputs, with witness serialization allowed: the second 0 byte is read as the
    // extended format's flags (equal to 0, so no outputs are read).
    CheckDeserialization(ParseHex("02000000" "00" "00" "00000000"), TX_WITH_WITNESS);
    // No inputs, but outputs, without witness serialization.
    CheckDeserialization(ParseHex("02000000" "00" "01" "0100000000000000" "01" "51" "00000000"), TX_NO_WITNESS);
    // The same with witness serialization allowed: misinterpreted as the extended format with flags 1.
    CheckDeserialization(ParseHex("02000000" "00" "01" "0100000000000000" "01" "51" "00000000"), TX_WITH_WITNESS);

    // Superfluous witness record (all witness stacks empty).
    const auto superfluous{ParseHex("02000000" "0001" "01" "0000000000000000000000000000000000000000000000000000000000000000" "00000000" "00" "ffffffff" "00" "00" "00000000")};
    {
        SpanReader reader{superfluous};
        BOOST_CHECK_EXCEPTION(Transaction(deserialize, TX_WITH_WITNESS, reader), std::ios_base::failure, HasReason("Superfluous witness record"));
    }
    CheckDeserialization(superfluous, TX_WITH_WITNESS);
    // Unknown flags.
    const auto unknown_flags{ParseHex("02000000" "0002" "01" "0000000000000000000000000000000000000000000000000000000000000000" "00000000" "00" "ffffffff" "00" "00000000")};
    {
        SpanReader reader{unknown_flags};
        BOOST_CHECK_EXCEPTION(Transaction(deserialize, TX_WITH_WITNESS, reader), std::ios_base::failure, HasReason("Unknown transaction optional data"));
    }
    // Non-canonical CompactSize.
    const auto non_canonical{ParseHex("02000000" "fd0100" "0000000000000000000000000000000000000000000000000000000000000000" "00000000" "00" "ffffffff" "00" "00000000")};
    {
        SpanReader reader{non_canonical};
        BOOST_CHECK_EXCEPTION(Transaction(deserialize, TX_NO_WITNESS, reader), std::ios_base::failure, HasReason("non-canonical ReadCompactSize()"));
    }
    // Truncated in the middle of a script.
    CheckDeserialization(ParseHex("02000000" "01" "0000000000000000000000000000000000000000000000000000000000000000" "00000000" "05" "5151"), TX_NO_WITNESS);

    // Witness stack element access, and the witness of an input without witness in a witness transaction.
    CMutableTransaction mtx;
    mtx.vin.resize(3);
    mtx.vin[0].scriptWitness.stack = {{1, 2, 3}, {}, std::vector<unsigned char>(300, 7)};
    mtx.vin[2].scriptWitness.stack = {{4}};
    mtx.vout.emplace_back(1000, CScript() << OP_TRUE);
    const Transaction tx{mtx};
    BOOST_CHECK(CompareTransaction(tx, mtx).empty());
    BOOST_CHECK(tx.HasWitness());
    BOOST_CHECK_EQUAL(tx.GetInputWitness(0).size(), 3U);
    BOOST_CHECK_EQUAL(tx.GetInputWitness(0).front().size(), 3U);
    BOOST_CHECK_EQUAL(tx.GetInputWitness(0).ToSpans()[2].size(), 300U);
    BOOST_CHECK(tx.GetInputWitness(1).empty());
    BOOST_CHECK_EQUAL(tx.GetInputWitness(1).GetSerializeSize(), 1U);
    BOOST_CHECK_EQUAL(tx.Inputs()[2].GetWitness().front()[0], 4);
    BOOST_CHECK(tx.GetWitnessHash().ToUint256() != tx.GetHash().ToUint256());
}

BOOST_AUTO_TEST_CASE(outpoint_view)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    // Outpoints with few distinct txids (differing only in their first or last byte) and output indices (whose
    // little-endian serializations order differently than their values), so that many pairs compare equal in
    // some part.
    std::vector<COutPoint> outpoints;
    for (int i = 0; i < 40; ++i) {
        uint256 hash{};
        if (rng.randbool()) *hash.begin() = rng.randrange(3);
        if (rng.randbool()) *(hash.end() - 1) = rng.randrange(3);
        static constexpr uint32_t INDICES[]{0, 1, 2, 0xff, 0x100, 0x101, 0x10000, COutPoint::NULL_INDEX};
        outpoints.emplace_back(Txid::FromUint256(hash), INDICES[rng.randrange(std::size(INDICES))]);
    }
    std::vector<std::vector<uint8_t>> serialized;
    for (const COutPoint& outpoint : outpoints) {
        serialized.emplace_back();
        VectorWriter{serialized.back(), 0, outpoint};
        BOOST_REQUIRE_EQUAL(serialized.back().size(), OutPointView::SIZE);
    }
    const auto view{[&](size_t i) { return OutPointView{std::span{serialized[i]}.first<OutPointView::SIZE>()}; }};
    for (size_t i = 0; i < outpoints.size(); ++i) {
        BOOST_CHECK(view(i).ToOutPoint() == outpoints[i]);
        BOOST_CHECK(view(i).GetHash() == outpoints[i].hash);
        BOOST_CHECK_EQUAL(view(i).GetN(), outpoints[i].n);
        for (size_t j = 0; j < outpoints.size(); ++j) {
            const COutPoint& a{outpoints[i]};
            const COutPoint& b{outpoints[j]};
            BOOST_CHECK_EQUAL(view(i) == view(j), a == b);
            BOOST_CHECK_EQUAL(view(i) < view(j), a < b);
            BOOST_CHECK_EQUAL(view(i) == b, a == b);
            BOOST_CHECK_EQUAL(view(i) < b, a < b);
            BOOST_CHECK_EQUAL(a < view(j), a < b);
            BOOST_CHECK_EQUAL(view(i).HasHash(b.hash), a.hash == b.hash);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
