// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

/** The shape of a synthetic transaction: all its inputs are alike, and so are all its outputs. */
struct TxShape {
    size_t num_inputs{1};
    size_t scriptsig_size{0};
    //! The number of elements in each input's witness (0 for a transaction without witnesses).
    size_t witness_items{0};
    //! The size of each witness element.
    size_t witness_item_size{0};
    size_t num_outputs{1};
    size_t scriptpubkey_size{0};
};

/** Write the serialization of a transaction of the given shape (with witnesses), byte by byte, so that this does not
 *  depend on how transactions are represented in memory. */
void WriteTx(VectorWriter& s, const TxShape& shape)
{
    const bool witness{shape.witness_items > 0};
    s << CTransaction::CURRENT_VERSION;
    if (witness) s << uint8_t{0} << uint8_t{1};
    WriteCompactSize(s, shape.num_inputs);
    for (size_t i = 0; i < shape.num_inputs; ++i) {
        s << uint256::ONE << uint32_t(i) << std::vector<unsigned char>(shape.scriptsig_size, 0x51) << CTxIn::SEQUENCE_FINAL;
    }
    WriteCompactSize(s, shape.num_outputs);
    for (size_t i = 0; i < shape.num_outputs; ++i) {
        s << COIN << std::vector<unsigned char>(shape.scriptpubkey_size, 0x51);
    }
    if (witness) {
        for (size_t i = 0; i < shape.num_inputs; ++i) {
            WriteCompactSize(s, shape.witness_items);
            for (size_t j = 0; j < shape.witness_items; ++j) s << std::vector<unsigned char>(shape.witness_item_size, 0x01);
        }
    }
    s << uint32_t{0}; // nLockTime
}

/** Benchmark deserializing a block of num_txs transactions of the given shape. */
void DeserializeBlock(benchmark::Bench& bench, const TxShape& shape, size_t num_txs)
{
    std::vector<unsigned char> tx;
    {
        VectorWriter s{tx, 0};
        WriteTx(s, shape);
    }
    std::vector<unsigned char> data;
    {
        VectorWriter s{data, 0};
        s << CBlockHeader{};
        WriteCompactSize(s, num_txs);
        for (size_t i = 0; i < num_txs; ++i) s.write(MakeByteSpan(tx));
    }
    {
        CBlock block;
        SpanReader{data} >> TX_WITH_WITNESS(block);
        assert(GetBlockWeight(block) <= MAX_BLOCK_WEIGHT);
    }
    bench.unit("block").run([&] {
        CBlock block;
        SpanReader{data} >> TX_WITH_WITNESS(block);
        assert(!block.vtx.empty());
    });
}

} // namespace

// The counts below are the largest that keep each block within MAX_BLOCK_WEIGHT.

/** Spends of P2WPKH outputs to P2WPKH outputs: a typical segwit block. */
static void DeserializeBlockP2WPKH(benchmark::Bench& bench)
{
    DeserializeBlock(bench, {.num_inputs = 2, .witness_items = 2, .witness_item_size = 72, .num_outputs = 2, .scriptpubkey_size = 22}, 4385);
}

/** The smallest segwit transactions: the most transactions (and memory per weight) a block can have. */
static void DeserializeBlockMinimalSegwitTxs(benchmark::Bench& bench)
{
    DeserializeBlock(bench, {.witness_items = 1}, 16392);
}

/** One transaction with as many inputs (each with a single-element witness) as fit. */
static void DeserializeBlockManyInputs(benchmark::Bench& bench)
{
    DeserializeBlock(bench, {.num_inputs = 24093, .witness_items = 1}, 1);
}

/** One transaction with as many outputs as fit. */
static void DeserializeBlockManyOutputs(benchmark::Bench& bench)
{
    DeserializeBlock(bench, {.num_outputs = 111096}, 1);
}

/** One transaction whose witness has as many 1-byte elements as fit. */
static void DeserializeBlockManyWitnessElements(benchmark::Bench& bench)
{
    DeserializeBlock(bench, {.witness_items = 1999714, .witness_item_size = 1}, 1);
}

BENCHMARK(DeserializeBlockP2WPKH);
BENCHMARK(DeserializeBlockMinimalSegwitTxs);
BENCHMARK(DeserializeBlockManyInputs);
BENCHMARK(DeserializeBlockManyOutputs);
BENCHMARK(DeserializeBlockManyWitnessElements);
