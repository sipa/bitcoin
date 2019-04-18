#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Test taproot softfork.

from test_framework.blocktools import create_coinbase, create_block, create_transaction, add_witness_commitment
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness, COIN
from test_framework.script import CScript, TaprootSignatureHash, taproot_construct, GetP2SH, OP_1, taproot_key_sign
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.key import ECKey
from test_framework.address import program_to_witness, script_to_p2sh
from binascii import hexlify
from hashlib import sha256
from secrets import token_bytes

EMPTYWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness program was passed an empty witness) (code 64)"
INVALIDKEYPATHSIG_ERROR = "non-mandatory-script-verify-flag (Invalid signature for taproot key path spending) (code 64)"
UNKNOWNWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness version reserved for soft-fork upgrades) (code 64)"

def get_taproot_bech32(info):
    if isinstance(info, tuple):
        info = info[0]
    return program_to_witness(1, info[2:])

def get_taproot_p2sh(info):
    return script_to_p2sh(info[0])

class TAPROOTTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1", "-acceptnonstdtxn=0"]]

    def block_submit(self, node, txs, witness=False, accept=False):
        block = create_block(self.tip, create_coinbase(self.lastblockheight + 1), self.lastblocktime + 1)
        block.nVersion = 4
        for tx in txs:
            tx.rehash()
            block.vtx.append(tx)
        block.hashMerkleRoot = block.calc_merkle_root()
        witness and add_witness_commitment(block)
        block.rehash()
        block.solve()
        node.submitblock(block.serialize(True).hex())
        if (accept):
            assert_equal(node.getbestblockhash(), block.hash)
            self.tip = block.sha256
            self.lastblockhash = block.hash
            self.lastblocktime += 1
            self.lastblockheight += 1
        else:
            assert_equal(node.getbestblockhash(), self.lastblockhash)

    def run_test(self):
        bare_taproot_key = ECKey()
        bare_taproot_key.generate()
        bare_taproot = taproot_construct(bare_taproot_key.get_pubkey())
        bare_taproot_spk = bare_taproot[0]

        blockhash = self.nodes[0].generate(250)
        self.coinbase = []
        for i in blockhash:
            self.coinbase.append(self.nodes[0].getblock(i)['tx'][0])

        self.lastblockhash = self.nodes[0].getbestblockhash()
        self.tip = int("0x" + self.lastblockhash, 0)
        block = self.nodes[0].getblock(self.lastblockhash)
        self.lastblockheight = block['height']
        self.lastblocktime = block['time']

        txid = []
        out1 = [CTxOut(49 * COIN, bare_taproot[0])]
        out2 = [CTxOut(49 * COIN, GetP2SH(bare_taproot[0]))]
        txid.append(self.send_with_coinbase(49, get_taproot_bech32(bare_taproot)))
        txid.append(self.send_with_coinbase(49, get_taproot_p2sh(bare_taproot)))
        hash = self.nodes[0].generate(1)
        block = self.nodes[0].getblock(hash[0])
        for i in txid:
            assert i in block['tx']

        taproots_keys = []
        taproots = []
        outputs = []
        for i in range(14):
            key = ECKey()
            key.generate()
            taproot = taproot_construct(key.get_pubkey())
            taproots_keys.append(key)
            taproots.append(taproot)
            spk = taproot[0]
            if (i % 2):
                spk = GetP2SH(spk)
            amount = int((i+1)*COIN/10)
            outputs.append(CTxOut(amount, spk))

        tx_native = self.create_tx(txid[0], 0, outputs)
        tx_p2sh = self.create_tx(txid[1], 0, outputs)
        tx_p2sh.vin[0].scriptSig = CScript([bare_taproot[0]])
        assert_raises_rpc_error(-26, EMPTYWITNESS_ERROR, self.nodes[0].sendrawtransaction, tx_native.serialize_with_witness().hex(), 0)
        assert_raises_rpc_error(-26, EMPTYWITNESS_ERROR, self.nodes[0].sendrawtransaction, tx_p2sh.serialize_with_witness().hex(), 0)
        taproot_key_sign(bare_taproot, bare_taproot_key, tx_native, out1, 0, 0)
        taproot_key_sign(bare_taproot, bare_taproot_key, tx_p2sh, out2, 0, 0, True)
        txid = []
        txid.append(self.nodes[0].sendrawtransaction(tx_native.serialize_with_witness().hex(), 0))
        txid.append(self.nodes[0].sendrawtransaction(tx_p2sh.serialize_with_witness().hex(), 0))
        hash = self.nodes[0].generate(1)
        block = self.nodes[0].getblock(hash[0])
        for i in txid:
            assert i in block['tx']

        tx = CTransaction()
        for i in range(14):
            tx.vin.append(CTxIn(COutPoint(int(txid[0], 16), i)))
        for i in range(4):
            tx.vout.append(CTxOut((i+1)*COIN, bare_taproot_spk)) # 4 outputs for SIGHASH_SINGLE
        tx.rehash()

        hash_types = [3,3,0x83,0x83,0,0,1,1,2,2,0x81,0x81,0x82,0x82]
        for i in range(14):
            taproot_key_sign(taproots[i], taproots_keys[i], tx, outputs, hash_types[i], i, i%2)
        self.nodes[0].sendrawtransaction(tx.serialize_with_witness().hex(), 0)


    def send_with_coinbase(self, value, address):
        tx = create_transaction(self.nodes[0], self.coinbase[0], address, amount = value)
        txid = self.nodes[0].sendrawtransaction(tx.serialize_with_witness().hex(), 0)
        self.coinbase = self.coinbase[1:]
        return txid

    def create_tx(self, txid, n, outputs):
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(txid, 16), n)))
        tx.vout = outputs
        tx.rehash()
        return tx

if __name__ == '__main__':
    TAPROOTTest().main()
