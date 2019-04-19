#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Test taproot softfork.

from test_framework.blocktools import create_coinbase, create_block, create_transaction, add_witness_commitment
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness, COIN
from test_framework.script import CScript, TaprootSignatureHash, taproot_construct, GetP2SH, OP_1, OP_CHECKSIG, OP_IF, OP_CODESEPARATOR, OP_ELSE, OP_ENDIF, OP_DROP, taproot_key_sign, SIGHASH_SINGLE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, hex_str_to_bytes
from test_framework.key import ECKey
from test_framework.address import program_to_witness, script_to_p2sh
from binascii import hexlify
from hashlib import sha256
from io import BytesIO
import random

EMPTYWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness program was passed an empty witness) (code 64)"
INVALIDKEYPATHSIG_ERROR = "non-mandatory-script-verify-flag (Invalid signature for taproot key path spending) (code 64)"
UNKNOWNWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness version reserved for soft-fork upgrades) (code 64)"

def tx_from_hex(hexstring):
    tx = CTransaction()
    f = BytesIO(hex_str_to_bytes(hexstring))
    tx.deserialize(f)
    return tx

def get_taproot_bech32(info):
    if isinstance(info, tuple):
        info = info[0]
    return program_to_witness(1, info[2:])

def get_taproot_p2sh(info):
    return script_to_p2sh(info[0])

def spend_single_sig(tx, input_index, spent_utxos, info, p2sh, key, annex=None, hashtype=0, prefix=[], suffix=[], script=None, pos=-1, damage_sighash=False):
    ht = hashtype
    # Taproot key path spend: tweak key
    if script is None:
        key = key.tweak_add(info[1])
        assert(key is not None)
    # Change SIGHASH_SINGLE into SIGHASH_ALL if no corresponding output
    if (ht & 3 == SIGHASH_SINGLE and input_index >= len(tx.vout)):
        ht ^= 2
    # Compute sighash
    if script:
        sighash = TaprootSignatureHash(tx, spent_utxos, ht, input_index, scriptpath = True, tapscript = script, codeseparator_pos = pos, annex = annex)
    else:
        sighash = TaprootSignatureHash(tx, spent_utxos, ht, input_index, scriptpath = False, annex = annex)
    if damage_sighash:
        sighash = (int.from_bytes(sighash, 'big') ^ (1 << random.randrange(256))).to_bytes(32, 'big')
    # Compute signature
    sig = key.sign_schnorr(sighash)
    if hashtype > 0:
        sig += bytes([ht])
    # Construct witness
    ret = prefix + [sig] + suffix
    if script is not None:
        ret += [script, info[2][script]]
    if annex is not None:
        ret += [annex]
    tx.wit.vtxinwit[input_index].scriptWitness.stack = ret
    # Construct P2SH redeemscript
    if p2sh:
        tx.vin[input_index].scriptSig = CScript([info[0]])

def spender_sighash_mutation(spenders, info, p2sh, comment, standard=True, **kwargs):
    spk = info[0]
    addr = get_taproot_bech32(info)
    if p2sh:
        spk = GetP2SH(spk)
        addr = get_taproot_p2sh(info)
    def fn(t, i, u, v):
        return spend_single_sig(t, i, u, damage_sighash=not v, info=info, p2sh=p2sh, **kwargs)
    spenders.append((spk, addr, comment, standard, fn))

class TAPROOTTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1", "-acceptnonstdtxn=0", "-par=1"]]

    def block_submit(self, node, txs, msg, witness=False, accept=False):
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
            assert node.getbestblockhash() == block.hash, "Failed to accept: " + msg
            self.tip = block.sha256
            self.lastblockhash = block.hash
            self.lastblocktime += 1
            self.lastblockheight += 1
        else:
            assert node.getbestblockhash() == self.lastblockhash, "Failed to reject: " + msg

    def test_spenders(self, spenders, input_counts):
        """Run randomized tests with a number of "spenders".

        Each spender is a tuple of:
        - A scriptPubKey (CScript)
        - An address for that scriptPubKey (string)
        - A comment describing the test (string)
        - Whether the spending (on itself) is expected to be standard (bool)
        - A lambda taking as inputs:
          - A transaction to sign (CTransaction)
          - An input position (int)
          - The spent UTXOs by this transaction (list of CTxOut)
          - Whether to produce a valid spend (bool)

        Each spender embodies a test; in a large randomized test, it is verified
        that toggling the valid argument to each lambda toggles the validity of
        the transaction. This is accomplished by constructing transactions consisting
        of all valid inputs, except one invalid one.
        """

        # Construct a UTXO to spend for each of the spenders
        self.nodes[0].generate(110)
        bal = self.nodes[0].getbalance() * 3 / (4*len(spenders))
        random.shuffle(spenders)
        num_spenders = len(spenders)
        utxos = []
        while len(spenders):
            # Create the necessary outputs in multiple transactions, as sPKs may be repeated (which sendmany does not support)
            outputs = {}
            new_spenders = []
            batch = []
            for spender in spenders:
                addr = spender[1]
                if addr in outputs:
                    new_spenders.append(spender)
                else:
                    amount = random.randrange(int(bal * 95000000), int(bal * 105000000))
                    outputs[addr] = amount / 100000000
                    batch.append(spender)
            self.log.info("Constructing %i UTXOs for spending tests" % len(batch))
            tx = tx_from_hex(self.nodes[0].getrawtransaction(self.nodes[0].sendmany("", outputs)))
            tx.rehash()
            spenders = new_spenders
            random.shuffle(spenders)

            # Map created UTXOs back to the spenders they were created for
            for n, out in enumerate(tx.vout):
                for spender in batch:
                    if out.scriptPubKey == spender[0]:
                        utxos.append((COutPoint(tx.sha256, n), out, spender))
                        break
        assert(len(utxos) == num_spenders)
        random.shuffle(utxos)
        self.nodes[0].generate(1)

        # Construct a bunch of sPKs that send coins back to the host wallet
        self.log.info("Constructing 100 addresses for returning coins")
        host_spks = []
        for i in range(100):
            addr = self.nodes[0].getnewaddress(address_type=random.choice(["legacy", "p2sh-segwit", "bech32"]))
            spk = hex_str_to_bytes(self.nodes[0].getaddressinfo(addr)['scriptPubKey'])
            host_spks.append(spk)

        # Pick random subsets of UTXOs to construct transactions with
        self.lastblockhash = self.nodes[0].getbestblockhash()
        self.tip = int("0x" + self.lastblockhash, 0)
        block = self.nodes[0].getblock(self.lastblockhash)
        self.lastblockheight = block['height']
        self.lastblocktime = block['time']
        while len(utxos):
            tx = CTransaction()
            tx.nLockTime = random.randrange(500000000, 1000000000) # all absolute locktimes in the past

            # Pick 1 to 4 UTXOs to construct transaction inputs
            acceptable_input_counts = [cnt for cnt in input_counts if cnt <= len(utxos)]
            while True:
                inputs = random.choice(acceptable_input_counts)
                remaining = len(utxos) - inputs
                if remaining == 0 or remaining >= max(input_counts) or remaining in input_counts:
                    break
            input_utxos = utxos[-inputs:]
            utxos = utxos[:-inputs]
            in_value = sum(utxo[1].nValue for utxo in input_utxos) - random.randrange(10000, 20000) # 10000-20000 sat fee
            tx.vin = [CTxIn(outpoint = input_utxos[i][0], nSequence = random.randrange(500000000, 1000000000)) for i in range(inputs)]
            tx.wit.vtxinwit = [CTxInWitness() for i in range(inputs)]
            self.log.info("Test: %s" % (", ".join(utxo[2][2] for utxo in input_utxos)))

            # Add 1 to 4 outputs
            outputs = random.choice([1,2,3,4])
            for i in range(outputs):
                tx.vout.append(CTxOut())
                tx.vout[-1].nValue = random.randrange(in_value) if i < outputs - 1 else in_value
                in_value -= tx.vout[-1].nValue
                tx.vout[-1].scriptPubKey = random.choice(host_spks)

            # For each inputs, make it fail once; then succeed once
            for fail_input in range(inputs + 1):
                # Wipe scriptSig/witness
                for i in range(inputs):
                    tx.vin[i].scriptSig = CScript()
                    tx.wit.vtxinwit[i] = CTxInWitness()
                # Fill inputs/witnesses
                for i in range(inputs):
                    fn = input_utxos[i][2][4]
                    fn(tx, i, [utxo[1] for utxo in input_utxos], i != fail_input)
                # If valid, submit to mempool to check standardness
                if fail_input == inputs:
                    standard = all(utxo[2][3] for utxo in input_utxos)
                    if standard:
                        self.nodes[0].sendrawtransaction(tx.serialize().hex(), 0)
                        assert(self.nodes[0].getmempoolentry(tx.hash) is not None)
                    else:
                        assert_raises_rpc_error(-26, None, self.nodes[0].sendrawtransaction, tx.serialize().hex(), 0)
                # Submit in a block
                tx.rehash()
                msg = ','.join(utxo[2][2] + ("*" if n == fail_input else "") for n, utxo in enumerate(input_utxos))
                self.block_submit(self.nodes[0], [tx], msg, True, fail_input == inputs)

    def run_test(self):
        VALID_SIGHASHES = [0,1,2,3,0x81,0x82,0x83]
        spenders = []

        # Sighash mutation tests
        for p2sh in [False, True]:
            for hashtype in VALID_SIGHASHES:
                random_annex = bytes([0xff] + [random.getrandbits(8) for i in range(random.randrange(0, 5))])
                for annex in [None, random_annex]:
                    standard = annex is None
                    sec1, sec2 = ECKey(), ECKey()
                    sec1.generate()
                    sec2.generate()
                    pub1, pub2 = sec1.get_pubkey(), sec2.get_pubkey()
                    # Pure pubkey
                    info = taproot_construct(pub1, [])
                    spender_sighash_mutation(spenders, info, p2sh, "sighash/pk#pk", key=sec1, hashtype=hashtype, annex=annex, standard=standard)
                    # Pubkey/P2PK script combination
                    scripts = [CScript([pub2.get_bytes(), OP_CHECKSIG])]
                    info = taproot_construct(pub1, scripts)
                    spender_sighash_mutation(spenders, info, p2sh, "sighash/p2pk#pk", key=sec1, hashtype=hashtype, annex=annex, standard=standard)
                    spender_sighash_mutation(spenders, info, p2sh, "sighash/p2pk#s0", script=scripts[0], key=sec2, hashtype=hashtype, annex=annex, standard=standard)
                    # More complex script structure
                    scripts = [
                        CScript([pub2.get_bytes(), OP_CHECKSIG, OP_CODESEPARATOR]), # codesep after checksig
                        CScript([OP_CODESEPARATOR, pub2.get_bytes(), OP_CHECKSIG]), # codesep before checksig
                        CScript([bytes([1,2,3]), OP_DROP, OP_IF, OP_CODESEPARATOR, pub1.get_bytes(), OP_ELSE, OP_CODESEPARATOR, pub2.get_bytes(), OP_ENDIF, OP_CHECKSIG]), # branch dependent codesep
                    ]
                    info = taproot_construct(pub1, scripts)
                    spender_sighash_mutation(spenders, info, p2sh, "sighash/codesep#pk", key=sec1, hashtype=hashtype, annex=annex, standard=standard)
                    spender_sighash_mutation(spenders, info, p2sh, "sighash/codesep#s0", script=scripts[0], key=sec2, hashtype=hashtype, annex=annex, standard=standard)
                    spender_sighash_mutation(spenders, info, p2sh, "sighash/codesep#s1", script=scripts[1], key=sec2, hashtype=hashtype, annex=annex, pos=0, standard=standard)
                    spender_sighash_mutation(spenders, info, p2sh, "sighash/codesep#s2a", script=scripts[2], key=sec1, hashtype=hashtype, annex=annex, pos=3, suffix=[bytes([1])], standard=standard)
                    spender_sighash_mutation(spenders, info, p2sh, "sighash/codesep#s2b", script=scripts[2], key=sec2, hashtype=hashtype, annex=annex, pos=6, suffix=[bytes([])], standard=standard)

        # Run all tests once with individual inputs, once with groups of inputs
        self.test_spenders(spenders, input_counts=[1])
        self.test_spenders(spenders, input_counts=[2,3,4])


if __name__ == '__main__':
    TAPROOTTest().main()
