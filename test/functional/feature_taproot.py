#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Test taproot softfork.

from test_framework.blocktools import create_coinbase, create_block, create_transaction, add_witness_commitment
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness
from test_framework.script import CScript, TaprootSignatureHash, taproot_construct, OP_0, OP_1, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD, OP_IF, OP_CODESEPARATOR, OP_ELSE, OP_ENDIF, OP_DROP, DEFAULT_TAPSCRIPT_VER, SIGHASH_SINGLE, is_op_success, CScriptOp, OP_RETURN, OP_VERIF, OP_RESERVED, OP_1NEGATE, OP_EQUAL, OP_SWAP, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_NOTIF, OP_2DROP, OP_NOT, OP_2DUP, OP_1SUB, OP_DUP, MAX_SCRIPT_ELEMENT_SIZE, LOCKTIME_THRESHOLD, ANNEX_TAG
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, hex_str_to_bytes
from test_framework.key import ECKey
from test_framework.address import program_to_witness
from binascii import hexlify
from collections import namedtuple
from hashlib import sha256
from io import BytesIO
import random
import struct

EMPTYWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness program was passed an empty witness) (code 64)"
INVALIDKEYPATHSIG_ERROR = "non-mandatory-script-verify-flag (Invalid signature for taproot key path spending) (code 64)"
UNKNOWNWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness version reserved for soft-fork upgrades) (code 64)"

DUST_LIMIT = 600
MIN_FEE = 5000

def tx_from_hex(hexstring):
    tx = CTransaction()
    f = BytesIO(hex_str_to_bytes(hexstring))
    tx.deserialize(f)
    return tx

def get_taproot_bech32(info):
    if isinstance(info, tuple):
        info = info[0]
    return program_to_witness(1, info[2:])

def random_op_success():
    ret = 0
    while (not is_op_success(ret)):
        ret = random.randint(0x50, 0xfe)
    return CScriptOp(ret)

def random_unknown_tapscript_ver(no_annex_tag=True):
    ret = DEFAULT_TAPSCRIPT_VER
    while (ret == DEFAULT_TAPSCRIPT_VER or (no_annex_tag and ret == (ANNEX_TAG & 0xfe))):
        ret = random.randrange(128) * 2
    return ret

def random_bytes(n):
    return bytes(random.getrandbits(8) for i in range(n))

def random_script(size, no_success = True):
    ret = bytes()
    while (len(ret) < size):
        remain = size - len(ret)
        opcode = random.randrange(256)
        while (no_success and is_op_success(opcode)):
            opcode = random.randrange(256)
        if opcode == 0 or opcode >= OP_1NEGATE:
            ret += bytes([opcode])
        elif opcode <= 75 and opcode <= remain - 1:
            ret += bytes([opcode]) + random_bytes(opcode)
        elif opcode == 76 and remain >= 2:
            pushsize = random.randint(0, min(0xff, remain - 2))
            ret += bytes([opcode]) + bytes([pushsize]) + random_bytes(pushsize)
        elif opcode == 77 and remain >= 3:
            pushsize = random.randint(0, min(0xffff, remain - 3))
            ret += bytes([opcode]) + struct.pack(b'<H', pushsize) + random_bytes(pushsize)
        elif opcode == 78 and remain >= 5:
            pushsize = random.randint(0, min(0xffffffff, remain - 5))
            ret += bytes([opcode]) + struct.pack(b'<I', pushsize) + random_bytes(pushsize)
    assert len(ret) == size
    return ret

def random_invalid_push(size):
    assert size > 0
    ret = bytes()
    opcode = 78
    if size <= 75:
        opcode = random.randint(75, 78)
    elif size <= 255:
        opcode = random.randint(76, 78)
    elif size <= 0xffff:
        opcode = random.randint(77, 78)
    if opcode == 75:
        ret = bytes([size]) + random_bytes(size - 1)
    elif opcode == 76:
        ret = bytes([opcode]) + bytes([size]) + random_bytes(size - 2)
    elif opcode == 77:
        ret = bytes([opcode]) + struct.pack(b'<H', size) + random_bytes(max(0, size - 3))
    else:
        ret = bytes([opcode]) + struct.pack(b'<I', size) + random_bytes(max(0, size - 5))
    assert len(ret) >= size
    return ret[:size]

def random_checksig_style(pubkey):
    opcode = random.choice([OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD])
    if (opcode == OP_CHECKSIGVERIFY):
        ret = CScript([pubkey, opcode, OP_1])
    elif (opcode == OP_CHECKSIGADD):
        num = random.choice([0, 0x7fffffff, -0x7fffffff])
        ret = CScript([num, pubkey, opcode, num+1, OP_EQUAL])
    else:
        ret = CScript([pubkey, opcode])
    return bytes(ret)

def damage_bytes(b):
    return (int.from_bytes(b, 'big') ^ (1 << random.randrange(len(b)*8))).to_bytes(len(b), 'big')

# Each spender is a tuple of:
# - A scriptPubKey (CScript)
# - An address for that scriptPubKey (string)
# - A comment describing the test (string)
# - Whether the spending (on itself) is expected to be standard (bool)
# - A witness stack-producing lambda taking as inputs:
#   - A transaction to sign (CTransaction)
#   - An input position (int)
#   - The spent UTXOs by this transaction (list of CTxOut)
#   - Whether to produce a valid spend (bool)

Spender = namedtuple("Spender", "script,address,comment,is_standard,sat_function")

def spend_single_sig(tx, input_index, spent_utxos, info, key, annex=None, hashtype=0, prefix=[], suffix=[], script=None, pos=-1, damage=False):
    ht = hashtype

    damage_type = random.randrange(5) if damage else -1
    '''
    * 0. bit flip the sighash
    * 1. bit flip the signature
    * If the expected hashtype is 0:
    -- 2. append a 0 to the signature
    -- 3. append a random value of 1-255 to the signature
    * If the expected hashtype is not 0:
    -- 2. do not append hashtype to the signature
    -- 3. append a random incorrect value of 0-255 to the signature
    * 4. extra witness element
    '''

    # Taproot key path spend: tweak key
    if script is None:
        pubkey = key.get_pubkey()
        if not pubkey.is_positive:
            key.negate()
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
    if damage_type == 0:
        sighash = damage_bytes(sighash)
    # Compute signature
    sig = key.sign_schnorr(sighash)
    assert(key.get_pubkey().verify_schnorr(sig, sighash))
    if damage_type == 1:
        sig = damage_bytes(sig)
    if damage_type == 2:
        if ht == 0:
            sig += bytes([0])
    elif damage_type == 3:
        random_ht = ht
        while random_ht == ht:
            random_ht = random.randrange(256)
        sig += bytes([random_ht])
    elif ht > 0:
        sig += bytes([ht])
    # Construct witness
    ret = prefix + [sig] + suffix
    if script is not None:
        ret += [script, info[2][script]]
    if annex is not None:
        ret += [annex]
    if damage_type == 4:
        ret = [random_bytes(random.randrange(5))] + ret
    tx.wit.vtxinwit[input_index].scriptWitness.stack = ret

def spend_alwaysvalid(tx, input_index, info, script, annex=None, damage=False):
    if isinstance(script, tuple):
        version, script = script
    ret = [script, info[2][script]]
    if damage:
        # With 50% chance, we bit flip the script (unless the script is an empty vector)
        # With 50% chance, we bit flip the control block
        if random.choice([True, False]) or len(ret[0]) == 0:
            # Annex is always required for tapscript version 0x50
            # Unless the original version is 0x50, we couldn't convert it to 0x50 without using annex
            tmp = damage_bytes(ret[1])
            while annex is None and tmp[0] == ANNEX_TAG and ret[1][0] != ANNEX_TAG:
                tmp = damage_bytes(ret[1])
            ret[1] = tmp
        else:
            ret[0] = damage_bytes(ret[0])
    if annex is not None:
        ret += [annex]
    # Randomly add input witness
    if random.choice([True, False]):
        for i in range(random.randint(1, 10)):
            ret = [random_bytes(random.randint(0, MAX_SCRIPT_ELEMENT_SIZE*2))] + ret
    tx.wit.vtxinwit[input_index].scriptWitness.stack = ret

def spender_sighash_mutation(spenders, info, comment, standard=True, **kwargs):
    spk = info[0]
    addr = get_taproot_bech32(info)
    def fn(t, i, u, v):
        return spend_single_sig(t, i, u, damage=not v, info=info, **kwargs)
    spenders.append(Spender(script=spk, address=addr, comment=comment, is_standard=standard, sat_function=fn))

def spender_two_paths(spenders, info, comment, standard, success, failure):
    spk = info[0]
    addr = get_taproot_bech32(info)
    def fn(t, i, u, v):
        return spend_single_sig(t, i, u, damage=False, info=info, **(success if v else failure))
    spenders.append(Spender(script=spk, address=addr, comment=comment, is_standard=standard, sat_function=fn))

def spender_alwaysvalid(spenders, info, comment, **kwargs):
    spk = info[0]
    addr = get_taproot_bech32(info)
    def fn(t, i, u, v):
        return spend_alwaysvalid(t, i, damage=not v, info=info, **kwargs)
    spenders.append(Spender(script=spk, address=addr, comment=comment, is_standard=False, sat_function=fn))

def nested_script(script, depth):
    if depth == 0:
        return script
    return [nested_script(script, depth - 1), CScript([OP_RETURN])]

UTXOData = namedtuple('UTXOData', 'input,output,spender')

class TAPROOTTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1", "-acceptnonstdtxn=0", "-par=1"]]

    def block_submit(self, node, txs, msg, cb_pubkey=None, fees=0, witness=False, accept=False):
        block = create_block(self.tip, create_coinbase(self.lastblockheight + 1, pubkey=cb_pubkey, fees=fees), self.lastblocktime + 1)
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
                addr = spender.address
                if len(batch) == 100 or addr in outputs:
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
                    if out.scriptPubKey == spender.script:
                        utxos.append(UTXOData(input=COutPoint(tx.sha256, n), output=out, spender=spender))
                        break
        assert(len(utxos) == num_spenders)
        random.shuffle(utxos)
        self.nodes[0].generate(1)

        # Construct a bunch of sPKs that send coins back to the host wallet
        self.log.info("Constructing 100 addresses for returning coins")
        host_spks = []
        host_pubkeys = []
        for i in range(100):
            addr = self.nodes[0].getnewaddress(address_type=random.choice(["legacy", "p2sh-segwit", "bech32"]))
            info = self.nodes[0].getaddressinfo(addr)
            spk = hex_str_to_bytes(info['scriptPubKey'])
            host_spks.append(spk)
            host_pubkeys.append(hex_str_to_bytes(info['pubkey']))

        # Pick random subsets of UTXOs to construct transactions with
        self.lastblockhash = self.nodes[0].getbestblockhash()
        self.tip = int("0x" + self.lastblockhash, 0)
        block = self.nodes[0].getblock(self.lastblockhash)
        self.lastblockheight = block['height']
        self.lastblocktime = block['time']
        while len(utxos):
            tx = CTransaction()
            tx.nVersion = random.choice([1, 2, random.randint(-0x80000000,0x7fffffff)])
            min_sequence = (tx.nVersion != 1 and tx.nVersion != 0) * 0x80000000 # The minimum sequence number to disable relative locktime
            if random.choice([True, False]):
                tx.nLockTime = random.randrange(LOCKTIME_THRESHOLD, self.lastblocktime - 7200) # all absolute locktimes in the past
            else:
                tx.nLockTime = random.randrange(self.lastblockheight+1) # all block heights in the past

            # Pick 1 to 4 UTXOs to construct transaction inputs
            acceptable_input_counts = [cnt for cnt in input_counts if cnt <= len(utxos)]
            while True:
                inputs = random.choice(acceptable_input_counts)
                remaining = len(utxos) - inputs
                if remaining == 0 or remaining >= max(input_counts) or remaining in input_counts:
                    break
            input_utxos = utxos[-inputs:]
            utxos = utxos[:-inputs]
            fee = random.randrange(MIN_FEE * 2, MIN_FEE * 4) # 10000-20000 sat fee
            in_value = sum(utxo.output.nValue for utxo in input_utxos) - fee
            tx.vin = [CTxIn(outpoint = input_utxos[i].input, nSequence = random.randint(min_sequence, 0xffffffff)) for i in range(inputs)]
            tx.wit.vtxinwit = [CTxInWitness() for i in range(inputs)]
            self.log.info("Test: %s" % (", ".join(utxo.spender.comment for utxo in input_utxos)))

            # Add 1 to 4 outputs
            outputs = random.choice([1,2,3,4])
            assert in_value >= 0 and fee - outputs * DUST_LIMIT >= MIN_FEE
            for i in range(outputs):
                tx.vout.append(CTxOut())
                if in_value <= DUST_LIMIT:
                    tx.vout[-1].nValue = DUST_LIMIT
                elif i < outputs - 1:
                    tx.vout[-1].nValue = in_value
                else:
                    tx.vout[-1].nValue = random.randint(DUST_LIMIT, in_value)
                in_value -= tx.vout[-1].nValue
                tx.vout[-1].scriptPubKey = random.choice(host_spks)
            fee += in_value
            assert(fee >= 0)

            # For each inputs, make it fail once; then succeed once
            for fail_input in range(inputs + 1):
                # Wipe scriptSig/witness
                for i in range(inputs):
                    tx.vin[i].scriptSig = CScript()
                    tx.wit.vtxinwit[i] = CTxInWitness()
                # Fill inputs/witnesses
                for i in range(inputs):
                    fn = input_utxos[i].spender.sat_function
                    fn(tx, i, [utxo.output for utxo in input_utxos], i != fail_input)
                # Submit to mempool to check standardness
                standard = fail_input == inputs and all(utxo.spender.is_standard for utxo in input_utxos) and tx.nVersion >= 1 and tx.nVersion <= 2
                if standard:
                    self.nodes[0].sendrawtransaction(tx.serialize().hex(), 0)
                    assert(self.nodes[0].getmempoolentry(tx.hash) is not None)
                else:
                    assert_raises_rpc_error(-26, None, self.nodes[0].sendrawtransaction, tx.serialize().hex(), 0)
                # Submit in a block
                tx.rehash()
                msg = ','.join(utxo.spender.comment + ("*" if n == fail_input else "") for n, utxo in enumerate(input_utxos))
                self.block_submit(self.nodes[0], [tx], msg, witness=True, accept=fail_input == inputs, cb_pubkey=random.choice(host_pubkeys), fees=fee)

    def build_spenders(self):
        VALID_SIGHASHES = [0,1,2,3,0x81,0x82,0x83]
        spenders = []

        for annex in [None, bytes([ANNEX_TAG]) + random_bytes(random.randrange(0, 250))]:
            standard = annex is None
            sec1, sec2 = ECKey(), ECKey()
            sec1.generate()
            sec2.generate()
            pub1, pub2 = sec1.get_pubkey(), sec2.get_pubkey()

            # Sighash mutation tests (test all sighash combinations)
            for hashtype in VALID_SIGHASHES:
                # Pure pubkey
                info = taproot_construct(pub1, [])
                spender_sighash_mutation(spenders, info, "sighash/pk#pk", key=sec1, hashtype=hashtype, annex=annex, standard=standard)
                # Pubkey/P2PK script combination
                scripts = [CScript(random_checksig_style(pub2.get_xonly_bytes()))]
                info = taproot_construct(pub1, scripts)
                spender_sighash_mutation(spenders, info, "sighash/p2pk#pk", key=sec1, hashtype=hashtype, annex=annex, standard=standard)
                spender_sighash_mutation(spenders, info, "sighash/p2pk#s0", script=scripts[0], key=sec2, hashtype=hashtype, annex=annex, standard=standard)

            # For more complex scripts only test one sighash type
            hashtype = random.choice(VALID_SIGHASHES)
            scripts = [
                CScript(random_checksig_style(pub2.get_xonly_bytes()) + bytes([OP_CODESEPARATOR])), # codesep after checksig
                CScript(bytes([OP_CODESEPARATOR]) + random_checksig_style(pub2.get_xonly_bytes())), # codesep before checksig
                CScript([bytes([1,2,3]), OP_DROP, OP_IF, OP_CODESEPARATOR, pub1.get_xonly_bytes(), OP_ELSE, OP_CODESEPARATOR, pub2.get_xonly_bytes(), OP_ENDIF, OP_CHECKSIG]), # branch dependent codesep
            ]
            info = taproot_construct(pub1, scripts)
            spender_sighash_mutation(spenders, info, "sighash/codesep#pk", key=sec1, hashtype=hashtype, annex=annex, standard=standard)
            spender_sighash_mutation(spenders, info, "sighash/codesep#s0", script=scripts[0], key=sec2, hashtype=hashtype, annex=annex, standard=standard)
            spender_sighash_mutation(spenders, info, "sighash/codesep#s1", script=scripts[1], key=sec2, hashtype=hashtype, annex=annex, pos=0, standard=standard)
            spender_sighash_mutation(spenders, info, "sighash/codesep#s2a", script=scripts[2], key=sec1, hashtype=hashtype, annex=annex, pos=3, suffix=[bytes([1])], standard=standard)
            spender_sighash_mutation(spenders, info, "sighash/codesep#s2b", script=scripts[2], key=sec2, hashtype=hashtype, annex=annex, pos=6, suffix=[bytes([])], standard=standard)

            # Taproot max Merkle path length
            scripts = [
                CScript([pub2.get_xonly_bytes(), OP_CHECKSIG]),
                [
                    CScript([pub1.get_xonly_bytes(), OP_CHECKSIG]),
                    CScript([OP_RETURN])
                ]
            ]
            info = taproot_construct(pub1, nested_script(scripts, 127))
            spender_two_paths(spenders, info, "taproot/merklelimit", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0]}, failure={"key": sec1, "hashtype": hashtype, "annex": annex, "script": scripts[1][0]})

            # Various tapscript features
            pubkey = pub2.get_xonly_bytes()
            scripts = [
                # 0) drop stack element and OP_CHECKSIG
                CScript([OP_DROP, pubkey, OP_CHECKSIG]),
                # 1) normal OP_CHECKSIG
                CScript([pubkey, OP_CHECKSIG]),
                # 2) normal OP_CHECKSIGVERIFY
                CScript([pubkey, OP_CHECKSIGVERIFY, OP_1]),
                # 3) Hypothetical OP_CHECKMULTISIG script that takes a single sig as input
                CScript([OP_0, OP_SWAP, OP_1, pubkey, OP_1, OP_CHECKMULTISIG]),
                # 4) Hypothetical OP_CHECKMULTISIGVERIFY script that takes a single sig as input
                CScript([OP_0, OP_SWAP, OP_1, pubkey, OP_1, OP_CHECKMULTISIGVERIFY, OP_1]),
                # 5) OP_IF script that needs a true input
                CScript([OP_IF, pubkey, OP_CHECKSIG, OP_ELSE, OP_RETURN, OP_ENDIF]),
                # 6) OP_NOTIF script that needs a true input
                CScript([OP_NOTIF, OP_RETURN, OP_ELSE, pubkey, OP_CHECKSIG, OP_ENDIF]),
                # 7) OP_CHECKSIG with an empty key
                CScript([OP_0, OP_CHECKSIG]),
                # 8) OP_CHECKSIGVERIFY with an empty key
                CScript([OP_0, OP_CHECKSIGVERIFY, OP_1]),
                # 9) normal OP_CHECKSIGADD
                CScript([OP_0, pubkey, OP_CHECKSIGADD]),
                # 10) OP_CHECKSIGADD with empty key
                CScript([OP_0, OP_0, OP_CHECKSIGADD]),
                # 11) OP_CHECKSIGADD with missing counter stack element
                CScript([pubkey, OP_CHECKSIGADD]),
                # 12) OP_CHECKSIG that needs invalid signature
                CScript([pubkey, OP_CHECKSIGVERIFY, pub1.get_xonly_bytes(), OP_CHECKSIG, OP_NOT]),
                # 13) OP_CHECKSIG with empty key that needs invalid signature
                CScript([pubkey, OP_CHECKSIGVERIFY, OP_0, OP_CHECKSIG, OP_NOT]),
                # 14) OP_CHECKSIGADD that needs invalid signature
                CScript([pubkey, OP_CHECKSIGVERIFY, OP_0, pub1.get_xonly_bytes(), OP_CHECKSIGADD, OP_NOT]),
                # 15) OP_CHECKSIGADD with empty key that needs invalid signature
                CScript([pubkey, OP_CHECKSIGVERIFY, OP_0, OP_0, OP_CHECKSIGADD, OP_NOT]),
                # 16) OP_CHECKSIG with unknown pubkey type
                CScript([OP_1, OP_CHECKSIG]),
                # 17) OP_CHECKSIGADD with unknown pubkey type
                CScript([OP_0, OP_1, OP_CHECKSIGADD]),
                # 18) OP_CHECKSIGVERIFY with unknown pubkey type
                CScript([OP_1, OP_CHECKSIGVERIFY, OP_1]),
                # 19) script longer than 10000 bytes and over 201 non-push opcodes
                CScript([OP_0, OP_0, OP_2DROP] * 10001 + [pubkey, OP_CHECKSIG]),
                # 20) OP_CHECKSIGVERIFY with empty key
                CScript([pubkey, OP_CHECKSIGVERIFY, OP_0, OP_0, OP_CHECKSIGVERIFY, OP_1]),
                # 21) Script that grows the stack to 1000 elements
                CScript([pubkey, OP_CHECKSIGVERIFY, OP_1] + [OP_DUP] * 999 + [OP_DROP] * 999),
                # 22) Script that grows the stack to 1001 elements
                CScript([pubkey, OP_CHECKSIGVERIFY, OP_1] + [OP_DUP] * 1000 + [OP_DROP] * 1000),
                # 23) Script that expects an input stack of 1000 elements
                CScript([OP_DROP] * 999 + [pubkey, OP_CHECKSIG]),
                # 24) Script that expects an input stack of 1001 elements
                CScript([OP_DROP] * 1000 + [pubkey, OP_CHECKSIG]),
                # 25) Script that pushes a 520 byte element
                CScript([random_bytes(520), OP_DROP, pubkey, OP_CHECKSIG]),
                # 26) Script that pushes a 521 byte element
                CScript([random_bytes(521), OP_DROP, pubkey, OP_CHECKSIG]),
            ]
            # For the next test we must predict the exact witness size
            witness_size = 141 + (hashtype != 0) + (0 if annex is None else len(annex) + 1)
            checks = (witness_size + 50) // 48
            scripts2 = [
                # 0) Script with variable number of duplicated signature checks
                CScript([pubkey, OP_SWAP, OP_1SUB, OP_IF, OP_2DUP, OP_CHECKSIGVERIFY, OP_ENDIF] + [OP_2DUP, OP_CHECKSIGVERIFY] * (checks - 1) + [OP_CHECKSIG])
            ]
            info = taproot_construct(pub1, scripts)
            info2 = taproot_construct(pub1, scripts2)
            # Test that 520 byte stack element inputs are valid, but 521 byte ones are not.
            spender_two_paths(spenders, info, "tapscript/input520limit", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(520)]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(521)]})
            # Test that 80 byte stack element inputs are valid and standard; 81 bytes ones are valid and nonstandard
            spender_two_paths(spenders, info, "tapscript/input80limit", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(80)]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(521)]})
            spender_two_paths(spenders, info, "tapscript/input81limit", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(81)]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(521)]})
            # Test that OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY cause failure, but OP_CHECKSIG and OP_CHECKSIGVERIFY work.
            spender_two_paths(spenders, info, "tapscript/disabled/checkmultisig", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[1]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[3]})
            spender_two_paths(spenders, info, "tapscript/disabled/checkmultisigverify", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[2]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[4]})
            # Test that OP_IF and OP_NOTIF do not accept 0x02 as truth value (the MINIMALIF rule is consensus in Tapscript)
            spender_two_paths(spenders, info, "tapscript/minimalif", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[5], "suffix": [bytes([1])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[5], "suffix": [bytes([2])]})
            spender_two_paths(spenders, info, "tapscript/minimalnotif", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[6], "suffix": [bytes([1])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[6], "suffix": [bytes([3])]})
            # Test that 1-byte public keys (which are unknown) are acceptable but nonstandard with unrelated signatures, but 0-byte public keys are not valid.
            spender_two_paths(spenders, info, "tapscript/unkpk/checksig", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[16]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[7]})
            spender_two_paths(spenders, info, "tapscript/unkpk/checksigadd", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[17]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[10]})
            spender_two_paths(spenders, info, "tapscript/unkpk/checksigverify", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[18]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[8]})
            # Test that 0-byte public keys are not acceptable.
            spender_two_paths(spenders, info, "tapscript/emptypk/checksig", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[1]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[7]})
            spender_two_paths(spenders, info, "tapscript/emptypk/checksigverify", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[2]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[8]})
            spender_two_paths(spenders, info, "tapscript/emptypk/checksigadd", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[9]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[10]})
            # Test that OP_CHECKSIGADD requires 3 stack elements.
            spender_two_paths(spenders, info, "tapscript/checksigadd3args", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[9]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[11]})
            # Test that empty signatures do not cause script failure in OP_CHECKSIG and OP_CHECKSIGADD (but do fail with empty pubkey, and do fail OP_CHECKSIGVERIFY)
            spender_two_paths(spenders, info, "tapscript/emptysigs/checksig", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[12], "prefix": [bytes([])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[13], "prefix": [bytes([])]})
            spender_two_paths(spenders, info, "tapscript/emptysigs/nochecksigverify", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[12], "prefix": [bytes([])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[20], "prefix": [bytes([])]})
            spender_two_paths(spenders, info, "tapscript/emptysigs/checksigadd", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[14], "prefix": [bytes([])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[15], "prefix": [bytes([])]})
            # Test that scripts over 10000 bytes (and over 201 non-push ops) are acceptable.
            spender_two_paths(spenders, info, "tapscript/no10000limit", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[19]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[7]})
            # Test that the (witsize+50 >= 50*(1+sigchecks)) rule is enforced (but only for executed checksigs)
            spender_two_paths(spenders, info2, "tapscript/sigopratio", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts2[0], "suffix": [bytes([1])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts2[0], "suffix": [bytes([2])]})
            # Test that a stack size of 1000 elements is permitted, but 1001 isn't.
            spender_two_paths(spenders, info, "tapscript/1000stack", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[21]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[22]})
            # Test that an input stack size of 1000 elements is permitted, but 1001 isn't.
            spender_two_paths(spenders, info, "tapscript/1000stack", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[23], "suffix": [bytes() for _ in range(999)]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[24], "suffix": [bytes() for _ in range(1000)]})
            # Test that pushing a 520 byte stack element is valid, but a 521 byte one is not.
            spender_two_paths(spenders, info, "tapscript/push520limit", standard=standard, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[25]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[26]})

            # OP_SUCCESSx and unknown tapscript versions
            scripts = [
                CScript([random_op_success()]),
                CScript([OP_0, OP_IF, random_op_success(), OP_RETURN]),
                CScript([random_op_success(), OP_VERIF]),
                (random_unknown_tapscript_ver(), CScript([OP_RETURN])),
                (ANNEX_TAG & 0xfe, CScript()),
            ]
            info = taproot_construct(pub1, scripts)
            spender_sighash_mutation(spenders, info, "alwaysvalid/pk", key=sec1, hashtype=random.choice(VALID_SIGHASHES), annex=annex, standard=standard)
            spender_alwaysvalid(spenders, info, "alwaysvalid/success", script=scripts[0], annex=annex)
            spender_alwaysvalid(spenders, info, "alwaysvalid/success#if", script=scripts[1], annex=annex)
            spender_alwaysvalid(spenders, info, "alwaysvalid/success#verif", script=scripts[2], annex=annex)
            spender_alwaysvalid(spenders, info, "alwaysvalid/unknownversion#return", script=scripts[3], annex=annex)
            if (info[2][scripts[4][1]][0] != ANNEX_TAG):
                # Annex is mandatory for control block with leaf version 0x50
                spender_alwaysvalid(spenders, info, "alwaysvalid/unknownversion#fe", script=scripts[4], annex=annex)

        return spenders

    def run_test(self):
        # Run all tests once with individual inputs
        spenders = self.build_spenders()
        self.test_spenders(spenders, input_counts=[1])

        # Run 10 instances of all tests in groups of 2, 3, and 4 inputs.
        spenders = []
        for i in range(10):
            spenders += self.build_spenders()
        self.test_spenders(spenders, input_counts=[2,3,4])


if __name__ == '__main__':
    TAPROOTTest().main()
