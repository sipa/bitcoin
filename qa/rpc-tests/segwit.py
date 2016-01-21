#!/usr/bin/env python2
# Copyright (c) 2014 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test the SegWit changeover logic
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import os
import shutil
import hashlib
from binascii import hexlify

NODE_0 = 0
NODE_1 = 1
NODE_2 = 2
WIT_V0 = 0
WIT_V1 = 1

def sha256(s):
    return hashlib.new('sha256', s).digest()

def ripemd160(s):
    return hashlib.new('ripemd160', s).digest()

def witness_script(version, pubkey):
    if (version == 0):
        pubkeyhash = hexlify(ripemd160(sha256(pubkey.decode("hex"))))
        pkscript = "001976a914" + pubkeyhash + "88ac"
    elif (version == 1):
        witnessprogram = "21"+pubkey+"ac"
        hashwitnessprogram = hexlify(sha256(witnessprogram.decode("hex")))
        pkscript = "5120" + hashwitnessprogram
    else:
        assert("Wrong version" == "0 or 1")
    return pkscript

def addlength(script):
    scriptlen = format(len(script)/2, 'x')
    assert(len(scriptlen) == 2)
    return scriptlen + script

def create_witnessprogram(version, node, utxo, pubkey, encode_p2sh, amount):
    pkscript = witness_script(version, pubkey);
    if (encode_p2sh):
        p2sh_hash = hexlify(ripemd160(sha256(pkscript.decode("hex"))))
        pkscript = "a914"+p2sh_hash+"87"
    inputs = []
    outputs = {}
    inputs.append({ "txid" : utxo["txid"], "vout" : utxo["vout"]} )
    DUMMY_P2SH = "2MySexEGVzZpRgNQ1JdjdP5bRETznm3roQ2" # P2SH of "OP_1 OP_DROP"
    outputs[DUMMY_P2SH] = amount
    tx_to_witness = node.createrawtransaction(inputs,outputs)
    #replace dummy output with our own
    tx_to_witness = tx_to_witness[0:110] + addlength(pkscript) + tx_to_witness[-8:]
    return tx_to_witness

def send_to_witness(version, node, utxo, pubkey, encode_p2sh, amount, sign=True, insert_redeem_script=""):
    tx_to_witness = create_witnessprogram(version, node, utxo, pubkey, encode_p2sh, amount)
    if (sign):
        signed = node.signrawtransaction(tx_to_witness)
        return node.sendrawtransaction(signed["hex"])
    else:
        if (insert_redeem_script):
            tx_to_witness = tx_to_witness[0:82] + addlength(insert_redeem_script) + tx_to_witness[84:]

    return node.sendrawtransaction(tx_to_witness)

def getutxo(txid):
    utxo = {}
    utxo["vout"] = 0
    utxo["txid"] = txid
    return utxo

class SegWitTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 3)

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-logtimemicros", "-debug"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-logtimemicros", "-debug", "-blockversion=4", "-promiscuousmempoolflags=517", "-prematurewitness"]))
        self.nodes.append(start_node(2, self.options.tmpdir, ["-logtimemicros", "-debug", "-blockversion=5", "-promiscuousmempoolflags=517", "-prematurewitness"]))
        connect_nodes(self.nodes[1], 0)
        connect_nodes(self.nodes[2], 1)
        connect_nodes(self.nodes[0], 2)
        self.is_network_split = False
        self.sync_all()

    def success_mine(self, node, txid, sign, redeem_script=""):
        send_to_witness(1, node, getutxo(txid), self.pubkey[0], False, Decimal("49.998"), sign, redeem_script)
        block = node.generate(1)
        assert_equal(len(node.getblock(block[0])["tx"]), 2)
        sync_blocks(self.nodes)

    def skip_mine(self, node, txid, sign, redeem_script=""):
        send_to_witness(1, node, getutxo(txid), self.pubkey[0], False, Decimal("49.998"), sign, redeem_script)
        block = node.generate(1)
        assert_equal(len(node.getblock(block[0])["tx"]), 1)
        sync_blocks(self.nodes)

    def fail_accept(self, node, txid, sign, redeem_script=""):
        try:
            send_to_witness(1, node, getutxo(txid), self.pubkey[0], False, Decimal("49.998"), sign, redeem_script)
        except JSONRPCException as exp:
            assert(exp.error["code"] == -26)
        else:
            raise AssertionError("Tx should not have been accepted")

    def fail_mine(self, node, txid, sign, redeem_script=""):
        send_to_witness(1, node, getutxo(txid), self.pubkey[0], False, Decimal("49.998"), sign, redeem_script)
        try:
            node.generate(1)
        except JSONRPCException as exp:
            assert(exp.error["code"] == -1)
        else:
            raise AssertionError("Created valid block when TestBlockValidity should have failed")
        sync_blocks(self.nodes)

    def run_test(self):
        self.nodes[0].generate(160) #block 160

        self.pubkey = []
        p2sh_ids = [] # p2sh_ids[NODE][VER] is an array of txids that spend to a witness version VER pkscript to an address for NODE embedded in p2sh
        wit_ids = [] # wit_ids[NODE][VER] is an array of txids that spend to a witness version VER pkscript to an address for NODE via bare witness
        for i in xrange(3):
            newaddress = self.nodes[i].getnewaddress()
            self.nodes[i].addwitnessaddress(newaddress)
            self.pubkey.append(self.nodes[i].validateaddress(newaddress)["pubkey"])
            p2sh_ids.append([])
            wit_ids.append([])
            for v in xrange(2):
                p2sh_ids[i].append([])
                wit_ids[i].append([])

        for i in xrange(5):
            for n in xrange(3):
                for v in xrange(2):
                    wit_ids[n][v].append(send_to_witness(v, self.nodes[0], self.nodes[0].listunspent()[0], self.pubkey[n], False, Decimal("49.999")))
                    p2sh_ids[n][v].append(send_to_witness(v, self.nodes[0], self.nodes[0].listunspent()[0], self.pubkey[n], True, Decimal("49.999")))

        self.nodes[0].generate(1) #block 161
        sync_blocks(self.nodes)

        # Make sure all nodes recognize the transactions as theirs
        assert_equal(self.nodes[0].getbalance(), 60*50 - 60*50 + 20*Decimal("49.999") + 50)
        assert_equal(self.nodes[1].getbalance(), 20*Decimal("49.999"))
        assert_equal(self.nodes[2].getbalance(), 20*Decimal("49.999"))

        self.nodes[0].generate(581) #block 742
        sync_blocks(self.nodes)

        print "Verify default node can't accept any witness format txs before fork"
        # unsigned, no scriptsig
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V0][0], False)
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V1][0], False)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], False)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], False)
        # unsigned with redeem script
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], False, addlength(witness_script(0, self.pubkey[0])))
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], False, addlength(witness_script(1, self.pubkey[0])))
        # signed
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V0][0], True)
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V1][0], True)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], True)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], True)

        print "Verify witness txs are skipped for mining before the fork"
        self.skip_mine(self.nodes[2], wit_ids[NODE_2][WIT_V0][0], True) #block 743
        self.skip_mine(self.nodes[2], wit_ids[NODE_2][WIT_V1][0], True) #block 744
        self.skip_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V0][0], True) #block 745
        self.skip_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V1][0], True) #block 746

        # TODO: An old node would see these txs without witnesses and be able to mine them

        print "Verify unsigned bare witness txs in version 5 blocks are valid before the fork"
        self.success_mine(self.nodes[2], wit_ids[NODE_2][WIT_V0][1], False) #block 747
        self.success_mine(self.nodes[2], wit_ids[NODE_2][WIT_V1][1], False) #block 748

        print "Verify unsigned p2sh witness txs without a redeem script are invalid"
        self.fail_accept(self.nodes[2], p2sh_ids[NODE_2][WIT_V0][1], False)
        self.fail_accept(self.nodes[2], p2sh_ids[NODE_2][WIT_V1][1], False)

        print "Verify unsigned p2sh witness txs with a redeem script in version 5 blocks are valid before the fork"
        self.success_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V0][1], False, addlength(witness_script(0, self.pubkey[2]))) #block 749
        self.success_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V1][1], False, addlength(witness_script(1, self.pubkey[2]))) #block 750

        print "Verify previous witness txs skipped for mining can now be mined"
        assert_equal(len(self.nodes[2].getrawmempool()), 4)
        block = self.nodes[2].generate(1) #block 751
        sync_blocks(self.nodes)
        assert_equal(len(self.nodes[2].getrawmempool()), 0)
        assert_equal(len(self.nodes[2].getblock(block[0])["tx"]), 5)

        print "Verify witness txs without witness data in version 5 blocks are invalid after the fork"
        self.fail_mine(self.nodes[2], wit_ids[NODE_2][WIT_V0][2], False)
        self.fail_mine(self.nodes[2], wit_ids[NODE_2][WIT_V1][2], False)
        self.fail_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V0][2], False, addlength(witness_script(0, self.pubkey[2])))
        self.fail_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V1][2], False, addlength(witness_script(1, self.pubkey[2])))


        print "Verify that a version 4 block can still mine those unsigned txs"
        assert_equal(len(self.nodes[2].getrawmempool()), 4)
        sync_mempools(self.nodes[1:3])
        block = self.nodes[1].generate(1) #block 752
        sync_blocks(self.nodes)
        assert_equal(len(self.nodes[2].getrawmempool()), 0)
        assert_equal(len(self.nodes[1].getblock(block[0])["tx"]), 5)

        print "Verify all types of witness txs can be submitted signed after the fork to node with -prematurewitness"
        self.success_mine(self.nodes[2], wit_ids[NODE_2][WIT_V0][3], True) #block 753
        self.success_mine(self.nodes[2], wit_ids[NODE_2][WIT_V1][3], True) #block 754
        self.success_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V0][3], True) #block 755
        self.success_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V1][3], True) #block 756

        print "Verify default node can't accept any witness format txs between enforce and reject points of fork"
        # unsigned, no scriptsig
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V0][0], False)
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V1][0], False)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], False)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], False)
        # unsigned with redeem script
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], False, addlength(witness_script(0, self.pubkey[0])))
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], False, addlength(witness_script(1, self.pubkey[0])))
        # signed
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V0][0], True)
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V1][0], True)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], True)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], True)

        # TODO: verify witness txs are invalid if in a v4 block
        print "Verify witness txs aren't mined in a v4 block"
        self.skip_mine(self.nodes[1], wit_ids[NODE_1][WIT_V0][0], True) #block 757
        self.skip_mine(self.nodes[1], wit_ids[NODE_1][WIT_V1][0], True) #block 758
        self.skip_mine(self.nodes[1], p2sh_ids[NODE_1][WIT_V0][0], True) #block 759
        self.skip_mine(self.nodes[1], p2sh_ids[NODE_1][WIT_V1][0], True) #block 760

        # Mine them from ver 5 node
        sync_mempools(self.nodes[1:3])
        assert_equal(len(self.nodes[2].getrawmempool()), 4)
        block = self.nodes[2].generate(1) #block 761
        sync_blocks(self.nodes)
        assert_equal(len(self.nodes[2].getrawmempool()), 0)
        assert_equal(len(self.nodes[2].getblock(block[0])["tx"]), 5)

        self.nodes[0].generate(195) #block 956 (5 of which are v4 blocks)
        sync_blocks(self.nodes)

        print "Verify that version 4 blocks are invalid period after reject point"
        try:
            self.nodes[1].generate(1)
        except JSONRPCException as exp:
            assert(exp.error["code"] == -1)
        else:
            raise AssertionError("Created valid block when TestBlockValidity should have failed")

        print "Verify default node can now use witness txs"
        self.success_mine(self.nodes[0], wit_ids[NODE_0][WIT_V0][0], True) #block 957
        self.success_mine(self.nodes[0], wit_ids[NODE_0][WIT_V1][0], True) #block 958
        self.success_mine(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], True) #block 959
        self.success_mine(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], True) #block 960

if __name__ == '__main__':
    SegWitTest().main()
