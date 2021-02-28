#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test generation and spending of P2TR addresses."""

import random

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.descriptors import descsum_create
from test_framework.script import (CScript, OP_CHECKSIG, taproot_construct)
from test_framework.segwit_addr import encode_segwit_address

# xprvs/xpubs, and m/* derived x-only pubkeys (created using independent implementation)
KEYS = [
    {
        "xprv": "tprv8ZgxMBicQKsPeNLUGrbv3b7qhUk1LQJZAGMuk9gVuKh9sd4BWGp1eMsehUni6qGb8bjkdwBxCbgNGdh2bYGACK5C5dRTaif9KBKGVnSezxV",
        "xpub": "tpubD6NzVbkrYhZ4XqNGAWGWSzmxGWFwVjVTjZxh2fioKbVYi7Jx8fdbprVWsdW7mHwqjchBVas8TLZG4Xwuz4RKU4iaCqiCvoSkFCzQptqk5Y1",
        "pubs": [
            "83d8ee77a0f3a32a5cea96fd1624d623b836c1e5d1ac2dcde46814b619320c18",
            "a30253b018ea6fca966135bf7dd8026915427f24ccf10d4e03f7870f4128569b",
            "a61e5749f2f3db9dc871d7b187e30bfd3297eea2557e9be99897ea8ff7a29a21",
            "8110cf482f66dc37125e619d73075af932521724ffc7108309e88f361efe8c8a",
        ]
    },
    {
        "xprv": "tprv8ZgxMBicQKsPe98QUPieXy5KFPVjuZNpcC9JY7K7buJEm8nWvJogK4kTda7eLjK9U4PnMNbSjEkpjDJazeBZ4rhYNYD7N6GEdaysj1AYSb5",
        "xpub": "tpubD6NzVbkrYhZ4XcACN3PEwNjRpR1g4tZjBVk5pdMR2B6dbd3HYhdGVZNKofAiFZd9okBserZvv58A6tBX4pE64UpXGNTSesfUW7PpW36HuKz",
        "pubs": [
            "f95886b02a84928c5c15bdca32784993105f73de27fa6ad8c1a60389b999267c",
            "71522134160685eb779857033bfc84c7626f13556154653a51dd42619064e679",
            "48957b4158b2c5c3f4c000f51fd2cf0fd5ff8868ebfb194256f5e9131fc74bd8",
            "086dda8139b3a84944010648d2b674b70447be3ae59322c09a4907bc80be62c1",
        ]
    },
    {
        "xprv": "tprv8ZgxMBicQKsPe3ZJmcj9aJ2EPZJYYCh6Lp3v82p75wspgaXmtDZ2RBtkAtWcGnW2VQDzMHQPBkCKMoYTqh1RfJKjv4PcmWVR7KqTpjsdboN",
        "xpub": "tpubD6NzVbkrYhZ4XWb6fGPjyhgLxapUhXszv7ehQYrQWDgDX4nYWcNcbgWcM2RhYo9s2mbZcfZJ8t5LzYcr24FK79zVybsw5Qj3Rtqug8jpJMy",
        "pubs": [
            "9fa5ffb68821cf559001caa0577eeea4978b29416def328a707b15e91701a2f7",
            "8a104c54cd34acba60c97dd8f1f7abc89ba9587afd88dc928e91aca7b1c50d20",
            "13ba6b252a4eb5ef31d39cb521724cdab19a698323f5c17093f28fb1821d052f",
            "f6c2b4863fd5ba1ba09e3a890caed8b75ffbe013ebab31a06ab87cd6f72506af",
        ]
    },
    {
        "xprv": "tprv8ZgxMBicQKsPdKziibn63Rm6aNzp7dSjDnufZMStXr71Huz7iihCRpbZZZ6Voy5HyuHCWx6foHMipzMzUq4tZrtkZ24DJwz5EeNWdsuwX5h",
        "xpub": "tpubD6NzVbkrYhZ4Wo2WcFSgSqRD9QWkGxddo6WSqsVBx7uQ8QEtM7WncKDRjhFEexK119NigyCsFygA4b7sAPQxqebyFGAZ9XVV1BtcgNzbCRR",
        "pubs": [
            "03a669ea926f381582ec4a000b9472ba8a17347f5fb159eddd4a07036a6718eb",
            "bbf56b14b119bccafb686adec2e3d2a6b51b1626213590c3afa815d1fd36f85d",
            "2994519e31bbc238a07d82f85c9832b831705d2ee4a2dbb477ecec8a3f570fe5",
            "68991b5c139a4c479f8c89d6254d288c533aefc0c5b91fac6c89019c4de64988",
        ]
    },
    {
        "xprv": "tprv8ZgxMBicQKsPen4PGtDwURYnCtVMDejyE8vVwMGhQWfVqB2FBPdekhTacDW4vmsKTsgC1wsncVqXiZdX2YFGAnKoLXYf42M78fQJFzuDYFN",
        "xpub": "tpubD6NzVbkrYhZ4YF6BAXtXsqCtmv1HNyvsoSXHDsJzpnTtffH1onTEwC5SnLzCHPKPebh2i7Gxvi9kJNADcpuSmH8oM3rCYcHVtdXHjpYoKnX",
        "pubs": [
            "aba457d16a8d59151c387f24d1eb887efbe24644c1ee64b261282e7baebdb247",
            "c8558b7caf198e892032d91f1a48ee9bdc25462b83b4d0ac62bb7fb2a0df630e",
            "8a4bcaba0e970685858d133a4d0079c8b55bbc755599e212285691eb779ce3dc",
            "b0d68ada13e0d954b3921b88160d4453e9c151131c2b7c724e08f538a666ceb3",
        ]
    },
    {
        "xprv": "tprv8ZgxMBicQKsPd91vCgRmbzA13wyip2RimYeVEkAyZvsEN5pUSB3T43SEBxPsytkxb42d64W2EiRE9CewpJQkzR8HKHLV8Uhk4dMF5yRPaTv",
        "xpub": "tpubD6NzVbkrYhZ4Wc3i6L6N1Pp7cyVeyMcdLrFGXGDGzCfdCa5F4Zs3EY46N72Ws8QDEUYBVwXfDfda2UKSseSdU1fsBegJBhGCZyxkf28bkQ6",
        "pubs": [
            "9b4d495b74887815a1ff623c055c6eac6b6b2e07d2a016d6526ebac71dd99744",
            "8e971b781b7ce7ab742d80278f2dfe7dd330f3efd6d00047f4a2071f2e7553cb",
            "b811d66739b9f07435ccda907ec5cd225355321c35e0a7c7791232f24cf10632",
            "4cd27a5552c272bc80ba544e9cc6340bb906969f5e7a1510b6cef9592683fbc9",
        ]
    },
    {
        "xprv": "tprv8ZgxMBicQKsPdEhLRxxwzTv2t18j7ruoffPeqAwVA2qXJ2P66RaMZLUWQ85SjoA7xPxdSgCB9UZ72m65qbnaLPtFTfHVP3MEmkpZk1Bv8RT",
        "xpub": "tpubD6NzVbkrYhZ4Whj8KcdYPsa9T2efHC6iExzS7gynaJdv8WdripPwjq6NaH5gQJGrLmvUwHY1smhiakUosXNDTEa6qfKUQdLKV6DJBre6XvQ",
        "pubs": [
            "d0c19def28bb1b39451c1a814737615983967780d223b79969ba692182c6006b",
            "cb1d1b1dc62fec1894d4c3d9a1b6738e5ff9c273a64f74e9ab363095f45e9c47",
            "245be588f41acfaeb9481aa132717db56ee1e23eb289729fe2b8bde8f9a00830",
            "5bc4ad6d6187fa82728c85a073b428483295288f8aef5722e47305b5872f7169",
        ]
    },
    {
        "xprv": "tprv8ZgxMBicQKsPcxbqxzcMAwQpiCD8x6qaZEJTxdKxw4w9GuMzDACTD9yhEsHGfqQcfYX4LivosLDDngTykYEp9JnTdcqY7cHqU8PpeFFKyV3",
        "xpub": "tpubD6NzVbkrYhZ4WRddreGwaM4wHDj57S2V8XuFF9NGMLjY7PckqZ23PebZR1wGA4w84uX2vZphdZVsnREjij1ibYjEBTaTVQCEZCLs4xUDapx",
        "pubs": [
            "065cc1b92bd99e5a3e626e8296a366b2d132688eb43aea19bc14fd8f43bf07fb",
            "5b95633a7dda34578b6985e6bfd85d83ec38b7ded892a9b74a3d899c85890562",
            "dc86d434b9a34495c8e845b969d51f80d19a8df03b400353ffe8036a0c22eb60",
            "06c8ffde238745b29ae8a97ae533e1f3edf214bba6ec58b5e7b9451d1d61ec19",
        ]
    },
    {
        "xprv": "tprv8ZgxMBicQKsPe6zLoU8MTTXgsdJVNBErrYGpoGwHf5VGvwUzdNc7NHeCSzkJkniCxBhZWujXjmD4HZmBBrnr3URgJjM6GxRgMmEhLdqNTWG",
        "xpub": "tpubD6NzVbkrYhZ4Xa28h7nwrsBoSepRXWRmRqsc5nyb5MHfmRjmFmRhYnG4d9dC7uxixN5AfsEv1Lz3mCAuWvERyvPgKozHUVjfo8EG6foJGy7",
        "pubs": [
            "d826a0a53abb6ffc60df25b9c152870578faef4b2eb5a09bdd672bbe32cdd79b",
            "939365e0359ff6bc6f6404ee220714c5d4a0d1e36838b9e2081ede217674e2ba",
            "4e8767edcf7d3d90258cfbbea01b784f4d2de813c4277b51279cf808bac410a2",
            "d42a2c280940bfc6ede971ae72cde2e1df96c6da7dab06a132900c6751ade208",
        ]
    }
]

CHANGE_XPRV = "tprv8ZgxMBicQKsPcyDrWwiecVnTtFmfRwbfFqEfR4ZGWvq5aTTwLBWmAm5zrbMcYtb9gQNFfhRfqhhrBG37U3nhmXxEgeEPBJGHAPrHCrAd1WX"
CHANGE_XPUB = "tpubD6NzVbkrYhZ4WSFeQbPF1uSaTHHbbGnZq8qShabZwCdUQwihxaLMMFhs2kidGF2qrRKiQVqw8VoyuTHj1bZqmMXMeciaU1gBjWA1sim2zUB"

# Point with no known discrete log.
H_POINT = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"


def key(hex_key):
    """Construct an x-only pubkey from its hex representation."""
    return bytes.fromhex(hex_key)

def pk(hex_key):
    """Construct a script expression for taproot_construct for pk(hex_key)."""
    return (None, CScript([bytes.fromhex(hex_key), OP_CHECKSIG]))

def compute_taproot_address(pubkey, scripts):
    """Compute the address for a taproot output with given inner key and scripts."""
    tap = taproot_construct(pubkey, scripts)
    assert tap.scriptPubKey[0] == 0x51
    assert tap.scriptPubKey[1] == 0x20
    return encode_segwit_address("bcrt", 1, tap.scriptPubKey[2:])

class WalletTaprootTest(BitcoinTestFramework):
    """Test generation and spending of P2TR address outputs."""

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def setup_network(self):
        self.setup_nodes()

    def init_wallet(self, i):
        pass

    @staticmethod
    def rand_keys(n):
        ret = []
        idxes = set()
        for _ in range(n):
            while True:
                i = random.randrange(len(KEYS))
                if not i in idxes:
                    break
            idxes.add(i)
            ret.append(KEYS[i])
        return ret

    @staticmethod
    def make_desc(pattern, privmap, keys, pub_only = False):
        args = []
        pat = pattern.replace("$H", H_POINT)
        for i in range(len(privmap)):
            if privmap[i] and not pub_only:
                args.append(keys[i]['xprv'])
            else:
                args.append(keys[i]['xpub'])
        return descsum_create(pat % tuple(args))

    @staticmethod
    def make_addr(treefn, keys, i):
        args = []
        for j in range(len(keys)):
            args.append(keys[j]['pubs'][i])
        return compute_taproot_address(*treefn(*args))

    def do_test(self, comment, pattern, privmap, treefn, nkeys):
        self.log.info("Testing %s" % comment)
        keys = self.rand_keys(nkeys * 2)
        keys_pay = keys[:nkeys]
        keys_change = keys[nkeys:]
        desc_pay = self.make_desc(pattern, privmap, keys_pay)
        desc_change = self.make_desc(pattern, privmap, keys_change)
        result = self.rpc_online.importdescriptors([{"desc": desc_pay, "active": True, "timestamp": "now"}])
        assert(result[0]['success'])
        result = self.rpc_online.importdescriptors([{"desc": desc_change, "active": True, "timestamp": "now", "internal": True}])
        assert(result[0]['success'])
        for i in range(4):
            addr_g = self.rpc_online.getnewaddress(address_type='bech32')
            addr_r = self.make_addr(treefn, keys_pay, i)
            assert_equal(addr_g, addr_r)
            boring_balance = int(self.boring.getbalance() * 100000000)
            to_amnt = random.randrange(1000000, boring_balance)
            self.boring.sendtoaddress(address=addr_g, amount=Decimal(to_amnt) / 100000000, subtractfeefromamount=True)
            self.nodes[0].generatetoaddress(1, self.boring.getnewaddress())
            tap_balance = int(self.rpc_online.getbalance() * 100000000)
            ret_amnt = random.randrange(100000, tap_balance)
            res = self.rpc_online.sendtoaddress(address=self.boring.getnewaddress(), amount=Decimal(ret_amnt) / 100000000, subtractfeefromamount=True)
            self.rpc_online.gettransaction(res)

    def run_test(self):
        self.log.info("Creating wallets...")
        self.nodes[0].createwallet(wallet_name="boring")
        self.nodes[0].createwallet(wallet_name="rpc_online", descriptors=True)
        self.boring = self.nodes[0].get_wallet_rpc("boring")
        self.rpc_online = self.nodes[0].get_wallet_rpc("rpc_online")

        self.log.info("Mining blocks...")
        gen_addr = self.boring.getnewaddress()
        self.nodes[0].generatetoaddress(101, gen_addr)

        self.do_test(
            "tr(XPRV)",
            "tr(%s/*)",
            [True],
            lambda k1: (key(k1), []),
            1
        )
        self.do_test(
            "tr(H,0:XPRV)",
            "tr($H,0:pk(%s/*))",
            [True],
            lambda k1: (key(H_POINT), [pk(k1)]),
            1
        )
        self.do_test(
            "tr(XPRV,1:H,2:H,2:XPUB)",
            "tr(%s/*,1:pk($H),2:pk($H),2:pk(%s/*))",
            [True, False],
            lambda k1, k2: (key(k1), [pk(H_POINT), [pk(H_POINT), pk(k2)]]),
            2
        )
        self.do_test(
            "tr(XPUB,2:H,3:H,3:XPUB,2:H,3:H,4:H,4:XPRV)",
            "tr(%s/*,2:pk($H),3:pk($H),3:pk(%s/*),2:pk($H),3:pk($H),4:pk($H),4:pk(%s/*))",
            [False, False, True],
            lambda k1, k2, k3: (key(k1), [[pk(H_POINT), [pk(H_POINT), pk(k2)]], [pk(H_POINT), [pk(H_POINT), [pk(H_POINT), pk(k3)]]]]),
            3
        )

        self.log.info("Sending everything back...")
        res = self.rpc_online.sendtoaddress(address=self.boring.getnewaddress(), amount=self.rpc_online.getbalance(), subtractfeefromamount=True)
        self.rpc_online.gettransaction(res)

if __name__ == '__main__':
    WalletTaprootTest().main()
