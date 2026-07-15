// Copyright (c) 2013-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <clientversion.h>
#include <crypto/siphash.h>
#include <hash.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <variant>

using namespace util::hex_literals;

BOOST_FIXTURE_TEST_SUITE(hash_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(murmurhash3)
{

#define T(expected, seed, data) BOOST_CHECK_EQUAL(MurmurHash3(seed, ParseHex(data)), expected)

    // Test MurmurHash3 with various inputs. Of course this is retested in the
    // bloom filter tests - they would fail if MurmurHash3() had any problems -
    // but is useful for those trying to implement Bitcoin libraries as a
    // source of test data for their MurmurHash3() primitive during
    // development.
    //
    // The magic number 0xFBA4C795 comes from CBloomFilter::Hash()

    T(0x00000000U, 0x00000000, "");
    T(0x6a396f08U, 0xFBA4C795, "");
    T(0x81f16f39U, 0xffffffff, "");

    T(0x514e28b7U, 0x00000000, "00");
    T(0xea3f0b17U, 0xFBA4C795, "00");
    T(0xfd6cf10dU, 0x00000000, "ff");

    T(0x16c6b7abU, 0x00000000, "0011");
    T(0x8eb51c3dU, 0x00000000, "001122");
    T(0xb4471bf8U, 0x00000000, "00112233");
    T(0xe2301fa8U, 0x00000000, "0011223344");
    T(0xfc2e4a15U, 0x00000000, "001122334455");
    T(0xb074502cU, 0x00000000, "00112233445566");
    T(0x8034d2a0U, 0x00000000, "0011223344556677");
    T(0xb4698defU, 0x00000000, "001122334455667788");

#undef T
}

/*
   SipHash-2-4 output with
   k = 00 01 02 ...
   and
   in = (empty string)
   in = 00 (1 byte)
   in = 00 01 (2 bytes)
   in = 00 01 02 (3 bytes)
   ...
   in = 00 01 02 ... 3e (63 bytes)

   from: https://131002.net/siphash/siphash24.c
*/
uint64_t siphash_4_2_testvec[] = {
    0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a, 0x85676696d7fb7e2d,
    0xcf2794e0277187b7, 0x18765564cd99a68d, 0xcbc9466e58fee3ce, 0xab0200f58b01d137,
    0x93f5f5799a932462, 0x9e0082df0ba9e4b0, 0x7a5dbbc594ddb9f3, 0xf4b32f46226bada7,
    0x751e8fbc860ee5fb, 0x14ea5627c0843d90, 0xf723ca908e7af2ee, 0xa129ca6149be45e5,
    0x3f2acc7f57c29bdb, 0x699ae9f52cbe4794, 0x4bc1b3f0968dd39c, 0xbb6dc91da77961bd,
    0xbed65cf21aa2ee98, 0xd0f2cbb02e3b67c7, 0x93536795e3a33e88, 0xa80c038ccd5ccec8,
    0xb8ad50c6f649af94, 0xbce192de8a85b8ea, 0x17d835b85bbb15f3, 0x2f2e6163076bcfad,
    0xde4daaaca71dc9a5, 0xa6a2506687956571, 0xad87a3535c49ef28, 0x32d892fad841c342,
    0x7127512f72f27cce, 0xa7f32346f95978e3, 0x12e0b01abb051238, 0x15e034d40fa197ae,
    0x314dffbe0815a3b4, 0x027990f029623981, 0xcadcd4e59ef40c4d, 0x9abfd8766a33735c,
    0x0e3ea96b5304a7d0, 0xad0c42d6fc585992, 0x187306c89bc215a9, 0xd4a60abcf3792b95,
    0xf935451de4f21df2, 0xa9538f0419755787, 0xdb9acddff56ca510, 0xd06c98cd5c0975eb,
    0xe612a3cb9ecba951, 0xc766e62cfcadaf96, 0xee64435a9752fe72, 0xa192d576b245165a,
    0x0a8787bf8ecb74b2, 0x81b3e73d20b49b6f, 0x7fa8220ba3b2ecea, 0x245731c13ca42499,
    0xb78dbfaf3a8d83bd, 0xea1ad565322a1a0b, 0x60e61c23a3795013, 0x6606d7e446282b93,
    0x6ca4ecb15c5f91e1, 0x9f626da15c9625f3, 0xe51b38608ef25f57, 0x958a324ceb064572
};

BOOST_AUTO_TEST_CASE(siphash)
{
    CSipHasher hasher(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  0x726fdb47dd0e0e31ull);
    static const unsigned char t0[1] = {0};
    hasher.Write(t0);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  0x74f839c593dc67fdull);
    static const unsigned char t1[7] = {1,2,3,4,5,6,7};
    hasher.Write(t1);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  0x93f5f5799a932462ull);
    hasher.Write(0x0F0E0D0C0B0A0908ULL);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  0x3f2acc7f57c29bdbull);
    static const unsigned char t2[2] = {16,17};
    hasher.Write(t2);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  0x4bc1b3f0968dd39cull);
    static const unsigned char t3[9] = {18,19,20,21,22,23,24,25,26};
    hasher.Write(t3);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  0x2f2e6163076bcfadull);
    static const unsigned char t4[5] = {27,28,29,30,31};
    hasher.Write(t4);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  0x7127512f72f27cceull);
    hasher.Write(0x2726252423222120ULL);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  0x0e3ea96b5304a7d0ull);
    hasher.Write(0x2F2E2D2C2B2A2928ULL);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  0xe612a3cb9ecba951ull);

    BOOST_CHECK_EQUAL(PresaltedSipHasher(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL)(uint256{"1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"}), 0x7127512f72f27cceull);

    // Check test vectors from spec, one byte at a time
    CSipHasher hasher2(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);
    for (uint8_t x=0; x<std::size(siphash_4_2_testvec); ++x)
    {
        BOOST_CHECK_EQUAL(hasher2.Finalize(), siphash_4_2_testvec[x]);
        hasher2.Write(std::span{&x, 1});
    }
    // Check test vectors from spec, eight bytes at a time
    CSipHasher hasher3(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);
    for (uint8_t x=0; x<std::size(siphash_4_2_testvec); x+=8)
    {
        BOOST_CHECK_EQUAL(hasher3.Finalize(), siphash_4_2_testvec[x]);
        hasher3.Write(uint64_t(x)|(uint64_t(x+1)<<8)|(uint64_t(x+2)<<16)|(uint64_t(x+3)<<24)|
                     (uint64_t(x+4)<<32)|(uint64_t(x+5)<<40)|(uint64_t(x+6)<<48)|(uint64_t(x+7)<<56));
    }

    HashWriter ss{};
    CMutableTransaction tx;
    // Note these tests were originally written with tx.version=1
    // and the test would be affected by default tx version bumps if not fixed.
    tx.version = 1;
    ss << TX_WITH_WITNESS(tx);
    BOOST_CHECK_EQUAL(PresaltedSipHasher(1, 2)(ss.GetHash()), 0x79751e980c2a0a35ULL);

    // Check consistency between CSipHasher and PresaltedSipHasher.
    FastRandomContext ctx;
    for (int i = 0; i < 16; ++i) {
        uint64_t k0 = ctx.rand64();
        uint64_t k1 = ctx.rand64();
        uint256 x = m_rng.rand256();

        CSipHasher sip256(k0, k1);
        sip256.Write(x);
        BOOST_CHECK_EQUAL(PresaltedSipHasher(k0, k1)(x), sip256.Finalize());

        CSipHasher sip288 = sip256;
        uint32_t n = ctx.rand32();
        uint8_t nb[4];
        WriteLE32(nb, n);
        sip288.Write(nb);
        BOOST_CHECK_EQUAL(PresaltedSipHasher(k0, k1)(x, n), sip288.Finalize());
    }
}

BOOST_AUTO_TEST_CASE(siphasher13uj_test_vectors)
{
    /** Data type for SipHasher13UJ test vector. */
    struct TestVector {
        /** 128-bit key. */
        uint64_t k0, k1;
        /** Input blocks, normal (uint64_t) or jumbo (uint256). */
        std::vector<std::variant<uint64_t, uint256>> blocks;
        /** Expected output of SipHash-1-3-UJ. */
        uint64_t expected;
    };

    /** Test vectors for SipHash-1-3-UJ, created using an independent implementation. */
    static const TestVector TEST_VECTORS[] = {
        {0x0000000000000000, 0x0000000000000000, {}, 0x74fdd8982aa99156},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {}, 0xfeee657d7e331ac3},
        {0xffffffffffffffff, 0xffffffffffffffff, {}, 0xb2203b65f6fc20f2},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0000000000000000}}, 0x6a74cba00ddbfeba},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0xffffffffffffffff}}, 0xa49b16683645df11},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0706050403020100}}, 0x636d75a66b0b2dee},
        {0x0000000000000000, 0x0000000000000000, {uint64_t{0x0000000000000000}}, 0x44ba508bb47f860a},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("0000000000000000000000000000000000000000000000000000000000000000"_hex_u8)}, 0x6a74cba00ddbfeba},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex_u8)}, 0x7f745a471ec7c2f6},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"_hex_u8)}, 0xc67d87b08ca4b5c6},
        {0x0000000000000000, 0x0000000000000000, {uint256("0000000000000000000000000000000000000000000000000000000000000000"_hex_u8)}, 0x44ba508bb47f860a},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x1716151413121110}}, 0x17bd848a0ddd6294},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("1011121314151617000000000000000000000000000000000000000000000000"_hex_u8)}, 0x17bd848a0ddd6294},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0807060504030201}, uint64_t{0x0908070605040302}, uint64_t{0x0a09080706050403}}, 0x46b8c5978195f0d0},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("0102030405060708000000000000000000000000000000000000000000000000"_hex_u8), uint256("0203040506070809000000000000000000000000000000000000000000000000"_hex_u8), uint256("030405060708090a000000000000000000000000000000000000000000000000"_hex_u8)}, 0x46b8c5978195f0d0},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"_hex_u8)}, 0xd2c0b9ab84599147},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x4746454443424140}, uint64_t{0x4f4e4d4c4b4a4948}, uint64_t{0x5756555453525150}, uint64_t{0x5f5e5d5c5b5a5958}}, 0xd630244e335448dd},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0706050403020100}, uint64_t{0x0f0e0d0c0b0a0908}}, 0x7c25d372353b5aa1},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0706050403020100}, uint64_t{0x0f0e0d0c0b0a0908}, uint64_t{0x1716151413121110}, uint64_t{0x1f1e1d1c1b1a1918}}, 0x1aba99b7cf175f4a},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0706050403020100}, uint64_t{0x0f0e0d0c0b0a0908}, uint64_t{0x1716151413121110}, uint64_t{0x1f1e1d1c1b1a1918}, uint64_t{0x2726252423222120}, uint64_t{0x2f2e2d2c2b2a2928}, uint64_t{0x3736353433323130}, uint64_t{0x3f3e3d3c3b3a3938}}, 0xba4cdea787bdabb9},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}, uint64_t{0x0000000000000000}}, 0xb40ca9149482127a},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"_hex_u8), uint256("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"_hex_u8)}, 0x6bd1d4ec2ccd0192},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"_hex_u8), uint256("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"_hex_u8), uint256("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"_hex_u8), uint256("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"_hex_u8)}, 0x497a4c5f66a6c9ac},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"_hex_u8), uint256("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"_hex_u8), uint256("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"_hex_u8), uint256("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"_hex_u8), uint256("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"_hex_u8), uint256("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"_hex_u8), uint256("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"_hex_u8), uint256("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"_hex_u8)}, 0x33f9f36a0690842d},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x1817161514131211}, uint256("22232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041"_hex_u8)}, 0x2e989a98fc8ab941},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("22232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041"_hex_u8), uint64_t{0x1817161514131211}}, 0x6f62e14ce40a8928},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0xa7a6a5a4a3a2a1a0}, uint64_t{0xb7b6b5b4b3b2b1b0}}, 0x3d50654ce19fef0a},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0xb7b6b5b4b3b2b1b0}, uint64_t{0xa7a6a5a4a3a2a1a0}}, 0x93d52229e1bf3f12},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0807060504030201}, uint256("02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"_hex_u8), uint64_t{0x0a09080706050403}}, 0x93d4844f68473bde},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"_hex_u8), uint64_t{0x0908070605040302}, uint256("030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122"_hex_u8)}, 0x1eeb5627f80ec45e},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0101010101010101}, uint64_t{0x0202020202020202}, uint256("0303030303030303030303030303030303030303030303030303030303030303"_hex_u8), uint256("0404040404040404040404040404040404040404040404040404040404040404"_hex_u8), uint64_t{0x0505050505050505}}, 0x36c183e8c31960ca},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0706050403020100}, uint256("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"_hex_u8), uint64_t{0x2f2e2d2c2b2a2928}, uint256("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"_hex_u8), uint64_t{0x5756555453525150}, uint256("58595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677"_hex_u8)}, 0x0373fa0d4680e12a},
        {0x0000000000000000, 0x0000000000000000, {uint64_t{0x3736353433323130}, uint256("505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"_hex_u8)}, 0x0ca784307a2b3941},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x3736353433323130}, uint256("505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"_hex_u8)}, 0x40a0e330ade3b826},
        {0xffffffffffffffff, 0xffffffffffffffff, {uint64_t{0x3736353433323130}, uint256("505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"_hex_u8)}, 0x39b802d0fb124208},
        {0x0123456789abcdef, 0x0000000000000000, {uint64_t{0x3736353433323130}, uint256("505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"_hex_u8)}, 0x21bd1ab2c8db2044},
        {0x0000000000000000, 0x0123456789abcdef, {uint64_t{0x3736353433323130}, uint256("505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"_hex_u8)}, 0xbc66d61864912a68},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x0000000000000001}}, 0x7426afff81e13e5d},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint64_t{0x8000000000000000}}, 0xdbd8592fe9fd3b1b},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("0000000000000000000000000000000000000000000000000000000000000080"_hex_u8)}, 0xc946b5eafdebf91d},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("0100000000000000010000000000000001000000000000000100000000000000"_hex_u8)}, 0x28193aab7f7f53b5},
        {0x3becfe231ec833e1, 0xe5fe84a1124e5b76, {uint256("5d6fae7bea1143a44b6a307d8dd3a8d5946d1b50943a0a4edb5390d7f41c6e29"_hex_u8), uint64_t{0x8d4dbba54ee72ed2}, uint64_t{0xefb9b159b0bb3280}, uint64_t{0x603cad0d55e42aec}}, 0x8f201c9a3e7ca92a},
        {0xcff49392d5b0aefe, 0xb8a0d7022086fc70, {}, 0x25f929e44740ac55},
        {0x9bf012bb0d65f966, 0xf15a2c8514da1d9d, {}, 0xe317bf983b4cf183},
        {0x4ac23ef0d1555a54, 0x4a498a3964dd2bc1, {uint64_t{0x32d735b3e8c8833e}, uint64_t{0x8fae72789cea9a53}, uint64_t{0x81913a3d80ac146f}}, 0x3adb5b8275ff1694},
        {0xeef84fb309e552b9, 0xe60195c78faa2ee8, {}, 0x2bdc46f9f5e83bdc},
        {0xecfdd5a1ea62a991, 0x6448b8f842081342, {uint64_t{0x51f7f0e2bcf7726d}, uint64_t{0x7fafa860968477e2}}, 0x89510c79ae874736},
        {0xab7a12b9c8774c7d, 0x38056b7041eb2098, {uint64_t{0x7e2ca9185faaebfe}, uint64_t{0xa73a2ee8c9792619}}, 0xa7cb7379701c754e},
        {0x13551d7a6089e83e, 0xec3f8c0f4cbc1f7c, {uint64_t{0x97d965937804077a}, uint256("4bb21a07f4b75d0208d5d4638edcc438c9f8ffcc78e2106a0637c629f81ffbdb"_hex_u8), uint256("a7d8197a04173065ec896b73a6803d6113201c56fd643b241200b7ea357e6efd"_hex_u8), uint64_t{0xa8e115cfebe10202}, uint64_t{0x73a44f46f5966c31}, uint256("0700f913bbe4dad357c5db1b7e79abd29e6e590e842141a16cb6e97e6933206c"_hex_u8)}, 0x638ab9733accc61a},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("0000000000000000000000000000000000000000000000000000000000000000"_hex_u8)}, 0x6a74cba00ddbfeba},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex_u8)}, 0x7f745a471ec7c2f6},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"_hex_u8)}, 0xc67d87b08ca4b5c6},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("0000000000000000000000000000000000000000000000000000000000000080"_hex_u8)}, 0xc946b5eafdebf91d},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("0100000000000000010000000000000001000000000000000100000000000000"_hex_u8)}, 0x28193aab7f7f53b5},
        {0x0000000000000000, 0x0000000000000000, {uint256("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"_hex_u8)}, 0x071384882b8b1ef6},
        {0xffffffffffffffff, 0xffffffffffffffff, {uint256("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"_hex_u8)}, 0x6d3cb0c74116cdd5},
        {0x25fd75c04a240044, 0x4e3816151d29e2ce, {uint256("8940d79240a5bf8acdf428eece829dc27d8cc2ff7b74aaeb134f66062192d308"_hex_u8)}, 0x16823b5389538dba},
        {0xaea4345a0fc4e761, 0x49456a8e8d82e5ee, {uint256("6e0e507f21292ad46a49aa0b20efec23000474f6203f5ceaf4f9325c4e032bbe"_hex_u8)}, 0x36ae52fdbe166c9a},
        {0xf7ce16edcfe54eeb, 0x81c22c4aed3e516d, {uint256("caf32c2d8d827c8e55ee92253cffc657359af1cab7f24804afabac89a436fc75"_hex_u8)}, 0xd8ebd74386d41628},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("0000000000000000000000000000000000000000000000000000000000000000"_hex_u8), uint64_t{0x0000000000000000}}, 0x71c3a354a6b56058},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex_u8), uint64_t{0xffffffffffffffff}}, 0x958c1a52a5e57e8b},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"_hex_u8), uint64_t{0x4746454443424140}}, 0x6cfc788446f0491d},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("0100000000000000000000000000000000000000000000000000000000000000"_hex_u8), uint64_t{0x8000000000000000}}, 0x9e89e2fc7abb2ba2},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"_hex_u8), uint64_t{0x2726252423222120}}, 0xcdcd25f7a2ba32c5},
        {0x0706050403020100, 0x0f0e0d0c0b0a0908, {uint256("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"_hex_u8), uint64_t{0x2827262524232221}}, 0x738d1f7d2d53622b},
        {0x0000000000000000, 0x0000000000000000, {uint256("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"_hex_u8), uint64_t{0x2726252423222120}}, 0x0f078522df1349f3},
        {0x49b001bc5a213d62, 0x80a330a42e60a89d, {uint256("6f7438d2dd360dcea691dd40e87426f4af6870315898ccbde0d3b19fcbb5ae6d"_hex_u8), uint64_t{0xc9ff5ff2126cc355}}, 0xda1c5bf6cf31653d},
        {0xf4d704fa00ce074d, 0x6f1a65f3fe494b0a, {uint256("175202cb9f976ebd6c4ddc4a80d63b2b53e2976466041ae43b41397c41fe66ac"_hex_u8), uint64_t{0xa9c5d00a72013a80}}, 0x5725ddc762049274},
        {0xc3f929b4cb53785c, 0x1693fa676a8ee165, {uint256("2ac097c589bc75eb6e294605cafb3198891ff93764032225756aab86de06514b"_hex_u8), uint64_t{0x85f91dd6ed2e645c}}, 0x49b121224ea53698},
    };

    FastRandomContext rng;
    for (const auto& testvec : TEST_VECTORS) {
        // Run every test vector 10 times, with different randomness.
        for (int i = 0; i < 10; ++i) {
            SipHasher13UJ hasher(testvec.k0, testvec.k1);
            for (const auto& block : testvec.blocks) {
                if (const auto* value = std::get_if<uint64_t>(&block)) {
                    // Test that normal 64-bit blocks are processed identically to 256-bit blocks with
                    // the same data, if padded with 192 bits of zero bits. Note that this is not
                    // expected to occur in production usage, as jumbo blocks must be hashes which
                    // won't have 192 zero bits.
                    if (rng.randbool()) {
                        hasher.Write(*value);
                    } else {
                        uint256 v256;
                        WriteLE64(v256.data(), *value);
                        hasher.WriteJumbo(v256);
                    }
                } else if (const auto* jumbo = std::get_if<uint256>(&block)) {
                    hasher.WriteJumbo(*jumbo);
                }
            }
            BOOST_CHECK_EQUAL(hasher.Finalize(), testvec.expected);
        }
        // If the test vector data consists of a single uint256 input, or a uint256+uint64_t, test
        // PresaltedSipHasher13UJ too.
        if (testvec.blocks.size() == 1 && std::holds_alternative<uint256>(testvec.blocks[0])) {
            BOOST_CHECK_EQUAL(PresaltedSipHasher13UJ(testvec.k0, testvec.k1)(std::get<uint256>(testvec.blocks[0])), testvec.expected);
        } else if (testvec.blocks.size() == 2 && std::holds_alternative<uint256>(testvec.blocks[0]) && std::holds_alternative<uint64_t>(testvec.blocks[1])) {
            BOOST_CHECK_EQUAL(PresaltedSipHasher13UJ(testvec.k0, testvec.k1)(std::get<uint256>(testvec.blocks[0]), std::get<uint64_t>(testvec.blocks[1])), testvec.expected);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
