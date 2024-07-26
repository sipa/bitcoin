// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <util/feefrac.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <compare>
#include <cstdint>
#include <iostream>

namespace {

/** Compute a * b, represented in 4x32 bits, highest limb first. */
std::array<uint32_t, 4> Mul128(uint64_t a, uint64_t b)
{
    std::array<uint32_t, 4> ret{0, 0, 0, 0};

    /** Perform ret += v << (32 * pos), at 128-bit precision. */
    auto add_fn = [&](uint64_t v, int pos) {
        uint64_t accum{0};
        for (int i = 0; i + pos < 4; ++i) {
            // Add current value at limb pos in ret.
            accum += ret[3 - pos - i];
            // Add low or high half of v.
            if (i == 0) accum += v & 0xffffffff;
            if (i == 1) accum += v >> 32;
            // Store lower half of result in limb pos in ret.
            ret[3 - pos - i] = accum & 0xffffffff;
            // Leave carry in accum.
            accum >>= 32;
        }
        // Make sure no overflow.
        assert(accum == 0);
    };

    // Multiply the 4 individual limbs (schoolbook multiply, with base 2^32).
    add_fn((a & 0xffffffff) * (b & 0xffffffff), 0);
    add_fn((a >> 32) * (b & 0xffffffff), 1);
    add_fn((a & 0xffffffff) * (b >> 32), 1);
    add_fn((a >> 32) * (b >> 32), 2);
    return ret;
}

/* comparison helper for std::array */
std::strong_ordering compare_arrays(const std::array<uint32_t, 4>& a, const std::array<uint32_t, 4>& b) {
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return a[i] <=> b[i];
    }
    return std::strong_ordering::equal;
}

std::strong_ordering MulCompare(int64_t a1, int64_t a2, int64_t b1, int64_t b2)
{
    // Compute and compare signs.
    int sign_a = (a1 == 0 ? 0 : a1 < 0 ? -1 : 1) * (a2 == 0 ? 0 : a2 < 0 ? -1 : 1);
    int sign_b = (b1 == 0 ? 0 : b1 < 0 ? -1 : 1) * (b2 == 0 ? 0 : b2 < 0 ? -1 : 1);
    if (sign_a != sign_b) return sign_a <=> sign_b;

    // Compute absolute values.
    uint64_t abs_a1 = static_cast<uint64_t>(a1), abs_a2 = static_cast<uint64_t>(a2);
    uint64_t abs_b1 = static_cast<uint64_t>(b1), abs_b2 = static_cast<uint64_t>(b2);
    // Use (~x + 1) instead of the equivalent (-x) to silence the linter; mod 2^64 behavior is
    // intentional here.
    if (a1 < 0) abs_a1 = ~abs_a1 + 1;
    if (a2 < 0) abs_a2 = ~abs_a2 + 1;
    if (b1 < 0) abs_b1 = ~abs_b1 + 1;
    if (b2 < 0) abs_b2 = ~abs_b2 + 1;

    // Compute products of absolute values.
    auto mul_abs_a = Mul128(abs_a1, abs_a2);
    auto mul_abs_b = Mul128(abs_b1, abs_b2);
    if (sign_a < 0) {
        return compare_arrays(mul_abs_b, mul_abs_a);
    } else {
        return compare_arrays(mul_abs_a, mul_abs_b);
    }
}

} // namespace

FUZZ_TARGET(feefrac)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    int64_t f1 = provider.ConsumeIntegral<int64_t>();
    int32_t s1 = provider.ConsumeIntegral<int32_t>();
    if (s1 == 0) f1 = 0;
    FeeFrac fr1(f1, s1);
    assert(fr1.IsEmpty() == (s1 == 0));

    int64_t f2 = provider.ConsumeIntegral<int64_t>();
    int32_t s2 = provider.ConsumeIntegral<int32_t>();
    if (s2 == 0) f2 = 0;
    FeeFrac fr2(f2, s2);
    assert(fr2.IsEmpty() == (s2 == 0));

    // Feerate comparisons
    auto cmp_feerate = MulCompare(f1, s2, f2, s1);
    assert(FeeRateCompare(fr1, fr2) == cmp_feerate);
    assert((fr1 << fr2) == std::is_lt(cmp_feerate));
    assert((fr1 >> fr2) == std::is_gt(cmp_feerate));

    // Compare with manual invocation of FeeFrac::Mul.
    auto cmp_mul = FeeFrac::Mul(f1, s2) <=> FeeFrac::Mul(f2, s1);
    assert(cmp_mul == cmp_feerate);

    // Same, but using FeeFrac::MulFallback.
    auto cmp_fallback = FeeFrac::MulFallback(f1, s2) <=> FeeFrac::MulFallback(f2, s1);
    assert(cmp_fallback == cmp_feerate);

    // Total order comparisons
    auto cmp_total = std::is_eq(cmp_feerate) ? (s2 <=> s1) : cmp_feerate;
    assert((fr1 <=> fr2) == cmp_total);
    assert((fr1 < fr2) == std::is_lt(cmp_total));
    assert((fr1 > fr2) == std::is_gt(cmp_total));
    assert((fr1 <= fr2) == std::is_lteq(cmp_total));
    assert((fr1 >= fr2) == std::is_gteq(cmp_total));
    assert((fr1 == fr2) == std::is_eq(cmp_total));
    assert((fr1 != fr2) == std::is_neq(cmp_total));
}

FUZZ_TARGET(feefrac_evaluate)
{
    // Construct a feefrac (with positive size), and a non-negative size to evaluate at.
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    auto frac_fee = provider.ConsumeIntegral<int64_t>();
    auto frac_size = provider.ConsumeIntegralInRange<int32_t>(1, 0x7fffffff);
    auto at_size = provider.ConsumeIntegralInRange<int32_t>(0, 0x7fffffff);
    FeeFrac feefrac{frac_fee, frac_size};

    // Simple case: frac_fee or at_size is 0.
    if (frac_fee == 0 || at_size == 0) {
        assert(feefrac.Evaluate(at_size) == 0);
    }

    // Simple case: at_size is 1.
    if (at_size == 1) {
        auto result = feefrac.Evaluate(at_size);
        if (frac_fee < 0) {
            assert(result == frac_fee / frac_size - !!(frac_fee % frac_size));
        } else {
            assert(result == frac_fee / frac_size);
        }
    }

    // Simple case: at_size == frac_size.
    if (at_size == frac_size) {
        assert(feefrac.Evaluate(at_size) == frac_fee);
    }

    // Compute 2**63 + floor((frac_fee * at_size) / frac_size) using arith_uint256.
    // - Start by computing frac_fee % 2**64.
    arith_uint256 arith{uint64_t(frac_fee)};
    // - Subtract 2**64 if frac_fee is negative, so arith == frac_fee (mod 2^256).
    if (frac_fee < 0) arith -= arith_uint256{1} << 64;
    // - Multiply by at_size, so we get arith == frac_fee * at_size (mod 2^256).
    arith *= at_size;
    // - Add 2**63 * frac_size, so arith == frac_fee * at_size + 2**63 * frac_size.
    arith += arith_uint256{uint64_t(frac_size)} << 63;
    // - Divide by frac_size, so arith = floor((frac_fee * at_size) / frac_size) + 2**63.
    arith /= frac_size;
    // Check if Evaluate can be called.
    if (arith.bits() <= 64) {
        // arith (= expected_result + 2**63) < 2**64, so -2**63 <= expected_result < 2**63, in
        // other words, expected_result fits in an int64_t, and Evaluate can be called.
        int64_t result = feefrac.Evaluate(at_size);
        /** The expected result modulo 2**63. */
        int64_t mod63 = arith.GetLow64() & 0x7fffffffffffffff;
        if (arith.bits() == 64) {
            // expected_result + 2**63 >= 2**63, so expected result is non-negative.
            assert(result == mod63);
        } else {
            // expected_result + 2**63 < 2**63, so expected result is negative.
            assert(result == mod63 + std::numeric_limits<int64_t>::min());
        }
    } else {
        // The result must fit in a int64_t if 0 <= at_size <= frac_size.
        assert(at_size > frac_size);
    }
}
