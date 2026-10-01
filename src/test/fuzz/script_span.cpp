// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Differential fuzz tests comparing span-based script functions with verbatim copies of the original
//! CScript-based implementations they replace. The copies call OldGetScriptOp instead of CScript::GetOp,
//! as the latter is now itself implemented using the span-based functions.

#include <crypto/common.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <span>
#include <vector>

namespace {

/** Original GetScriptOp, as used by CScript::GetOp. */
bool OldGetScriptOp(CScriptBase::const_iterator& pc, CScriptBase::const_iterator end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet)
{
    opcodeRet = OP_INVALIDOPCODE;
    if (pvchRet)
        pvchRet->clear();
    if (pc >= end)
        return false;

    // Read instruction
    if (end - pc < 1)
        return false;
    unsigned int opcode = *pc++;

    // Immediate operand
    if (opcode <= OP_PUSHDATA4)
    {
        unsigned int nSize = 0;
        if (opcode < OP_PUSHDATA1)
        {
            nSize = opcode;
        }
        else if (opcode == OP_PUSHDATA1)
        {
            if (end - pc < 1)
                return false;
            nSize = *pc++;
        }
        else if (opcode == OP_PUSHDATA2)
        {
            if (end - pc < 2)
                return false;
            nSize = ReadLE16(&pc[0]);
            pc += 2;
        }
        else if (opcode == OP_PUSHDATA4)
        {
            if (end - pc < 4)
                return false;
            nSize = ReadLE32(&pc[0]);
            pc += 4;
        }
        if (end - pc < 0 || (unsigned int)(end - pc) < nSize)
            return false;
        if (pvchRet)
            pvchRet->assign(pc, pc + nSize);
        pc += nSize;
    }

    opcodeRet = static_cast<opcodetype>(opcode);
    return true;
}

/** Consume a script, biased towards the shapes that script functions treat specially (P2SH, witness programs,
 *  pushes of various encodings, OP_CODESEPARATOR), with random modifications. */
CScript ConsumeShapedScript(FuzzedDataProvider& provider)
{
    std::vector<unsigned char> bytes;
    switch (provider.ConsumeIntegralInRange(0, 3)) {
    case 0: // OP_HASH160 <20 bytes> OP_EQUAL
        bytes = {OP_HASH160, 0x14};
        bytes.resize(22);
        bytes.push_back(OP_EQUAL);
        break;
    case 1: { // Witness-program-like: version opcode followed by a direct push.
        bytes.push_back(provider.PickValueInArray({OP_0, OP_1, OP_2, OP_16, OP_1NEGATE, OP_RESERVED, OP_PUSHDATA1}));
        const size_t len{provider.ConsumeIntegralInRange<size_t>(0, 45)};
        bytes.push_back(len);
        bytes.resize(2 + len);
        break;
    }
    case 2: { // A sequence of opcodes and pushes.
        const int n{provider.ConsumeIntegralInRange(0, 16)};
        for (int i = 0; i < n && provider.remaining_bytes(); ++i) {
            const unsigned char op{provider.PickValueInArray<unsigned char>({OP_0, OP_1, OP_16, OP_CODESEPARATOR, OP_CHECKSIG,
                OP_CHECKMULTISIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIGVERIFY, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, 0x01, 0x4b, 0xff})};
            bytes.push_back(op);
            if (op == OP_PUSHDATA1 || op == OP_PUSHDATA2 || op == OP_PUSHDATA4 || (op >= 0x01 && op <= 0x4b)) {
                const auto data{provider.ConsumeBytes<unsigned char>(provider.ConsumeIntegralInRange<size_t>(0, 80))};
                bytes.insert(bytes.end(), data.begin(), data.end());
            }
        }
        break;
    }
    default: // Raw bytes.
        break;
    }
    // Apply random byte modifications, then append random bytes, and possibly truncate.
    const int mods{provider.ConsumeIntegralInRange(0, 3)};
    for (int i = 0; i < mods && !bytes.empty(); ++i) {
        bytes[provider.ConsumeIntegralInRange<size_t>(0, bytes.size() - 1)] = provider.ConsumeIntegral<unsigned char>();
    }
    const auto extra{ConsumeRandomLengthByteVector<unsigned char>(provider, 64)};
    bytes.insert(bytes.end(), extra.begin(), extra.end());
    if (provider.ConsumeBool() && !bytes.empty()) bytes.resize(provider.ConsumeIntegralInRange<size_t>(0, bytes.size()));
    return CScript(bytes.begin(), bytes.end());
}

} // namespace

FUZZ_TARGET(script_span_getscriptop)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const CScript script{ConsumeShapedScript(provider)};

    // Compare the span-based GetScriptOp with the original, including how far the input was consumed on failure.
    CScript::const_iterator old_pc{script.begin()};
    std::span<const unsigned char> remaining{script};
    while (true) {
        opcodetype old_opcode;
        std::vector<unsigned char> old_data;
        const bool old_ret{OldGetScriptOp(old_pc, script.end(), old_opcode, &old_data)};
        const auto op{GetScriptOp(remaining)};
        assert(old_ret == op.has_value());
        assert(size_t(script.end() - old_pc) == remaining.size());
        if (!old_ret) break;
        assert(old_opcode == op->first);
        assert(std::ranges::equal(old_data, op->second));
    }

    // Compare the iterator-based GetScriptOp (now implemented using the span-based one) with the original.
    CScript::const_iterator pc{script.begin()};
    old_pc = script.begin();
    while (true) {
        const bool want_data{provider.ConsumeBool()};
        opcodetype old_opcode, opcode;
        std::vector<unsigned char> old_data, data;
        if (want_data) {
            old_data = data = provider.ConsumeBytes<unsigned char>(provider.ConsumeIntegralInRange<size_t>(0, 3));
        }
        const bool old_ret{OldGetScriptOp(old_pc, script.end(), old_opcode, want_data ? &old_data : nullptr)};
        const bool ret{GetScriptOp(pc, script.end(), opcode, want_data ? &data : nullptr)};
        assert(old_ret == ret);
        assert(old_pc == pc);
        assert(old_opcode == opcode);
        assert(old_data == data);
        if (!ret) break;
    }
}

namespace {

/** Original CScript::IsPayToScriptHash. */
bool OldIsPayToScriptHash(const CScript& script)
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (script.size() == 23 &&
            script[0] == OP_HASH160 &&
            script[1] == 0x14 &&
            script[22] == OP_EQUAL);
}

/** Original CScript::IsWitnessProgram. */
bool OldIsWitnessProgram(const CScript& script, int& version, std::vector<unsigned char>& program)
{
    if (script.size() < 4 || script.size() > 42) {
        return false;
    }
    if (script[0] != OP_0 && (script[0] < OP_1 || script[0] > OP_16)) {
        return false;
    }
    if ((size_t)(script[1] + 2) == script.size()) {
        version = CScript::DecodeOP_N((opcodetype)script[0]);
        program = std::vector<unsigned char>(script.begin() + 2, script.end());
        return true;
    }
    return false;
}

/** Original CScript::IsPushOnly. */
bool OldIsPushOnly(const CScript& script, CScript::const_iterator pc)
{
    while (pc < script.end())
    {
        opcodetype opcode;
        if (!OldGetScriptOp(pc, script.end(), opcode, nullptr))
            return false;
        // Note that IsPushOnly() *does* consider OP_RESERVED to be a
        // push-type opcode, however execution of OP_RESERVED fails, so
        // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
        // the P2SH special validation code being executed.
        if (opcode > OP_16)
            return false;
    }
    return true;
}

} // namespace

FUZZ_TARGET(script_span_checks)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const CScript script{ConsumeShapedScript(provider)};

    const bool old_p2sh{OldIsPayToScriptHash(script)};
    assert(IsPayToScriptHash(script) == old_p2sh);
    assert(script.IsPayToScriptHash() == old_p2sh);

    int old_version{-1};
    std::vector<unsigned char> old_program;
    const bool old_witness{OldIsWitnessProgram(script, old_version, old_program)};
    const auto witness_program{GetWitnessProgram(script)};
    assert(witness_program.has_value() == old_witness);
    if (old_witness) {
        assert(witness_program->first == old_version);
        assert(std::ranges::equal(witness_program->second, old_program));
    }
    int version{-1};
    std::vector<unsigned char> program;
    assert(script.IsWitnessProgram(version, program) == old_witness);
    assert(version == old_version);
    assert(program == old_program);

    const bool old_push_only{OldIsPushOnly(script, script.begin())};
    assert(IsPushOnly(script) == old_push_only);
    assert(script.IsPushOnly() == old_push_only);
    const size_t offset{provider.ConsumeIntegralInRange<size_t>(0, script.size())};
    assert(script.IsPushOnly(script.begin() + offset) == OldIsPushOnly(script, script.begin() + offset));
}

namespace {

/** Original CScript::GetSigOpCount(bool). */
unsigned int OldGetSigOpCount(const CScript& script, bool fAccurate)
{
    unsigned int n = 0;
    CScript::const_iterator pc = script.begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < script.end())
    {
        opcodetype opcode;
        if (!OldGetScriptOp(pc, script.end(), opcode, nullptr))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += CScript::DecodeOP_N(lastOpcode);
            else
                n += MAX_PUBKEYS_PER_MULTISIG;
        }
        lastOpcode = opcode;
    }
    return n;
}

/** Original CScript::GetSigOpCount(const CScript&). */
unsigned int OldGetSigOpCount(const CScript& script, const CScript& scriptSig)
{
    if (!OldIsPayToScriptHash(script))
        return OldGetSigOpCount(script, true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    CScript::const_iterator pc = scriptSig.begin();
    std::vector<unsigned char> vData;
    while (pc < scriptSig.end())
    {
        opcodetype opcode;
        if (!OldGetScriptOp(pc, scriptSig.end(), opcode, &vData))
            return 0;
        if (opcode > OP_16)
            return 0;
    }

    /// ... and return its opcount:
    CScript subscript(vData.begin(), vData.end());
    return OldGetSigOpCount(subscript, true);
}

} // namespace

FUZZ_TARGET(script_span_sigopcount)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const CScript script{ConsumeShapedScript(provider)};
    CScript script_sig;
    if (provider.ConsumeBool()) {
        // A scriptSig whose last push is a (redeem) script.
        script_sig = ConsumeShapedScript(provider);
        script_sig << std::span<const unsigned char>{ConsumeShapedScript(provider)};
    } else {
        script_sig = ConsumeShapedScript(provider);
    }

    for (const bool accurate : {false, true}) {
        const unsigned int old_count{OldGetSigOpCount(script, accurate)};
        assert(GetSigOpCount(script, accurate) == old_count);
        assert(script.GetSigOpCount(accurate) == old_count);
    }
    const unsigned int old_p2sh_count{OldGetSigOpCount(script, script_sig)};
    assert(GetSigOpCount(script, script_sig) == old_p2sh_count);
    assert(script.GetSigOpCount(script_sig) == old_p2sh_count);
}
