// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/script.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <algorithm>
#include <cassert>
#include <ios>
#include <optional>
#include <vector>

//! Deserialization of a CScriptWitness behaves exactly like that of a std::vector<std::vector<unsigned char>>, and its
//! accessors and serialization agree with that vector.
FUZZ_TARGET(script_witness_deserialize)
{
    std::optional<std::vector<std::vector<unsigned char>>> stack;
    size_t stack_left{0};
    {
        SpanReader reader{buffer};
        try {
            std::vector<std::vector<unsigned char>> tmp;
            reader >> tmp;
            stack = std::move(tmp);
            stack_left = reader.size();
        } catch (const std::ios_base::failure&) {
        }
    }
    std::optional<CScriptWitness> witness;
    size_t witness_left{0};
    {
        SpanReader reader{buffer};
        try {
            CScriptWitness tmp;
            reader >> tmp;
            witness = std::move(tmp);
            witness_left = reader.size();
        } catch (const std::ios_base::failure&) {
        }
    }
    assert(stack.has_value() == witness.has_value());
    if (!stack) return;
    assert(stack_left == witness_left);
    assert(witness->ToStack() == *stack);
    assert(witness->size() == stack->size());
    assert(witness->IsNull() == stack->empty());
    assert(CScriptWitness{*stack} == *witness);
    if (!stack->empty()) {
        assert(std::ranges::equal(witness->front(), stack->front()));
        assert(std::ranges::equal(witness->back(), stack->back()));
        assert(std::ranges::equal(CScriptWitness{*witness}.back(), stack->back()));
        for (const size_t i : {size_t{0}, stack->size() / 2, stack->size() - 1}) {
            assert(std::ranges::equal(witness->GetElementAtSlow(i), (*stack)[i]));
        }
    }
    std::vector<unsigned char> ser_stack, ser_witness;
    VectorWriter{ser_stack, 0, *stack};
    VectorWriter{ser_witness, 0, *witness};
    assert(ser_stack == ser_witness);
    assert(witness->GetSerializeSize() == ser_stack.size());
    assert(witness->DynamicMemoryUsage() >= (stack->empty() ? 0 : ser_stack.size()));
}
