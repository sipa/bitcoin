// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_PACKING_H
#define BITCOIN_BLOCK_PACKING_H

#include "util/feefrac.h"

#include <span>
#include <vector>
#include <utility>

// Simple wrapper around HiGHS

std::pair<std::vector<size_t>, FeeFrac> PackBlock(std::span<const FeeFrac> feerates, std::span<const std::pair<size_t, size_t>> dependencies, uint32_t max_weight);

#endif
