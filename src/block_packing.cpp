// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "block_packing.h"
#include "util/check.h"
#include "util/feefrac.h"
#include "random.h"
#include <span>
#include <vector>
#include <utility>

#include <Highs.h>

std::pair<std::vector<size_t>, FeeFrac> PackBlock(std::span<const FeeFrac> feerates, std::span<const std::pair<size_t, size_t>> dependencies, uint32_t max_weight)
{
    FastRandomContext rng;

    Highs highs;
    highs.setOptionValue("presolve", "off");
    highs.setOptionValue("parallel", "on");
    highs.setOptionValue("simplex_max_concurrency", 8);
    highs.setOptionValue("mip_rel_gap", 1e-15);
    highs.setOptionValue("random_seed", rng.randrange<int>(1000000000));

    // Add binary variables (0 or 1) for each transaction
    const auto n = feerates.size();
    for (size_t i = 0; i < n; ++i) {
        highs.addVar(-0.001, 1.001);  // Lower bound 0, upper bound 1, with some tolerance.
    }
    // Set variables as integer (binary)
    highs.changeColsIntegrality(0, n - 1, std::vector<HighsVarType>(n, HighsVarType::kInteger).data());

    // Set objective: maximize sum of fees.
    std::vector<double> obj_coeffs(n, 0.0);
    for (size_t i = 0; i < n; ++i) {
        obj_coeffs[i] = double(feerates[i].fee);
    }
    highs.changeObjectiveSense(ObjSense::kMaximize);
    highs.changeColsCost(0, n - 1, obj_coeffs.data());

    // Weight constraint: 0 <= sum(weight_i * x_i) <= max_weight, with some tolerance.
    std::vector<int> weight_indices(n);
    std::vector<double> weight_values(n);
    for (size_t i = 0; i < n; ++i) {
        weight_indices[i] = i;
        weight_values[i] = double(feerates[i].size);
    }
    highs.addRow(-0.001, max_weight + 0.001, n, weight_indices.data(), weight_values.data());

    // Build direct parent relationships.
    std::vector<int> dep_indices;
    std::vector<double> dep_values = {1.0, -1.0};
    for (const auto& [par, chl] : dependencies) {
        dep_indices.resize(2);
        dep_indices[0] = par;
        dep_indices[1] = chl;
        // Dependency constraint: 0 <= tx_{par_j} - tx_{chl_j} <= 1, with some tolerance.
        highs.addRow(-0.001, highs.getInfinity(), 2, dep_indices.data(), dep_values.data());
    }

    // Solve the MIP
    HighsStatus solve_status = highs.run();
    Assert(solve_status == HighsStatus::kOk);

    // Extract solution
    const HighsSolution& solution = highs.getSolution();

    // Collect selected transactions (integer solution, threshold 0.5)
    FeeFrac total;
    std::vector<size_t> included;
    for (size_t i = 0; i < n; ++i) {
        if (solution.col_value[i] > 0.5) {
            included.push_back(i);
            total += feerates[i];
        }
    }

    return {std::move(included), total};
}
