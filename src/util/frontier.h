// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_FRONTIER_H
#define BITCOIN_UTIL_FRONTIER_H

#include <bit>
#include <cstdint>
#include <vector>

template<typename ValueType>
class Frontier
{
    std::vector<ValueType> m_data;
    uint64_t m_updates{0};

public:
    Frontier(size_t reserve, ValueType init) noexcept
    {
        m_data.reserve(reserve + 1);
        m_data.push_back(init);
    }

    bool Set(size_t key, ValueType value) noexcept
    {
        if (key >= m_data.size()) [[unlikely]] {
            if (m_data.back() >= value) return false;
            while (key > m_data.size()) {
                m_data.push_back(m_data.back());
                ++m_updates;
            }
            m_data.push_back(value);
            ++m_updates;
            return true;
        } else {
            if (value <= m_data[key]) return false;
            do {
                m_data[key] = value;
                ++key;
                ++m_updates;
            } while (key < m_data.size() && value > m_data[key]);
            return true;
        }
    }

    bool Test(size_t key, ValueType value) const noexcept
    {
        if (key < m_data.size()) [[likely]] {
            return m_data[key] >= value;
        } else {
            return m_data.back() >= value;
        }
    }

    std::pair<size_t, ValueType> Last() noexcept
    {
        while (m_data.size() > 1 && *m_data.rbegin() == *(m_data.rbegin() + 1)) {
            m_data.pop_back();
        }
        return {m_data.size() - 1, m_data.back()};
    }

    bool PreviousTick(std::pair<size_t, ValueType>& cur) const noexcept
    {
        if (cur.first == 0) return false;
        --cur.first;
        cur.second = m_data[cur.first];
        while (cur.first > 0 && cur.second == m_data[cur.first - 1]) --cur.first;
        return true;
    }

    uint64_t Updates() const noexcept { return m_updates; }
};

#endif
