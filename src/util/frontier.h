// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_FRONTIER_H
#define BITCOIN_UTIL_FRONTIER_H

#include <bit>
#include <cstdint>

#include <iostream>

namespace {

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

template<typename ValueType>
class FancyFrontier
{
    std::vector<ValueType> m_data;
    uint64_t m_updates{0};
    size_t max_key{0};

    void Decrease(size_t& key) const noexcept
    {
        ValueType value = m_data[key];
        while (true) {
            if (key == 0) return;
            size_t new_key = key - (key & (~key + 1));
//            Assume(m_data[new_key] <= value);
            if (m_data[new_key] < value) break;
            key = new_key;
        }
        size_t diff = (key & (~key + 1)) >> 1;
        while (diff > 0) {
            size_t new_key = key - diff;
//            Assume(m_data[new_key] <= value);
            if (m_data[new_key] >= value) key = new_key;
            diff >>= 1;
        }
    }

public:
    FancyFrontier(size_t reserve, ValueType init) noexcept
    {
        m_data.assign(reserve + 1, init);
    }

    bool Test(size_t key, ValueType value) const noexcept
    {
        while (true) {
            if (m_data[key] >= value) return true;
            if (key == 0) break;
            key -= (key & (~key + 1));
        }
        return false;
    }

    bool Set(size_t key, ValueType value) noexcept
    {
        if (value > m_data[max_key] || (value == m_data[max_key] && key < max_key)) {
            max_key = key;
        } else {
            if (Test(key, value)) return false;
        }
        do {
            m_updates += 1;
            std::cerr << "- UPDATE key=" << key << " value=" << value << "\n";
            m_data[key] = value;
            key += (key & (~key + 1));
            if (key >= m_data.size()) break;
        } while (value > m_data[key]);
        return true;
    }


    std::pair<size_t, ValueType> Last() noexcept
    {
        std::pair<size_t, ValueType> cur{max_key, m_data[max_key]};
//        Decrease(cur.first);
//        cur.second = m_data[cur.first];
        return cur;
    }

    bool PreviousTick(std::pair<size_t, ValueType>& cur) const noexcept
    {
        if (cur.first == 0) return false;
        --cur.first;
        Decrease(cur.first);
        cur.second = m_data[cur.first];
        return true;
    }

    uint64_t Updates() const noexcept { return m_updates; }
};

} // namespace

#endif // BITCOIN_UTIL_GOLOMBRICE_H
