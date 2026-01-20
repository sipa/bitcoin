#ifndef BITCOIN_UTIL_TDIGEST_H
#define BITCOIN_UTIL_TDIGEST_H

#include <cmath>
#include <cstdint>
#include <limits>
#include <vector>

class TDigest
{
    struct Centroid
    {
        double sum;
        double count;

        Centroid() noexcept : sum{0.0}, count{0.0} {}
        Centroid(double value) noexcept : sum{value}, count{1.0} {}

        double GetAverage() const noexcept { return sum / count; }

        bool operator<(const Centroid& other) const noexcept
        {
            return sum * other.count < other.sum * count;
        }

        Centroid& operator+=(const Centroid& other) noexcept
        {
            sum += other.sum;
            count += other.count;
            return *this;
        }
    };

    std::vector<Centroid> m_data;
    size_t m_max_size;
    uint64_t m_total_count{0};
    bool m_sorted{true};
    double m_delta;

    void Sort() noexcept
    {
        if (m_sorted) return;
        std::sort(m_data.begin(), m_data.end());
        m_sorted = true;
    }

    void Coalesce() noexcept
    {
        Sort();
        Centroid sigma = m_data[0];
        size_t o = 0;
        for (size_t i = 1; i < m_data.size(); ++i) {
            Centroid x = m_data[i];
            if (::fabs(sigma.sum * x.count - x.sum * sigma.count) <= x.sum * sigma.count * 1e-12) {
                sigma += x;
            } else {
                m_data[o++] = sigma;
                sigma = x;
            }
        }
        m_data[o++] = sigma;
        m_data.resize(o);
    }


public:
    TDigest(double delta, size_t max_size) noexcept : m_max_size{max_size}, m_delta{delta}
    {
        m_data.reserve(size_t(std::ceil(delta)));
    }

    void Shrink() noexcept
    {
        Coalesce();
        if (m_data.size() < m_delta) return;
        double p = std::expm1((4.0 * std::log(m_total_count / m_delta) + 24.0) / m_delta);
        double param_1 = p + 1.0;
        double param_2 = p / m_total_count;
        double q0 = 0.0;
        double q_limit = 0.0;
        Centroid sigma = m_data[0];
        size_t o = 0;
        for (size_t i = 1; i < m_data.size(); ++i) {
            Centroid x = m_data[i];
            double q = q0 + sigma.count + x.count;
            if (q < q_limit) {
                sigma += x;
            } else {
                m_data[o++] = sigma;
                q0 += sigma.count;
                q_limit = (param_1 * q0) / (param_2 * q0 + 1.0);
                sigma = x;
            }
        }
        m_data[o++] = sigma;
        m_data.resize(o);
    }

    void Absorb(TDigest&& tdigest) noexcept
    {
        if (!tdigest.m_data.empty()) {
            m_data.insert(m_data.end(), tdigest.m_data.begin(), tdigest.m_data.end());
            tdigest.m_data.clear();
            m_sorted = false;
        }
    }

    inline void Add(double value) noexcept
    {
        m_data.emplace_back(value);
        m_total_count += 1;
        m_sorted = false;
        if (m_data.size() >= m_max_size) {
            Shrink();
        }
    }

    std::pair<double, double> GetQRange() noexcept
    {
        Sort();
        double scale = 1.0 / m_total_count;
        return {0.5 * m_data.front().count * scale, 1.0 - 0.5 * m_data.back().count * scale};
    }

    double Evaluate(double q) noexcept
    {
        Sort();
        double scale = 1.0 / m_total_count;
        double prev_q = 0.0;
        double prev_m = -std::numeric_limits<double>::infinity();
        double sum_count = 0.0;
        for (const auto& elem : m_data) {
            double next_q = (sum_count + 0.5 * elem.count) * scale;
            double next_m = elem.GetAverage();
            if (next_q > q) {
                double est = (prev_m * (next_q - q) + next_m * (q - prev_q)) / (next_q - prev_q);
                return est;
            }
            sum_count += elem.count;
            prev_q = next_q;
            prev_m = next_m;
        }
        return std::numeric_limits<double>::infinity();
    }

    uint64_t NumEvents() const noexcept { return m_total_count; }

    std::vector<std::pair<double, double>> Dump() noexcept
    {
        Coalesce();
        std::vector<std::pair<double, double>> ret;
        ret.reserve(m_data.size());
        for (const auto& centroid : m_data) {
            ret.emplace_back(centroid.GetAverage(), centroid.count);
        }
        return ret;
    }
};

#endif
