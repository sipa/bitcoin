// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_RINGBUFFER_H
#define BITCOIN_UTIL_RINGBUFFER_H

#include <util/check.h>

#include <memory>

/** Data structure largely mimicking std::deque, but using single preallocated ring buffer.
 *
 * - More efficient and better memory locality than std::deque.
 * - Most operations ({push_,pop_,emplace_,}{front,back}(), operator[], ...) are O(1),
 *   unless reallocation is needed (in which case they are O(n)).
 * - Supports reserve(), capacity(), shrink_to_fit() like vectors.
 * - No iterator support.
 * - Data is not stored in a single contiguous block, so no data().
 */
template<typename T>
class RingBuffer
{
    /** Pointer to allocated memory. Can contain constructed and uninitialized T objects. */
    T* m_buffer{nullptr};
    /** m_buffer + m_offset points to first object. m_offset < m_capacity. */
    size_t m_offset{0};
    /** Number of objects in the container. m_size < m_capacity. */
    size_t m_size{0};
    /** The size of m_buffer, expressed as a multiple of the size of T. */
    size_t m_capacity{0};

    inline size_t FirstPart() const noexcept { return std::min(m_capacity - m_offset, m_size); }

    void Reallocate(size_t capacity)
    {
        Assume(capacity >= m_size);
        Assume(m_capacity == 0 || m_offset < m_capacity);
        // Allocate new buffer.
        T* new_buffer = capacity ? std::allocator<T>().allocate(capacity) : nullptr;
        if constexpr (std::is_trivially_copyable_v<T>) {
            // When T is trivially copyable, just copy the data over from old to new buffer.
            size_t first_part = FirstPart();
            if (first_part != 0) {
                std::memcpy(new_buffer, m_buffer + m_offset, first_part * sizeof(T));
            }
            if (first_part != m_size) {
                std::memcpy(new_buffer + first_part, m_buffer, (m_size - first_part) * sizeof(T));
            }
        } else {
            // Otherwise move-construct in place in the new buffer, and destroy old buffer objects.
            size_t old_pos = m_offset;
            for (size_t new_pos = 0; new_pos < m_size; ++new_pos) {
                std::construct_at<T>(new_buffer + new_pos, std::move(*(m_buffer + old_pos)));
                std::destroy_at<T>(m_buffer + old_pos);
                ++old_pos;
                if (old_pos == m_capacity) old_pos = 0;
            }
        }
        // Deallocate old buffer and update housekeeping.
        std::allocator<T>().deallocate(m_buffer, m_capacity);
        m_buffer = new_buffer;
        m_offset = 0;
        m_capacity = capacity;
    }

    /** What index in the buffer does logical entry number pos have? */
    inline size_t Index(size_t pos) const noexcept
    {
        pos += m_offset;
        if (pos >= m_capacity) pos -= m_capacity;
        return pos;
    }

    /** Specialization of resize() that can only shrink. Separate so that clear() can call it
     *  without requiring a default T constructor. */
    void ResizeDown(size_t size)
    {
        Assume(size <= m_size);
        if constexpr (std::is_trivially_destructible_v<T>) {
            // If T is trivially destructible, we do not need to do anything but update the
            // housekeeping record. Default constructor or zero-filling will be used when
            // the space is reused.
            m_size = size;
        } else {
            // If not, we need to invoke the destructor for every element separately.
            while (m_size > size) {
                std::destroy_at<T>(m_buffer + Index(m_size - 1));
                --m_size;
            }
        }
    }

public:
    RingBuffer() noexcept = default;

    void resize(size_t size)
    {
        if (size < m_size) {
            // Delegate to ResizeDown when shrinking.
            ResizeDown(size);
        } else if (size > m_size) {
            // When growing, first see if we need to allocate more space.
            if (size > m_capacity) Reallocate(size);
            if constexpr (std::is_trivially_constructible_v<T>) {
                // If T is trivially constructible, just zero-initialize the area being used.
                size_t first_part = std::min(m_capacity - Index(m_size), size - m_size);
                if (first_part) std::fill(m_buffer + Index(m_size), m_buffer + Index(m_size) + first_part, 0);
                if (first_part < size - m_size) std::fill(m_buffer, m_buffer + size - m_size - first_part, 0);
                m_size = size;
            } else {
                // Otherwise invoke the default constructor for every element separately.
                while (m_size < size) {
                    std::construct_at<T>(m_buffer + Index(m_size));
                    ++m_size;
                }
            }
        }
    }

    void clear() { ResizeDown(0); }

    ~RingBuffer()
    {
        clear();
        Reallocate(0);
    }

    RingBuffer& operator=(const RingBuffer& other)
    {
        clear();
        Reallocate(other.m_size);
        if constexpr (std::is_trivially_copyable_v<T>) {
            size_t first_part = other.FirstPart();
            if (first_part != 0) {
                std::memcpy(m_buffer, other.m_buffer + other.m_offset, first_part * sizeof(T));
            }
            if (first_part != other.m_size) {
                std::memcpy(m_buffer + first_part, other.m_buffer, (other.m_size - first_part) * sizeof(T));
            }
            m_size = other.m_size;
        } else {
            while (m_size < other.m_size) {
                std::construct_at<T>(m_buffer + Index(m_size), other[m_size]);
                ++m_size;
            }
        }
        return *this;
    }

    void swap(RingBuffer& other) noexcept
    {
        std::swap(m_buffer, other.m_buffer);
        std::swap(m_offset, other.m_offset);
        std::swap(m_size, other.m_size);
        std::swap(m_capacity, other.m_capacity);
    }

    friend void swap(RingBuffer& a, RingBuffer& b) noexcept { a.swap(b); }
    RingBuffer& operator=(RingBuffer&& other) noexcept { swap(other); return *this; }
    RingBuffer(const RingBuffer& other) { *this = other; }
    RingBuffer(RingBuffer&& other) noexcept { swap(other); }

    bool friend operator==(const RingBuffer& a, const RingBuffer& b)
    {
        if (a.m_size != b.m_size) return false;
        for (size_t i = 0; i < a.m_size; ++i) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    std::strong_ordering friend operator<=>(const RingBuffer& a, const RingBuffer& b)
    {
        size_t pos_a{0}, pos_b{0};
        while (pos_a < a.m_size && pos_b < b.m_size) {
            auto cmp = a[pos_a++] <=> b[pos_b++];
            if (cmp != 0) return cmp;
        }
        return a.m_size <=> b.m_size;
    }

    void reserve(size_t capacity)
    {
        if (capacity > m_capacity) Reallocate(capacity);
    }

    void shrink_to_fit()
    {
        if (m_capacity > m_size) Reallocate(m_size);
    }

    template<typename U>
    void push_back(U&& elem)
    {
        if (m_size == m_capacity) Reallocate((m_size + 1) * 2);
        std::construct_at<T>(m_buffer + Index(m_size), std::forward<U>(elem));
        ++m_size;
    }

    template<typename... Args>
    void emplace_back(Args&&... args)
    {
        if (m_size == m_capacity) Reallocate((m_size + 1) * 2);
        std::construct_at<T>(m_buffer + Index(m_size), std::forward<Args>(args)...);
        ++m_size;
    }

    template<typename U>
    void push_front(U&& elem)
    {
        if (m_size == m_capacity) Reallocate((m_size + 1) * 2);
        std::construct_at<T>(m_buffer + Index(m_capacity - 1), std::forward<U>(elem));
        if (m_offset == 0) m_offset = m_capacity;
        --m_offset;
        ++m_size;
    }

    template<typename... Args>
    void emplace_front(Args&&... args)
    {
        if (m_size == m_capacity) Reallocate((m_size + 1) * 2);
        std::construct_at<T>(m_buffer + Index(m_capacity - 1), std::forward<Args>(args)...);
        if (m_offset == 0) m_offset = m_capacity;
        --m_offset;
        ++m_size;
    }

    void pop_front()
    {
        Assume(m_size);
        std::destroy_at<T>(m_buffer + m_offset);
        --m_size;
        ++m_offset;
        if (m_offset == m_capacity) m_offset = 0;
    }

    void pop_back()
    {
        Assume(m_size);
        std::destroy_at<T>(m_buffer + Index(m_size - 1));
        --m_size;
    }

    T& front() noexcept { Assume(m_size); return m_buffer[m_offset]; }
    const T& front() const noexcept { Assume(m_size); return m_buffer[m_offset]; }
    T& back() noexcept { Assume(m_size); return m_buffer[Index(m_size - 1)]; }
    const T& back() const noexcept { Assume(m_size); return m_buffer[Index(m_size - 1)]; }
    T& operator[](size_t idx) noexcept { Assume(idx < m_size); return m_buffer[Index(idx)]; }
    const T& operator[](size_t idx) const noexcept { Assume(idx < m_size); return m_buffer[Index(idx)]; }
    bool empty() const noexcept { return m_size == 0; }
    size_t size() const noexcept { return m_size; }
    size_t capacity() const noexcept { return m_capacity; }
};

#endif // BITCOIN_UTIL_RINGBUFFER_H
