// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CUCKOOFILTER_H
#define BITCOIN_CUCKOOFILTER_H

#include <random.h>
#include <span.h>
#include <util/bitpack.h>

#include <map>

#include <stdint.h>

class RollingCuckooFilter
{
public:
    // 4 entries per bucket.
    static constexpr unsigned BUCKET_BITS = 2;
    static constexpr unsigned BUCKET_SIZE = 1U << BUCKET_BITS;

    struct Params
    {
        //! Number of buckets in the table. Must be even.
        uint32_t m_buckets;
        //! Number of insertions per generation.
        uint32_t m_gen_size;
        //! Number of bits the high part of generation numbers are compressed into (per bucket).
        unsigned m_gen_cbits;
        //! Number of fingerprint bits per entry.
        unsigned m_fpr_bits;
        //! Maximum number of kicks performed when inserting, before resorting to overflow table.
        unsigned m_max_kicks;

        //! Implied number of active generations.
        unsigned Generations() const;

        //! Implied number of bits for a serialized bucket.
        unsigned BucketBits() const { return m_gen_cbits + (m_fpr_bits << BUCKET_BITS); }

        //! Implied number of bits for the entire table.
        uint64_t TableBits() const { return uint64_t{BucketBits()} * m_buckets; }

        //! Implied maximum number of active entries in the table.
        uint64_t MaxEntries() const { return uint64_t{Generations()} * m_gen_size; }
    };

private:
    //! Configuration parameters
    const Params m_params;

    //! Encoded size (in bits) of one bucket. Equal to m_params.BucketBits().
    const unsigned m_bits_per_bucket; //!< Equal to m_gen_cbits + BUCKET_SIZE * m_fpr_bits

    //! Number of active generations. Generation numbers range from 0..2*m_gens-1. Equal to m_params.Generations().
    const uint32_t m_gens;

    //! Maximum number of active entries in the table. Equal to m_params.MaxEntries().
    const uint64_t m_max_entries;

    //! Private random number generator.
    FastRandomContext m_rng;

    // Salts for the fingerprint and index hash functions.
    const uint64_t m_phi_k0;
    const uint64_t m_phi_k1;
    const uint64_t m_h1_k0;
    const uint64_t m_h1_k1;

    //! The current generation number (in range 0..m_gen*2-1).
    uint32_t m_this_gen = 0;

    //! Number of insertions in this generation so far.
    uint32_t m_count_this_gen = 0;

    //! Number of insertions this cycle (first half or second half of generations).
    uint64_t m_count_this_cycle = 0;

    //! Number of buckets that have been swept in this cycle.
    uint32_t m_swept_this_cycle = 0;

    //! The actual bit-packed table.
    BitPack m_data;

    //! Overflow table ((fpr, min(bucket1, bucket1)) -> gen)
    std::map<std::pair<uint64_t, uint32_t>, unsigned> m_overflow;

    size_t m_max_overflow = 0;

    struct DecodedEntry
    {
        uint64_t m_fpr;
        unsigned m_gen;
    };

    struct DecodedBucket
    {
        DecodedEntry m_entries[BUCKET_SIZE];
    };

    //! Determine if generation gen is currently active.
    bool IsActive(unsigned gen) const;

    //! Decode an entire bucket from m_data.
    DecodedBucket LoadBucket(uint32_t index) const;

    //! Encode a bucket back into m_data.
    void SaveBucket(uint32_t index, DecodedBucket&& bucket);

    //! Find whether fingerprint fpr is present (with active generation) in bucket with given index.
    int Find(uint32_t index, uint64_t fpr) const;

    //! Count how many free positions (incl. inactive generations) there are in bucket.
    int CountFree(const DecodedBucket& bucket) const;

    //! Compute the fingerprint for data.
    uint64_t Fingerprint(Span<const unsigned char> data) const;

    //! Compute the (first) index for data.
    uint32_t Index1(Span<const unsigned char> data) const;

    //! Given the fingerprint of an item, and one of its index positions, find the other.
    uint32_t OtherIndex(uint32_t index, uint64_t fpr) const;

    //! Add (fpr,gen) to bucket if it has an empty entry; otherwise do nothing.
    bool AddEntryToBucket(DecodedBucket& bucket, uint64_t fpr, unsigned gen) const;

    //! Store (fpr,gen) in bucket index1 or index2; otherwise kick until space is found; as a last resort, store in overflow map.
    int AddEntry(uint32_t index1, uint32_t index2, uint64_t fpr, unsigned gen, int access);

public:
    //! Construct a rolling cuckoo filter with the specified parameters.
    RollingCuckooFilter(const Params& param, bool deterministic);

    //! Construct a rolling cuckoo filter, choosing parameters automatically.
    RollingCuckooFilter(uint32_t window, unsigned fpbits, double alpha, int max_access = 0, bool deterministic = false);

    //! Check if data is present.
    bool Check(Span<const unsigned char> data) const;

    //! Insert data.
    void Insert(Span<const unsigned char> data);

    size_t MaxOverflow() const { return m_max_overflow; }
};


#endif // BITCOIN_CUCKOOFILTER_H
