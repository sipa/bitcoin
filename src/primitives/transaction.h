// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include <attributes.h>
#include <consensus/amount.h>
#include <crypto/common.h>
#include <primitives/transaction_identifier.h> // IWYU pragma: export
#include <script/script.h>
#include <serialize.h>

#include <algorithm>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <iterator>
#include <limits>
#include <memory>
#include <numeric>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    Txid hash;
    uint32_t n;

    static constexpr uint32_t NULL_INDEX = std::numeric_limits<uint32_t>::max();

    COutPoint(): n(NULL_INDEX) { }
    COutPoint(const Txid& hashIn, uint32_t nIn): hash(hashIn), n(nIn) { }

    SERIALIZE_METHODS(COutPoint, obj) { READWRITE(obj.hash, obj.n); }

    void SetNull() { hash.SetNull(); n = NULL_INDEX; }
    bool IsNull() const { return (hash.IsNull() && n == NULL_INDEX); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return std::tie(a.hash, a.n) < std::tie(b.hash, b.n);
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    std::string ToString() const;
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScriptWitness scriptWitness; //!< Only serialized through Transaction and CMutableTransaction

    /**
     * Setting nSequence to this value for every input in a transaction
     * disables nLockTime/IsFinalTx().
     * It fails OP_CHECKLOCKTIMEVERIFY/CheckLockTime() for any input that has
     * it set (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static constexpr uint32_t SEQUENCE_FINAL{0xffffffff};
    /**
     * This is the maximum sequence number that enables both nLockTime and
     * OP_CHECKLOCKTIMEVERIFY (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static constexpr uint32_t MAX_SEQUENCE_NONFINAL{SEQUENCE_FINAL - 1};

    // Below flags apply in the context of BIP 68. BIP 68 requires the tx
    // version to be set to 2, or higher.
    /**
     * If this flag is set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time.
     * It skips SequenceLocks() for any input that has it set (BIP 68).
     * It fails OP_CHECKSEQUENCEVERIFY/CheckSequence() for any input that has
     * it set (BIP 112).
     */
    static constexpr uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG{1U << 31};

    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static constexpr uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG{1 << 22};

    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static constexpr uint32_t SEQUENCE_LOCKTIME_MASK{0x0000ffff};

    /**
     * In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static constexpr int SEQUENCE_LOCKTIME_GRANULARITY{9};

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CTxIn(Txid hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    SERIALIZE_METHODS(CTxIn, obj) { READWRITE(obj.prevout, obj.scriptSig, obj.nSequence); }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    std::string ToString() const;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    SERIALIZE_METHODS(CTxOut, obj) { READWRITE(obj.nValue, obj.scriptPubKey); }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    std::string ToString() const;
};

struct CMutableTransaction;

struct TransactionSerParams {
    const bool allow_witness;
    SER_PARAMS_OPFUNC
};
inline constexpr TransactionSerParams TX_WITH_WITNESS{.allow_witness = true};
inline constexpr TransactionSerParams TX_NO_WITNESS{.allow_witness = false};

/**
 * Basic transaction serialization format:
 * - uint32_t version
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - uint32_t version
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CScriptWitness scriptWitness; (deserialized into CTxIn)
 * - uint32_t nLockTime
 */
template<typename Stream, typename TxType>
void UnserializeTransaction(TxType& tx, Stream& s, const TransactionSerParams& params)
{
    const bool fAllowWitness = params.allow_witness;

    s >> tx.version;
    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
    /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags != 0) {
            s >> tx.vin;
            s >> tx.vout;
        }
    } else {
        /* We read a non-empty vin. Assume a normal vout follows. */
        s >> tx.vout;
    }
    if ((flags & 1) && fAllowWitness) {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s >> tx.vin[i].scriptWitness.stack;
        }
        if (!tx.HasWitness()) {
            /* It's illegal to encode witnesses when all witness stacks are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if (flags) {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.nLockTime;
}

template<typename Stream, typename TxType>
void SerializeTransaction(const TxType& tx, Stream& s, const TransactionSerParams& params)
{
    const bool fAllowWitness = params.allow_witness;

    s << tx.version;
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness) {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness()) {
            flags |= 1;
        }
    }
    if (flags) {
        /* Use extended format in case witnesses are to be serialized. */
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    s << tx.vout;
    if (flags & 1) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s << tx.vin[i].scriptWitness.stack;
        }
    }
    s << tx.nLockTime;
}

template<typename TxType>
inline CAmount CalculateOutputValue(const TxType& tx)
{
    return std::accumulate(tx.vout.cbegin(), tx.vout.cend(), CAmount{0}, [](CAmount sum, const auto& txout) { return sum + txout.nValue; });
}

struct EqualsOptions {
    bool include_script_sig{true};
    bool include_witness_data{true};
};


class Transaction;

namespace transaction_detail {

/** Decode a CompactSize from the front of data, and advance data past it. The data must be valid (this is only
 *  used on data that was validated when the Transaction was constructed). */
inline uint64_t DecodeCompactSize(std::span<const uint8_t>& data) noexcept
{
    const uint8_t first{data[0]};
    if (first < 253) {
        data = data.subspan(1);
        return first;
    } else if (first == 253) {
        const uint64_t ret{ReadLE16(data.data() + 1)};
        data = data.subspan(3);
        return ret;
    } else if (first == 254) {
        const uint64_t ret{ReadLE32(data.data() + 1)};
        data = data.subspan(5);
        return ret;
    } else {
        const uint64_t ret{ReadLE64(data.data() + 1)};
        data = data.subspan(9);
        return ret;
    }
}

/** Decode a CompactSize-prefixed byte string from the front of data, and advance data past it. */
inline std::span<const uint8_t> DecodeBytes(std::span<const uint8_t>& data) noexcept
{
    const uint64_t len{DecodeCompactSize(data)};
    const auto ret{data.first(len)};
    data = data.subspan(len);
    return ret;
}

/** Append the (canonical) CompactSize encoding of n to data. */
inline void AppendCompactSize(std::vector<uint8_t>& data, uint64_t n)
{
    uint8_t buf[9];
    size_t len;
    if (n < 253) {
        buf[0] = n;
        len = 1;
    } else if (n <= 0xffff) {
        buf[0] = 253;
        WriteLE16(buf + 1, n);
        len = 3;
    } else if (n <= 0xffffffff) {
        buf[0] = 254;
        WriteLE32(buf + 1, n);
        len = 5;
    } else {
        buf[0] = 255;
        WriteLE64(buf + 1, n);
        len = 9;
    }
    data.insert(data.end(), buf, buf + len);
}

} // namespace transaction_detail

/** A view of the witness stack of a transaction input.
 *
 * The stack is not decoded up front; it is backed by its serialization (a CompactSize element count, followed by
 * the CompactSize-prefixed elements). Only forward iteration (and access to the first element) is supported, as
 * other elements can only be found by scanning. Code that needs random access must materialize the stack
 * (ToStack(), ToSpans()) explicitly. */
class WitnessView
{
    std::span<const uint8_t> m_serialized;

public:
    /** Forward iterator over the stack elements (bottom to top). */
    class iterator
    {
        std::span<const uint8_t> m_rest; //!< Serialization of the elements after the current one.
        std::span<const uint8_t> m_cur;  //!< Current element.
        uint64_t m_left{0};              //!< Number of elements left, including the current one.

    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = std::span<const unsigned char>;
        using reference = std::span<const unsigned char>;
        using difference_type = std::ptrdiff_t;

        iterator() noexcept = default;
        iterator(std::span<const uint8_t> elements, uint64_t count) noexcept : m_rest(elements), m_left(count)
        {
            if (m_left) m_cur = transaction_detail::DecodeBytes(m_rest);
        }
        std::span<const unsigned char> operator*() const noexcept { return m_cur; }
        iterator& operator++() noexcept
        {
            if (--m_left) m_cur = transaction_detail::DecodeBytes(m_rest);
            return *this;
        }
        iterator operator++(int) noexcept { auto ret{*this}; ++*this; return ret; }
        friend bool operator==(const iterator& a, const iterator& b) noexcept { return a.m_left == b.m_left; }
    };

    /** Construct from the serialization of a witness stack (which must be valid). */
    explicit WitnessView(std::span<const uint8_t> serialized LIFETIMEBOUND) noexcept : m_serialized(serialized) {}

    /** Number of elements on the stack. */
    size_t size() const noexcept
    {
        auto data{m_serialized};
        return transaction_detail::DecodeCompactSize(data);
    }
    bool empty() const noexcept { return m_serialized[0] == 0; }
    /** Equivalent to CScriptWitness::IsNull(). */
    bool IsNull() const noexcept { return empty(); }
    iterator begin() const noexcept
    {
        auto data{m_serialized};
        const uint64_t count{transaction_detail::DecodeCompactSize(data)};
        return {data, count};
    }
    iterator end() const noexcept { return {}; }
    /** The first (bottom) element. Requires !empty(). */
    std::span<const unsigned char> front() const noexcept { return *begin(); }

    /** The serialization of the stack (as in CScriptWitness::stack). */
    std::span<const uint8_t> Serialized() const noexcept { return m_serialized; }
    /** The size of the serialization of the stack (equal to ::GetSerializeSize(CScriptWitness::stack)). */
    size_t GetSerializeSize() const noexcept { return m_serialized.size(); }
    /** Decode the stack into spans. */
    std::vector<std::span<const unsigned char>> ToSpans() const;
    /** Decode the stack into owned elements, as in CScriptWitness::stack. */
    std::vector<std::vector<unsigned char>> ToStack() const;

    /** Serialize like CScriptWitness::stack. */
    template <typename Stream>
    void Serialize(Stream& s) const { s.write(std::as_bytes(m_serialized)); }
};

/** A view of a transaction input in a Transaction. */
class CTxInView
{
    const Transaction* m_tx;
    uint32_t m_idx;

public:
    CTxInView(const Transaction& tx LIFETIMEBOUND, uint32_t idx) noexcept : m_tx(&tx), m_idx(idx) {}

    const Transaction& GetTransaction() const noexcept { return *m_tx; }
    uint32_t GetIndex() const noexcept { return m_idx; }

    inline COutPoint GetPrevout() const noexcept;
    inline std::span<const unsigned char> GetScriptSig() const noexcept;
    inline uint32_t GetSequence() const noexcept;
    inline WitnessView GetWitness() const noexcept;

    /** Convert to an (owning) CTxIn. */
    CTxIn ToTxIn() const;
};

/** A view of a transaction output in a Transaction. */
class CTxOutView
{
    const Transaction* m_tx;
    uint32_t m_idx;

public:
    CTxOutView(const Transaction& tx LIFETIMEBOUND, uint32_t idx) noexcept : m_tx(&tx), m_idx(idx) {}

    const Transaction& GetTransaction() const noexcept { return *m_tx; }
    uint32_t GetIndex() const noexcept { return m_idx; }

    inline CAmount GetValue() const noexcept;
    inline std::span<const unsigned char> GetScriptPubKey() const noexcept;

    /** Convert to an (owning) CTxOut. */
    CTxOut ToTxOut() const;

    /** Serialize like the corresponding CTxOut. */
    template <typename Stream>
    void Serialize(Stream& s) const;

    friend bool operator==(const CTxOutView& a, const CTxOut& b) noexcept
    {
        return a.GetValue() == b.nValue && std::ranges::equal(a.GetScriptPubKey(), b.scriptPubKey);
    }
};

namespace transaction_detail {

/** Random-access iterator over the indices [0, N) of a Transaction's inputs or outputs, producing views (by
 *  value) of type View. */
template <typename View>
class ViewIterator
{
    const Transaction* m_tx{nullptr};
    uint32_t m_idx{0};

public:
    using iterator_concept = std::random_access_iterator_tag;
    using iterator_category = std::input_iterator_tag;
    using value_type = View;
    using reference = View;
    using difference_type = std::ptrdiff_t;

    ViewIterator() noexcept = default;
    ViewIterator(const Transaction* tx, uint32_t idx) noexcept : m_tx(tx), m_idx(idx) {}

    View operator*() const noexcept { return View{*m_tx, m_idx}; }
    View operator[](difference_type n) const noexcept { return View{*m_tx, uint32_t(m_idx + n)}; }
    ViewIterator& operator++() noexcept { ++m_idx; return *this; }
    ViewIterator operator++(int) noexcept { auto ret{*this}; ++m_idx; return ret; }
    ViewIterator& operator--() noexcept { --m_idx; return *this; }
    ViewIterator operator--(int) noexcept { auto ret{*this}; --m_idx; return ret; }
    ViewIterator& operator+=(difference_type n) noexcept { m_idx += n; return *this; }
    ViewIterator& operator-=(difference_type n) noexcept { m_idx -= n; return *this; }
    friend ViewIterator operator+(ViewIterator it, difference_type n) noexcept { return it += n; }
    friend ViewIterator operator+(difference_type n, ViewIterator it) noexcept { return it += n; }
    friend ViewIterator operator-(ViewIterator it, difference_type n) noexcept { return it -= n; }
    friend difference_type operator-(const ViewIterator& a, const ViewIterator& b) noexcept { return difference_type(a.m_idx) - difference_type(b.m_idx); }
    friend bool operator==(const ViewIterator& a, const ViewIterator& b) noexcept { return a.m_idx == b.m_idx; }
    friend auto operator<=>(const ViewIterator& a, const ViewIterator& b) noexcept { return a.m_idx <=> b.m_idx; }
};

/** A range of views over a Transaction's inputs or outputs. */
template <typename View>
class ViewRange
{
    const Transaction* m_tx;
    uint32_t m_size;

public:
    ViewRange(const Transaction& tx LIFETIMEBOUND, uint32_t size) noexcept : m_tx(&tx), m_size(size) {}
    ViewIterator<View> begin() const noexcept { return {m_tx, 0}; }
    ViewIterator<View> end() const noexcept { return {m_tx, m_size}; }
    uint32_t size() const noexcept { return m_size; }
    bool empty() const noexcept { return m_size == 0; }
    View operator[](uint32_t idx) const noexcept { return View{*m_tx, idx}; }
    View front() const noexcept { return View{*m_tx, 0}; }
    View back() const noexcept { return View{*m_tx, m_size - 1}; }
};

} // namespace transaction_detail

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 *
 * Transactions are immutable, and have a compact memory representation: all their data is stored in two
 * vectors:
 * - m_data: the serialization of the transaction with witness data (i.e., using the extended format if and only
 *   if some input has a non-empty witness).
 * - m_offsets: offsets into m_data: for each input, the offset of its prevout and (only meaningful if the
 *   transaction has witness data) the offset of its witness stack, followed by, for each output, the offset of
 *   its value.
 *
 * Together with the cached txid and wtxid, this makes accessing any input or output field O(1), while witness
 * stack elements are found by scanning the (serialized) witness stack of their input. There is no
 * per-element memory overhead: the memory usage is the serialized size plus 8 bytes per input and 4 bytes per
 * output.
 *
 * Whether the transaction has witness data is not stored separately: it does if and only if it has inputs and
 * the byte after the version (which would be the input count otherwise) is 0 (the extended format's marker).
 *
 * Its contents are only accessible through accessor functions and views.
 */
class Transaction
{
public:
    // Default transaction version.
    static constexpr uint32_t CURRENT_VERSION{2};

private:
    uint32_t m_num_inputs{0};
    uint32_t m_num_outputs{0};
    Txid m_txid;
    Wtxid m_wtxid;
    std::vector<uint8_t> m_data;
    std::vector<uint32_t> m_offsets;

    /** Per-thread scratch buffers, to construct Transactions without repeated reallocations. */
    struct Scratch
    {
        std::vector<uint8_t> data;
        std::vector<uint32_t> offsets;
    };
    static Scratch& GetScratch();
    /** Start constructing this object: let m_data and m_offsets use the (cleared) per-thread scratch buffers. */
    void UseScratchBuffers();
    /** Finish constructing this object, after m_data and m_offsets have been filled in: copy them into
     *  exactly-sized vectors (handing the scratch buffers back), and compute the hashes. */
    void Finalize();

    /** Read n bytes from s, appending them to m_data (allocating in chunks, as vector deserialization does). */
    template <typename Stream>
    void ReadBytes(Stream& s, uint64_t n)
    {
        while (n > 0) {
            const size_t chunk = std::min<uint64_t>(n, MAX_VECTOR_ALLOCATE);
            const size_t old_size{m_data.size()};
            m_data.resize(old_size + chunk);
            s.read(MakeWritableByteSpan(std::span{m_data}.subspan(old_size)));
            n -= chunk;
        }
    }
    /** Read a CompactSize from s (range checked, as in vector deserialization), appending it to m_data. */
    template <typename Stream>
    uint64_t ReadCompactSizeInto(Stream& s);
    /** Read a CompactSize-prefixed byte string from s, appending it to m_data. */
    template <typename Stream>
    void ReadBytesInto(Stream& s) { ReadBytes(s, ReadCompactSizeInto(s)); }
    /** The current size of m_data, as an offset. */
    uint32_t CurrentOffset() const
    {
        if (m_data.size() > std::numeric_limits<uint32_t>::max()) throw std::ios_base::failure("Transaction too large");
        return m_data.size();
    }

    std::span<const uint8_t> Data() const noexcept LIFETIMEBOUND { return m_data; }
    uint32_t InputOffset(uint32_t idx) const noexcept { return m_offsets[2 * size_t{idx}]; }
    uint32_t WitnessOffset(uint32_t idx) const noexcept { return m_offsets[2 * size_t{idx} + 1]; }
    uint32_t OutputOffset(uint32_t idx) const noexcept { return m_offsets[2 * size_t{m_num_inputs} + idx]; }
    /** Offset of the CompactSize-prefixed scriptSig of input idx. */
    uint32_t ScriptSigOffset(uint32_t idx) const noexcept { return InputOffset(idx) + 36; }
    /** Offset of the start of the input count (after the version, and the marker and flag if present). */
    uint32_t InputsStart() const noexcept { return HasWitness() ? 6 : 4; }
    /** Offset of the end of the outputs (start of the witness data, or of the lock time). */
    uint32_t OutputsEnd() const noexcept { return HasWitness() ? WitnessOffset(0) : LockTimeOffset(); }
    uint32_t LockTimeOffset() const noexcept { return GetTotalSize() - 4; }

    /** Write the serialization without witness data to s. */
    template <typename Stream>
    void SerializeWithoutWitness(Stream& s) const
    {
        const auto data{Data()};
        s.write(std::as_bytes(data.subspan(0, 4)));
        s.write(std::as_bytes(data.subspan(InputsStart(), OutputsEnd() - InputsStart())));
        s.write(std::as_bytes(data.subspan(LockTimeOffset(), 4)));
    }

public:
    using InputRange = transaction_detail::ViewRange<CTxInView>;
    using OutputRange = transaction_detail::ViewRange<CTxOutView>;

    /** Convert a CMutableTransaction into a Transaction. */
    explicit Transaction(const CMutableTransaction& tx);

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (s.template GetParams<TransactionSerParams>().allow_witness) {
            s.write(std::as_bytes(GetSerialization()));
        } else {
            SerializeWithoutWitness(s);
        }
    }

    /** This deserializing constructor is provided instead of an Unserialize method, as Transactions are
     *  immutable. It has the same semantics (and failures) as CMutableTransaction deserialization. */
    template <typename Stream>
    Transaction(deserialize_type, const TransactionSerParams& params, Stream& s);
    template <typename Stream>
    Transaction(deserialize_type, Stream& s) : Transaction(deserialize, s.template GetParams<TransactionSerParams>(), s) {}

    bool IsNull() const noexcept { return m_num_inputs == 0 && m_num_outputs == 0; }

    const Txid& GetHash() const noexcept LIFETIMEBOUND { return m_txid; }
    const Wtxid& GetWitnessHash() const noexcept LIFETIMEBOUND { return m_wtxid; };

    // Return sum of txouts.
    CAmount GetValueOut() const;

    /**
     * Calculate the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int ComputeTotalSize() const noexcept { return GetTotalSize(); }

    bool IsCoinBase() const noexcept { return m_num_inputs == 1 && GetInputPrevout(0).IsNull(); }

    bool Equals(const Transaction& other, const EqualsOptions opts = {}) const;

    std::string ToString() const;

    bool HasWitness() const noexcept { return m_num_inputs > 0 && m_data[4] == 0; }

    uint32_t GetNumInputs() const noexcept { return m_num_inputs; }
    uint32_t GetNumOutputs() const noexcept { return m_num_outputs; }
    uint32_t GetVersion() const noexcept { return ReadLE32(m_data.data()); }
    uint32_t GetLockTime() const noexcept { return ReadLE32(m_data.data() + LockTimeOffset()); }

    COutPoint GetInputPrevout(uint32_t input_idx) const noexcept
    {
        const uint8_t* ptr{m_data.data() + InputOffset(input_idx)};
        return COutPoint{Txid::FromUint256(uint256{std::span{ptr, 32}}), ReadLE32(ptr + 32)};
    }
    /** The serialization of an input's prevout (32-byte txid and 4-byte output index). */
    std::span<const uint8_t> GetInputPrevoutSerialization(uint32_t input_idx) const noexcept LIFETIMEBOUND
    {
        return Data().subspan(InputOffset(input_idx), 36);
    }
    std::span<const unsigned char> GetInputScriptSig(uint32_t input_idx) const noexcept LIFETIMEBOUND
    {
        auto data{Data().subspan(ScriptSigOffset(input_idx))};
        return transaction_detail::DecodeBytes(data);
    }
    uint32_t GetInputSequence(uint32_t input_idx) const noexcept
    {
        auto data{Data().subspan(ScriptSigOffset(input_idx))};
        transaction_detail::DecodeBytes(data);
        return ReadLE32(data.data());
    }
    /** Get a view of the witness stack of an input (empty if the transaction has no witness data). */
    WitnessView GetInputWitness(uint32_t input_idx) const noexcept LIFETIMEBOUND
    {
        static constexpr uint8_t EMPTY_STACK[1] = {0};
        if (!HasWitness()) return WitnessView{EMPTY_STACK};
        const uint32_t start{WitnessOffset(input_idx)};
        const uint32_t end{input_idx + 1 < m_num_inputs ? WitnessOffset(input_idx + 1) : LockTimeOffset()};
        return WitnessView{Data().subspan(start, end - start)};
    }
    CAmount GetOutputValue(uint32_t output_idx) const noexcept
    {
        return static_cast<int64_t>(ReadLE64(m_data.data() + OutputOffset(output_idx)));
    }
    /** The serialization of an output (value and CompactSize-prefixed scriptPubKey). */
    std::span<const uint8_t> GetOutputSerialization(uint32_t output_idx) const noexcept LIFETIMEBOUND
    {
        const uint32_t start{OutputOffset(output_idx)};
        const uint32_t end{output_idx + 1 < m_num_outputs ? OutputOffset(output_idx + 1) : OutputsEnd()};
        return Data().subspan(start, end - start);
    }
    std::span<const unsigned char> GetOutputScriptPubKey(uint32_t output_idx) const noexcept LIFETIMEBOUND
    {
        auto data{Data().subspan(OutputOffset(output_idx) + 8)};
        return transaction_detail::DecodeBytes(data);
    }

    CTxInView GetInput(uint32_t input_idx) const noexcept LIFETIMEBOUND { return {*this, input_idx}; }
    CTxOutView GetOutput(uint32_t output_idx) const noexcept LIFETIMEBOUND { return {*this, output_idx}; }
    InputRange Inputs() const noexcept LIFETIMEBOUND { return {*this, GetNumInputs()}; }
    OutputRange Outputs() const noexcept LIFETIMEBOUND { return {*this, GetNumOutputs()}; }

    /** Serialized size including witness data ("total size" in BIP141). */
    uint32_t GetTotalSize() const noexcept { return m_data.size(); }
    /** Serialized size without witness data. */
    uint32_t GetStrippedSize() const noexcept { return HasWitness() ? 4 + (OutputsEnd() - InputsStart()) + 4 : GetTotalSize(); }
    /** The serialization including witness data. */
    std::span<const uint8_t> GetSerialization() const noexcept LIFETIMEBOUND { return Data(); }

    /** Heap memory used by this object (see RecursiveDynamicUsage). */
    size_t DynamicMemoryUsage() const;
};

COutPoint CTxInView::GetPrevout() const noexcept { return m_tx->GetInputPrevout(m_idx); }
std::span<const unsigned char> CTxInView::GetScriptSig() const noexcept { return m_tx->GetInputScriptSig(m_idx); }
uint32_t CTxInView::GetSequence() const noexcept { return m_tx->GetInputSequence(m_idx); }
WitnessView CTxInView::GetWitness() const noexcept { return m_tx->GetInputWitness(m_idx); }
CAmount CTxOutView::GetValue() const noexcept { return m_tx->GetOutputValue(m_idx); }
std::span<const unsigned char> CTxOutView::GetScriptPubKey() const noexcept { return m_tx->GetOutputScriptPubKey(m_idx); }
template <typename Stream>
void CTxOutView::Serialize(Stream& s) const { s.write(std::as_bytes(m_tx->GetOutputSerialization(m_idx))); }

template <typename Stream>
uint64_t Transaction::ReadCompactSizeInto(Stream& s)
{
    const uint64_t ret{ReadCompactSize(s)};
    transaction_detail::AppendCompactSize(m_data, ret);
    return ret;
}

template <typename Stream>
Transaction::Transaction(deserialize_type, const TransactionSerParams& params, Stream& s)
{
    UseScratchBuffers();
    // This mirrors UnserializeTransaction, but appends the bytes read to m_data, and records offsets in m_offsets.
    const auto read_inputs = [&](uint64_t count) {
        for (uint64_t i = 0; i < count; ++i) {
            m_offsets.push_back(CurrentOffset()); // prevout
            m_offsets.push_back(0);               // witness stack (filled in below, if present)
            ReadBytes(s, 36);                     // prevout
            ReadBytesInto(s);                     // scriptSig
            ReadBytes(s, 4);                      // nSequence
        }
    };
    const auto read_outputs = [&](uint64_t count) {
        for (uint64_t i = 0; i < count; ++i) {
            m_offsets.push_back(CurrentOffset());
            ReadBytes(s, 8);  // nValue
            ReadBytesInto(s); // scriptPubKey
        }
    };

    ReadBytes(s, 4); // version
    uint8_t flags{0};
    // Try to read the inputs. In case the dummy is there, this will read an input count of 0.
    uint64_t num_inputs{ReadCompactSizeInto(s)};
    if (num_inputs == 0 && params.allow_witness) {
        // We read a dummy or an empty input vector.
        s >> flags;
        // If flags is 0, there are no inputs and no outputs, and this byte is the (empty) output count.
        m_data.push_back(flags);
        if (flags != 0) {
            num_inputs = ReadCompactSizeInto(s);
            read_inputs(num_inputs);
            read_outputs(ReadCompactSizeInto(s));
        }
    } else {
        // We read a non-empty input vector. Assume a normal output vector follows.
        read_inputs(num_inputs);
        read_outputs(ReadCompactSizeInto(s));
    }
    m_num_inputs = num_inputs;
    m_num_outputs = m_offsets.size() - 2 * num_inputs;
    if ((flags & 1) && params.allow_witness) {
        // The witness flag is present, and we support witnesses.
        flags ^= 1;
        bool any_witness{false};
        for (uint64_t i = 0; i < num_inputs; ++i) {
            m_offsets[2 * i + 1] = CurrentOffset();
            const uint64_t num_elements{ReadCompactSizeInto(s)};
            any_witness |= num_elements != 0;
            for (uint64_t j = 0; j < num_elements; ++j) ReadBytesInto(s);
        }
        if (!any_witness) {
            // It's illegal to encode witnesses when all witness stacks are empty.
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if (flags) {
        // Unknown flag in the serialization.
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    ReadBytes(s, 4); // nLockTime
    CurrentOffset();
    Finalize();
}

/** A mutable version of Transaction. */
struct CMutableTransaction
{
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t version;
    uint32_t nLockTime;

    explicit CMutableTransaction();
    explicit CMutableTransaction(const Transaction& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        UnserializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, const TransactionSerParams& params, Stream& s) {
        UnserializeTransaction(*this, s, params);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in Transaction, which uses a cached result.
     */
    Txid GetHash() const;

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }
    /** Accessors with the same names as Transaction's, so code can work with either. The non-const ones
     *  return mutable references. */
    uint32_t GetNumInputs() const { return vin.size(); }
    uint32_t GetNumOutputs() const { return vout.size(); }
    uint32_t GetVersion() const { return version; }
    uint32_t GetLockTime() const { return nLockTime; }
    const std::vector<CTxIn>& Inputs() const LIFETIMEBOUND { return vin; }
    std::vector<CTxIn>& Inputs() LIFETIMEBOUND { return vin; }
    const std::vector<CTxOut>& Outputs() const LIFETIMEBOUND { return vout; }
    std::vector<CTxOut>& Outputs() LIFETIMEBOUND { return vout; }
    const CTxIn& GetInput(uint32_t input_idx) const LIFETIMEBOUND { return vin[input_idx]; }
    CTxIn& GetInput(uint32_t input_idx) LIFETIMEBOUND { return vin[input_idx]; }
    const CTxOut& GetOutput(uint32_t output_idx) const LIFETIMEBOUND { return vout[output_idx]; }
    CTxOut& GetOutput(uint32_t output_idx) LIFETIMEBOUND { return vout[output_idx]; }
    const COutPoint& GetInputPrevout(uint32_t input_idx) const LIFETIMEBOUND { return vin[input_idx].prevout; }
    COutPoint& GetInputPrevout(uint32_t input_idx) LIFETIMEBOUND { return vin[input_idx].prevout; }
    std::span<const unsigned char> GetInputScriptSig(uint32_t input_idx) const LIFETIMEBOUND { return vin[input_idx].scriptSig; }
    CScript& GetInputScriptSig(uint32_t input_idx) LIFETIMEBOUND { return vin[input_idx].scriptSig; }
    uint32_t GetInputSequence(uint32_t input_idx) const { return vin[input_idx].nSequence; }
    uint32_t& GetInputSequence(uint32_t input_idx) LIFETIMEBOUND { return vin[input_idx].nSequence; }
    const CScriptWitness& GetInputWitness(uint32_t input_idx) const LIFETIMEBOUND { return vin[input_idx].scriptWitness; }
    CScriptWitness& GetInputWitness(uint32_t input_idx) LIFETIMEBOUND { return vin[input_idx].scriptWitness; }
    CAmount GetOutputValue(uint32_t output_idx) const { return vout[output_idx].nValue; }
    CAmount& GetOutputValue(uint32_t output_idx) LIFETIMEBOUND { return vout[output_idx].nValue; }
    std::span<const unsigned char> GetOutputScriptPubKey(uint32_t output_idx) const LIFETIMEBOUND { return vout[output_idx].scriptPubKey; }
    CScript& GetOutputScriptPubKey(uint32_t output_idx) LIFETIMEBOUND { return vout[output_idx].scriptPubKey; }
};

typedef std::shared_ptr<const Transaction> TransactionRef;
template <typename Tx> static inline TransactionRef MakeTransactionRef(Tx&& txIn) { return std::make_shared<const Transaction>(std::forward<Tx>(txIn)); }

namespace std {
/** Disable default std::hash for TransactionRef to prevent accidentally
 *  comparing by pointer. Use TransactionRefHash or provide a custom
 *  hasher. */
template <>
struct hash<TransactionRef> {
    hash() = delete;
    // Belt-and-suspenders, already implied by the above.
    size_t operator()(const TransactionRef&) const = delete;
};
} // namespace std

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
