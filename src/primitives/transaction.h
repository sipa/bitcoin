// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include <attributes.h>
#include <consensus/amount.h>
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

/** A view of the witness stack of a transaction input.
 *
 * Elements are accessed as spans. Only forward iteration (and access to the first element) is supported, so that
 * this can be backed by a serialized stack. Code that needs random access must materialize the stack (ToStack(),
 * ToSpans()) explicitly. */
class WitnessView
{
    const std::vector<std::vector<unsigned char>>* m_stack;

public:
    /** Forward iterator over the stack elements (bottom to top). */
    class iterator
    {
        std::vector<std::vector<unsigned char>>::const_iterator m_it;

    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = std::span<const unsigned char>;
        using reference = std::span<const unsigned char>;
        using difference_type = std::ptrdiff_t;

        iterator() noexcept = default;
        explicit iterator(std::vector<std::vector<unsigned char>>::const_iterator it) noexcept : m_it(it) {}
        std::span<const unsigned char> operator*() const noexcept { return *m_it; }
        iterator& operator++() noexcept { ++m_it; return *this; }
        iterator operator++(int) noexcept { auto ret{*this}; ++m_it; return ret; }
        friend bool operator==(const iterator& a, const iterator& b) noexcept { return a.m_it == b.m_it; }
    };

    explicit WitnessView(const CScriptWitness& witness LIFETIMEBOUND) noexcept : m_stack(&witness.stack) {}

    /** Number of elements on the stack. */
    size_t size() const noexcept { return m_stack->size(); }
    bool empty() const noexcept { return m_stack->empty(); }
    /** Equivalent to CScriptWitness::IsNull(). */
    bool IsNull() const noexcept { return empty(); }
    iterator begin() const noexcept { return iterator{m_stack->begin()}; }
    iterator end() const noexcept { return iterator{m_stack->end()}; }
    /** The first (bottom) element. Requires !empty(). */
    std::span<const unsigned char> front() const noexcept { return m_stack->front(); }

    /** The size of the serialization of the stack (equal to ::GetSerializeSize(CScriptWitness::stack)). */
    size_t GetSerializeSize() const noexcept;
    /** Decode the stack into spans. */
    std::vector<std::span<const unsigned char>> ToSpans() const { return {begin(), end()}; }
    /** Decode the stack into owned elements, as in CScriptWitness::stack. */
    std::vector<std::vector<unsigned char>> ToStack() const { return *m_stack; }

    /** Serialize like CScriptWitness::stack. */
    template <typename Stream>
    void Serialize(Stream& s) const { s << *m_stack; }
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
 * Its contents are only accessible through accessor functions and views, so
 * that its representation can be changed.
 */
class Transaction
{
    template <typename Stream, typename TxType>
    friend void SerializeTransaction(const TxType& tx, Stream& s, const TransactionSerParams& params);

public:
    // Default transaction version.
    static constexpr uint32_t CURRENT_VERSION{2};

protected:
    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, Transaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t version;
    const uint32_t nLockTime;

private:
    /** Memory only. */
    const bool m_has_witness;
    const Txid hash;
    const Wtxid m_witness_hash;

    Txid ComputeHash() const;
    Wtxid ComputeWitnessHash() const;

    bool ComputeHasWitness() const;

public:
    /** Convert a CMutableTransaction into a Transaction. */
    explicit Transaction(const CMutableTransaction& tx);
    explicit Transaction(CMutableTransaction&& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    /** This deserializing constructor is provided instead of an Unserialize method.
     *  Unserialize is not possible, since it would require overwriting const fields. */
    template <typename Stream>
    Transaction(deserialize_type, const TransactionSerParams& params, Stream& s) : Transaction(CMutableTransaction(deserialize, params, s)) {}
    template <typename Stream>
    Transaction(deserialize_type, Stream& s) : Transaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const Txid& GetHash() const LIFETIMEBOUND { return hash; }
    const Wtxid& GetWitnessHash() const LIFETIMEBOUND { return m_witness_hash; };

    // Return sum of txouts.
    CAmount GetValueOut() const;

    /**
     * Calculate the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int ComputeTotalSize() const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    bool Equals(const Transaction& other, const EqualsOptions opts = {}) const
    {
        return nLockTime == other.nLockTime &&
            version == other.version &&
            vout == other.vout &&
            std::ranges::equal(vin, other.vin, [&opts](const CTxIn& self, const CTxIn& other) {
                return self.prevout == other.prevout &&
                    self.nSequence == other.nSequence &&
                    (opts.include_script_sig ? self.scriptSig == other.scriptSig : true) &&
                    (opts.include_witness_data ? self.scriptWitness.stack == other.scriptWitness.stack : true);
            });
    }

    std::string ToString() const;

    bool HasWitness() const { return m_has_witness; }
    // Accessors. Code should use these (or the views below) instead of the fields, so that the representation
    // can be changed.
    using InputRange = transaction_detail::ViewRange<CTxInView>;
    using OutputRange = transaction_detail::ViewRange<CTxOutView>;

    uint32_t GetNumInputs() const noexcept { return vin.size(); }
    uint32_t GetNumOutputs() const noexcept { return vout.size(); }
    uint32_t GetVersion() const noexcept { return version; }
    uint32_t GetLockTime() const noexcept { return nLockTime; }

    COutPoint GetInputPrevout(uint32_t input_idx) const noexcept { return vin[input_idx].prevout; }
    std::span<const unsigned char> GetInputScriptSig(uint32_t input_idx) const noexcept LIFETIMEBOUND { return vin[input_idx].scriptSig; }
    uint32_t GetInputSequence(uint32_t input_idx) const noexcept { return vin[input_idx].nSequence; }
    WitnessView GetInputWitness(uint32_t input_idx) const noexcept LIFETIMEBOUND { return WitnessView{vin[input_idx].scriptWitness}; }
    CAmount GetOutputValue(uint32_t output_idx) const noexcept { return vout[output_idx].nValue; }
    std::span<const unsigned char> GetOutputScriptPubKey(uint32_t output_idx) const noexcept LIFETIMEBOUND { return vout[output_idx].scriptPubKey; }

    CTxInView GetInput(uint32_t input_idx) const noexcept LIFETIMEBOUND { return {*this, input_idx}; }
    CTxOutView GetOutput(uint32_t output_idx) const noexcept LIFETIMEBOUND { return {*this, output_idx}; }
    InputRange Inputs() const noexcept LIFETIMEBOUND { return {*this, GetNumInputs()}; }
    OutputRange Outputs() const noexcept LIFETIMEBOUND { return {*this, GetNumOutputs()}; }

    /** Serialized size including witness data (equal to ComputeTotalSize()). */
    uint32_t GetTotalSize() const { return ComputeTotalSize(); }
    /** Serialized size without witness data. */
    uint32_t GetStrippedSize() const;

    /** Heap memory used by this object (see RecursiveDynamicUsage). */
    size_t DynamicMemoryUsage() const;
};

/** A Transaction whose fields are publicly accessible. Code is being migrated to Transaction (and its
 *  accessors) instead. */
class CTransaction : public Transaction
{
public:
    using Transaction::Transaction;
    explicit CTransaction(const Transaction& tx) : Transaction(tx) {}

    using Transaction::vin;
    using Transaction::vout;
    using Transaction::version;
    using Transaction::nLockTime;
};

COutPoint CTxInView::GetPrevout() const noexcept { return m_tx->GetInputPrevout(m_idx); }
std::span<const unsigned char> CTxInView::GetScriptSig() const noexcept { return m_tx->GetInputScriptSig(m_idx); }
uint32_t CTxInView::GetSequence() const noexcept { return m_tx->GetInputSequence(m_idx); }
WitnessView CTxInView::GetWitness() const noexcept { return m_tx->GetInputWitness(m_idx); }
CAmount CTxOutView::GetValue() const noexcept { return m_tx->GetOutputValue(m_idx); }
std::span<const unsigned char> CTxOutView::GetScriptPubKey() const noexcept { return m_tx->GetOutputScriptPubKey(m_idx); }
template <typename Stream>
void CTxOutView::Serialize(Stream& s) const { s << GetValue() << CompactSizeWriter(GetScriptPubKey().size()) << GetScriptPubKey(); }

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
typedef std::shared_ptr<const CTransaction> CTransactionRef;
template <typename Tx> static inline CTransactionRef MakeTransactionRef(Tx&& txIn) { return std::make_shared<const CTransaction>(std::forward<Tx>(txIn)); }

namespace std {
/** Disable default std::hash for TransactionRef to prevent accidentally
 *  comparing by pointer. Use TransactionRefHash or provide a custom
 *  hasher. */
template <>
struct hash<CTransactionRef> {
    hash() = delete;
    size_t operator()(const CTransactionRef&) const = delete;
};
template <>
struct hash<TransactionRef> {
    hash() = delete;
    // Belt-and-suspenders, already implied by the above.
    size_t operator()(const TransactionRef&) const = delete;
};
} // namespace std

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
