// Copyright (c) 2012 Pieter Wuille
// Copyright (c) 2012-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>

#include <hash.h>
#include <logging.h>
#include <netaddress.h>
#include <serialize.h>

#include <cmath>
#include <optional>
#include <unordered_map>
#include <unordered_set>

int CAddrInfo::GetTriedBucket(const uint256& nKey, const std::vector<bool> &asmap) const
{
    uint64_t hash1 = (CHashWriter(SER_GETHASH, 0) << nKey << GetKey()).GetCheapHash();
    uint64_t hash2 = (CHashWriter(SER_GETHASH, 0) << nKey << GetGroup(asmap) << (hash1 % ADDRMAN_TRIED_BUCKETS_PER_GROUP)).GetCheapHash();
    int tried_bucket = hash2 % ADDRMAN_TRIED_BUCKET_COUNT;
    uint32_t mapped_as = GetMappedAS(asmap);
    LogPrint(BCLog::NET, "IP %s mapped to AS%i belongs to tried bucket %i\n", ToStringIP(), mapped_as, tried_bucket);
    return tried_bucket;
}

int CAddrInfo::GetNewBucket(const uint256& nKey, const CNetAddr& src, const std::vector<bool> &asmap) const
{
    std::vector<unsigned char> vchSourceGroupKey = src.GetGroup(asmap);
    uint64_t hash1 = (CHashWriter(SER_GETHASH, 0) << nKey << GetGroup(asmap) << vchSourceGroupKey).GetCheapHash();
    uint64_t hash2 = (CHashWriter(SER_GETHASH, 0) << nKey << vchSourceGroupKey << (hash1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP)).GetCheapHash();
    int new_bucket = hash2 % ADDRMAN_NEW_BUCKET_COUNT;
    uint32_t mapped_as = GetMappedAS(asmap);
    LogPrint(BCLog::NET, "IP %s mapped to AS%i belongs to new bucket %i\n", ToStringIP(), mapped_as, new_bucket);
    return new_bucket;
}

int CAddrInfo::GetBucketPosition(const uint256 &nKey, bool fNew, int nBucket) const
{
    uint64_t hash1 = (CHashWriter(SER_GETHASH, 0) << nKey << (fNew ? uint8_t{'N'} : uint8_t{'K'}) << nBucket << GetKey()).GetCheapHash();
    return hash1 % ADDRMAN_BUCKET_SIZE;
}

bool CAddrInfo::IsTerrible(int64_t nNow) const
{
    if (nLastTry && nLastTry >= nNow - 60) // never remove things tried in the last minute
        return false;

    if (nTime > nNow + 10 * 60) // came in a flying DeLorean
        return true;

    if (nTime == 0 || nNow - nTime > ADDRMAN_HORIZON_DAYS * 24 * 60 * 60) // not seen in recent history
        return true;

    if (nLastSuccess == 0 && nAttempts >= ADDRMAN_RETRIES) // tried N times and never a success
        return true;

    if (nNow - nLastSuccess > ADDRMAN_MIN_FAIL_DAYS * 24 * 60 * 60 && nAttempts >= ADDRMAN_MAX_FAILURES) // N successive failures in the last week
        return true;

    return false;
}

double CAddrInfo::GetChance(int64_t nNow) const
{
    double fChance = 1.0;
    int64_t nSinceLastTry = std::max<int64_t>(nNow - nLastTry, 0);

    // deprioritize very recent attempts away
    if (nSinceLastTry < 60 * 10)
        fChance *= 0.01;

    // deprioritize 66% after each failed attempt, but at most 1/28th to avoid the search taking forever or overly penalizing outages.
    fChance *= pow(0.66, std::min(nAttempts, 8));

    return fChance;
}

void CAddrMan::SwapRandom(unsigned int nRndPos1, unsigned int nRndPos2)
{
    AssertLockHeld(cs);

    if (nRndPos1 == nRndPos2)
        return;

    assert(nRndPos1 < vRandom.size() && nRndPos2 < vRandom.size());

    auto it1 = vRandom[nRndPos1];
    auto it2 = vRandom[nRndPos2];

    it1->nRandomPos = nRndPos2;
    it2->nRandomPos = nRndPos1;

    vRandom[nRndPos1] = it2;
    vRandom[nRndPos2] = it1;
}

void CAddrMan::MakeTried(AddrManIndex::index<ByAddress>::type::iterator it)
{
    AssertLockHeld(cs);

    // Extract the entry.
    CAddrInfo info = *it;
    assert(!it->fInTried);
    Erase(it);

    // remove the entry from all new buckets
    while (true) {
        auto it_existing = m_index.get<ByAddress>().lower_bound(std::pair<const CNetAddr&, bool>(*it, false));
        if (it_existing == m_index.get<ByAddress>().end() || *it_existing != static_cast<const CNetAddr&>(info)) break;
        Erase(it);
    }

    // first make space to add it (the existing tried entry there is moved to new, deleting whatever is there).
    info.fInTried = true;
    info.Rebucket(nKey, m_asmap);
    auto it_existing = m_index.get<ByBucket>().find(ByBucketExtractor()(info));
    if (it_existing != m_index.get<ByBucket>().end()) {
        // find an item to evict
        CAddrInfo info_evict = *it_existing;

        // Remove the to-be-evicted item from the tried set.
        Erase(it_existing);

        // find which new bucket it belongs to
        info_evict.fInTried = false;
        info_evict.Rebucket(nKey, m_asmap);
        auto it_new_existing = m_index.get<ByBucket>().find(ByBucketExtractor()(info_evict));
        if (it_new_existing != m_index.get<ByBucket>().end()) {
            Erase(it_new_existing);
        }

        // Enter it into the new set again.
        bool alias = m_index.get<ByAddress>().count(std::pair<const CNetAddr&, bool>(info_evict, false));
        Insert(std::move(info_evict), alias);
    }

    Insert(std::move(info), false);
}

void CAddrMan::Good_(const CService& addr, bool test_before_evict, int64_t nTime)
{
    AssertLockHeld(cs);

    nLastGood = nTime;

    auto it = m_index.get<ByAddress>().find(std::pair<const CNetAddr&, bool>(addr, false));

    // if not found, bail out
    if (it == m_index.get<ByAddress>().end()) return;

    const CAddrInfo& info = *it;

    // check whether we are talking about the exact same CService (including same port)
    if (info != addr) return;

    // update info
    Modify(it, [&](CAddrInfo& info) {
        info.nLastSuccess = nTime;
        info.nLastTry = nTime;
        info.nAttempts = 0;
    });
    // nTime is not updated here, to avoid leaking information about
    // currently-connected peers.

    // if it is already in the tried set, don't do anything else
    if (info.fInTried) return;

    // find a bucket it is in now
    std::advance(it, insecure_rand.randrange(CountAddr(addr)));

    // which tried bucket to move the entry to
    int tried_bucket = info.GetTriedBucket(nKey, m_asmap);
    int tried_bucket_pos = info.GetBucketPosition(nKey, false, tried_bucket);

    // Will moving this address into tried evict another entry?
    auto it_collision = m_index.get<ByBucket>().find(ByBucketView{true, tried_bucket, tried_bucket_pos});
    if (test_before_evict && it_collision != m_index.get<ByBucket>().end()) {
        // Output the entry we'd be colliding with, for debugging purposes
        LogPrint(BCLog::ADDRMAN, "Collision inserting element into tried table (%s), moving %s to m_tried_collisions=%d\n", it_collision->ToString(), addr.ToString(), m_tried_collisions.size());
        if (m_tried_collisions.size() < ADDRMAN_SET_TRIED_COLLISION_SIZE) {
            m_tried_collisions.insert(&*it);
        }
    } else {
        LogPrint(BCLog::ADDRMAN, "Moving %s to tried\n", addr.ToString());

        // move it to the tried tables
        MakeTried(it);
    }
}

bool CAddrMan::Add_(const CAddress& addr, const CNetAddr& source, int64_t nTimePenalty)
{
    AssertLockHeld(cs);

    if (!addr.IsRoutable())
        return false;

    auto it = m_index.get<ByAddress>().find(std::pair<const CNetAddr&, bool>(addr, false));

    // Do not set a penalty for a source's self-announcement
    if (addr == source) {
        nTimePenalty = 0;
    }

    CAddrInfo info(addr, source);
    info.fInTried = false;

    bool alias;
    if (it != m_index.get<ByAddress>().end()) {
        // periodically update nTime
        bool fCurrentlyOnline = (GetAdjustedTime() - addr.nTime < 24 * 60 * 60);
        int64_t nUpdateInterval = (fCurrentlyOnline ? 60 * 60 : 24 * 60 * 60);
        if (addr.nTime && (!it->nTime || it->nTime < addr.nTime - nUpdateInterval - nTimePenalty)) {
            Modify(it, [&](CAddrInfo& info) { info.nTime = std::max((int64_t)0, addr.nTime - nTimePenalty); });
        }

        // add services
        Modify(it, [&](CAddrInfo& info) { info.nServices = ServiceFlags(info.nServices | addr.nServices);});

        // do not update if no new information is present
        if (!addr.nTime || (it->nTime && addr.nTime <= it->nTime))
            return false;

        // do not update if the entry was already in the "tried" table
        if (it->fInTried)
            return false;

        // do not update if the max reference count is reached
        int aliases = CountAddr(addr);
        if (aliases == ADDRMAN_NEW_BUCKETS_PER_ADDRESS)
            return false;

        // stochastic test: previous nRefCount == N: 2^N times harder to increase it
        int nFactor = 1;
        for (int n = 0; n < aliases; n++)
            nFactor *= 2;
        if (nFactor > 1 && (insecure_rand.randrange(nFactor) != 0))
            return false;

        alias = true;
    } else {
        info.nTime = std::max((int64_t)0, (int64_t)addr.nTime - nTimePenalty);
        alias = false;
    }

    info.Rebucket(nKey, m_asmap);
    auto it_existing = m_index.get<ByBucket>().find(ByBucketExtractor()(info));
    if (it_existing == m_index.get<ByBucket>().end() || static_cast<const CNetAddr&>(*it_existing) != addr) {
        bool fInsert = it_existing == m_index.get<ByBucket>().end();
        if (!fInsert) {
            const CAddrInfo& infoExisting = *it_existing;
            if (infoExisting.IsTerrible() || (!alias && CountAddr(infoExisting) > 1)) {
                // Overwriting the existing new table entry.
                fInsert = true;
            }
        }
        if (fInsert) {
            if (it_existing != m_index.get<ByBucket>().end()) Erase(it_existing);
            Insert(std::move(info), alias);
        }
    }

    return !alias;
}

void CAddrMan::Attempt_(const CService& addr, bool fCountFailure, int64_t nTime)
{
    AssertLockHeld(cs);

    auto it = m_index.get<ByAddress>().find(std::pair<const CNetAddr&, bool>(addr, false));

    // if not found, bail out
    if (it == m_index.get<ByAddress>().end()) return;

    const CAddrInfo& info = *it;

    // check whether we are talking about the exact same CService (including same port)
    if (info != addr)
        return;

    // update info
    Modify(it, [&](CAddrInfo& info) {
        info.nLastTry = nTime;
        if (fCountFailure && info.nLastCountAttempt < nLastGood) {
            info.nLastCountAttempt = nTime;
            info.nAttempts++;
        }
    });
}

CAddrInfo CAddrMan::Select_(bool newOnly)
{
    AssertLockHeld(cs);

    if (m_index.empty()) return CAddrInfo();

    if (newOnly && nNew == 0) return CAddrInfo();

    // Use a 50% chance for choosing between tried and new table entries.
    if (!newOnly &&
       (nTried > 0 && (nNew == 0 || insecure_rand.randbool() == 0))) {
        // use a tried node
        double fChanceFactor = 1.0;
        while (1) {
            AddrManIndex::index<ByBucket>::type::iterator it;
            int nKBucket = insecure_rand.randrange(ADDRMAN_TRIED_BUCKET_COUNT);
            int nKBucketPos = insecure_rand.randrange(ADDRMAN_BUCKET_SIZE);
            int i;
            for (i = 0; i < ADDRMAN_BUCKET_SIZE; ++i) {
                it = m_index.get<ByBucket>().find(ByBucketView{true, nKBucket, nKBucketPos ^ i});
                if (it != m_index.get<ByBucket>().end()) break;
            }
            if (i == ADDRMAN_BUCKET_SIZE) continue;
            if (insecure_rand.randbits(30) < fChanceFactor * it->GetChance() * (1 << 30)) return *it;
            fChanceFactor *= 1.2;
        }
    } else {
        // use a new node
        double fChanceFactor = 1.0;
        while (1) {
            AddrManIndex::index<ByBucket>::type::iterator it;
            int nUBucket = insecure_rand.randrange(ADDRMAN_NEW_BUCKET_COUNT);
            int nUBucketPos = insecure_rand.randrange(ADDRMAN_BUCKET_SIZE);
            int i;
            for (i = 0; i < ADDRMAN_BUCKET_SIZE; ++i) {
                it = m_index.get<ByBucket>().find(ByBucketView{false, nUBucket, nUBucketPos ^ i});
                if (it != m_index.get<ByBucket>().end()) break;
            }
            if (i == ADDRMAN_BUCKET_SIZE) continue;
            if (insecure_rand.randbits(30) < fChanceFactor * it->GetChance() * (1 << 30)) return *it;
            fChanceFactor *= 1.2;
        }
    }
}

#ifdef DEBUG_ADDRMAN
int CAddrMan::Check_() const
{
    AssertLockHeld(cs);

    int counted_new = 0;
    int counted_tried = 0;

    for (auto it = m_index.get<ByAddress>().begin(); it != m_index.get<ByAddress>().end(); ++it) {
        const CAddrInfo& info = *it;
        if (info.nRandomPos == -1) {
            // Tried entries cannot have aliases.
            if (info.fInTried) return -1;
            // Aliases must have the same address as their precessor in this iteration order.
            if (it == m_index.get<ByAddress>().begin() || static_cast<const CNetAddr&>(info) != *std::prev(it)) return -2;
        } else {
            if (info.nRandomPos >= vRandom.size()) return -22;
            if (vRandom[info.nRandomPos] != it) return -23;
            if (info.fInTried) {
                counted_tried++;
            } else {
                counted_new++;
            }
            // Non-alias entries must have a different address as their predecessor in this iteration order.
            if (it != m_index.get<ByAddress>().begin() && static_cast<const CNetAddr&>(info) == *std::prev(it)) return -3;
        }

        CAddrInfo copy = info;
        copy.Rebucket(nKey, m_asmap);
        if (copy.m_bucket != info.m_bucket || copy.m_bucketpos != info.m_bucketpos) return -5;
    }

    if (counted_new != nNew) return -6;
    if (counted_tried != nTried) return -7;
    if (counted_new + counted_tried != vRandom.size()) return -8;

    for (auto it = m_index.get<ByBucket>().begin(); it != m_index.get<ByBucket>().end(); ++it) {
        if (it != m_index.get<ByBucket>().begin()) {
            if (it->fInTried == std::prev(it)->fInTried &&
                it->m_bucket == std::prev(it)->m_bucket &&
                it->m_bucketpos == std::prev(it)->m_bucketpos) {
                return -10;
            }
        }
    }

    return 0;
}
#endif

void CAddrMan::GetAddr_(std::vector<CAddress>& vAddr, size_t max_addresses, size_t max_pct, std::optional<Network> network)
{
    AssertLockHeld(cs);

    size_t nNodes = vRandom.size();
    if (max_pct != 0) {
        nNodes = max_pct * nNodes / 100;
    }
    if (max_addresses != 0) {
        nNodes = std::min(nNodes, max_addresses);
    }

    // gather a list of random nodes, skipping those of low quality
    const int64_t now{GetAdjustedTime()};
    for (unsigned int n = 0; n < vRandom.size(); n++) {
        if (vAddr.size() >= nNodes)
            break;

        int nRndPos = insecure_rand.randrange(vRandom.size() - n) + n;
        SwapRandom(n, nRndPos);

        const CAddrInfo& ai = *vRandom[n];

        // Filter by network (optional)
        if (network != std::nullopt && ai.GetNetClass() != network) continue;

        // Filter for quality
        if (ai.IsTerrible(now)) continue;

        vAddr.push_back(ai);
    }
}

void CAddrMan::Connected_(const CService& addr, int64_t nTime)
{
    AssertLockHeld(cs);

    auto it = m_index.get<ByAddress>().find(std::pair<const CNetAddr&, bool>(addr, false));

    // if not found, bail out
    if (it == m_index.get<ByAddress>().end()) return;

    const CAddrInfo& info = *it;

    // check whether we are talking about the exact same CService (including same port)
    if (info != addr) return;

    // update info
    int64_t nUpdateInterval = 20 * 60;
    if (nTime - info.nTime > nUpdateInterval) {
        Modify(it, [&](CAddrInfo& info){ info.nTime = nTime; });
    }
}

void CAddrMan::SetServices_(const CService& addr, ServiceFlags nServices)
{
    AssertLockHeld(cs);

    auto it = m_index.get<ByAddress>().find(std::pair<const CNetAddr&, bool>(addr, false));

    // if not found, bail out
    if (it == m_index.get<ByAddress>().end()) return;

    // check whether we are talking about the exact same CService (including same port)
    if (*it != addr) return;

    // update info
    Modify(it, [&](CAddrInfo& info){ info.nServices = nServices; });
}

void CAddrMan::ResolveCollisions_()
{
    AssertLockHeld(cs);

    for (auto it = m_tried_collisions.begin(); it != m_tried_collisions.end();) {
        auto it_old = *it;
        auto next_it = std::next(it); // Needs to be precomputed, as it may be deleted by the Good_() calls.

        bool erase_collision = false;

        {
            const CAddrInfo& info_new = **it;

            // Which tried bucket to move the entry to.
            int tried_bucket = info_new.GetTriedBucket(nKey, m_asmap);
            int tried_bucket_pos = info_new.GetBucketPosition(nKey, false, tried_bucket);
            auto it_old = m_index.get<ByBucket>().find(ByBucketView{true, tried_bucket, tried_bucket_pos});
            if (it_old != m_index.get<ByBucket>().end()) { // The position in the tried bucket is not empty

                // Get the to-be-evicted address that is being tested
                const CAddrInfo& info_old = *it_old;

                // Has successfully connected in last X hours
                if (GetAdjustedTime() - info_old.nLastSuccess < ADDRMAN_REPLACEMENT_HOURS*(60*60)) {
                    erase_collision = true;
                } else if (GetAdjustedTime() - info_old.nLastTry < ADDRMAN_REPLACEMENT_HOURS*(60*60)) { // attempted to connect and failed in last X hours

                    // Give address at least 60 seconds to successfully connect
                    if (GetAdjustedTime() - info_old.nLastTry > 60) {
                        LogPrint(BCLog::ADDRMAN, "Replacing %s with %s in tried table\n", info_old.ToString(), info_new.ToString());

                        // Replaces an existing address already in the tried table with the new address
                        Good_(info_new, false, GetAdjustedTime());
                        erase_collision = true;
                    }
                } else if (GetAdjustedTime() - info_new.nLastSuccess > ADDRMAN_TEST_WINDOW) {
                    // If the collision hasn't resolved in some reasonable amount of time,
                    // just evict the old entry -- we must not be able to
                    // connect to it for some reason.
                    LogPrint(BCLog::ADDRMAN, "Unable to test; replacing %s with %s in tried table anyway\n", info_old.ToString(), info_new.ToString());
                    Good_(info_new, false, GetAdjustedTime());
                    erase_collision = true;
                }
            } else { // Collision is not actually a collision anymore
                Good_(info_new, false, GetAdjustedTime());
                erase_collision = true;
            }
        }

        if (erase_collision) {
            m_tried_collisions.erase(it_old);
        }
        it = next_it;
    }
}

CAddrInfo CAddrMan::SelectTriedCollision_()
{
    AssertLockHeld(cs);

    if (m_tried_collisions.size() == 0) return CAddrInfo();

    auto it = m_tried_collisions.begin();

    // Selects a random element from m_tried_collisions
    std::advance(it, insecure_rand.randrange(m_tried_collisions.size()));
    auto it_new = *it;

    const CAddrInfo& newInfo = *it_new;

    // which tried bucket to move the entry to
    int tried_bucket = newInfo.GetTriedBucket(nKey, m_asmap);
    int tried_bucket_pos = newInfo.GetBucketPosition(nKey, false, tried_bucket);

    auto it_old = m_index.get<ByBucket>().find(ByBucketView{true, tried_bucket, tried_bucket_pos});

    if (it_old != m_index.get<ByBucket>().end()) return *it_old;
    return CAddrInfo();
}

std::vector<bool> CAddrMan::DecodeAsmap(fs::path path)
{
    std::vector<bool> bits;
    FILE *filestr = fsbridge::fopen(path, "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open asmap file from disk\n");
        return bits;
    }
    fseek(filestr, 0, SEEK_END);
    int length = ftell(filestr);
    LogPrintf("Opened asmap file %s (%d bytes) from disk\n", path, length);
    fseek(filestr, 0, SEEK_SET);
    uint8_t cur_byte;
    for (int i = 0; i < length; ++i) {
        file >> cur_byte;
        for (int bit = 0; bit < 8; ++bit) {
            bits.push_back((cur_byte >> bit) & 1);
        }
    }
    if (!SanityCheckASMap(bits)) {
        LogPrintf("Sanity check of asmap file %s failed\n", path);
        return {};
    }
    return bits;
}

void CAddrMan::EraseInner(AddrManIndex::index<ByAddress>::type::iterator it)
{
    AssertLockHeld(cs);

    if (it->nRandomPos != -1) {
        // In case the entry being deleted has an alias, we don't delete the requested one, but
        // the alias instead. The alias' source IP is moved to the actual entry however, so
        // it is preserved.
        auto it_alias = m_index.get<ByAddress>().find(std::make_pair<const CNetAddr&, bool>(*it, true));
        if (it_alias != m_index.get<ByAddress>().end()) {
            if (m_tried_collisions.count(&*it_alias)) m_tried_collisions.insert(&*it);
            Modify(it, [&](CAddrInfo& info) { info.source = it_alias->source; });
            it = it_alias;
        } else {
            // Actually deleting a non-alias entry; remove it from vRandom.
            SwapRandom(it->nRandomPos, vRandom.size() - 1);
            vRandom.pop_back();
        }
    }

    m_tried_collisions.erase(&*it);
    UpdateStat(*it, -1);
    m_index.erase(it);
}

void CAddrMan::UpdateStat(const CAddrInfo& info, int inc)
{
    if (info.nRandomPos != -1) {
        if (info.fInTried) {
            nTried += inc;
        } else {
            nNew += inc;
        }
    }
}

int CAddrMan::CountAddr(const CNetAddr& addr) const
{
    AssertLockHeld(cs);
    auto it = m_index.get<ByAddress>().lower_bound(std::pair<const CNetAddr&, bool>(addr, false));
    if (it == m_index.get<ByAddress>().end()) return 0;
    auto it_end = m_index.get<ByAddress>().upper_bound(std::pair<const CNetAddr&, bool>(addr, true));
    return std::distance(it, it_end);
}
