// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <minisketch.h>
#include <net.h>
#include <node/minisketchwrapper.h>
#include <node/txreconciliation.h>
#include <node/txreconciliation_impl.h>
#include <primitives/transaction_identifier.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/random.h>
#include <test/util/time.h>
#include <uint256.h>
#include <util/check.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <variant>
#include <vector>

using node::AddToSetError;
using node::BYTES_PER_SKETCH_CAPACITY;
using node::ComputeSalt;
using node::HandleSketchResult;
using node::MakeMinisketch32;
using node::MAX_RECONSET_SIZE;
using node::MAX_SKETCH_CAPACITY;
using node::Q_PRECISION;
using node::RECON_FALSE_POSITIVE_COEF;
using node::RECON_FIELD_SIZE;
using node::RECON_REQUEST_INTERVAL;
using node::ReconCoefficients;
using node::ReconciliationError;
using node::ReconciliationPhase;
using node::TXRECONCILIATION_VERSION;
using node::TxReconciliationState;
using node::TxReconciliationTracker;

namespace {

//! Number of wtxids the fuzzer picks from. Few enough that the same transactions keep showing up
//! across peers and rounds.
constexpr uint32_t NUM_WTXIDS{64};
//! Maximum capacity of the well-formed sketches fuzzed peers send. Decoding is quadratic in the
//! capacity, so larger ones would only slow the fuzzer down. The limits the tracker enforces are
//! exercised with sketches that get rejected before being decoded.
constexpr uint32_t MAX_FUZZ_CAPACITY{64};
//! Maximum number of connections over the lifetime of a fuzz input.
constexpr size_t MAX_CONNECTIONS{8};

//! Two wtxids whose short ids collide on a link salted with 1 and 2, see txreconciliation_tests.
const Wtxid COLLIDING_WTXID_1{Wtxid::FromUint256(uint256{"fdfb332e93ecd3b28835f51f9d999278dba2c10fb45611229a17136a00a4d3c9"})};
const Wtxid COLLIDING_WTXID_2{Wtxid::FromUint256(uint256{"8f16f117d30b68c6fcdd1ee033d2b4f8aba719088e5aff78c8f9536aeb1388b4"})};

//! Wtxids the fuzzer picks from, including the colliding pair.
std::vector<Wtxid> g_wtxids;
//! Enough other wtxids to fill up a reconciliation set.
std::vector<Wtxid> g_fillers;

void initialize_txreconciliation()
{
    for (uint32_t i{0}; i < NUM_WTXIDS; ++i) {
        g_wtxids.push_back(Wtxid::FromUint256((HashWriter{} << i).GetSHA256()));
    }
    g_wtxids.push_back(COLLIDING_WTXID_1);
    g_wtxids.push_back(COLLIDING_WTXID_2);
    for (uint32_t i{0}; i <= MAX_RECONSET_SIZE; ++i) {
        g_fillers.push_back(Wtxid::FromUint256((HashWriter{} << (NUM_WTXIDS + i)).GetSHA256()));
    }
    // Picking a minisketch implementation benchmarks all of them, get that out of the way.
    (void)MakeMinisketch32(1);
}

uint64_t ConsumeSalt(FuzzedDataProvider& fuzzed_data_provider)
{
    // Small salts make the colliding pair of wtxids reachable.
    return fuzzed_data_provider.ConsumeBool() ? fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(0, 3) :
                                                fuzzed_data_provider.ConsumeIntegral<uint64_t>();
}

const Wtxid& ConsumeWtxid(FuzzedDataProvider& fuzzed_data_provider)
{
    return PickValue(fuzzed_data_provider, g_wtxids);
}

uint32_t ConsumeShortId(FuzzedDataProvider& fuzzed_data_provider)
{
    return fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(1, std::numeric_limits<uint32_t>::max());
}

//! A reconciliation set: transactions by their short id on a given link.
using ShortIdMap = std::map<uint32_t, Wtxid>;

std::set<uint32_t> ShortIdsOf(const ShortIdMap& set)
{
    std::set<uint32_t> short_ids;
    for (const auto& entry : set) short_ids.insert(entry.first);
    return short_ids;
}

std::set<Wtxid> WtxidsOf(const ShortIdMap& set)
{
    std::set<Wtxid> wtxids;
    for (const auto& entry : set) wtxids.insert(entry.second);
    return wtxids;
}

template <typename T>
std::set<T> ToSetWithoutDuplicates(const std::vector<T>& elements)
{
    std::set<T> result(elements.begin(), elements.end());
    Assert(result.size() == elements.size());
    return result;
}

/** Serialized sketch of the given short ids. */
std::vector<uint8_t> SketchOf(const std::set<uint32_t>& short_ids, uint32_t capacity)
{
    if (capacity == 0) return {};
    Minisketch sketch{MakeMinisketch32(capacity)};
    for (const uint32_t short_id : short_ids) sketch.Add(short_id);
    return sketch.Serialize();
}

/** Decode the difference between our short ids and a sketch received from the peer, as the
 *  initiator does. Returns std::nullopt if the sketch was not large enough to decode it. */
std::optional<std::set<uint32_t>> DecodeDifference(const std::set<uint32_t>& ours, const std::vector<uint8_t>& skdata)
{
    Assert(!skdata.empty() && skdata.size() % BYTES_PER_SKETCH_CAPACITY == 0);
    const uint32_t capacity{static_cast<uint32_t>(skdata.size() / BYTES_PER_SKETCH_CAPACITY)};
    Minisketch theirs{MakeMinisketch32(capacity)};
    theirs.Deserialize(skdata);
    Minisketch sketch{MakeMinisketch32(capacity)};
    // Sketches are randomly seeded by default. The result does not depend on it, the path taken does.
    sketch.SetSeed(std::numeric_limits<uint64_t>::max());
    for (const uint32_t short_id : ours) sketch.Add(short_id);
    std::vector<uint64_t> difference(minisketch_compute_max_elements(RECON_FIELD_SIZE, capacity, RECON_FALSE_POSITIVE_COEF));
    if (!sketch.Merge(theirs).Decode(difference)) return std::nullopt;
    std::set<uint32_t> result;
    for (const uint64_t element : difference) {
        Assert(element > 0 && element <= std::numeric_limits<uint32_t>::max());
        result.insert(static_cast<uint32_t>(element));
    }
    return result;
}

/** What the initiator does with a decoded difference. */
struct DifferenceSplit {
    //! Short ids of the transactions we are missing, to request.
    std::set<uint32_t> to_request;
    //! Our transactions the peer is missing, to announce.
    std::set<Wtxid> to_announce;
};

DifferenceSplit SplitDifference(const std::set<uint32_t>& difference, const ShortIdMap& ours)
{
    DifferenceSplit split;
    for (const uint32_t short_id : difference) {
        if (const auto it{ours.find(short_id)}; it != ours.end()) {
            split.to_announce.insert(it->second);
        } else {
            split.to_request.insert(short_id);
        }
    }
    return split;
}

void CheckSketchResult(const HandleSketchResult& result, std::optional<bool> succeeded,
                       const std::set<uint32_t>& to_request, const std::set<Wtxid>& to_announce)
{
    Assert(result.m_succeeded == succeeded);
    Assert(ToSetWithoutDuplicates(result.m_txs_to_request) == to_request);
    Assert(ToSetWithoutDuplicates(result.m_txs_to_announce) == to_announce);
}

template <typename T>
void AssertError(const std::variant<T, ReconciliationError>& result, ReconciliationError error)
{
    Assert(std::holds_alternative<ReconciliationError>(result));
    Assert(std::get<ReconciliationError>(result) == error);
}

HandleSketchResult ExpectSketchResult(const std::variant<HandleSketchResult, ReconciliationError>& result)
{
    Assert(std::holds_alternative<HandleSketchResult>(result));
    return std::get<HandleSketchResult>(result);
}

TxReconciliationState MakeLink(bool we_initiate, uint64_t salt1, uint64_t salt2)
{
    const uint256 full_salt{ComputeSalt(salt1, salt2)};
    return TxReconciliationState{we_initiate, full_salt.GetUint64(0), full_salt.GetUint64(1)};
}

/** Naive reimplementation of the reconciliation state kept for a registered peer. */
struct SimRecon {
    //! Whether we initiate reconciliations, i.e. the peer is an outbound connection.
    const bool we_initiate;
    //! Only used to compute the short ids of this link.
    const TxReconciliationState link;
    ReconciliationPhase phase{ReconciliationPhase::NONE};
    //! Transactions we would announce to the peer.
    ShortIdMap set;
    //! The set as it was sketched for the ongoing round.
    ShortIdMap snapshot;
    //! Snapshotted transactions that the peer announced to us, or that left our mempool, during the round.
    std::set<Wtxid> announced_while_reconciling;
    //! Responder: the set size the peer reported in its request, as clamped.
    uint16_t remote_set_size{0};
    //! Responder: capacity of the initial sketch sent, and of everything sketched in the round.
    uint32_t initial_capacity{0};
    uint32_t sketched_capacity{0};
    //! Initiator: the initial sketch received, which an extension completes.
    std::vector<uint8_t> remote_sketch;

    SimRecon(bool we_initiate_in, uint64_t local_salt, uint64_t remote_salt)
        : we_initiate{we_initiate_in}, link{MakeLink(we_initiate_in, local_salt, remote_salt)} {}

    uint32_t ShortId(const Wtxid& wtxid) const { return link.ComputeShortID(wtxid); }
};

struct SimPeer {
    //! Set while the peer is pre-registered.
    std::optional<uint64_t> local_salt;
    //! Set once the peer is registered.
    std::optional<SimRecon> recon;
};

/**
 * A TxReconciliationTracker, together with a naive reimplementation of its behavior.
 *
 * Each public member function calls its TxReconciliationTracker counterpart, checks the result
 * against what the reimplementation expects, and applies the same change to the reimplementation.
 */
class TrackerSim
{
    using SketchResult = std::variant<HandleSketchResult, ReconciliationError>;

    TxReconciliationTracker m_tracker{TXRECONCILIATION_VERSION};
    std::map<NodeId, SimPeer> m_peers;
    //! Outbound peers in the order we initiate reconciliations with them.
    std::deque<NodeId> m_queue;
    std::chrono::microseconds m_next_request{0};

    SimRecon* Recon(NodeId peer)
    {
        const auto it{m_peers.find(peer)};
        return it != m_peers.end() && it->second.recon ? &*it->second.recon : nullptr;
    }

    /** Remove a transaction from the peer's set, and remember it if it is in the snapshot. */
    static bool Remove(SimRecon& recon, const Wtxid& wtxid)
    {
        const uint32_t short_id{recon.ShortId(wtxid)};
        bool removed{false};
        if (const auto it{recon.set.find(short_id)}; it != recon.set.end() && it->second == wtxid) {
            recon.set.erase(it);
            removed = true;
        }
        if (const auto it{recon.snapshot.find(short_id)}; it != recon.snapshot.end() && it->second == wtxid) {
            recon.announced_while_reconciling.insert(wtxid);
        }
        return removed;
    }

    /** Move the set to the snapshot, to keep sketching the same transactions until the round ends. */
    static void Snapshot(SimRecon& recon)
    {
        Assert(recon.snapshot.empty());
        recon.snapshot.swap(recon.set);
    }

    static void EndRound(SimRecon& recon)
    {
        // The initiator only snapshotted its set if it asked for an extension, in which case what it
        // added since is for the next round.
        if (recon.we_initiate && recon.phase != ReconciliationPhase::EXT_REQUESTED) recon.set.clear();
        recon.snapshot.clear();
        recon.announced_while_reconciling.clear();
        recon.remote_sketch.clear();
        recon.initial_capacity = 0;
        recon.sketched_capacity = 0;
        recon.phase = ReconciliationPhase::NONE;
    }

    static void HandleInitialSketch(SimRecon& recon, const std::vector<uint8_t>& skdata, const SketchResult& result)
    {
        if (skdata.size() % BYTES_PER_SKETCH_CAPACITY != 0 || skdata.size() / BYTES_PER_SKETCH_CAPACITY > MAX_SKETCH_CAPACITY) {
            AssertError(result, ReconciliationError::PROTOCOL_VIOLATION);
            return;
        }
        const HandleSketchResult actual{ExpectSketchResult(result)};
        if (skdata.empty() || recon.set.empty()) {
            // Reconciliation cannot help, so we announce everything we have for the peer instead.
            CheckSketchResult(actual, /*succeeded=*/false, /*to_request=*/{}, WtxidsOf(recon.set));
            EndRound(recon);
        } else if (const auto difference{DecodeDifference(ShortIdsOf(recon.set), skdata)}) {
            const auto split{SplitDifference(*difference, recon.set)};
            CheckSketchResult(actual, /*succeeded=*/true, split.to_request, split.to_announce);
            EndRound(recon);
        } else {
            // Keep what we sketched for the extension we ask for.
            CheckSketchResult(actual, /*succeeded=*/std::nullopt, /*to_request=*/{}, /*to_announce=*/{});
            Snapshot(recon);
            recon.remote_sketch = skdata;
            recon.phase = ReconciliationPhase::EXT_REQUESTED;
        }
    }

    static void HandleSketchExtension(SimRecon& recon, const std::vector<uint8_t>& skdata, const SketchResult& result)
    {
        const size_t size{recon.remote_sketch.size() + skdata.size()};
        if (size % BYTES_PER_SKETCH_CAPACITY != 0 || size / BYTES_PER_SKETCH_CAPACITY > 2 * MAX_SKETCH_CAPACITY) {
            AssertError(result, ReconciliationError::PROTOCOL_VIOLATION);
            return;
        }
        const HandleSketchResult actual{ExpectSketchResult(result)};
        // The extension completes the sketch received initially.
        auto extended{recon.remote_sketch};
        extended.insert(extended.end(), skdata.begin(), skdata.end());
        const auto difference{DecodeDifference(ShortIdsOf(recon.snapshot), extended)};
        DifferenceSplit split;
        if (difference) {
            split = SplitDifference(*difference, recon.snapshot);
        } else {
            split.to_announce = WtxidsOf(recon.snapshot);
        }
        for (const Wtxid& wtxid : recon.announced_while_reconciling) split.to_announce.erase(wtxid);
        CheckSketchResult(actual, /*succeeded=*/difference.has_value(), split.to_request, split.to_announce);
        EndRound(recon);
    }

public:
    const SimRecon* GetRecon(NodeId peer) const
    {
        const auto it{m_peers.find(peer)};
        return it != m_peers.end() && it->second.recon ? &*it->second.recon : nullptr;
    }
    const std::deque<NodeId>& Queue() const { return m_queue; }
    std::chrono::microseconds NextRequest() const { return m_next_request; }

    void Check(NodeId peer) const
    {
        Assert(m_tracker.IsPeerRegistered(peer) == (GetRecon(peer) != nullptr));
    }

    void CheckEmpty() const
    {
        Assert(m_queue.empty());
        for (const auto& [id, peer] : m_peers) {
            Assert(!peer.local_salt && !peer.recon);
            Assert(!m_tracker.IsPeerRegistered(id));
        }
    }

    void PreRegisterPeer(NodeId peer, uint64_t local_salt)
    {
        SimPeer& sim{m_peers[peer]};
        // Peer ids are never reused, and a peer is offered reconciliation at most once.
        Assert(!sim.local_salt && !sim.recon);
        m_tracker.PreRegisterPeerWithSalt(peer, local_salt);
        sim.local_salt = local_salt;
        Check(peer);
    }

    std::optional<ReconciliationError> RegisterPeer(NodeId peer, bool is_peer_inbound, uint32_t peer_version, uint64_t remote_salt)
    {
        const auto result{m_tracker.RegisterPeer(peer, is_peer_inbound, peer_version, remote_salt)};
        SimPeer& sim{m_peers[peer]};
        if (sim.recon) {
            Assert(result == ReconciliationError::ALREADY_REGISTERED);
        } else if (!sim.local_salt) {
            Assert(result == ReconciliationError::NOT_FOUND);
        } else if (peer_version < 1) {
            Assert(result == ReconciliationError::PROTOCOL_VIOLATION);
        } else {
            Assert(!result);
            sim.recon.emplace(/*we_initiate_in=*/!is_peer_inbound, *sim.local_salt, remote_salt);
            sim.local_salt.reset();
            if (!is_peer_inbound) {
                m_queue.push_back(peer);
                if (m_queue.size() == 1) m_next_request = GetTime<std::chrono::microseconds>() + RECON_REQUEST_INTERVAL / m_queue.size();
            }
        }
        Check(peer);
        return result;
    }

    bool IsPeerRegistered(NodeId peer) const
    {
        Check(peer);
        return GetRecon(peer) != nullptr;
    }

    bool ForgetPeer(NodeId peer)
    {
        const bool forgotten{m_tracker.ForgetPeer(peer)};
        SimPeer& sim{m_peers[peer]};
        Assert(forgotten == (sim.local_salt || sim.recon));
        if (sim.recon && sim.recon->we_initiate) {
            m_queue.erase(std::remove(m_queue.begin(), m_queue.end(), peer), m_queue.end());
        }
        sim.local_salt.reset();
        sim.recon.reset();
        Check(peer);
        return forgotten;
    }

    bool IsPeerNextToReconcileWith(NodeId peer, std::chrono::microseconds now)
    {
        const bool next{m_tracker.IsPeerNextToReconcileWith(peer, now)};
        SimRecon* recon{Recon(peer)};
        const bool expected{recon && !m_queue.empty() && m_next_request <= now && m_queue.front() == peer};
        Assert(next == expected);
        if (expected) {
            Assert(recon->we_initiate);
            m_queue.pop_front();
            m_queue.push_back(peer);
            // A peer still busy with its previous round does not hold up the next one in the queue.
            if (recon->phase == ReconciliationPhase::NONE) m_next_request = now + RECON_REQUEST_INTERVAL / m_queue.size();
        }
        return next;
    }

    std::optional<AddToSetError> AddToSet(NodeId peer, const Wtxid& wtxid)
    {
        const auto result{m_tracker.AddToSet(peer, wtxid)};
        SimRecon* recon{Recon(peer)};
        if (!recon) {
            Assert(result && result->m_error == ReconciliationError::NOT_FOUND && !result->m_collision);
            return result;
        }
        const uint32_t short_id{recon->ShortId(wtxid)};
        const auto it{recon->set.find(short_id)};
        if (it != recon->set.end() && it->second == wtxid) {
            // Already in the set.
            Assert(!result);
        } else if (it != recon->set.end()) {
            Assert(result && result->m_error == ReconciliationError::SHORTID_COLLISION && result->GetCollision() == it->second);
        } else if (recon->set.size() >= MAX_RECONSET_SIZE) {
            Assert(result && result->m_error == ReconciliationError::FULL_RECON_SET && !result->m_collision);
        } else {
            Assert(!result);
            recon->set.emplace(short_id, wtxid);
        }
        return result;
    }

    bool TryRemovingFromSet(NodeId peer, const Wtxid& wtxid)
    {
        const bool removed{m_tracker.TryRemovingFromSet(peer, wtxid)};
        SimRecon* recon{Recon(peer)};
        const bool expected{recon && Remove(*recon, wtxid)};
        Assert(removed == expected);
        return removed;
    }

    void RemoveFromSets(const std::vector<Wtxid>& wtxids)
    {
        m_tracker.RemoveFromSets(wtxids);
        for (auto& [_, peer] : m_peers) {
            if (!peer.recon) continue;
            for (const Wtxid& wtxid : wtxids) Remove(*peer.recon, wtxid);
        }
    }

    std::variant<ReconCoefficients, ReconciliationError> InitiateReconciliationRequest(NodeId peer)
    {
        const auto result{m_tracker.InitiateReconciliationRequest(peer)};
        SimRecon* recon{Recon(peer)};
        if (!recon) {
            AssertError(result, ReconciliationError::NOT_FOUND);
        } else if (!recon->we_initiate) {
            AssertError(result, ReconciliationError::WRONG_ROLE);
        } else if (recon->phase != ReconciliationPhase::NONE) {
            AssertError(result, ReconciliationError::WRONG_PHASE);
        } else {
            Assert(std::holds_alternative<ReconCoefficients>(result));
            const auto& [set_size, q]{std::get<ReconCoefficients>(result)};
            Assert(size_t{set_size} == recon->set.size());
            // Responders reject anything larger.
            Assert(q <= Q_PRECISION);
            recon->phase = ReconciliationPhase::INIT_REQUESTED;
        }
        return result;
    }

    std::optional<ReconciliationError> HandleReconciliationRequest(NodeId peer, uint16_t set_size, uint16_t q)
    {
        const auto result{m_tracker.HandleReconciliationRequest(peer, set_size, q)};
        SimRecon* recon{Recon(peer)};
        if (!recon) {
            Assert(result == ReconciliationError::NOT_FOUND);
        } else if (recon->we_initiate) {
            Assert(result == ReconciliationError::WRONG_ROLE);
        } else if (recon->phase != ReconciliationPhase::NONE) {
            Assert(result == ReconciliationError::WRONG_PHASE);
        } else if (q > Q_PRECISION) {
            Assert(result == ReconciliationError::PROTOCOL_VIOLATION);
        } else {
            Assert(!result);
            recon->remote_set_size = std::min(set_size, static_cast<uint16_t>(MAX_RECONSET_SIZE));
            recon->phase = ReconciliationPhase::INIT_REQUESTED;
        }
        return result;
    }

    bool ShouldRespondToReconciliationRequest(NodeId peer, std::vector<uint8_t>& skdata)
    {
        Assert(skdata.empty());
        const bool respond{m_tracker.ShouldRespondToReconciliationRequest(peer, skdata)};
        SimRecon* recon{Recon(peer)};
        if (!recon || recon->we_initiate ||
            (recon->phase != ReconciliationPhase::INIT_REQUESTED && recon->phase != ReconciliationPhase::EXT_REQUESTED)) {
            Assert(!respond && skdata.empty());
            return respond;
        }
        Assert(respond && skdata.size() % BYTES_PER_SKETCH_CAPACITY == 0);
        const uint32_t capacity{static_cast<uint32_t>(skdata.size() / BYTES_PER_SKETCH_CAPACITY)};
        if (recon->phase == ReconciliationPhase::INIT_REQUESTED) {
            const size_t ours{recon->set.size()};
            const size_t theirs{recon->remote_set_size};
            if (ours == 0 || theirs == 0) {
                // Reconciliation cannot help. An empty sketch makes the initiator announce everything instead.
                Assert(capacity == 0);
            } else {
                // The difference in set sizes is a lower bound for the set difference, and the larger set
                // an upper one.
                Assert(capacity >= 1 + std::max(ours, theirs) - std::min(ours, theirs));
                Assert(capacity <= minisketch_compute_capacity(RECON_FIELD_SIZE, 1 + std::max(ours, theirs), RECON_FALSE_POSITIVE_COEF));
                Assert(capacity <= MAX_SKETCH_CAPACITY);
                Assert(skdata == SketchOf(ShortIdsOf(recon->set), capacity));
            }
            Snapshot(*recon);
            recon->initial_capacity = capacity;
            recon->sketched_capacity = capacity;
            recon->phase = ReconciliationPhase::INIT_RESPONDED;
        } else {
            // An extension: the part not sent yet of a larger sketch, over the same transactions.
            Assert(capacity > 0);
            const uint32_t extended_capacity{recon->initial_capacity + capacity};
            const auto extended{SketchOf(ShortIdsOf(recon->snapshot), extended_capacity)};
            Assert(std::equal(skdata.begin(), skdata.end(), extended.begin() + recon->initial_capacity * BYTES_PER_SKETCH_CAPACITY, extended.end()));
            recon->sketched_capacity = extended_capacity;
            recon->phase = ReconciliationPhase::EXT_RESPONDED;
        }
        return respond;
    }

    SketchResult HandleSketch(NodeId peer, const std::vector<uint8_t>& skdata)
    {
        const auto result{m_tracker.HandleSketch(peer, skdata)};
        SimRecon* recon{Recon(peer)};
        if (!recon) {
            AssertError(result, ReconciliationError::NOT_FOUND);
        } else if (!recon->we_initiate) {
            AssertError(result, ReconciliationError::WRONG_ROLE);
        } else if (recon->phase == ReconciliationPhase::INIT_REQUESTED) {
            HandleInitialSketch(*recon, skdata, result);
        } else if (recon->phase == ReconciliationPhase::EXT_REQUESTED) {
            HandleSketchExtension(*recon, skdata, result);
        } else {
            AssertError(result, ReconciliationError::WRONG_PHASE);
        }
        return result;
    }

    std::optional<ReconciliationError> HandleExtensionRequest(NodeId peer)
    {
        const auto result{m_tracker.HandleExtensionRequest(peer)};
        SimRecon* recon{Recon(peer)};
        if (!recon) {
            Assert(result == ReconciliationError::NOT_FOUND);
        } else if (recon->we_initiate) {
            Assert(result == ReconciliationError::WRONG_ROLE);
        } else if (recon->phase != ReconciliationPhase::INIT_RESPONDED) {
            Assert(result == ReconciliationError::WRONG_PHASE);
        } else if (recon->initial_capacity == 0) {
            // After an empty sketch, the initiator has to end the round instead.
            Assert(result == ReconciliationError::PROTOCOL_VIOLATION);
        } else {
            Assert(!result);
            recon->phase = ReconciliationPhase::EXT_REQUESTED;
        }
        return result;
    }

    std::variant<std::vector<Wtxid>, ReconciliationError> HandleReconcilDiff(NodeId peer, bool success, const std::vector<uint32_t>& ask_short_ids)
    {
        const auto result{m_tracker.HandleReconcilDiff(peer, success, ask_short_ids)};
        SimRecon* recon{Recon(peer)};
        if (!recon) {
            AssertError(result, ReconciliationError::NOT_FOUND);
        } else if (recon->we_initiate) {
            AssertError(result, ReconciliationError::WRONG_ROLE);
        } else if (recon->phase != ReconciliationPhase::INIT_RESPONDED && recon->phase != ReconciliationPhase::EXT_RESPONDED) {
            AssertError(result, ReconciliationError::WRONG_PHASE);
        } else if (success && recon->initial_capacity == 0) {
            // Nothing can be decoded from an empty sketch.
            AssertError(result, ReconciliationError::PROTOCOL_VIOLATION);
        } else if (ask_short_ids.size() > recon->sketched_capacity) {
            // More than our sketches could have revealed.
            AssertError(result, ReconciliationError::PROTOCOL_VIOLATION);
        } else {
            Assert(std::holds_alternative<std::vector<Wtxid>>(result));
            std::set<Wtxid> expected;
            if (success) {
                for (const uint32_t short_id : ask_short_ids) {
                    if (const auto it{recon->snapshot.find(short_id)}; it != recon->snapshot.end()) expected.insert(it->second);
                }
            } else {
                expected = WtxidsOf(recon->snapshot);
            }
            for (const Wtxid& wtxid : recon->announced_while_reconciling) expected.erase(wtxid);
            Assert(ToSetWithoutDuplicates(std::get<std::vector<Wtxid>>(result)) == expected);
            EndRound(*recon);
        }
        return result;
    }
};

enum class ConnType {
    INBOUND,
    OUTBOUND_FULL_RELAY,
    OUTBOUND_RECONCILIATION,
};

/** What net_processing knows about a connection, as far as reconciliation is concerned. */
struct SimConnection {
    NodeId id;
    ConnType type;
    bool version_received{false};
    bool verack_received{false};
    bool disconnected{false};
    //! Short ids the peer sketched for the ongoing round, to send a consistent extension.
    std::set<uint32_t> remote_short_ids{};

    //! Until the version handshake completes, net_processing only reaches the tracker for this peer
    //! when processing VERSION, SENDTXRCNCL and VERACK.
    bool Ready() const { return verack_received && !disconnected; }
};

/** One end of a reconciliation link. */
struct LinkEnd {
    TrackerSim sim;
    //! Transactions this node has.
    std::set<Wtxid> known;
};

} // namespace

/**
 * Drive a single tracker the way net_processing does, on behalf of peers that may send anything,
 * and compare each result with the naive reimplementation.
 */
FUZZ_TARGET(txreconciliation, .init = initialize_txreconciliation)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    FakeNodeClock clock{ConsumeTime(fuzzed_data_provider)};

    TrackerSim sim;
    std::vector<SimConnection> connections;
    connections.reserve(MAX_CONNECTIONS);
    // While in IBD, net_processing neither initiates reconciliations nor adds to the sets.
    bool in_ibd{fuzzed_data_provider.ConsumeBool()};
    // Rounds over a full set are expensive, so only fill one up a couple of times.
    int fills_left{2};

    const auto pick{[&]() -> SimConnection* {
        return connections.empty() ? nullptr : &PickValue(fuzzed_data_provider, connections);
    }};

    // The peer disconnects, or violated the protocol and gets disconnected.
    const auto disconnect{[&](SimConnection& conn) {
        if (conn.disconnected) return;
        conn.disconnected = true;
        sim.ForgetPeer(conn.id);
    }};

    // A SendMessages call for the peer. With `trickle`, it is time to announce transactions to it.
    const auto send_messages{[&](SimConnection& conn, bool trickle) {
        if (!conn.Ready()) return;
        const auto now{GetTime<std::chrono::microseconds>()};
        const bool reconcile{!in_ibd && sim.IsPeerNextToReconcileWith(conn.id, now)};
        if (trickle && !in_ibd && sim.IsPeerRegistered(conn.id)) {
            // Transactions due for announcement go to the reconciliation set instead.
            std::vector<Wtxid> due;
            if (fills_left > 0 && fuzzed_data_provider.ConsumeBool()) {
                --fills_left;
                due = g_fillers;
            } else {
                LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 8) due.push_back(ConsumeWtxid(fuzzed_data_provider));
            }
            for (const Wtxid& wtxid : due) {
                const auto error{sim.AddToSet(conn.id, wtxid)};
                if (error && error->m_error == ReconciliationError::SHORTID_COLLISION) {
                    // Colliding transactions cannot be told apart, so both get announced instead.
                    const bool removed{sim.TryRemovingFromSet(conn.id, error->GetCollision())};
                    Assert(removed);
                }
            }
        }
        std::vector<uint8_t> skdata;
        sim.ShouldRespondToReconciliationRequest(conn.id, skdata);
        if (reconcile) sim.InitiateReconciliationRequest(conn.id);
    }};

    // A pass of the message handler thread over all peers.
    const auto send_messages_to_all{[&] {
        for (SimConnection& conn : connections) send_messages(conn, /*trickle=*/false);
        const auto& queue{sim.Queue()};
        if (in_ibd || queue.empty() || sim.NextRequest() > GetTime<std::chrono::microseconds>()) return;
        // A request is still due after every peer had a SendMessages call. Only peers that completed
        // the handshake get to consult the queue, so one that has not cannot be holding up the others.
        const auto consults_queue{[&](NodeId id) {
            return std::ranges::any_of(connections, [&](const SimConnection& conn) { return conn.id == id && conn.Ready(); });
        }};
        Assert(consults_queue(queue.front()) || std::ranges::none_of(queue, consults_queue));
    }};

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 500)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                if (connections.size() >= MAX_CONNECTIONS) return;
                connections.push_back({.id = static_cast<NodeId>(connections.size()),
                                       .type = fuzzed_data_provider.PickValueInArray({ConnType::INBOUND, ConnType::OUTBOUND_FULL_RELAY, ConnType::OUTBOUND_RECONCILIATION})});
            },
            [&] {
                // VERSION. We offer reconciliation to outbound reconciliation peers, and to inbound
                // ones while there is room for them, if both sides relay transactions.
                SimConnection* conn{pick()};
                if (!conn || conn->version_received || conn->disconnected) return;
                conn->version_received = true;
                if (conn->type != ConnType::OUTBOUND_FULL_RELAY && fuzzed_data_provider.ConsumeBool()) {
                    sim.PreRegisterPeer(conn->id, ConsumeSalt(fuzzed_data_provider));
                }
            },
            [&] {
                // SENDTXRCNCL
                SimConnection* conn{pick()};
                if (!conn || !conn->version_received || conn->verack_received || conn->disconnected) return;
                const uint32_t version{fuzzed_data_provider.ConsumeBool() ? TXRECONCILIATION_VERSION : fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
                const auto error{sim.RegisterPeer(conn->id, conn->type == ConnType::INBOUND, version, ConsumeSalt(fuzzed_data_provider))};
                // An unsolicited SENDTXRCNCL is ignored, anything else is a protocol violation.
                if (error && *error != ReconciliationError::NOT_FOUND) disconnect(*conn);
            },
            [&] {
                // VERACK. Reconciliation must have been negotiated by now, alongside wtxid relay.
                SimConnection* conn{pick()};
                if (!conn || !conn->version_received || conn->verack_received || conn->disconnected) return;
                conn->verack_received = true;
                const bool wtxid_relay{fuzzed_data_provider.ConsumeBool()};
                if (!wtxid_relay || !sim.IsPeerRegistered(conn->id)) {
                    sim.ForgetPeer(conn->id);
                    // Outbound reconciliation slots are reserved for peers that negotiate it.
                    if (conn->type == ConnType::OUTBOUND_RECONCILIATION) disconnect(*conn);
                }
            },
            [&] {
                if (SimConnection* conn{pick()}) disconnect(*conn);
            },
            [&] {
                if (SimConnection* conn{pick()}) send_messages(*conn, /*trickle=*/fuzzed_data_provider.ConsumeBool());
            },
            [&] {
                send_messages_to_all();
            },
            [&] {
                // REQTXRCNCL
                SimConnection* conn{pick()};
                if (!conn || !conn->Ready()) return;
                const uint16_t set_size{fuzzed_data_provider.ConsumeIntegral<uint16_t>()};
                const uint16_t q{fuzzed_data_provider.ConsumeBool() ? fuzzed_data_provider.ConsumeIntegralInRange<uint16_t>(0, Q_PRECISION) :
                                                                      fuzzed_data_provider.ConsumeIntegral<uint16_t>()};
                if (sim.HandleReconciliationRequest(conn->id, set_size, q)) disconnect(*conn);
            },
            [&] {
                // SKETCH
                SimConnection* conn{pick()};
                if (!conn || !conn->Ready()) return;
                const SimRecon* recon{sim.GetRecon(conn->id)};
                const bool extension{recon && recon->phase == ReconciliationPhase::EXT_REQUESTED};
                std::vector<uint8_t> skdata;
                CallOneOf(
                    fuzzed_data_provider,
                    [&] {
                        if (extension) {
                            // The rest of a larger sketch over what was sketched initially.
                            const uint32_t initial{static_cast<uint32_t>(recon->remote_sketch.size() / BYTES_PER_SKETCH_CAPACITY)};
                            const uint32_t added{fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, MAX_FUZZ_CAPACITY)};
                            const auto extended{SketchOf(conn->remote_short_ids, initial + added)};
                            skdata.assign(extended.begin() + initial * BYTES_PER_SKETCH_CAPACITY, extended.end());
                            return;
                        }
                        // A sketch over some of the transactions we have for the peer, and some others.
                        conn->remote_short_ids.clear();
                        if (recon) {
                            for (const auto& entry : recon->set) {
                                if (fuzzed_data_provider.ConsumeBool()) conn->remote_short_ids.insert(entry.first);
                            }
                        }
                        LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), MAX_FUZZ_CAPACITY) {
                            conn->remote_short_ids.insert(ConsumeShortId(fuzzed_data_provider));
                        }
                        skdata = SketchOf(conn->remote_short_ids, fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, MAX_FUZZ_CAPACITY));
                    },
                    [&] {
                        skdata = ConsumeRandomLengthByteVector(fuzzed_data_provider, MAX_FUZZ_CAPACITY * BYTES_PER_SKETCH_CAPACITY + BYTES_PER_SKETCH_CAPACITY - 1);
                    },
                    [&] {
                        // More than we accept.
                        skdata.resize(((extension ? 2 * MAX_SKETCH_CAPACITY : MAX_SKETCH_CAPACITY) + 1) * BYTES_PER_SKETCH_CAPACITY);
                    });
                if (std::holds_alternative<ReconciliationError>(sim.HandleSketch(conn->id, skdata))) disconnect(*conn);
            },
            [&] {
                // REQSKETCHEXT
                SimConnection* conn{pick()};
                if (!conn || !conn->Ready()) return;
                if (sim.HandleExtensionRequest(conn->id)) disconnect(*conn);
            },
            [&] {
                // RECONCILDIFF
                SimConnection* conn{pick()};
                if (!conn || !conn->Ready()) return;
                const SimRecon* recon{sim.GetRecon(conn->id)};
                std::vector<uint32_t> ask;
                CallOneOf(
                    fuzzed_data_provider,
                    [&] {
                        // Some of what we sketched, as a peer that is missing it would ask for.
                        if (!recon) return;
                        for (const auto& entry : recon->snapshot) {
                            if (fuzzed_data_provider.ConsumeBool()) ask.push_back(entry.first);
                        }
                    },
                    [&] {
                        LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), MAX_FUZZ_CAPACITY) ask.push_back(ConsumeShortId(fuzzed_data_provider));
                    },
                    [&] {
                        // More than our sketches could have revealed.
                        ask.assign((recon ? recon->sketched_capacity : 0) + 1, ConsumeShortId(fuzzed_data_provider));
                    });
                if (!ask.empty() && fuzzed_data_provider.ConsumeBool()) {
                    const uint32_t repeated{ask.front()};
                    ask.push_back(repeated);
                }
                const bool success{fuzzed_data_provider.ConsumeBool()};
                if (std::holds_alternative<ReconciliationError>(sim.HandleReconcilDiff(conn->id, success, ask))) disconnect(*conn);
            },
            [&] {
                // INV or TX for a transaction
                SimConnection* conn{pick()};
                if (!conn || !conn->Ready()) return;
                sim.TryRemovingFromSet(conn->id, ConsumeWtxid(fuzzed_data_provider));
            },
            [&] {
                // Transactions leave the mempool
                std::vector<Wtxid> removed;
                LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 16) removed.push_back(ConsumeWtxid(fuzzed_data_provider));
                if (fills_left < 2 && fuzzed_data_provider.ConsumeBool()) removed.insert(removed.end(), g_fillers.begin(), g_fillers.end());
                sim.RemoveFromSets(removed);
            },
            [&] {
                clock += std::chrono::seconds{fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(-10, 60)};
            },
            [&] {
                in_ibd = false;
            });
        for (const SimConnection& conn : connections) sim.Check(conn.id);
    }

    for (SimConnection& conn : connections) disconnect(conn);
    sim.CheckEmpty();
}

/**
 * Two trackers reconciling with each other in good faith, while the transactions they have keep
 * changing. Each tracker is checked against the naive reimplementation, and the round as a whole
 * against what reconciliation is for: after it, both ends have what either end had sketched.
 */
FUZZ_TARGET(txreconciliation_protocol, .init = initialize_txreconciliation)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    FakeNodeClock clock{ConsumeTime(fuzzed_data_provider)};

    // Node A made an outbound reconciliation connection to node B, so A initiates and B responds.
    // Each knows the other as peer 0.
    constexpr NodeId PEER{0};
    LinkEnd a;
    LinkEnd b;
    const uint64_t salt_a{ConsumeSalt(fuzzed_data_provider)};
    const uint64_t salt_b{ConsumeSalt(fuzzed_data_provider)};
    a.sim.PreRegisterPeer(PEER, salt_a);
    b.sim.PreRegisterPeer(PEER, salt_b);
    Assert(!a.sim.RegisterPeer(PEER, /*is_peer_inbound=*/false, TXRECONCILIATION_VERSION, salt_b));
    Assert(!b.sim.RegisterPeer(PEER, /*is_peer_inbound=*/true, TXRECONCILIATION_VERSION, salt_a));

    //! Transactions that left the mempools, which nodes no longer need to learn about.
    std::set<Wtxid> gone;

    // `to` gets an announcement for a transaction from its peer, and fetches it.
    const auto deliver{[&](LinkEnd& to, const Wtxid& wtxid) {
        to.sim.TryRemovingFromSet(PEER, wtxid);
        to.known.insert(wtxid);
    }};

    // `self` learns about a transaction from elsewhere, so it would announce it to `peer`.
    const auto learn{[&](LinkEnd& self, LinkEnd& peer, const Wtxid& wtxid) {
        if (gone.contains(wtxid) || !self.known.insert(wtxid).second) return;
        const auto error{self.sim.AddToSet(PEER, wtxid)};
        if (!error) return;
        // What cannot be reconciled gets announced right away.
        if (error->m_error == ReconciliationError::SHORTID_COLLISION) {
            const Wtxid collision{error->GetCollision()};
            const bool removed{self.sim.TryRemovingFromSet(PEER, collision)};
            Assert(removed);
            deliver(peer, collision);
        } else {
            Assert(error->m_error == ReconciliationError::FULL_RECON_SET);
        }
        deliver(peer, wtxid);
    }};

    const auto leave_mempool{[&](const Wtxid& wtxid, bool on_a, bool on_b) {
        gone.insert(wtxid);
        if (on_a) a.sim.RemoveFromSets({wtxid});
        if (on_b) b.sim.RemoveFromSets({wtxid});
    }};

    // What happens while the messages of a round are in flight.
    const auto events{[&] {
        LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 4)
        {
            const Wtxid& wtxid{ConsumeWtxid(fuzzed_data_provider)};
            CallOneOf(
                fuzzed_data_provider,
                [&] { learn(a, b, wtxid); },
                [&] { learn(b, a, wtxid); },
                [&] {
                    learn(a, b, wtxid);
                    learn(b, a, wtxid);
                },
                [&] {
                    const bool on_a{fuzzed_data_provider.ConsumeBool()};
                    const bool on_b{fuzzed_data_provider.ConsumeBool()};
                    leave_mempool(wtxid, on_a, on_b);
                });
        }
    }};

    const auto max_elements{[](size_t capacity) -> size_t {
        return capacity == 0 ? 0 : minisketch_compute_max_elements(RECON_FIELD_SIZE, capacity, RECON_FALSE_POSITIVE_COEF);
    }};

    const auto reconcile{[&] {
        const auto request{a.sim.InitiateReconciliationRequest(PEER)};
        // Every round completes, so A can always start the next one.
        Assert(std::holds_alternative<ReconCoefficients>(request));
        const auto [set_size, q]{std::get<ReconCoefficients>(request)};
        events();
        Assert(!b.sim.HandleReconciliationRequest(PEER, set_size, q));
        std::vector<uint8_t> sketch;
        Assert(b.sim.ShouldRespondToReconciliationRequest(PEER, sketch));
        const ShortIdMap sketched_b{Assert(b.sim.GetRecon(PEER))->snapshot};
        events();
        const ShortIdMap sketched_a{Assert(a.sim.GetRecon(PEER))->set};
        auto result{ExpectSketchResult(a.sim.HandleSketch(PEER, sketch))};
        size_t capacity{sketch.size() / BYTES_PER_SKETCH_CAPACITY};

        // Both ends compute the same short ids, so this is what the sketches can reveal.
        const auto short_ids_a{ShortIdsOf(sketched_a)};
        const auto short_ids_b{ShortIdsOf(sketched_b)};
        std::set<uint32_t> difference;
        std::set_symmetric_difference(short_ids_a.begin(), short_ids_a.end(), short_ids_b.begin(), short_ids_b.end(),
                                      std::inserter(difference, difference.end()));

        if (capacity == 0 || sketched_a.empty()) {
            // One end has nothing to reconcile, so both fall back to announcing everything.
            Assert(result.m_succeeded == false);
        } else if (difference.size() <= max_elements(capacity)) {
            // A sketch with enough capacity always decodes, to the actual difference.
            Assert(result.m_succeeded == true);
        }
        if (!result.m_succeeded) {
            events();
            Assert(!b.sim.HandleExtensionRequest(PEER));
            std::vector<uint8_t> extension;
            Assert(b.sim.ShouldRespondToReconciliationRequest(PEER, extension));
            events();
            capacity += extension.size() / BYTES_PER_SKETCH_CAPACITY;
            result = ExpectSketchResult(a.sim.HandleSketch(PEER, extension));
            Assert(result.m_succeeded.has_value());
            if (difference.size() <= max_elements(capacity)) Assert(result.m_succeeded == true);
        }

        const bool succeeded{*result.m_succeeded};
        const auto b_announces{b.sim.HandleReconcilDiff(PEER, succeeded, result.m_txs_to_request)};
        Assert(std::holds_alternative<std::vector<Wtxid>>(b_announces));
        for (const Wtxid& wtxid : result.m_txs_to_announce) deliver(b, wtxid);
        for (const Wtxid& wtxid : std::get<std::vector<Wtxid>>(b_announces)) deliver(a, wtxid);

        // Decoding more elements than the sketch is meant to tell apart is a false positive, which
        // is rare by design and may leave transactions behind.
        if (succeeded && difference.size() > max_elements(capacity)) return;

        // Both ends now have what either sketched. Except for what left the mempool, and for colliding
        // transactions on either end, which the sketches cannot tell apart.
        const auto collides{[&](uint32_t short_id) {
            const auto it_a{sketched_a.find(short_id)};
            const auto it_b{sketched_b.find(short_id)};
            return it_a != sketched_a.end() && it_b != sketched_b.end() && it_a->second != it_b->second;
        }};
        for (const auto& [short_id, wtxid] : sketched_a) {
            if (!gone.contains(wtxid) && !collides(short_id)) Assert(b.known.contains(wtxid));
        }
        for (const auto& [short_id, wtxid] : sketched_b) {
            if (!gone.contains(wtxid) && !collides(short_id)) Assert(a.known.contains(wtxid));
        }
    }};

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 200)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] { events(); },
            [&] { reconcile(); });
    }
}
