// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txreconciliation.h>
#include <random.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <util/hasher.h>

#include <cassert>

constexpr int NUM_PEERS = 8;

void initialize_txreconciliation()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
}

FUZZ_TARGET(txreconciliation, .init = initialize_txreconciliation)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    uint32_t recon_version = TXRECONCILIATION_VERSION;
    CSipHasher sip_hasher{fuzzed_data_provider.ConsumeIntegral<uint64_t>(), 
                         fuzzed_data_provider.ConsumeIntegral<uint64_t>()};
    TxReconciliationTracker txrecontracker(recon_version, sip_hasher);

    std::vector<NodeId> peer_ids;
    std::vector<NodeId> registered_peers;
    std::vector<size_t> peer_set_sizes(NUM_PEERS, 0);
    std::unordered_set<NodeId> pre_registered_peers;

    for (int i = 0; i < NUM_PEERS; ++i) {
        peer_ids.push_back(fuzzed_data_provider.ConsumeIntegral<NodeId>());
    }

    for (NodeId peer_id : peer_ids) {
        if (pre_registered_peers.find(peer_id) == pre_registered_peers.end()) {
            (void)txrecontracker.PreRegisterPeer(peer_id);
            pre_registered_peers.insert(peer_id);

            if (fuzzed_data_provider.ConsumeBool()) {
                bool is_peer_inbound = fuzzed_data_provider.ConsumeBool();
                uint32_t peer_recon_version = TXRECONCILIATION_VERSION;
                uint64_t remote_salt = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
                auto result = txrecontracker.RegisterPeer(peer_id, is_peer_inbound, peer_recon_version, remote_salt);
                if (result == ReconciliationRegisterResult::SUCCESS) {
                    registered_peers.push_back(peer_id);
                }
            }
        }
    }

    NodeId rand_peer{};
    size_t rand_peer_index{};
    Wtxid random_wtxid{};

    if (!registered_peers.empty()) {
        rand_peer_index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, registered_peers.size() - 1);
        rand_peer = registered_peers[rand_peer_index];
        random_wtxid = Wtxid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
    }

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10000) 
	{
        if (registered_peers.empty()) continue;

        CallOneOf(
            fuzzed_data_provider,
            [&] {
                rand_peer_index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, registered_peers.size() - 1);
                rand_peer = registered_peers[rand_peer_index];
                random_wtxid = Wtxid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
            },
            [&] {
                auto result = txrecontracker.AddToSet(rand_peer, random_wtxid);
                if (result.m_succeeded) {
                    assert(txrecontracker.IsTransactionInSet(rand_peer, random_wtxid, true));
                    peer_set_sizes[rand_peer_index]++;
                }
            },
            [&] {
                (void)txrecontracker.ReadyDelayedTransactions(rand_peer);
            },
            [&] {
                bool include_delayed = fuzzed_data_provider.ConsumeBool();
                (void)txrecontracker.IsTransactionInSet(rand_peer, random_wtxid, include_delayed);
            },
            [&] {
                bool result = txrecontracker.TryRemovingFromSet(rand_peer, random_wtxid);
                if (result) {
                    assert(!txrecontracker.IsTransactionInSet(rand_peer, random_wtxid, true));
                    if (peer_set_sizes[rand_peer_index] > 0) {
                        peer_set_sizes[rand_peer_index]--;
                    }
                }
            },
            [&] {
                txrecontracker.ForgetPeer(rand_peer);
                registered_peers.erase(registered_peers.begin() + rand_peer_index);
                peer_set_sizes[rand_peer_index] = 0;
                assert(!txrecontracker.IsPeerRegistered(rand_peer));
                assert(!txrecontracker.IsTransactionInSet(rand_peer, random_wtxid, true));
                pre_registered_peers.erase(rand_peer);
            },
            [&] {
                assert(txrecontracker.IsPeerRegistered(rand_peer));
            },
            [&] {
                size_t inbounds_fanout = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, NUM_PEERS);
                size_t outbounds_fanout = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, NUM_PEERS);
                auto fanout_targets = txrecontracker.GetFanoutTargets(random_wtxid, inbounds_fanout, outbounds_fanout);
            },
            [&] {
                std::vector<Wtxid> parents;
                int num_parents = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 10);
                for (int i = 0; i < num_parents; ++i) {
                    parents.push_back(Wtxid::FromUint256(ConsumeUInt256(fuzzed_data_provider)));
                }
                auto sorted_peers = txrecontracker.SortPeersByFewestParents(parents);
            }
        );

        for (const auto& size : peer_set_sizes) {
            assert(size <= MAX_RECONSET_SIZE);
        }
    }
}
