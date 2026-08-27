#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Pruned node crashes on a more-work P2P fork from below the prune height.

Fails until the node survives: DisconnectTip hits pruned data, then
CheckBlockIndex aborts on setBlockIndexCandidates.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


class PruneDeepReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-prune=1", "-fastprune", "-checkblockindex=1"], []]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node0, node1 = self.nodes
        fork_height = node0.getblockcount()

        self.generate(node0, 600, sync_fun=self.no_op)
        self.generate(node1, 605, sync_fun=self.no_op)

        node0.pruneblockchain(node0.getblockcount() - 288)
        assert_raises_rpc_error(-1, "Block not available (pruned data)",
                                node0.getblock, node0.getblockhash(fork_height))

        self.connect_nodes(0, 1)
        # node0 aborts here while downloading node1's fork.
        self.wait_until(lambda: node0.getblockcount() == node1.getblockcount())


if __name__ == '__main__':
    PruneDeepReorgTest(__file__).main()
