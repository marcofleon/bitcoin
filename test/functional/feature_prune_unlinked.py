#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that pruned stale-fork blocks aren't re-added to m_blocks_unlinked on startup."""

from test_framework.blocktools import create_block
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class FeaturePruneUnlinkedTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-prune=1", "-fastprune"]]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create a 2-block stale fork with a header-only parent and a full child")
        fork_point = node.getblockhash(1)
        tip_time = node.getblock(node.getbestblockhash())["time"] + 1

        side_parent = create_block(int(fork_point, 16), height=2, ntime=tip_time)
        side_parent.solve()
        side_child = create_block(side_parent.hash_int, height=3, ntime=tip_time + 1)
        side_child.solve()

        node.submitheader(side_parent.serialize().hex())
        node.submitblock(side_child.serialize().hex())
        assert_equal(node.getblockheader(side_parent.hash_hex)["nTx"], 0)
        assert_equal(node.getblockheader(side_child.hash_hex)["nTx"], 1)

        self.log.info("Advance and prune so the stale-fork child loses BLOCK_HAVE_DATA")
        self.generate(node, 500)
        node.pruneblockchain(node.getblockcount() - 100)

        self.log.info("Restart and mine; the pruned block must stay out of m_blocks_unlinked")
        self.restart_node(0)
        self.generate(node, 1)


if __name__ == '__main__':
    FeaturePruneUnlinkedTest(__file__).main()
