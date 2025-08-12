// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <node/kernel_notifications.h>
#include <node/mining_types.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <uint256.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <set>
#include <utility>
#include <vector>


namespace {

TestingSetup* g_setup;

/** Vector of blocks to keep references to blocks (to enable fuzzing input to pick one to build upon) */
static std::vector<std::shared_ptr<CBlock>> g_blocks;
/** Set of block hashes in g_blocks */
static std::set<uint256> g_existing_block_hashes;
/** Spending scripts for all UTXOs (excluding OP_RETURN), including immature coinbase and already-spent ones */
static std::vector<CTxIn> g_all_utxo_txins;
/** Static P2SH_OP_TRUE script */
static const CScript P2SH_OP_TRUE = CScript() << OP_HASH160 << ToByteVector(ScriptHash(CScript() << OP_TRUE)) << OP_EQUAL;
/** Static P2SH_OP_TRUE unlock script */
static const CScript P2SH_OP_TRUE_UNLOCK = CScript() << MakeUCharSpan(CScript() << OP_TRUE);
/** Static TAPROOT_OP_TRUE script and its witness */
static CScript TAPROOT_OP_TRUE;
static std::vector<std::vector<uint8_t>> TAPROOT_OP_TRUE_WITNESS;

/**
 * Initialize TAPROOT_OP_TRUE and TAPROOT_OP_TRUE_WITNESS static variables.
 */
static void InitTaprootScript()
{
    uint256 merkle_tree_hash = ComputeTapleafHash(0xc0, MakeUCharSpan(CScript() << OP_TRUE));
    uint256 internal_key{std::vector<uint8_t>(32, 1)};
    auto res = XOnlyPubKey(internal_key).CreateTapTweak(&merkle_tree_hash);
    Assert(res.has_value());
    auto control = ToByteVector(internal_key);
    control.insert(control.begin(), 0xc0 | (res->second ? 1 : 0));

    TAPROOT_OP_TRUE = CScript() << OP_1 << ToByteVector(res->first);
    TAPROOT_OP_TRUE_WITNESS.clear();
    TAPROOT_OP_TRUE_WITNESS.emplace_back(ToByteVector(CScript() << OP_TRUE));
    TAPROOT_OP_TRUE_WITNESS.emplace_back(std::move(control));
}
/**
 * Given a transaction and an output index, create a CTxIn that can be used to
 * spend it (if possible).
 */
static CTxIn GetSpendingScript(const CTransaction& tx, unsigned vout_index)
{
    Assert(vout_index < tx.vout.size());
    const CTxOut& output = tx.vout[vout_index];

    CTxIn res{COutPoint(tx.GetHash(), vout_index)};
    if (output.scriptPubKey.size() >= 1 && output.scriptPubKey[0] == OP_RETURN)
        return res;

    if (output.scriptPubKey == P2WSH_OP_TRUE) {
        res.scriptSig = CScript();
        res.scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
    } else if (output.scriptPubKey == P2SH_OP_TRUE) {
        res.scriptSig = P2SH_OP_TRUE_UNLOCK;
    } else if (output.scriptPubKey == CScript()) {
        res.scriptSig = CScript() << OP_TRUE;
    } else if (output.scriptPubKey == TAPROOT_OP_TRUE) {
        res.scriptSig = CScript();
        res.scriptWitness.stack = TAPROOT_OP_TRUE_WITNESS;
    }

    return res;
}


/**
 * Read the block from the BlockManager and add it to g_blocks and g_existing_block_hashes.
 */
static void LoadCurrentBlock(Chainstate& chainstate, CBlockIndex* current_block)
{
    // Read the block from the BlockManager.
    Assert(current_block->nHeight >= 0);
    // Resize g_blocks if needed.
    if (g_blocks.size() <= (size_t)current_block->nHeight) {
        g_blocks.resize(current_block->nHeight + 1);
    }

    g_blocks[current_block->nHeight] = std::make_shared<CBlock>();
    Assert(chainstate.m_blockman.ReadBlock(*g_blocks[current_block->nHeight], *current_block));
    // Update hash set.
    g_existing_block_hashes.insert(g_blocks[current_block->nHeight]->GetHash());

    // Iterate all transaction outputs.
    for (const auto& tx : g_blocks[current_block->nHeight]->vtx) {
        for (unsigned vout_index = 0; vout_index < tx->vout.size(); vout_index++) {
            auto& vout = tx->vout[vout_index];
            // Do not keep OP_RETURN outputs as they are not spendable.
            if (vout.scriptPubKey.size() >= 1 && vout.scriptPubKey[0] == OP_RETURN) continue;
            // Create the CTxIn that can be used to spend this output.
            g_all_utxo_txins.push_back(GetSpendingScript(*tx, vout_index));
        }
    }
}

/**
 * Read the ChainState object into g_blocks.
 * Then fill g_all_utxo_txins to keep track of all UTXO available in the chain.
 */
static void LoadCurrentChain()
{
    // Clear existing data.
    g_blocks.clear();
    g_existing_block_hashes.clear();
    g_all_utxo_txins.clear();

    {
        LOCK(::cs_main);
        // Retrieve the current chainstate.
        auto& chainstate = Assert(g_setup->m_node.chainman)->ActiveChainstate();
        // Make sure it contains a valid mempool.
        Assert(chainstate.GetMempool());

        // Traverse the chain from tip to genesis.
        auto current_block = chainstate.m_chain.Tip();

        while (current_block != nullptr) {
            LoadCurrentBlock(chainstate, current_block);
            // Move to previous block.
            current_block = current_block->pprev;
        }
    }

    // Reverse the order of g_all_utxo_txins to have them in ascending order of
    // block height.
    std::reverse(g_all_utxo_txins.begin(), g_all_utxo_txins.end());
}


/**
 * Reset the chainman in the testing setup object.
 * Mine 2*COINBASE_MATURITY blocks to have spendable UTXOs.
 * It is called once in the initialization function;
 */
void ResetChainman(TestingSetup& setup)
{
    SetMockTime(setup.m_node.chainman->GetParams().GenesisBlock().Time());
    setup.m_node.chainman.reset();
    setup.m_node.notifications->m_shutdown_on_fatal_error = false;
    setup.m_make_chainman();
    setup.LoadVerifyActivateChainstate();

    for (int i = 0; i < 2 * COINBASE_MATURITY; i++) {
        node::BlockCreateOptions options;
        options.coinbase_output_script = P2WSH_OP_TRUE;
        MineBlock(setup.m_node, options);
    }
    setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

/** Create additional transactions in the mempool that spend
 * coins from mature blocks. Otherwise the mined chain only contains
 * coinbase transactions.
 */
void AddExtraTxsInMempool(TestingSetup& setup)
{
    Assert(Assert(Assert(setup.m_node.chainman)->ActiveChainstate().GetMempool())->size() == 0);
    for (unsigned i = 1; i < 11; i++) {
        CMutableTransaction ctx;
        ctx.version = CTransaction::CURRENT_VERSION;
        ctx.vin.resize(1);
        // CTxIn is spendable as g_all_utxo_txins comes from early blocks whose
        // coinbases are mature.
        ctx.vin[0] = g_all_utxo_txins[i];
        ctx.vout.resize(4);
        // Arbitrarily create various outputs of different kinds in the same tx.
        // P2WSH
        ctx.vout[0].nValue = CAmount(15 * COIN);
        ctx.vout[0].scriptPubKey = P2WSH_OP_TRUE;
        // P2SH
        ctx.vout[1].nValue = CAmount(15 * COIN);
        ctx.vout[1].scriptPubKey = P2SH_OP_TRUE;
        // Taproot
        ctx.vout[2].nValue = CAmount(10 * COIN);
        ctx.vout[2].scriptPubKey = TAPROOT_OP_TRUE;
        // Empty script
        ctx.vout[3].nValue = CAmount(10 * COIN);
        ctx.vout[3].scriptPubKey = CScript();

        LOCK(::cs_main);
        // Add transaction to the mempool.
        const MempoolAcceptResult ctx_result = setup.m_node.chainman->ProcessTransaction(MakeTransactionRef(ctx));
        Assert(ctx_result.m_result_type == MempoolAcceptResult::ResultType::VALID);

        Assert(setup.m_node.chainman->ActiveChainstate().GetMempool()->size() == i);
        // Force the mempool to select this transaction even though its fee is zero.
        setup.m_node.chainman->ActiveChainstate().GetMempool()->PrioritiseTransaction(ctx.GetHash(), COIN);
    }
}

/** Initialize the chain for this target. */
static void initialize_connect_block()
{
    // Instantiate REGTEST chain.
    static auto testing_setup = MakeNoLogFileContext<TestingSetup>(
        /*chain_type=*/ChainType::REGTEST, TestOpts{
                                               .extra_args = {
                                                   "-minrelaytxfee=0",
                                                   "-acceptnonstdtxn",
                                               },
                                           });
    g_setup = testing_setup.get();

    // Reset the chainman in the testing setup object.
    ResetChainman(*g_setup);

    // Initialize Taproot script declared as static variables.
    InitTaprootScript();

    // Load the chain mined in ResetChainman in global variables g_blocks and
    // g_all_utxo_txins, to make them available to pick by the target.
    LoadCurrentChain();

    // Prepare multiple transactions for the first 201 blocks. They spend coins
    // from various coinbases that are now mature enough.
    AddExtraTxsInMempool(*g_setup);
    // Mine block 201, which contains the transactions added to the mempool.
    node::BlockCreateOptions options;
    options.coinbase_output_script = P2WSH_OP_TRUE;
    MineBlock(g_setup->m_node, options);
    Assert(g_setup->m_node.chainman->ActiveChainstate().GetMempool()->size() == 0);

    // Load the 201th block into g_blocks.
    LOCK(::cs_main);
    auto& chainstate = Assert(g_setup->m_node.chainman)->ActiveChainstate();
    auto current_block = chainstate.m_chain.Tip();
    LoadCurrentBlock(chainstate, current_block);

    g_setup->m_node.chainman->ActiveChainstate().ForceFlushStateToDisk();
}

/**
 * Read one transaction from the fuzzing input through the FuzzedDataProvider.
 * It is intended to leave more space to craft complex transactions, especially
 * with various script types (P2SH, P2WSH, TAPROOT, NOSCRIPT).
 * It is exclusively used by ConsumeBlock to read transactions inside a block.
 */
CTransactionRef ConsumeTransaction(FuzzedDataProvider& fuzzed_data_provider,
                                   std::vector<CTxIn>& additional_utxo,
                                   bool coinbase = false,
                                   unsigned target_height = 0)
{
    CMutableTransaction tx;

    // Some harnesses want to explicitly read coinbase transactions from input.
    if (coinbase) {
        // vin size is hardcoded.
        tx.vin.resize(1);
        tx.vin[0].prevout.SetNull();
        tx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
        if (fuzzed_data_provider.ConsumeBool()) {
            // 1/2 probability of a valid vin.
            tx.vin[0].scriptSig = CScript() << target_height << OP_0;
        } else {
            // Read arbitrary data from input as scriptSig.
            auto script_sig = ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 100);
            tx.vin[0].scriptSig << script_sig;
        }
    } else {
        // Read a normal transaction, with up to 10 inputs.
        int num_inputs = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 10);
        tx.vin.resize(num_inputs);
        for (int i = 0; i < num_inputs; i++) {
            // Read an integer to choose input coins from pre-mined UTXOs or reuse
            // one generated by the input. The content of the CTxIn is not read
            // from the input per se.
            uint32_t target_utxo = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, g_all_utxo_txins.size() + additional_utxo.size() - 1);
            if (target_utxo < g_all_utxo_txins.size()) {
                // Pick it in the UTXO set.
                tx.vin[i] = g_all_utxo_txins[target_utxo];
            } else {
                // Pick it in the additional_utxo set.
                Assert((target_utxo - g_all_utxo_txins.size()) < additional_utxo.size());
                tx.vin[i] = additional_utxo[target_utxo - g_all_utxo_txins.size()];
            }

            // Enable the fuzzer to mutate every CTxIn field after it is taken
            // from existing UTXOs.
            if (fuzzed_data_provider.ConsumeBool()) {
                tx.vin[i].nSequence = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                tx.vin[i].prevout.n = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                tx.vin[i].prevout.hash = Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                auto script_sig = ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 100);
                tx.vin[i].scriptSig << script_sig;
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                tx.vin[i].scriptWitness.stack.clear();
                int num_wit = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 10);
                for (int j = 0; j < num_wit; j++) {
                    tx.vin[i].scriptWitness.stack.push_back(ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 100));
                }
            }
        }
    }

    // Read outputs.
    int num_outputs = fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 10);
    tx.vout.resize(num_outputs);
    for (int i = 0; i < num_outputs; i++) {
        // Read CAmount to spend.
        tx.vout[i].nValue = fuzzed_data_provider.ConsumeIntegral<int64_t>();

        // Read scriptPubKey type into one of the valid types.
        switch (fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 4)) {
        case 0:
            // P2WSH
            tx.vout[i].scriptPubKey = P2WSH_OP_TRUE;
            break;
        case 1:
            // P2SH
            tx.vout[i].scriptPubKey = P2SH_OP_TRUE;
            break;
        case 2:
            // Taproot
            tx.vout[i].scriptPubKey = TAPROOT_OP_TRUE;
            break;
        case 3:
            // Empty script
            tx.vout[i].scriptPubKey = CScript();
            break;
        default: {
            // Read arbitrary scriptPubKey.
            auto script_pub_key = ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 100);
            tx.vout[i].scriptPubKey << script_pub_key;
            break;
        }
        }
    }

    // Create the shared pointer to the CTransaction object.
    auto res = MakeTransactionRef(tx);

    if (!coinbase) {
        // Create spending scripts for all CTxOuts so they can be spent in later
        // transactions. Do it here as the transaction hash is definitive.
        for (int i = 0; i < num_outputs; i++) {
            additional_utxo.emplace_back(GetSpendingScript(*res, i));
        }
    }

    return res;
}

/**
 * Consume a block from the fuzzing input.
 * It builds a block on top of the given prev_block.
 */
CBlock ConsumeBlock(FuzzedDataProvider& fuzzed_data_provider, const CBlock& prev_block, unsigned target_height,
                    std::vector<CTxIn>& additional_utxo, bool force_valid_block = false)
{
    CBlock block;

    // First create a valid block header.
    block.nVersion = g_blocks.back()->nVersion;
    block.hashPrevBlock = prev_block.GetHash();
    block.nTime = g_blocks.back()->nTime + 2;
    block.nBits = g_blocks.back()->nBits;

    // Give the fuzzer input the ability to mutate block header fields.
    if (fuzzed_data_provider.ConsumeBool()) {
        block.nVersion = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    }
    if (fuzzed_data_provider.ConsumeBool() && !force_valid_block) {
        block.hashPrevBlock = ConsumeUInt256(fuzzed_data_provider);
    }

    if (fuzzed_data_provider.ConsumeBool()) {
        block.nTime = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    }
    if (fuzzed_data_provider.ConsumeBool()) {
        block.nBits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    }

    // Read the coinbase transaction from the input.
    block.vtx.push_back(ConsumeTransaction(fuzzed_data_provider, additional_utxo, true, target_height));

    // Read up to num_tx transactions from the input.
    int num_tx = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 5);
    for (int i = 0; i < num_tx; i++) {
        block.vtx.push_back(ConsumeTransaction(fuzzed_data_provider, additional_utxo));
    }

    // Commit witness.
    if (num_tx > 0) {
        g_setup->m_node.chainman->GenerateCoinbaseCommitment(block, nullptr);
    }
    for (unsigned i = 0; i < block.vtx[0]->vout.size(); i++) {
        additional_utxo.emplace_back(GetSpendingScript(*block.vtx[0], i));
    }

    // Set hashMerkleRoot to expected value.
    block.hashMerkleRoot = BlockMerkleRoot(block);
    // Let fuzzer mutate hashMerkleRoot if not forced to create a valid block.
    if (fuzzed_data_provider.ConsumeBool() && !force_valid_block) {
        block.hashMerkleRoot = ConsumeUInt256(fuzzed_data_provider);
    }

    // Adjust nonce if decided to generate a valid block or we already generated
    // a block with the same hash.
    auto read_valid_nonce = fuzzed_data_provider.ConsumeBool();
    if (read_valid_nonce || force_valid_block || g_existing_block_hashes.contains(block.GetHash())) {
        const auto& consensus = g_setup->m_node.chainman->GetConsensus();
        block.nNonce = 0;
        // Do not check against current nBits (as it may be a huge value).
        while (!CheckProofOfWork(block.GetHash(), g_blocks.back()->nBits, consensus) || g_existing_block_hashes.contains(block.GetHash())) {
            ++block.nNonce;
            if (block.nNonce == 0) break;
        }
    } else {
        // Read the nonce from the input.
        block.nNonce = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    }

    return block;
}


FUZZ_TARGET(connect_block, .init = initialize_connect_block)
{
    LOCK(::cs_main);
    SeedRandomStateForTest(SeedRand::ZEROS);
    SetMockTime(g_blocks.back()->GetBlockTime() + 2);

    // Initialize data provider.
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());


    Chainstate& active_chainstate = g_setup->m_node.chainman->ActiveChainstate();
    CBlockIndex* active_tip = active_chainstate.m_chain.Tip();
    CCoinsViewCache active_coins(&active_chainstate.CoinsTip());

    // Read the new block from the input.
    std::vector<CTxIn> additional_utxo;
    CBlock block = ConsumeBlock(fuzzed_data_provider, *g_blocks.back(), active_tip->nHeight + 1, additional_utxo);
    CBlockHeader current_header = static_cast<const CBlockHeader&>(block);

    // Compute new CBlockIndex object.
    uint256 current_hash = current_header.GetHash();
    CBlockIndex new_index(current_header);
    new_index.pprev = active_tip;
    new_index.nHeight = active_tip->nHeight + 1;
    new_index.phashBlock = &current_hash;

    // Try to connect the block.
    BlockValidationState state;
    (void)active_chainstate.ConnectBlock(block,
                                         state,
                                         &new_index,
                                         active_coins,
                                         /*fJustCheck=*/true);
}

} // namespace
