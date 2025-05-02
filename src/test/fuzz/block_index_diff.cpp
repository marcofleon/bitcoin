#include <chain.h>
#include <chainparams.h>
#include <kernel/headerstorage.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <test/util/random.h>
#include <validation.h>

namespace {

const BasicTestingSetup* g_setup;


bool AreBlockIndicesEqual(const CBlockIndex* a, const CBlockIndex* b) {    
    if (!a || !b) return a == b;

    bool prev_match = (!a->pprev && !b->pprev) ||
                      (a->pprev && b->pprev && a->pprev->GetBlockHash() == b->pprev->GetBlockHash());

    return a->nHeight == b->nHeight &&
           a->nFile == b->nFile &&
           a->nDataPos == b->nDataPos &&
           a->nUndoPos == b->nUndoPos &&
           a->nVersion == b->nVersion &&
           a->hashMerkleRoot == b->hashMerkleRoot &&
           a->nTime == b->nTime &&
           a->nBits == b->nBits &&
           a->nNonce == b->nNonce &&
           a->nStatus == b->nStatus &&
           a->nTx == b->nTx &&
           prev_match;
}

bool operator==(const CBlockFileInfo& a, const CBlockFileInfo& b)
{
    return a.nBlocks == b.nBlocks &&
        a.nSize == b.nSize &&
        a.nUndoSize == b.nUndoSize &&
        a.nHeightFirst == b.nHeightFirst &&
        a.nHeightLast == b.nHeightLast &&
        a.nTimeFirst == b.nTimeFirst &&
        a.nTimeLast == b.nTimeLast;
}

CBlockHeader ConsumeHeader(FuzzedDataProvider& fuzzed_data_provider, const uint256& prev_hash, uint32_t prev_nbits)
{
    CBlockHeader header;
    header.nNonce = 0;
    if (fuzzed_data_provider.ConsumeBool()) {
        header.nBits = prev_nbits;
    } else {
        arith_uint256 lower_target = UintToArith256(uint256{"0000000000000000000342190000000000000000000000000000000000000000"});
        arith_uint256 upper_target = UintToArith256(uint256{"00000000ffff0000000000000000000000000000000000000000000000000000"});
        arith_uint256 target = ConsumeArithUInt256InRange(fuzzed_data_provider, lower_target, upper_target);
        header.nBits = target.GetCompact();
    }
    header.nTime = ConsumeTime(fuzzed_data_provider);
    header.hashPrevBlock = prev_hash;
    header.hashMerkleRoot = ConsumeUInt256(fuzzed_data_provider);
    header.nVersion = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    return header;
}

void FinalizeHeader(CBlockHeader& header)
{
    while (!CheckProofOfWork(header.GetHash(), header.nBits, Params().GetConsensus())) {
        ++(header.nNonce);
    }
}

} // namespace

void init()
{
    static const auto testing_setup = MakeNoLogFileContext<>(ChainType::MAIN);
    g_setup = testing_setup.get();
}

FUZZ_TARGET(block_index_diff, .init = init)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    auto block_index_db = kernel::BlockTreeDB(DBParams{
        .path = "", // Memory only.
        .cache_bytes = 1 << 20, // 1MB.
        .memory_only = true,
    });
    
    //const auto path = gArgs.GetDataDirNet() / "blockfiles";
    const auto block_store_dir{g_setup->m_args.GetDataDirBase()};
    fs::remove_all(block_store_dir);
    auto block_index_store = kernel::BlockTreeStore(block_store_dir, ::Params(), true);

    // Generate a number of block files to be stored in the index.
    int files_count = fuzzed_data_provider.ConsumeIntegralInRange(1, 100);
    std::vector<std::unique_ptr<CBlockFileInfo>> files;
    files.reserve(files_count);
    std::vector<std::pair<int, const CBlockFileInfo*>> files_info_db;
    files_info_db.reserve(files_count);
    std::vector<std::pair<int, CBlockFileInfo*>> files_info_store;
    files_info_store.reserve(files_count);
    for (int i = 0; i < files_count; i++) {
        if (auto file_info = ConsumeDeserializable<CBlockFileInfo>(fuzzed_data_provider)) {
            files.push_back(std::make_unique<CBlockFileInfo>(std::move(*file_info)));
            files_info_db.emplace_back(i, files.back().get());
            files_info_store.emplace_back(i, files.back().get());
        } else {
            return;
        }
    }

    // Generate a number of block headers to be stored in the index.
    uint256 prev_block_hash = uint256();
    uint32_t prev_nbits = Params().GenesisBlock().nBits;
    CBlockIndex* pprev_block_index = nullptr;
    int blocks_count = fuzzed_data_provider.ConsumeIntegralInRange(files_count * 10, files_count * 100);
    std::vector<std::unique_ptr<CBlockIndex>> blocks;
    std::vector<uint256> block_hashes;
    blocks.reserve(blocks_count);
    block_hashes.reserve(blocks_count);
    std::vector<const CBlockIndex*> blocks_info_db;
    std::vector<CBlockIndex*> blocks_info_store;
    blocks_info_db.reserve(blocks_count);
    blocks_info_store.reserve(blocks_count);
    
    for (int i = 0; i < blocks_count; i++) {
        CBlockHeader header{ConsumeHeader(fuzzed_data_provider, prev_block_hash, prev_nbits)};
        FinalizeHeader(header);
        uint256 current_block_hash = header.GetHash();
        blocks.push_back(std::make_unique<CBlockIndex>(std::move(header)));
        CBlockIndex* pindexNew = blocks.back().get();
        block_hashes.push_back(current_block_hash);
        pindexNew->phashBlock = &block_hashes.back();
        pindexNew->pprev = pprev_block_index;
        prev_block_hash = current_block_hash;
        prev_nbits = pindexNew->nBits;
        pprev_block_index = pindexNew;
        blocks_info_db.push_back(pindexNew);
        blocks_info_store.push_back(pindexNew);
    }

    // Store these files and blocks in the block index. It should not fail.
    assert(block_index_db.WriteBatchSync(files_info_db, files_count - 1, blocks_info_db));
    WITH_LOCK(::cs_main, assert(block_index_store.WriteBatchSync(files_info_store, files_count - 1, blocks_info_store)));

    // We should be able to read every block file info we stored. Its value should correspond to
    // what we stored above.
    CBlockFileInfo info_db, info_store;
    for (const auto& [n, file_info_ptr] : files_info_db) {
        assert(block_index_db.ReadBlockFileInfo(n, info_db));
        assert(block_index_store.ReadBlockFileInfo(n, info_store));
        assert(info_db == info_store);
        assert(info_db == *file_info_ptr);
    }

    // We should be able to read the last block file number. Its value should be consistent.
    int last_block_file_db;
    int32_t last_block_file_store;
    assert(block_index_db.ReadLastBlockFile(last_block_file_db));
    block_index_store.ReadLastBlockFile(last_block_file_store);
    assert(last_block_file_db == last_block_file_store);
    assert(last_block_file_db == files_count - 1);

    // We should be able to flip and read the reindexing flag.
    bool reindexing_db, reindexing_store;
    block_index_db.WriteReindexing(true);
    block_index_store.WriteReindexing(true);
    block_index_db.ReadReindexing(reindexing_db);
    block_index_store.ReadReindexing(reindexing_store);
    assert(reindexing_db);
    assert(reindexing_store);
    assert(reindexing_db == reindexing_store);

    block_index_db.WriteReindexing(false);
    block_index_store.WriteReindexing(false);
    block_index_db.ReadReindexing(reindexing_db);
    block_index_store.ReadReindexing(reindexing_store);
    assert(!reindexing_db);
    assert(!reindexing_store);
    assert(reindexing_db == reindexing_store);

    bool pruned_db_read, pruned_store_read;
    assert(block_index_db.WriteFlag("prunedblockfiles", true));
    block_index_store.WritePruned(true);

    assert(block_index_db.ReadFlag("prunedblockfiles", pruned_db_read));
    block_index_store.ReadPruned(pruned_store_read);

    assert(pruned_db_read);
    assert(pruned_store_read);
    assert(pruned_db_read == pruned_store_read);

    assert(block_index_db.WriteFlag("prunedblockfiles", false));
    block_index_store.WritePruned(false);

    assert(block_index_db.ReadFlag("prunedblockfiles", pruned_db_read));
    block_index_store.ReadPruned(pruned_store_read);

    assert(!pruned_db_read);
    assert(!pruned_store_read);
    assert(pruned_db_read == pruned_store_read);

    // We should be able to load everything we've previously stored. Note to assert on the
    // return value we need to make sure all blocks pass the pow check.
    node::BlockMap map_db;
    node::BlockMap map_store;

    const auto params{Params().GetConsensus()};

    const auto inserter_db = [&](const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        if (hash.IsNull()) return (CBlockIndex*)nullptr;
        auto [iter, inserted] = map_db.try_emplace(hash);
        CBlockIndex* pindex = &iter->second;
        if (inserted) pindex->phashBlock = &iter->first;
        return pindex;
    };

    const auto inserter_store = [&](const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        if (hash.IsNull()) return (CBlockIndex*)nullptr;
        auto [iter, inserted] = map_store.try_emplace(hash);
        CBlockIndex* pindex = &iter->second;
        if (inserted) pindex->phashBlock = &iter->first;
        return pindex;
    };

    bool load_db;
    WITH_LOCK(::cs_main, load_db = block_index_db.LoadBlockIndexGuts(params, inserter_db, g_setup->m_interrupt));
    bool load_store;
    WITH_LOCK(::cs_main, load_store = block_index_store.LoadBlockIndexGuts(params, inserter_store, g_setup->m_interrupt));

    assert(load_db == load_store);

    if (load_db) {
        LOCK(::cs_main);
        assert(map_db.size() == map_store.size());

        for(const auto& [hash, index_db_ptr] : map_db) {
            assert(map_store.count(hash));
            const CBlockIndex* index_store = &map_store.at(hash);
            const CBlockIndex* index_db = &index_db_ptr;

            assert(AreBlockIndicesEqual(index_db, index_store));
        }
    }
}
