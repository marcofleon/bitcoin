// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <dbwrapper.h>
#include <kernel/blocktreestorage.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <primitives/block.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/fs.h>
#include <validation.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using kernel::CBlockFileInfo;

namespace {

const BasicTestingSetup* g_setup;

constexpr uint8_t DB_BLOCK_FILES{'f'};
constexpr uint8_t DB_BLOCK_INDEX{'b'};
constexpr uint8_t DB_FLAG{'F'};
constexpr uint8_t DB_REINDEX_FLAG{'R'};
constexpr uint8_t DB_LAST_BLOCK{'l'};

// Test-only writer for the legacy LevelDB block tree format.
class LegacyBlockTreeDB : public kernel::BlockTreeDB
{
public:
    using kernel::BlockTreeDB::BlockTreeDB;

    void WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*>>& file_info,
                        int last_file,
                        const std::vector<CBlockIndex*>& block_info)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        CDBBatch batch{*this};
        for (const auto& [file, info] : file_info) {
            batch.Write(std::make_pair(DB_BLOCK_FILES, file), *info);
        }
        batch.Write(DB_LAST_BLOCK, last_file);
        for (const CBlockIndex* bi : block_info) {
            batch.Write(std::make_pair(DB_BLOCK_INDEX, bi->GetBlockHash()), CDiskBlockIndex{bi});
        }
        WriteBatch(batch, /*fSync=*/true);
    }

    void WriteReindexing(bool reindexing)
    {
        if (reindexing) {
            Write(DB_REINDEX_FLAG, uint8_t{'1'});
        } else {
            Erase(DB_REINDEX_FLAG);
        }
    }

    void WriteFlag(const std::string& name, bool value)
    {
        Write(std::make_pair(DB_FLAG, name), value ? uint8_t{'1'} : uint8_t{'0'});
    }
};

bool AreBlockIndicesEqual(const CBlockIndex* a, const CBlockIndex* b) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    if (!a || !b) return a == b;

    const bool prev_match = (!a->pprev && !b->pprev) ||
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

int ConsumeBoundedCount(FuzzedDataProvider& provider, int max_count, size_t bytes_per_entry)
{
    const size_t input_bound{std::max<size_t>(1, std::min<size_t>(static_cast<size_t>(max_count), provider.remaining_bytes() / bytes_per_entry))};
    return provider.ConsumeIntegralInRange<int>(1, static_cast<int>(input_bound));
}

CBlockHeader ConsumeHeader(FuzzedDataProvider& provider, const uint256& prev_hash)
{
    CBlockHeader header;
    header.nVersion = provider.ConsumeIntegral<int32_t>();
    header.hashPrevBlock = prev_hash;
    header.hashMerkleRoot = ConsumeUInt256(provider);
    header.nTime = provider.ConsumeIntegral<uint32_t>();
    header.nBits = provider.ConsumeIntegral<uint32_t>();
    header.nNonce = provider.ConsumeIntegral<uint32_t>();
    while (!CheckProofOfWork(header.GetHash(), header.nBits, Params().GetConsensus())) {
        ++header.nNonce;
    }
    return header;
}

// Match CDiskBlockIndex's conditional serialization of file positions.
void FuzzIndexMetadata(FuzzedDataProvider& provider, CBlockIndex& index) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    index.nStatus = provider.ConsumeIntegral<uint32_t>();
    index.nFile = provider.ConsumeIntegralInRange<int>(0, std::numeric_limits<int>::max());
    index.nDataPos = provider.ConsumeIntegral<unsigned int>();
    index.nUndoPos = provider.ConsumeIntegral<unsigned int>();
    index.nTx = provider.ConsumeIntegral<unsigned int>();

    if (!(index.nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO))) index.nFile = 0;
    if (!(index.nStatus & BLOCK_HAVE_DATA)) index.nDataPos = 0;
    if (!(index.nStatus & BLOCK_HAVE_UNDO)) index.nUndoPos = 0;
}

void CheckHeaderPositions(const std::vector<CBlockIndex*>& indexes) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    std::vector<int64_t> positions;
    positions.reserve(indexes.size());
    for (const CBlockIndex* index : indexes) {
        assert(index->header_pos >= kernel::HEADER_FILE_DATA_START_POS);
        positions.push_back(index->header_pos);
    }
    std::ranges::sort(positions);
    assert(std::ranges::adjacent_find(positions) == positions.end());
}

void CheckHeaderPositions(const node::BlockMap& indexes) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    std::vector<int64_t> positions;
    positions.reserve(indexes.size());
    for (const auto& [_, index] : indexes) {
        assert(index.header_pos >= kernel::HEADER_FILE_DATA_START_POS);
        positions.push_back(index.header_pos);
    }
    std::ranges::sort(positions);
    assert(std::ranges::adjacent_find(positions) == positions.end());
}

} // namespace

void init_block_index_diff()
{
    static const auto testing_setup = MakeNoLogFileContext<const BasicTestingSetup>(ChainType::MAIN);
    g_setup = testing_setup.get();
}

FUZZ_TARGET(block_index_diff, .init = init_block_index_diff)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};

    const int files_count{ConsumeBoundedCount(provider, /*max_count=*/100, /*bytes_per_entry=*/8)};
    std::vector<std::unique_ptr<CBlockFileInfo>> files;
    files.reserve(files_count);
    std::vector<std::pair<int, const CBlockFileInfo*>> file_info;
    file_info.reserve(files_count);
    for (int i = 0; i < files_count; ++i) {
        auto info{ConsumeDeserializable<CBlockFileInfo>(provider)};
        if (!info) return;
        files.push_back(std::make_unique<CBlockFileInfo>(std::move(*info)));
        file_info.emplace_back(i, files.back().get());
    }

    const int blocks_count{ConsumeBoundedCount(provider, /*max_count=*/1000, /*bytes_per_entry=*/32)};
    const int32_t last_file{files_count - 1};

    LOCK(::cs_main);

    std::vector<std::unique_ptr<CBlockIndex>> blocks;
    std::vector<uint256> block_hashes;
    std::vector<CBlockIndex*> block_info;
    blocks.reserve(blocks_count);
    block_hashes.reserve(blocks_count);
    block_info.reserve(blocks_count);

    for (int i = 0; i < blocks_count; ++i) {
        CBlockIndex* parent{nullptr};
        if (!blocks.empty()) {
            parent = provider.ConsumeBool()
                         ? blocks.back().get()
                         : blocks[provider.ConsumeIntegralInRange<size_t>(0, blocks.size() - 1)].get();
        }
        const uint256 prev_hash{parent ? parent->GetBlockHash() : uint256{}};
        CBlockHeader header{ConsumeHeader(provider, prev_hash)};
        block_hashes.push_back(header.GetHash());
        blocks.push_back(std::make_unique<CBlockIndex>(header));
        CBlockIndex* index{blocks.back().get()};
        index->phashBlock = &block_hashes.back();
        index->pprev = parent;
        index->nHeight = parent ? parent->nHeight + 1 : 0;
        FuzzIndexMetadata(provider, *index);
        block_info.push_back(index);
    }

    LegacyBlockTreeDB db{DBParams{
        .path = "", // Memory only.
        .cache_bytes = 1 << 20,
        .memory_only = true,
    }};

    const fs::path store_dir{g_setup->m_args.GetDataDirBase() / "block_index_diff"};
    auto store = std::make_unique<kernel::BlockTreeStore>(store_dir, /*wipe_data=*/true);

    db.WriteBatchSync(file_info, last_file, block_info);
    store->WriteBatchSync(file_info, last_file, block_info);

    const auto check_file_infos{[&]() EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        CBlockFileInfo info_db, info_store;
        for (const auto& [n, expected] : file_info) {
            const bool ok_db{db.ReadBlockFileInfo(n, info_db)};
            const bool ok_store{store->ReadBlockFileInfo(n, info_store)};
            assert(ok_db == ok_store);
            assert(ok_db);
            assert(info_db == info_store);
            assert(info_db == *expected);
        }
        assert(!db.ReadBlockFileInfo(files_count, info_db));
        assert(!store->ReadBlockFileInfo(files_count, info_store));
    }};
    check_file_infos();
    CheckHeaderPositions(block_info);

    {
        int last_db;
        int32_t last_store;
        assert(db.ReadLastBlockFile(last_db));
        store->ReadLastBlockFile(last_store);
        assert(last_db == last_store);
        assert(last_db == last_file);
    }

    const bool want_reindex{provider.ConsumeBool()};
    {
        db.WriteReindexing(want_reindex);
        store->WriteReindexing(want_reindex);
        bool got_db{!want_reindex}, got_store{!want_reindex};
        db.ReadReindexing(got_db);
        store->ReadReindexing(got_store);
        assert(got_db == want_reindex);
        assert(got_store == want_reindex);
        assert(got_db == got_store);
    }

    const bool want_pruned{provider.ConsumeBool()};
    {
        db.WriteFlag("prunedblockfiles", want_pruned);
        store->WritePruned(want_pruned);
        bool got_db{!want_pruned}, got_store{!want_pruned};
        assert(db.ReadFlag("prunedblockfiles", got_db));
        store->ReadPruned(got_store);
        assert(got_db == want_pruned);
        assert(got_store == want_pruned);
        assert(got_db == got_store);
    }

    if (provider.ConsumeBool()) {
        for (CBlockIndex* bi : block_info) {
            if (provider.ConsumeBool()) FuzzIndexMetadata(provider, *bi);
        }
        for (auto& f : files) {
            if (provider.ConsumeBool()) {
                f->nBlocks = provider.ConsumeIntegral<unsigned int>();
                f->nSize = provider.ConsumeIntegral<unsigned int>();
                f->nUndoSize = provider.ConsumeIntegral<unsigned int>();
                f->nHeightFirst = provider.ConsumeIntegral<unsigned int>();
                f->nHeightLast = provider.ConsumeIntegral<unsigned int>();
                f->nTimeFirst = provider.ConsumeIntegral<uint64_t>();
                f->nTimeLast = provider.ConsumeIntegral<uint64_t>();
            }
        }
        db.WriteBatchSync(file_info, last_file, block_info);
        store->WriteBatchSync(file_info, last_file, block_info);
        check_file_infos();
        CheckHeaderPositions(block_info);
    }

    store.reset();
    store = std::make_unique<kernel::BlockTreeStore>(store_dir, /*wipe_data=*/false);
    check_file_infos();
    {
        bool got_reindex{!want_reindex};
        bool got_pruned{!want_pruned};
        store->ReadReindexing(got_reindex);
        store->ReadPruned(got_pruned);
        assert(got_reindex == want_reindex);
        assert(got_pruned == want_pruned);
    }

    node::BlockMap map_db;
    node::BlockMap map_store;
    const Consensus::Params& consensus{Params().GetConsensus()};

    const auto inserter{[](node::BlockMap& map, const uint256& hash) -> CBlockIndex* {
        if (hash.IsNull()) return nullptr;
        auto [it, inserted]{map.try_emplace(hash)};
        CBlockIndex* pindex{&it->second};
        if (inserted) pindex->phashBlock = &it->first;
        return pindex;
    }};

    const bool load_db{db.LoadBlockIndexGuts(
        consensus, [&](const uint256& hash) { return inserter(map_db, hash); }, g_setup->m_interrupt)};
    const bool load_store{store->LoadBlockIndexGuts(
        consensus, [&](const uint256& hash) { return inserter(map_store, hash); }, g_setup->m_interrupt)};
    assert(load_db == load_store);

    if (load_db) {
        assert(map_db.size() == map_store.size());
        CheckHeaderPositions(map_store);
        for (const auto& [hash, index_db] : map_db) {
            const auto it{map_store.find(hash)};
            assert(it != map_store.end());
            assert(AreBlockIndicesEqual(&index_db, &it->second));
        }
    }
}
