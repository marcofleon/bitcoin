#!/usr/bin/env bash
# Sweep all CallOneOf-using fuzz harnesses across multiple FUZZ_CALL_ONE_OF_SEED
# values, parallelised across cores. Each campaign is one (harness, seed) pair
# running as a single-process libFuzzer for DURATION seconds; PARALLEL such
# campaigns run concurrently. If a campaign crashes, the full log and a summary
# identifying the harness + seed (i.e. the branch subset that was in effect)
# are preserved under OUT_DIR for later inspection.
#
# Usage:
#   ./fuzz_calloneof_sweep.sh [DURATION [NUM_SEEDS [PARALLEL]]]
#
#     DURATION    Wall-clock seconds per (harness, seed) campaign.
#                 Default: 600  (10 minutes)
#     NUM_SEEDS   Distinct FUZZ_CALL_ONE_OF_SEED values to try per harness.
#                 Each value picks an independent branch subset at every
#                 CallOneOf site. 63 covers every non-empty subset of a
#                 6-branch site exactly.
#                 Default: 63
#     PARALLEL    Number of campaigns running concurrently (= cores in use,
#                 since each campaign is single-process).
#                 Default: $(nproc) or 4
#
# Environment overrides:
#   FUZZ_BIN                Path to the fuzz binary. Default: ./build/bin/fuzz
#   OUT_DIR                 Where to keep crash artifacts. Default: ./calloneof_sweep_runs
#   HARNESSES               Space-separated harness names. Overrides the built-in list.
#   SEED_START              First FUZZ_CALL_ONE_OF_SEED to try; seeds used are
#                           SEED_START .. SEED_START+NUM_SEEDS-1. Default: a fresh
#                           random 32-bit value per run, so consecutive sweeps hit
#                           different slices of the mask space.
#   FUZZ_CALL_ONE_OF_BIAS   Forwarded to every campaign. Unset = uniform default
#                           (proper non-empty subsets); set to e.g. 0.3 or 0.7
#                           to bias each branch's inclusion probability.
#
# Notes:
# - All FUZZ_CALL_ONE_OF_VERBOSE mask logs are kept on success too (just the
#   one-liner per call site), so you can always tell which subset of branches
#   was exercised in any campaign.
# - On crash, the artifact directory contains:
#     CRASH_SUMMARY.txt     (harness, seed, masks)
#     fuzz.log              (full libFuzzer stderr/stdout)
#     crash-<hash>          (libFuzzer's reproducer file)
#     corpus/               (the campaign's corpus at time of crash)

set -uo pipefail

DURATION="${1:-600}"
NUM_SEEDS="${2:-63}"
PARALLEL="${3:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

FUZZ_BIN="${FUZZ_BIN:-./build/bin/fuzz}"
OUT_DIR="${OUT_DIR:-./calloneof_sweep_runs}"

# A run-wide random offset so the seeds we sweep aren't always the same
# 0..NUM_SEEDS-1 range. Override with `SEED_START=N ./fuzz_calloneof_sweep.sh`
# to reproduce a previous sweep's exact mask configurations.
SEED_START="${SEED_START:-$(od -An -N4 -tu4 /dev/urandom | tr -d ' \n')}"

# Verified mapping: every FUZZ_TARGET where the CallOneOf is exercised
# repeatedly per fuzz iteration (i.e. inside a LIMITED_WHILE in the harness
# itself, or in a helper called from such a loop). Harnesses where the
# CallOneOf fires at most once per iteration (str_printf, muhash, float,
# merkleblock) are intentionally omitted - the masking feature has no
# cumulative effect there, so sweeping seeds would just toggle a single
# choice per input.
DEFAULT_HARNESSES=(
    # src/test/fuzz/txorphan.cpp
    txorphan
    txorphan_protected
    # src/test/fuzz/p2p_transport_serialization.cpp
    p2p_transport_serialization
    # src/test/fuzz/p2p_headers_presync.cpp
    p2p_headers_presync
    # src/test/fuzz/coins_view.cpp (CallOneOfs are in helpers used by all 3)
    coins_view
    coins_view_db
    coins_view_overlay
    # src/test/fuzz/coinscache_sim.cpp
    coinscache_sim
    # src/test/fuzz/cmpctblock.cpp
    cmpctblock
    # src/test/fuzz/block_index_tree.cpp
    block_index_tree
    # src/test/fuzz/addrman.cpp
    addrman
    # src/test/fuzz/connman.cpp
    connman
    
    # src/test/fuzz/txdownloadman.cpp
    txdownloadman
    txdownloadman_impl
    # src/test/fuzz/torcontrol.cpp
    torcontrol
    # src/test/fuzz/script_ops.cpp
    script_ops
    # src/test/fuzz/rpc.cpp
    rpc
    # src/test/fuzz/poolresource.cpp
    pool_resource
    # src/test/fuzz/utxo_total_supply.cpp
    utxo_total_supply
    # src/test/fuzz/system.cpp
    system
    # src/test/fuzz/scriptnum_ops.cpp
    scriptnum_ops
    # src/test/fuzz/rolling_bloom_filter.cpp
    rolling_bloom_filter
    # src/test/fuzz/minisketch.cpp
    minisketch
    # src/test/fuzz/crypto_diff_fuzz_chacha20.cpp
    crypto_diff_fuzz_chacha20
    # src/test/fuzz/crypto.cpp
    crypto
    # src/test/fuzz/crypto_chacha20.cpp
    crypto_chacha20
    # src/test/fuzz/buffered_file.cpp
    buffered_file
    # src/test/fuzz/bloom_filter.cpp
    bloom_filter
    # src/test/fuzz/bitdeque.cpp
    bitdeque
    # src/test/fuzz/banman.cpp
    banman
    # src/test/fuzz/autofile.cpp
    autofile
    # src/test/fuzz/policy_estimator.cpp
    policy_estimator
    # src/wallet/test/fuzz/scriptpubkeyman.cpp
    scriptpubkeyman
    spkm_migration
    # src/wallet/test/fuzz/crypter.cpp
    crypter
    # src/wallet/test/fuzz/coincontrol.cpp
    coincontrol
    # src/wallet/test/fuzz/spend.cpp
    wallet_create_transaction
)

if [[ -n "${HARNESSES:-}" ]]; then
    # shellcheck disable=SC2206
    HARNESSES=($HARNESSES)
else
    HARNESSES=("${DEFAULT_HARNESSES[@]}")
fi

if [[ ! -x "$FUZZ_BIN" ]]; then
    echo "error: fuzz binary not found or not executable: $FUZZ_BIN" >&2
    echo "       set FUZZ_BIN=path/to/fuzz to override" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

TOTAL=$(( ${#HARNESSES[@]} * NUM_SEEDS ))
echo "fuzz binary : $FUZZ_BIN"
echo "out dir     : $OUT_DIR"
echo "harnesses   : ${#HARNESSES[@]}"
echo "seeds/each  : $NUM_SEEDS  ($SEED_START .. $((SEED_START + NUM_SEEDS - 1)))"
echo "bias        : ${FUZZ_CALL_ONE_OF_BIAS:-(unset; default 0.5 uniform)}"
echo "duration    : ${DURATION}s per campaign"
echo "parallel    : $PARALLEL concurrent campaigns"
echo "total       : $TOTAL campaigns"
echo "approx wall : ~$(( (TOTAL + PARALLEL - 1) / PARALLEL * DURATION ))s"
echo ""

# Worker run by xargs: handles one (harness, seed) pair as a single-process
# libFuzzer campaign. Exits 0 always; crashes are signalled via the presence
# of $run_dir/CRASH_SUMMARY.txt under $OUT_DIR after the sweep completes.
run_one_campaign() {
    local harness="$1"
    local seed="$2"
    local run_dir="$OUT_DIR/${harness}_seed${seed}"
    mkdir -p "$run_dir"
    local log_file="$run_dir/fuzz.log"
    local corpus_dir="$run_dir/corpus"
    mkdir -p "$corpus_dir"

    if FUZZ="$harness" \
       FUZZ_CALL_ONE_OF_SEED="$seed" \
       FUZZ_CALL_ONE_OF_VERBOSE=1 \
       "$FUZZ_BIN" \
          -max_total_time="$DURATION" \
          -artifact_prefix="$run_dir/" \
          "$corpus_dir" \
          >"$log_file" 2>&1
    then
        grep '^\[FUZZ_CALL_ONE_OF\]' "$log_file" > "$run_dir/masks.log" 2>/dev/null || true
        rm -f "$log_file"
        rm -rf "$corpus_dir"
        [[ -s "$run_dir/masks.log" ]] || rm -f "$run_dir/masks.log"
        rmdir "$run_dir" 2>/dev/null || true
        printf 'ok    %-40s seed=%d\n' "$harness" "$seed"
    else
        {
            echo "harness=$harness"
            echo "FUZZ_CALL_ONE_OF_SEED=$seed"
            echo "FUZZ_CALL_ONE_OF_BIAS=${FUZZ_CALL_ONE_OF_BIAS:-(unset; default 0.5 uniform)}"
            echo "duration=${DURATION}s"
            echo "fuzz_bin=$FUZZ_BIN"
            echo "---- CallOneOf mask log ----"
            grep '^\[FUZZ_CALL_ONE_OF\]' "$log_file" 2>/dev/null || true
        } > "$run_dir/CRASH_SUMMARY.txt"
        printf 'CRASH %-40s seed=%d -> %s\n' "$harness" "$seed" "$run_dir"
    fi
}
export -f run_one_campaign
export FUZZ_BIN OUT_DIR DURATION

# Trap Ctrl+C so the user can bail without leaving zombie workers behind.
# `jobs -p | xargs kill` would also work, but PROPAGATE_SIGNAL=INT on xargs
# isn't portable; killing the process group is the simplest universal trick.
cleanup() {
    echo
    echo "interrupted; killing in-flight campaigns..."
    # Kill our entire process group so all xargs-spawned bash + fuzz workers die.
    kill -INT 0 2>/dev/null || true
    exit 130
}
trap cleanup INT

# Generate (harness, seed) pairs, one per line, and feed them to xargs -P
# for parallel dispatch. Using -n2 keeps the args tied: xargs reads two
# whitespace-separated tokens at a time and passes them to the bash worker.
{
    for h in "${HARNESSES[@]}"; do
        for s in $(seq "$SEED_START" $((SEED_START + NUM_SEEDS - 1))); do
            printf '%s %s\n' "$h" "$s"
        done
    done
} | xargs -P "$PARALLEL" -n 2 bash -c 'run_one_campaign "$1" "$2"' _

# Summarize after the pool drains.
echo ""
mapfile -t crash_dirs < <(find "$OUT_DIR" -maxdepth 2 -name CRASH_SUMMARY.txt -print 2>/dev/null | sed 's|/CRASH_SUMMARY\.txt$||' | sort)
echo "done: $TOTAL campaigns, ${#crash_dirs[@]} crashes"
if (( ${#crash_dirs[@]} > 0 )); then
    echo "crash dirs:"
    printf '  %s\n' "${crash_dirs[@]}"
    exit 1
fi
