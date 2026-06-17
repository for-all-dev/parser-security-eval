#!/bin/bash
# =============================================================================
# fuzzing_sweep_loop.sh — self-perpetuating, multi-core, resilient fuzzing sweep
# =============================================================================
# WHY THIS EXISTS
#   `parser-security-eval experiment run` processes its grid SEQUENTIALLY (one
#   inspect_eval at a time — see experiments/runner.py), so a single invocation
#   uses ~one core and grinds one (model,target) at a time. This wrapper drives
#   CONCURRENCY and BALANCE on top of it:
#     * launches up to $CAP `experiment run` processes at once (multi-core), and
#     * INTERLEAVES models and targets so every (model,target) combo advances
#       together — you get balanced data even if a round only partly finishes,
#       instead of grinding all of one slow target before the others start.
#   It also keeps the machine busy across long unattended runs and self-heals
#   from the failure modes we actually hit (Docker down, disk full, external
#   volume unmounting, transient sample failures).
#
# WHAT IT DOES
#   Repeatedly runs "rounds". Each round launches one shard per
#   (group x target x model); a shard is a 1-model x 1-target x $REPS experiment
#   with --retry-failed (up to $K attempts). Shards are resumable via their
#   manifest.json, so re-running is cheap and idempotent. Loops until the stop
#   file appears. Generates its per-shard TOML configs on the fly.
#
# USAGE
#   bash scaffold/scripts/fuzzing_sweep_loop.sh        # run in background
#   touch "$STATE_DIR/sweep-stop"                      # graceful stop (finishes round)
#   Tune via env vars (all optional, defaults below). Pick a unique PREFIX per
#   distinct run so result dirs / data namespaces don't collide.
#
# REQUIREMENTS
#   - Run from a checkout where ../.env holds API keys (sourced per shard).
#   - Docker/OrbStack running (auto-started if `orbctl` is present).
#   - macOS `df -g` is assumed for the disk guard; harmless elsewhere.
#   - Keep the machine awake separately, e.g.: caffeinate -dimsu &
# =============================================================================
set -u

# --- resolve repo paths from THIS script's location (portable across checkouts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAF="$(cd "$SCRIPT_DIR/.." && pwd)"            # the scaffold/ dir
STATE_DIR="${STATE_DIR:-/tmp}"                  # where stop/running/log files live
LOG="${LOG:-$STATE_DIR/fuzzing-sweep.log}"
STOP_FILE="$STATE_DIR/sweep-stop"
RUNNING_FILE="$STATE_DIR/sweep.running"

# --- tunable knobs -----------------------------------------------------------
PREFIX="${PREFIX:-fuzzing-sweep}"               # result-dir / data namespace prefix
TARGETS="${TARGETS:-libpng libxml2 libjpeg-turbo zlib}"
MODELS="${MODELS:-haiku:anthropic/claude-haiku-4-5 sonnet:anthropic/claude-sonnet-4-6 opus:anthropic/claude-opus-4-8}"
GRPS="${GRPS:-a b c}"                           # independent replicate groups per round
REPS="${REPS:-5}"                               # repetitions per shard
MSG="${MSG:-100}"                               # message_limit per agent sample
FUZZ="${FUZZ:-900}"                             # fuzz_duration (sec) per fuzz cycle
CAP="${CAP:-7}"                                 # max concurrent shards (cores)
MIN_FREE_GB="${MIN_FREE_GB:-8}"                 # emergency docker-prune threshold
K="${K:-6}"                                     # max retry attempts per shard
SSD_REMOUNT_DEV="${SSD_REMOUNT_DEV:-}"          # e.g. disk4s1 to auto-remount an external volume (macOS); empty = off

mkdir -p "$STATE_DIR"
echo "=== sweep start $(date -u '+%Y-%m-%dT%H:%M:%SZ') prefix=$PREFIX scaf=$SCAF ===" > "$LOG"

free_gb() { df -g "$SCAF" 2>/dev/null | awk 'NR==2{print $4}'; }
ensure_volume() {  # remount an external volume if the scaffold dir vanished (flaky NTFS/SSD)
  [ -d "$SCAF" ] && return 0
  [ -n "$SSD_REMOUNT_DEV" ] && command -v diskutil >/dev/null 2>&1 && diskutil mount "$SSD_REMOUNT_DEV" >/dev/null 2>&1
  sleep 6
}
docker_up() { docker info >/dev/null 2>&1; }
ensure_docker() {
  docker_up && return 0
  echo "[docker] down -> attempting start $(date -u '+%H:%M:%SZ')" >> "$LOG"
  command -v orbctl >/dev/null 2>&1 && orbctl start >/dev/null 2>&1
  local i; for i in $(seq 1 18); do docker_up && return 0; sleep 10; done
  return 1
}
disk_guard() {
  local f; f=$(free_gb)
  if [ -n "$f" ] && [ "$f" -lt "$MIN_FREE_GB" ] 2>/dev/null; then
    echo "[disk] LOW ${f}GB -> emergency prune $(date -u '+%H:%M:%SZ')" >> "$LOG"
    docker container prune -f >/dev/null 2>&1
    docker builder prune -af >/dev/null 2>&1
    docker image prune -f >/dev/null 2>&1
  fi
}
janitor() {  # background: keep disk clean without nuking tagged target images
  while [ -f "$RUNNING_FILE" ]; do
    if docker_up; then
      docker container prune -f >/dev/null 2>&1
      docker builder prune -f >/dev/null 2>&1
      docker image prune -f >/dev/null 2>&1
    fi
    echo "[janitor] free=$(free_gb)GB $(date -u '+%H:%M:%SZ')" >> "$LOG"
    sleep 300
  done
}
run_shard() {  # args: suffix mname mid target group
  local suf=$1 mname=$2 mid=$3 target=$4 group=$5
  local base="${PREFIX}${suf}-${mname}-${target}-${group}"
  local toml="experiments/${base}.toml"
  local mani="$SCAF/results/$base/manifest.json"
  ensure_volume
  cat > "$SCAF/$toml" <<EOF
name = "$base"
task = "fuzzing"
output_dir = "results/$base"
repetitions = $REPS
[defaults]
targets_root = "../targets"
engine = "libfuzzer"
message_limit = $MSG
fuzz_duration = $FUZZ
[grid]
model = ["$mid"]
target = ["$target"]
EOF
  local a out comp total
  for a in $(seq 1 "$K"); do
    ensure_volume
    [ -d "$SCAF" ] || { sleep 15; continue; }
    ensure_docker || { sleep 30; continue; }
    disk_guard
    out=$(python3 -c "
import json
from collections import Counter
try:
    d=json.load(open('$mani')); c=Counter(r['status'] for r in d['runs'].values())
    print(c.get('completed',0), len(d['runs']))
except Exception: print(0,-1)
" 2>/dev/null)
    comp=${out%% *}; total=${out##* }
    if [ "${total:-0}" -gt 0 ] 2>/dev/null && [ "${comp:-0}" -ge "${total:-1}" ] 2>/dev/null; then
      return 0  # shard fully complete
    fi
    ( cd "$SCAF" && set -a && source ../.env && set +a && \
      uv run parser-security-eval experiment run "$toml" --retry-failed ) >> "$LOG" 2>&1
    sleep 4
  done
}

touch "$RUNNING_FILE"
janitor &
JPID=$!
ROUND=1
while [ ! -f "$STOP_FILE" ]; do
  if [ "$ROUND" -eq 1 ]; then SUF=""; else SUF="-r$ROUND"; fi
  echo "=== ROUND $ROUND (suffix='$SUF') start $(date -u '+%Y-%m-%dT%H:%M:%SZ') free=$(free_gb)GB ===" >> "$LOG"
  # Group OUTERMOST, then target, then model INNERMOST. Launching model innermost
  # means haiku/sonnet/opus enter the concurrency pool together and progress in
  # lockstep; iterating targets above that means all targets advance in parallel
  # too -> balanced data even if a round only partly completes.
  for group in $GRPS; do
    for target in $TARGETS; do
      for mpair in $MODELS; do
        mname=${mpair%%:*}; mid=${mpair#*:}
        [ -f "$STOP_FILE" ] && break 3
        while [ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$CAP" ]; do
          [ -f "$STOP_FILE" ] && break
          sleep 8
        done
        run_shard "$SUF" "$mname" "$mid" "$target" "$group" &
        sleep 2
      done
    done
  done
  wait
  echo "=== ROUND $ROUND done $(date -u '+%Y-%m-%dT%H:%M:%SZ') free=$(free_gb)GB ===" >> "$LOG"
  ROUND=$((ROUND+1))
done
rm -f "$RUNNING_FILE"
kill "$JPID" 2>/dev/null
echo "=== sweep end (stop file seen) $(date -u '+%Y-%m-%dT%H:%M:%SZ') ===" >> "$LOG"
