#!/bin/zsh
# Overnight grid 2: successor drift × guard modes (sim channel), then API audit channel.
set -e
cd "${0:A:h}/.."  # repository root
S="uv run python -m quorumgraph.experiments.selection --init-nepotism-max 1.0 --seeds 30 --generations 60 --bonuses 1.0 --workers 9"
echo "== A1 $(date)"
eval $S --worlds recursive_soft --drifts 0 --costs 0.1 0.5 --audits 0 0.05 0.25 \
  --merge runs/selection-recursive/generations.csv --out runs/selection-drift0
echo "== A2 $(date)"
eval $S --worlds ungated revoke_only gated recursive recursive_guarded recursive_soft --drifts 0.2 \
  --costs 0.1 0.5 --audits 0 0.05 0.25 --out runs/selection-drift02
echo "== B $(date)"
eval $S --worlds revoke_only gated recursive recursive_guarded recursive_soft --drifts 0 0.2 \
  --costs 0.1 0.5 --audits 0.05 0.25 --audit-channel api --out runs/selection-api
echo "== done $(date)"
