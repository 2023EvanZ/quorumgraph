#!/bin/zsh
# Grid 5: robustness check for per-action spot checks at transparency cost 0.1
# (grid 4 stage A ran cost 0.5 only; api and sim grids already cover cost 0.1).
# Usage: ./runs/overnight5.sh [extra args] ; OUT_PREFIX to redirect
set -e
cd "${0:A:h}/.."  # repository root
P=${OUT_PREFIX:-runs/selection}
echo "== per-action checks, cost 0.1 $(date)"
uv run python -m quorumgraph.experiments.selection --init-nepotism-max 1.0 --seeds 30 --generations 60 \
  --bonuses 1.0 --workers 9 --audit-channel api_action --worlds revoke_only gated recursive_soft \
  --drifts 0 0.2 --costs 0.1 --audits 0.05 0.25 --out ${P}-api-action-c01 "$@"
echo "== done $(date)"
