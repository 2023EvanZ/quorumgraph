#!/bin/zsh
# Overnight grid 3 (bonus): does drift that hides itself make lineage guards pay?
# Then random drift at 0.4, then lineage-weighted spot checks vs uniform (api).
# Usage: ./runs/overnight3.sh [extra args, e.g. --seeds 1 --generations 3 for a smoke test] ; OUT_PREFIX to redirect
set -e
cd "${0:A:h}/.."  # repository root
P=${OUT_PREFIX:-runs/selection}
S="uv run python -m quorumgraph.experiments.selection --init-nepotism-max 1.0 --seeds 30 --generations 60 --bonuses 1.0 --workers 9"
G="gated recursive recursive_soft recursive_guarded"
echo "== B adversarial drift $(date)"
eval $S --worlds $G --drifts 0.2 0.4 --drift-mode adversarial --costs 0.1 0.5 --audits 0 0.05 0.25 \
  --out ${P}-adversarial "$@"
echo "== C random drift 0.4 $(date)"
eval $S --worlds $G --drifts 0.4 --costs 0.1 0.5 --audits 0 0.05 0.25 --out ${P}-drift04 "$@"
echo "== A lineage-weighted spot checks $(date)"
eval $S --worlds revoke_only gated recursive_soft --drifts 0 0.2 --costs 0.5 --audits 0.05 0.25 \
  --audit-channel api_lineage --out ${P}-api-lineage "$@"
echo "== done $(date)"
