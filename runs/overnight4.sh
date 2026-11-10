#!/bin/zsh
# Grid 4: per-action spot checks (api_action) at the cells where agent-level checks (api) were weak,
# then adversarial drift 0.4, where the lineage-guard result lives.
# Usage: ./runs/overnight4.sh [extra args, e.g. --seeds 1 --generations 3 for a smoke test] ; OUT_PREFIX to redirect
set -e
cd "${0:A:h}/.."  # repository root
P=${OUT_PREFIX:-runs/selection}
S="uv run python -m quorumgraph.experiments.selection --init-nepotism-max 1.0 --seeds 30 --generations 60 --bonuses 1.0 --workers 9 --audit-channel api_action"
echo "== A per-action checks, matching the api grid $(date)"
eval $S --worlds revoke_only gated recursive_soft --drifts 0 0.2 --costs 0.5 --audits 0.05 0.25 \
  --out ${P}-api-action "$@"
echo "== B per-action checks, adversarial drift 0.4 $(date)"
eval $S --worlds gated recursive recursive_soft recursive_guarded --drifts 0.4 --drift-mode adversarial \
  --costs 0.5 --audits 0.05 0.25 --out ${P}-api-action-adv "$@"
echo "== done $(date)"
