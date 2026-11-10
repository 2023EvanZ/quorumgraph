#!/bin/zsh
# Grid 6: cousin collusion vs kin radius. Adversarial drift 0.4, sim audits.
# Primary outcome (fixed before the run): fraction of drifted agents trusted. Secondary: capture, collapse.
# Baseline without cousin nepotism = runs/selection-adversarial (same cells, nepotism radius 0).
set -e
cd "${0:A:h}/.."  # repository root
P=${OUT_PREFIX:-runs/selection}
S=(uv run python -m quorumgraph.experiments.selection --init-nepotism-max 1.0 --seeds 30 --generations 60
   --bonuses 1.0 --workers 9 --drifts 0.4 --drift-mode adversarial --costs 0.1 0.5 --audits 0.05 0.25
   --nepotism-radius 2)
echo "== A cousin nepotism, kin radius 0 $(date)"
"${S[@]}" --worlds recursive recursive_soft recursive_guarded --kin-radius 0 --out ${P}-cousin-k0 "$@"
echo "== B cousin nepotism, kin radius 2 $(date)"
"${S[@]}" --worlds recursive_soft recursive_guarded --kin-radius 2 --out ${P}-cousin-k2 "$@"
echo "== done $(date)"
