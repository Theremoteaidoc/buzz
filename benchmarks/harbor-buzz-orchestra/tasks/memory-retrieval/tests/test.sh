#!/bin/sh
set -eu
mkdir -p /logs/verifier
# Runtime writes the grade after observing the orchestrator's final answer.
# Missing runtime evidence fails closed.
python3 - <<'PYCODE'
from pathlib import Path
p = Path('/app/memory-retrieval-reward.txt')
reward = p.read_text().strip() if p.is_file() else '0.0'
Path('/logs/verifier/reward.txt').write_text('1.0' if reward == '1.0' else '0.0')
PYCODE
