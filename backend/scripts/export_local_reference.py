"""Reference data for validating the in-browser (TypeScript) detectors.

Runs the real Python/PyOD pipeline on a labelled synthetic dataset and saves:
  frontend/tests/local/flows.csv       the flows (with ground-truth label + src_ip)
  frontend/tests/local/reference.json  PyOD ECOD/LOF/IForest scores on the same
                                       preprocessing, and the Python engine's
                                       flag rate / recall / false-positive rate
Run from backend/:  python scripts/export_local_reference.py
"""
import json
import os
import sys
from pathlib import Path

os.environ["ENTITY_LEARNING_MIN_FLOWS"] = "0"
BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "scripts"))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from pyod.models.ecod import ECOD  # noqa: E402
from pyod.models.iforest import IForest  # noqa: E402
from pyod.models.lof import LOF  # noqa: E402
from sklearn.preprocessing import LabelEncoder, StandardScaler  # noqa: E402

from app.ml.engine import TenantDetector  # noqa: E402
from app.ml.generate_telemetry import generate  # noqa: E402
from seed_demo_tenant import _flow_records  # noqa: E402

OUT = BACKEND.parent / "frontend" / "tests" / "local"
OUT.mkdir(parents=True, exist_ok=True)

df = generate(n_benign=1500, attack_frac=0.12, seed=2024)
recs = _flow_records(df)
flows = pd.DataFrame(recs).drop(columns=["source_label"])
flows["label"] = df["Label"].values
flows.to_csv(OUT / "flows.csv", index=False)

cols = ["dur", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl"]
X = flows[cols].copy()
X["proto_enc"] = LabelEncoder().fit_transform(flows["proto"])
Xs = StandardScaler().fit_transform(X)

ecod = ECOD(contamination=0.10).fit(Xs)
lof = LOF(contamination=0.10, n_neighbors=20).fit(Xs)
ifo = IForest(contamination=0.10, random_state=42, n_estimators=200).fit(Xs)

# Python engine in the same "fit on the file, score the file" setting
det = TenantDetector("ref")
det.refit_on_real(flows[["dur", "proto", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl"]])
scored = det.score(flows.assign(src_ip="10.0.0.1"))   # single source: entity logic is not what we compare
attack = flows["label"].ne("Benign").values
flag = scored["severity"].notna().values
ref = {
    "n": len(flows),
    "ecod": ecod.decision_scores_.tolist(),
    "lof": lof.decision_scores_.tolist(),
    "iforest": ifo.decision_scores_.tolist(),
    "python_engine": {
        "flag_rate": float(flag.mean()),
        "attack_recall": float(flag[attack].mean()),
        "benign_flag_rate": float(flag[~attack].mean()),
        "attacks": int(attack.sum()),
    },
}
(OUT / "reference.json").write_text(json.dumps(ref))
print("rows", len(flows), "python engine:", ref["python_engine"])
