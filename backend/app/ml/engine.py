"""
Live detection engine — the same method validated in the standalone demo
(ECOD + Isolation Forest from PyOD, unsupervised), refactored to score
incoming flows in small batches rather than one static CSV, with additions
aimed at closing the gap with commercial network-anomaly tooling:

  1. Explainability: for each flagged flow, which features deviated most
     from the fitted baseline, and by how much (z-score). Turns "anomaly
     score 27.4" into "flagged because packet rate was 8.2x baseline" —
     the difference between a black-box score and something an analyst
     can act on.
  2. Severity tiers: low/medium/high/critical derived from where a flow's
     score falls in the *training distribution's* own percentiles, so
     severity is calibrated to this tenant's actual traffic.
  3. Ensemble consensus (v4): a third detector, Local Outlier Factor, runs
     alongside ECOD and Isolation Forest. These three disagree in different
     ways on different attack shapes (ECOD: distributional extremes, IForest:
     isolable points, LOF: local density) — a flow all three flag is a much
     stronger signal than one. `consensus_count` is reported per flow, and
     a flow 2+ detectors agree on gets escalated a severity tier, or picked
     up even when ECOD's own percentile missed it.
  4. Entity-level burst detection (v4): beyond per-flow scoring, the engine
     tracks a short sliding window of *flagged* events per source IP. A
     source that trips several independent detections within a short window
     is promoted to critical even if no single flow in isolation looked
     extreme — this is the "low-and-slow" pattern a single-flow detector
     alone will miss.
  5. Adaptive thresholds (v4): severity cut points are not frozen at fit
     time. A rolling window of recent live scores (seeded from the fitted
     training distribution) is recomputed periodically, so the baseline
     drifts with the tenant's actual traffic instead of staying pinned to
     whatever it looked like at bootstrap.
  6. True online learning (v5): ECOD/IForest/LOF are all batch learners --
     they only ever update at bootstrap or on an explicit refit_on_real(),
     flagged honestly in earlier versions as "a cold-start strategy, not
     production-grade online learning." River's HalfSpaceTrees closes that
     gap for real: it's a streaming anomaly detector built for exactly this
     setting (Tan, Ting & Liu, "Fast Anomaly Detection for Streaming Data",
     IJCAI 2011) that scores *then* incrementally updates on every single
     flow, with no refit step at all. It's the 4th ensemble member, and the
     only one that is actually learning online in the literal sense.
  7. Per-entity behavioral baseline (v5): separate from the tenant-wide
     scaler baseline, each source IP gets its own running mean/variance
     (Welford's online algorithm) over its own flow history. A flow that's
     unremarkable for the tenant as a whole but wildly unlike what *that
     specific host* normally does — the "there's nothing wrong with this
     traffic, but this printer has never spoken to this host before"
     pattern — gets its own escalation reason, independent of the
     tenant-wide ensemble. This is the per-asset baselining commercial NDR
     tools lead with, not just a global threshold.
  8. Cross-instance checkpointing (v6): the model state described above
     used to live only in one process's memory, which breaks the moment
     more than one backend instance runs behind a load balancer. See
     ml/persistence.py for exactly what was and wasn't solved here --
     short version: periodic Redis checkpointing gives recovery and
     warm-start across instances, not live per-flow replication. Real
     per-flow consistency across concurrent writers needs sticky routing
     (same tenant always hits the same instance), which is a deployment
     concern documented in DEPLOY.md, not something this module can do by
     itself.

Per-tenant model state: a brand-new tenant has no history to fit on, so we
bootstrap each tenant's detector on synthetic representative traffic (see
ml/generate_telemetry.py) until enough of their own real flows have arrived
(MIN_REAL_FLOWS_TO_REFIT), at which point we refit on their real traffic.
This is a pragmatic cold-start strategy for the batch detectors specifically
-- HalfSpaceTrees (point 6 above) is the one genuinely online member.
"""
from __future__ import annotations
import os
import zlib
import time
from collections import deque

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from pyod.models.ecod import ECOD
from pyod.models.iforest import IForest
from pyod.models.lof import LOF
from river import anomaly as river_anomaly

from .generate_telemetry import generate

FEATURES = ["dur", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl"]
MIN_REAL_FLOWS_TO_REFIT = int(os.environ.get("MIN_REAL_FLOWS_TO_REFIT", "1000"))
DEFAULT_CONTAMINATION = 0.10  # prior assumption until a tenant's own rate is known

# Severity cut points, as percentiles of this tenant's own fitted score
# distribution -- e.g. a score above the 99.5th percentile of normal
# training scores is "critical" for THIS tenant's traffic, not some
# universal constant that doesn't fit every network's baseline.
SEVERITY_PERCENTILES = {"low": 90.0, "medium": 97.0, "high": 99.5}
SEVERITY_ORDER = [None, "low", "medium", "high", "critical"]

# Adaptive-threshold window: how many recent live scores to keep, and how
# often (in flows scored) to recompute severity cuts from that window.
ADAPTIVE_WINDOW_SIZE = 5000
ADAPTIVE_RECOMPUTE_EVERY = 100

# Entity burst window: if a single source IP accrues this many independently
# flagged events within this many seconds, escalate to critical regardless
# of individual flow severity.
ENTITY_BURST_WINDOW_SECONDS = 60
ENTITY_BURST_THRESHOLD = 5
# ...AND those flagged events must be a real concentration, not just a busy
# host: flagged / all-flows-scored-for-that-source within the window must be
# at least this share. Without it, any source sending a few hundred flows a
# minute trips "5 flagged in 60s" purely from the ~10% base flag rate, so
# every busy host (your own PC, a gateway) went critical on ordinary traffic.
ENTITY_BURST_MIN_SHARE = 0.30

# Online-detector (HalfSpaceTrees) adaptive window -- same pattern as the
# ECOD severity window, kept separately since the two detectors' score
# distributions aren't comparable.
HST_WINDOW_SIZE = 5000
HST_RECOMPUTE_EVERY = 100
HST_SEVERITY_PERCENTILE = 90.0  # HalfSpaceTrees scores are already a 0-1
                                 # anomaly probability, so one cut is enough
                                 # to call it "flagged" for consensus purposes.

# Per-entity behavioral baseline: minimum history before we trust an
# entity's own mean/variance enough to escalate on it (too few points and
# the "baseline" is just noise), and how many standard deviations from
# that entity's own baseline counts as a drift worth flagging.
ENTITY_BASELINE_MIN_SAMPLES = 20
ENTITY_BASELINE_Z_THRESHOLD = 5.0

# Learning period for a source seen for the first time: its first N flows are
# stored and learned from but NOT judged (no severity, no event). Judging a
# brand-new device against everyone else's traffic is exactly what produced
# the false alarms on real captures (first-seen hosts look "foreign" to a
# model that has never seen them). 0 disables the learning period.
ENTITY_LEARNING_MIN_FLOWS = int(os.environ.get("ENTITY_LEARNING_MIN_FLOWS", "50"))
# When a source finishes learning, the tenant's models are refit on the pool
# of real flows seen so far, so they include the new device's normal -- but
# at most once per this many seconds and only with a pool of at least
# LEARNING_REFIT_MIN_POOL flows (refits cost a second or two of CPU).
LEARNING_REFIT_MIN_POOL = int(os.environ.get("LEARNING_REFIT_MIN_POOL", "300"))
LEARNING_REFIT_MIN_INTERVAL_S = int(os.environ.get("LEARNING_REFIT_MIN_INTERVAL_S", "300"))
LEARNING_POOL_SIZE = 5000
_RAW_COLS = ["dur", "proto", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl"]

# Cross-instance checkpoint cadence (see ml/persistence.py). Pickling and
# shipping a ~5MB detector to Redis on every single flow would be absurd
# overhead for a once-every-N-flows freshness guarantee -- this interval
# trades a bounded staleness window (worst case: this many flows' worth of
# threshold/baseline drift lost on failover) for a sane write rate.
CHECKPOINT_EVERY_FLOWS = 500


def _stable_seed(tenant_id: str) -> int:
    """Python's str hash() is randomised per process (PYTHONHASHSEED), so the
    old `hash(tenant_id)` gave the same tenant a DIFFERENT synthetic bootstrap
    model on every restart and on every backend instance. crc32 is stable."""
    return zlib.crc32(tenant_id.encode()) % (2**31)


class EntityBaseline:
    """One source IP's own running mean/variance over raw (unscaled)
    feature values, via Welford's online algorithm -- numerically stable,
    single-pass, exact (not an approximation like a fixed-alpha EWMA), and
    the standard textbook approach for streaming variance."""

    __slots__ = ("n", "mean", "m2")

    def __init__(self):
        self.n = 0
        self.mean = np.zeros(len(FEATURES))
        self.m2 = np.zeros(len(FEATURES))

    def deviation(self, x: np.ndarray) -> np.ndarray | None:
        """Z-score of x against this entity's own baseline so far, or None
        if there isn't yet enough history to trust it."""
        if self.n < ENTITY_BASELINE_MIN_SAMPLES:
            return None
        variance = self.m2 / max(self.n - 1, 1)
        std = np.sqrt(np.maximum(variance, 1e-6))
        return (x - self.mean) / std

    def update(self, x: np.ndarray):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2


class TenantDetector:
    """One detector ensemble per tenant, held in memory. For a real
    deployment this would be persisted (e.g. pickled to Supabase Storage)
    rather than refit on every cold start -- noted here, not yet built."""

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.scaler = StandardScaler()
        self.proto_encoder = LabelEncoder()
        self.ecod = ECOD(contamination=DEFAULT_CONTAMINATION)
        self.iforest = IForest(contamination=DEFAULT_CONTAMINATION, random_state=42, n_estimators=200)
        self.lof = LOF(contamination=DEFAULT_CONTAMINATION, n_neighbors=20)
        self.hst = river_anomaly.HalfSpaceTrees(seed=_stable_seed(tenant_id))
        self._score_window: deque[float] = deque(maxlen=ADAPTIVE_WINDOW_SIZE)
        self._hst_score_window: deque[float] = deque(maxlen=HST_WINDOW_SIZE)
        self._hst_flows_since_recompute = 0
        self._hst_cut = 0.5  # replaced as soon as the bootstrap window is seeded
        self._flows_since_recompute = 0
        self._entity_events: dict[str, deque[float]] = {}
        self._entity_flows: dict[str, deque[float]] = {}
        self._entity_baselines: dict[str, EntityBaseline] = {}
        self._flows_since_checkpoint = 0
        self.is_from_checkpoint = False
        self._pool: deque = deque(maxlen=LEARNING_POOL_SIZE)  # raw rows of real flows seen
        self._graduated_pending = 0   # sources that finished learning since last refit
        self._last_learning_refit = 0.0
        self._fit_bootstrap()

    def _build_matrix(self, df: pd.DataFrame, fit_encoders: bool) -> np.ndarray:
        X = df[["Dur", "TotPkts", "SrcBytes", "DstBytes", "Rate", "Load", "sTtl"]].copy() \
            if "Dur" in df.columns else df[["dur", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl"]].copy()
        X.columns = ["dur", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl"]
        proto_col = df["Proto"] if "Proto" in df.columns else df["proto"]
        if fit_encoders:
            X["proto_enc"] = self.proto_encoder.fit_transform(proto_col)
            return self.scaler.fit_transform(X)
        else:
            known = set(self.proto_encoder.classes_)
            safe_proto = proto_col.apply(lambda p: p if p in known else self.proto_encoder.classes_[0])
            X["proto_enc"] = self.proto_encoder.transform(safe_proto)
            return self.scaler.transform(X)

    def _fit_severity_thresholds(self, train_scores: np.ndarray):
        """Seed the adaptive score window from the freshly fitted training
        distribution, then derive severity cuts from that window. After
        this point the window also absorbs live scores (see `score()`), so
        cuts drift with real traffic rather than staying pinned to fit time."""
        self._score_window.clear()
        self._score_window.extend(float(s) for s in train_scores)
        self._flows_since_recompute = 0
        self._recompute_severity_cuts()

    def _recompute_severity_cuts(self):
        window = np.array(self._score_window)
        self._severity_cuts = {
            tier: float(np.percentile(window, pct))
            for tier, pct in SEVERITY_PERCENTILES.items()
        }

    def _row_to_river_dict(self, row_scaled: np.ndarray) -> dict:
        feature_names = FEATURES + ["proto_enc"]
        return {feature_names[i]: float(row_scaled[i]) for i in range(len(feature_names))}

    def _seed_hst(self, X: np.ndarray):
        """River's HalfSpaceTrees has no batch .fit(): it only ever learns
        one flow at a time. To give a brand-new tenant usable HST detection
        from flow #1 (same promise the ECOD/IForest/LOF bootstrap makes),
        we replay the bootstrap rows through score_one/learn_one in
        sequence -- this *is* how the model is meant to be warmed up, not a
        workaround. Freshly re-instantiated so refit_on_real() gets a clean
        online model rather than one still carrying synthetic history."""
        self.hst = river_anomaly.HalfSpaceTrees(seed=_stable_seed(self.tenant_id))
        self._hst_score_window.clear()
        for i in range(len(X)):
            d = self._row_to_river_dict(X[i])
            self._hst_score_window.append(self.hst.score_one(d))
            self.hst.learn_one(d)
        self._hst_flows_since_recompute = 0
        self._recompute_hst_cut()

    def _recompute_hst_cut(self):
        if self._hst_score_window:
            self._hst_cut = float(np.percentile(np.array(self._hst_score_window), HST_SEVERITY_PERCENTILE))

    def _fit_bootstrap(self):
        """Cold start: fit on synthetic representative traffic so a brand-new
        tenant gets usable (if imperfect) detection from flow #1."""
        bootstrap_df = generate(n_benign=4000, attack_frac=0.10, seed=_stable_seed(self.tenant_id))
        X = self._build_matrix(bootstrap_df, fit_encoders=True)
        self.ecod.fit(X)
        self.iforest.fit(X)
        self.lof.fit(X)
        self._fit_severity_thresholds(self.ecod.decision_scores_)
        self._seed_hst(X)
        self.is_bootstrapped_on_synthetic = True

    def refit_on_real(self, real_flows_df: pd.DataFrame):
        X = self._build_matrix(real_flows_df, fit_encoders=True)
        self.ecod.fit(X)
        self.iforest.fit(X)
        self.lof.fit(X)
        self._fit_severity_thresholds(self.ecod.decision_scores_)
        self._seed_hst(X)
        self.is_bootstrapped_on_synthetic = False

    def _severity_for(self, score: float) -> str | None:
        if score < self._severity_cuts["low"]:
            return None  # below the 90th percentile of normal traffic -- not flagged
        if score < self._severity_cuts["medium"]:
            return "low"
        if score < self._severity_cuts["high"]:
            return "medium"
        if score < self._severity_cuts["high"] * 1.3:
            return "high"
        return "critical"

    def _explain(self, row_scaled: np.ndarray) -> list[dict]:
        """Per-feature z-scores for one scaled flow (proto excluded -- its
        encoding isn't meaningfully a z-score). Returns the top 3 features
        by absolute deviation, so an analyst sees *why*, not just *that*."""
        feature_names = FEATURES  # matches the first len(FEATURES) columns before proto_enc
        contributions = [
            {"feature": feature_names[i], "z_score": round(float(row_scaled[i]), 2)}
            for i in range(len(feature_names))
        ]
        contributions.sort(key=lambda c: abs(c["z_score"]), reverse=True)
        return contributions[:3]

    def _escalate(self, severity: str | None, steps: int = 1) -> str | None:
        idx = SEVERITY_ORDER.index(severity)
        return SEVERITY_ORDER[min(idx + steps, len(SEVERITY_ORDER) - 1)]

    def _entity_key(self, row) -> str:
        src = row.get("src_ip") if hasattr(row, "get") else None
        return src if src else "unidentified"

    def _check_burst(self, entity: str, now: float) -> int:
        """Record a flagged event for this entity and return how many
        flagged events it has accrued within the burst window (including
        this one). A source tripping several independent detections in a
        short window is the 'low-and-slow' pattern no single flow score
        reveals on its own."""
        dq = self._entity_events.setdefault(entity, deque())
        dq.append(now)
        cutoff = now - ENTITY_BURST_WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def _note_flow(self, entity: str, now: float) -> int:
        """Record that a flow from this entity was scored (flagged or not);
        returns how many flows it has had inside the burst window."""
        fq = getattr(self, "_entity_flows", None)
        if fq is None:  # detector unpickled from an older checkpoint
            fq = self._entity_flows = {}
        dq = fq.setdefault(entity, deque())
        dq.append(now)
        cutoff = now - ENTITY_BURST_WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def learning_refit_due(self) -> bool:
        """True when at least one source finished its learning period, the
        pool of real flows is big enough, and the refit throttle allows it."""
        pool = getattr(self, "_pool", None)
        return bool(
            getattr(self, "_graduated_pending", 0) > 0 and pool is not None
            and len(pool) >= LEARNING_REFIT_MIN_POOL
            and time.time() - getattr(self, "_last_learning_refit", 0.0) >= LEARNING_REFIT_MIN_INTERVAL_S
        )

    def refit_after_learning(self) -> bool:
        """Refit the tenant's models on the pool of real flows (which now
        includes the freshly learned sources). CPU-bound: call via
        asyncio.to_thread. Returns True if a refit ran."""
        if not self.learning_refit_due():
            return False
        df = pd.DataFrame(list(self._pool), columns=_RAW_COLS)
        self.refit_on_real(df)
        self._graduated_pending = 0
        self._last_learning_refit = time.time()
        return True

    def score(self, flows_df: pd.DataFrame) -> pd.DataFrame:
        X = self._build_matrix(flows_df, fit_encoders=False)
        if getattr(self, "_pool", None) is None:  # detector unpickled from an older checkpoint
            self._pool = deque(maxlen=LEARNING_POOL_SIZE)
            self._graduated_pending = 0
            self._last_learning_refit = 0.0
        canon = flows_df.rename(columns={"Dur": "dur", "Proto": "proto", "TotPkts": "tot_pkts",
                                         "SrcBytes": "src_bytes", "DstBytes": "dst_bytes",
                                         "Rate": "rate", "Load": "load", "sTtl": "s_ttl"})
        self._pool.extend(canon[_RAW_COLS].itertuples(index=False, name=None))
        learning_flags: list[bool] = []
        ecod_scores = self.ecod.decision_function(X)
        ecod_labels = self.ecod.predict(X)
        iforest_scores = self.iforest.decision_function(X)
        iforest_labels = self.iforest.predict(X)
        lof_scores = self.lof.decision_function(X)
        lof_labels = self.lof.predict(X)

        now = time.time()
        severities: list[str | None] = []
        consensus_counts: list[int] = []
        escalation_reasons: list[str | None] = []
        hst_scores: list[float] = []
        hst_labels: list[bool] = []
        entity_baseline_z: list[float | None] = []

        for i in range(len(X)):
            # HalfSpaceTrees: score this exact flow against everything it
            # has learned so far, THEN learn from it -- true single-pass
            # online learning, not a periodic refit. Order matters: scoring
            # before learning means a flow is judged against history, never
            # against itself.
            river_x = self._row_to_river_dict(X[i])
            hst_score = self.hst.score_one(river_x)
            self.hst.learn_one(river_x)
            hst_is_anomaly = hst_score >= self._hst_cut
            hst_scores.append(hst_score)
            hst_labels.append(hst_is_anomaly)
            self._hst_score_window.append(hst_score)
            self._hst_flows_since_recompute += 1
            if self._hst_flows_since_recompute >= HST_RECOMPUTE_EVERY:
                self._recompute_hst_cut()
                self._hst_flows_since_recompute = 0

            base_severity = self._severity_for(float(ecod_scores[i]))
            consensus = int(ecod_labels[i]) + int(iforest_labels[i]) + int(lof_labels[i]) + int(hst_is_anomaly)
            reason = None

            # Ensemble consensus (now out of 4 detectors): 2+ independently
            # agreeing is a stronger signal than ECOD's own percentile cut
            # alone -- promotes a flow ECOD missed, or escalates one it
            # already caught. Full 4/4 agreement escalates two tiers at
            # once: four different detection principles (distributional
            # extremes, isolability, local density, online streaming
            # distance) all firing together is about as strong a signal as
            # this engine can produce.
            if consensus >= 2 and base_severity is None:
                base_severity = "low"
                reason = "ensemble_consensus"
            elif consensus == 4 and base_severity is not None:
                escalated = self._escalate(base_severity, 2)
                if escalated != base_severity:
                    base_severity = escalated
                    reason = "ensemble_consensus"
            elif consensus == 3 and base_severity is not None:
                escalated = self._escalate(base_severity, 1)
                if escalated != base_severity:
                    base_severity = escalated
                    reason = "ensemble_consensus"

            # Per-entity behavioral baseline: independent of the tenant-wide
            # ensemble above. A flow can look unremarkable against the
            # tenant's overall traffic mix and still be wildly unlike what
            # THIS specific host normally does -- the per-asset deviation
            # commercial NDR tools lead with. Raw (unscaled) features, since
            # this baseline is about the entity's own history, not the
            # tenant-wide scaler.
            row = flows_df.iloc[i]
            entity = self._entity_key(row)
            raw_x = X[i][: len(FEATURES)]  # scaled features double as the entity-baseline input --
            # consistent with everything else in this engine, and still catches real drift since
            # it's relative to the entity's own running mean/variance of the same scaled values.
            baseline = self._entity_baselines.setdefault(entity, EntityBaseline())
            if baseline.n < ENTITY_LEARNING_MIN_FLOWS:
                # Learning period: learn this source's normal, judge nothing.
                baseline.update(raw_x)
                if baseline.n == ENTITY_LEARNING_MIN_FLOWS:
                    self._graduated_pending += 1
                learning_flags.append(True)
                entity_baseline_z.append(None)
                severities.append(None)
                consensus_counts.append(0)
                escalation_reasons.append(None)
                self._score_window.append(float(ecod_scores[i]))
                self._flows_since_recompute += 1
                if self._flows_since_recompute >= ADAPTIVE_RECOMPUTE_EVERY:
                    self._recompute_severity_cuts()
                    self._flows_since_recompute = 0
                self._flows_since_checkpoint += 1
                continue
            learning_flags.append(False)
            dev = baseline.deviation(raw_x)
            max_z = float(np.max(np.abs(dev))) if dev is not None else None
            entity_baseline_z.append(max_z)
            if max_z is not None and max_z >= ENTITY_BASELINE_Z_THRESHOLD:
                # A 5-sigma-plus departure from a host's own established
                # baseline is a strong, specific signal on its own -- floor
                # it at "medium" even with no other detector agreeing, and
                # escalate by a tier if one already flagged it.
                promoted = self._escalate(base_severity, 1) if base_severity else "medium"
                if base_severity is None or SEVERITY_ORDER.index(promoted) > SEVERITY_ORDER.index(base_severity):
                    base_severity = promoted
                    reason = "entity_baseline_drift"
            baseline.update(raw_x)

            # Entity burst: several flagged events from one source in a short
            # window outranks any single flow's severity.
            flows_in_window = self._note_flow(entity, now)
            if base_severity is not None:
                burst_count = self._check_burst(entity, now)
                if (burst_count >= ENTITY_BURST_THRESHOLD
                        and burst_count / max(flows_in_window, 1) >= ENTITY_BURST_MIN_SHARE
                        and base_severity != "critical"):
                    base_severity = "critical"
                    reason = "entity_burst"

            severities.append(base_severity)
            consensus_counts.append(consensus)
            escalation_reasons.append(reason)

            # Adaptive threshold: absorb this live score into the rolling
            # window and periodically re-derive severity cuts from it, so
            # the baseline tracks this tenant's actual traffic over time
            # instead of staying pinned to whatever it looked like at fit.
            self._score_window.append(float(ecod_scores[i]))
            self._flows_since_recompute += 1
            if self._flows_since_recompute >= ADAPTIVE_RECOMPUTE_EVERY:
                self._recompute_severity_cuts()
                self._flows_since_recompute = 0

            self._flows_since_checkpoint += 1

        out = flows_df.copy()
        out["ecod_score"] = ecod_scores
        out["ecod_is_anomaly"] = ecod_labels.astype(bool)
        out["iforest_score"] = iforest_scores
        out["iforest_is_anomaly"] = iforest_labels.astype(bool)
        out["lof_score"] = lof_scores
        out["lof_is_anomaly"] = lof_labels.astype(bool)
        out["hst_score"] = hst_scores
        out["hst_is_anomaly"] = hst_labels
        out["entity_baseline_z"] = entity_baseline_z
        out["consensus_count"] = consensus_counts
        out["severity"] = severities
        out["escalation_reason"] = escalation_reasons
        out["explanation"] = [self._explain(X[i]) for i in range(len(X))]
        out["learning"] = learning_flags
        if any(learning_flags):
            # A flow that is still in its source's learning period is not
            # judged: raw scores stay for transparency, verdicts are cleared.
            mask = np.array(learning_flags)
            for col in ("ecod_is_anomaly", "iforest_is_anomaly", "lof_is_anomaly", "hst_is_anomaly"):
                out.loc[mask, col] = False
        return out

    def due_for_checkpoint(self) -> bool:
        """True once CHECKPOINT_EVERY_FLOWS flows have been scored since the
        last checkpoint. Caller (DetectorRegistry) resets the counter after
        a successful save -- an unsuccessful one leaves it due again on the
        very next flow, which is the right failure mode (retry sooner, not
        silently go longer without a checkpoint)."""
        return self._flows_since_checkpoint >= CHECKPOINT_EVERY_FLOWS

    def mark_checkpointed(self):
        self._flows_since_checkpoint = 0


class DetectorRegistry:
    """One TenantDetector per tenant, cached in this process's memory as the
    hot path (every flow scores against the in-memory object -- there is no
    Redis round-trip on the per-flow path, which would be both slow and
    pointless given the sticky-routing assumption documented in
    ml/persistence.py). On a cache miss, checks Redis for a recent
    checkpoint from another instance before falling back to a fresh
    synthetic bootstrap -- see persistence.py's module docstring for
    exactly what cross-instance guarantee this does and doesn't give."""

    def __init__(self):
        self._detectors: dict[str, TenantDetector] = {}

    async def get(self, tenant_id: str) -> TenantDetector:
        if tenant_id in self._detectors:
            return self._detectors[tenant_id]

        from .persistence import load_checkpoint  # local import: avoids a
        # hard dependency on persistence.py (and therefore redis) for any
        # caller/test that only needs in-process scoring.
        checkpoint = await load_checkpoint(tenant_id)
        if checkpoint is not None:
            checkpoint.is_from_checkpoint = True
            self._detectors[tenant_id] = checkpoint
            return checkpoint

        detector = TenantDetector(tenant_id)
        self._detectors[tenant_id] = detector
        return detector

    async def checkpoint_if_due(self, detector: TenantDetector):
        """Fire this after scoring a batch. Never raises -- a checkpoint
        failure must not affect the ingestion response that triggered it."""
        if not detector.due_for_checkpoint():
            return
        from .persistence import save_checkpoint
        saved = await save_checkpoint(detector)
        if saved:
            detector.mark_checkpointed()
        # If the save failed, leave the counter as-is: due_for_checkpoint()
        # stays true, so the very next batch retries rather than waiting
        # another full CHECKPOINT_EVERY_FLOWS flows.


registry = DetectorRegistry()
