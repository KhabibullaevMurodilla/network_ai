import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

df = pd.read_csv("/home/claude/ad-demo/outputs/scored_flows.csv")

# Per-attack-type recall (using ECOD, the stronger detector) -----------------
# ECOD label: derive from its own contamination-based threshold already
# baked into decision scores; recompute predicted label via the same
# threshold used in detect.py (top-`contamination` scores flagged).
contamination = df["IsAnomaly"].mean()
threshold = df["score_ECOD"].quantile(1 - contamination)
df["pred_ECOD"] = (df["score_ECOD"] >= threshold).astype(int)

rows = []
for label, g in df.groupby("Label"):
    row = {"Label": label, "count": len(g)}
    if label == "Benign":
        row["detected"] = None
        row["detection_rate"] = None
        row["false_positive_rate"] = g["pred_ECOD"].mean()
    else:
        row["detected"] = int(g["pred_ECOD"].sum())
        row["detection_rate"] = g["pred_ECOD"].mean()
        row["false_positive_rate"] = None
    rows.append(row)
breakdown = pd.DataFrame(rows)
breakdown.to_csv("/home/claude/ad-demo/outputs/per_attack_breakdown.csv", index=False)
print(breakdown.to_string(index=False))

# Chart 1: detection rate by attack type -------------------------------------
attack_rows = breakdown[breakdown["Label"] != "Benign"].sort_values("detection_rate")
fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.barh(attack_rows["Label"], attack_rows["detection_rate"] * 100, color="#2b6cb0")
ax.set_xlabel("Detection rate (%)")
ax.set_title("Anomaly detection rate by attack type (ECOD detector)")
ax.set_xlim(0, 105)
for bar, val in zip(bars, attack_rows["detection_rate"] * 100):
    ax.text(val + 1, bar.get_y() + bar.get_height() / 2, f"{val:.0f}%", va="center")
plt.tight_layout()
plt.savefig("/home/claude/ad-demo/outputs/detection_rate_by_attack.png", dpi=150)
plt.close()

# Chart 2: anomaly score timeline with true anomalies highlighted -----------
sample = df.iloc[:800].copy()  # first 800 flows in arrival order for readability
fig, ax = plt.subplots(figsize=(11, 4.5))
ax.plot(sample.index, sample["score_ECOD"], color="#888888", linewidth=0.8, label="Anomaly score")
anomaly_pts = sample[sample["IsAnomaly"] == 1]
ax.scatter(anomaly_pts.index, anomaly_pts["score_ECOD"], color="#e53e3e", s=14, zorder=3, label="True anomaly")
ax.axhline(threshold, color="#2b6cb0", linestyle="--", linewidth=1, label="Detection threshold")
ax.set_xlabel("Flow arrival order")
ax.set_ylabel("ECOD anomaly score")
ax.set_title("Anomaly score over flow stream (first 800 flows)")
ax.legend(loc="upper right")
plt.tight_layout()
plt.savefig("/home/claude/ad-demo/outputs/score_timeline.png", dpi=150)
plt.close()

print("\nCharts saved: detection_rate_by_attack.png, score_timeline.png")
