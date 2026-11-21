"""
Synthetic 5G network-flow telemetry generator.

IMPORTANT: This generates SYNTHETIC data engineered to match the schema and
attack taxonomy described in the real 5G-NIDD dataset (Samarakoon et al.,
"5G-NIDD: A Comprehensive Network Intrusion Detection Dataset Generated over
a 5G Wireless Network", generated on a live 5G testbed at the University of
Oulu; available via IEEE DataPort, ieee-dataport.org/10203, CC BY 4.0).

It is NOT the real dataset -- this sandbox cannot reach ieee-dataport.org.
To use the real data instead: download the combined CSV from IEEE DataPort,
place it at data/5g_nidd_real.csv, and change USE_SYNTHETIC=False below.
The pipeline (detectors, evaluation, report) is written against the same
flow-level feature set either way, so the swap is a one-line change once
the real file is present.

Attack taxonomy mirrored here (per the 5G-NIDD paper):
  DoS:   ICMP Flood, UDP Flood, SYN Flood, HTTP Flood, Slowrate DoS
  Scan:  SYN Scan, TCP Connect Scan, UDP Scan
"""
import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)

ATTACK_TYPES = [
    "ICMPFlood", "UDPFlood", "SYNFlood", "HTTPFlood", "SlowrateDoS",
    "SYNScan", "TCPConnectScan", "UDPScan",
]

PROTOS = ["TCP", "UDP", "ICMP"]


def _benign_flows(n):
    """Normal 5G user-equipment traffic: web browsing, streaming, background sync."""
    return pd.DataFrame({
        "Dur": RNG.gamma(2.0, 0.8, n),
        "Proto": RNG.choice(["TCP", "UDP"], n, p=[0.75, 0.25]),
        "TotPkts": RNG.poisson(18, n) + 1,
        "SrcBytes": RNG.gamma(3.0, 300, n),
        "DstBytes": RNG.gamma(3.0, 900, n),
        "Rate": RNG.gamma(2.0, 12, n),
        "Load": RNG.gamma(2.0, 8, n),
        "sTtl": RNG.integers(58, 65, n),
        "Label": "Benign",
    })


def _attack_flows(kind, n):
    """Each attack type gets a distinct, literature-consistent signature."""
    if kind == "ICMPFlood":
        df = pd.DataFrame({
            "Dur": RNG.exponential(0.05, n),
            "Proto": "ICMP",
            "TotPkts": RNG.poisson(400, n) + 50,
            "SrcBytes": RNG.gamma(1.5, 60, n),
            "DstBytes": RNG.gamma(1.0, 10, n),
            "Rate": RNG.gamma(6.0, 250, n),
            "Load": RNG.gamma(6.0, 200, n),
            "sTtl": RNG.integers(30, 55, n),
        })
    elif kind == "UDPFlood":
        df = pd.DataFrame({
            "Dur": RNG.exponential(0.08, n),
            "Proto": "UDP",
            "TotPkts": RNG.poisson(600, n) + 80,
            "SrcBytes": RNG.gamma(2.0, 500, n),
            "DstBytes": RNG.gamma(1.0, 20, n),
            "Rate": RNG.gamma(7.0, 300, n),
            "Load": RNG.gamma(7.0, 260, n),
            "sTtl": RNG.integers(30, 55, n),
        })
    elif kind == "SYNFlood":
        df = pd.DataFrame({
            "Dur": RNG.exponential(0.03, n),
            "Proto": "TCP",
            "TotPkts": RNG.poisson(300, n) + 40,
            "SrcBytes": RNG.gamma(1.2, 60, n),
            "DstBytes": RNG.gamma(0.5, 5, n),
            "Rate": RNG.gamma(6.5, 280, n),
            "Load": RNG.gamma(6.5, 240, n),
            "sTtl": RNG.integers(30, 55, n),
        })
    elif kind == "HTTPFlood":
        df = pd.DataFrame({
            "Dur": RNG.exponential(0.4, n),
            "Proto": "TCP",
            "TotPkts": RNG.poisson(120, n) + 20,
            "SrcBytes": RNG.gamma(3.0, 800, n),
            "DstBytes": RNG.gamma(2.0, 400, n),
            "Rate": RNG.gamma(4.0, 150, n),
            "Load": RNG.gamma(4.0, 120, n),
            "sTtl": RNG.integers(40, 60, n),
        })
    elif kind == "SlowrateDoS":
        df = pd.DataFrame({
            "Dur": RNG.gamma(8.0, 3.0, n),
            "Proto": "TCP",
            "TotPkts": RNG.poisson(8, n) + 1,
            "SrcBytes": RNG.gamma(1.0, 40, n),
            "DstBytes": RNG.gamma(1.0, 20, n),
            "Rate": RNG.gamma(0.5, 2, n),
            "Load": RNG.gamma(0.5, 2, n),
            "sTtl": RNG.integers(40, 60, n),
        })
    elif kind == "SYNScan":
        df = pd.DataFrame({
            "Dur": RNG.exponential(0.01, n),
            "Proto": "TCP",
            "TotPkts": RNG.poisson(2, n) + 1,
            "SrcBytes": RNG.gamma(0.8, 20, n),
            "DstBytes": RNG.gamma(0.2, 5, n),
            "Rate": RNG.gamma(3.0, 100, n),
            "Load": RNG.gamma(3.0, 90, n),
            "sTtl": RNG.integers(40, 60, n),
        })
    elif kind == "TCPConnectScan":
        df = pd.DataFrame({
            "Dur": RNG.exponential(0.02, n),
            "Proto": "TCP",
            "TotPkts": RNG.poisson(4, n) + 1,
            "SrcBytes": RNG.gamma(1.0, 25, n),
            "DstBytes": RNG.gamma(0.5, 10, n),
            "Rate": RNG.gamma(2.5, 90, n),
            "Load": RNG.gamma(2.5, 80, n),
            "sTtl": RNG.integers(40, 60, n),
        })
    else:  # UDPScan
        df = pd.DataFrame({
            "Dur": RNG.exponential(0.01, n),
            "Proto": "UDP",
            "TotPkts": RNG.poisson(2, n) + 1,
            "SrcBytes": RNG.gamma(0.8, 20, n),
            "DstBytes": RNG.gamma(0.2, 5, n),
            "Rate": RNG.gamma(2.8, 95, n),
            "Load": RNG.gamma(2.8, 85, n),
            "sTtl": RNG.integers(40, 60, n),
        })
    df["Label"] = kind
    return df


def generate(n_benign=9000, attack_frac=0.10, seed=42):
    """Generate a labelled synthetic flow dataset. attack_frac mirrors the
    real 5G-NIDD's substantial-but-minority attack proportion."""
    global RNG
    RNG = np.random.default_rng(seed)
    n_attack_total = int(n_benign * attack_frac / (1 - attack_frac))
    per_attack = max(1, n_attack_total // len(ATTACK_TYPES))

    parts = [_benign_flows(n_benign)]
    for kind in ATTACK_TYPES:
        parts.append(_attack_flows(kind, per_attack))

    df = pd.concat(parts, ignore_index=True)
    df["IsAnomaly"] = (df["Label"] != "Benign").astype(int)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)  # shuffle -> arrival order
    df["FlowID"] = np.arange(len(df))
    return df


if __name__ == "__main__":
    df = generate()
    df.to_csv("/home/claude/ad-demo/data/synthetic_5g_flows.csv", index=False)
    print(f"Generated {len(df)} flows, {df['IsAnomaly'].sum()} labelled anomalous ({df['IsAnomaly'].mean():.1%})")
    print(df["Label"].value_counts())
