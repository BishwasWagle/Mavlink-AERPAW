import pandas as pd
import matplotlib.pyplot as plt

PLAIN_CSV = "bench_plain.csv"
ENC_CSV   = "bench_enc.csv"

plain = pd.read_csv(PLAIN_CSV)
enc   = pd.read_csv(ENC_CSV)

# keep only accepted packets
plain = plain[plain["verdict"] == "ACCEPT"].copy()
enc   = enc[enc["verdict"] == "ACCEPT"].copy()

# convert proc_ms to numeric
plain["proc_ms"] = pd.to_numeric(plain["proc_ms"], errors="coerce")
enc["proc_ms"]   = pd.to_numeric(enc["proc_ms"], errors="coerce")

# OPTIONAL: drop first few packets to remove warm-up effects
plain2 = plain.iloc[10:].copy() if len(plain) > 20 else plain
enc2   = enc.iloc[10:].copy()   if len(enc) > 20 else enc

def pct_stats(df, col="proc_ms"):
    return {
        "p50": df[col].quantile(0.50),
        "p95": df[col].quantile(0.95),
        "p99": df[col].quantile(0.99),
        "mean": df[col].mean()
    }

pstats = pct_stats(plain2)
estats = pct_stats(enc2)

print("PLAIN stats (ms):", pstats)
print("ENC   stats (ms):", estats)
print("Overhead ratio (p50):", estats["p50"] / pstats["p50"])

# 1) Histogram
plt.figure()
plt.hist(plain2["proc_ms"].dropna(), bins=100, alpha=0.6, label="PLAIN")
plt.hist(enc2["proc_ms"].dropna(), bins=100, alpha=0.6, label="ENC")
plt.xlabel("proc_ms (ms)")
plt.ylabel("count")
plt.title("Processing time per message (histogram)")
plt.legend()
plt.tight_layout()
plt.savefig("proc_ms_hist.png", dpi=200)

# 2) CDF
def plot_cdf(series, label):
    s = series.dropna().sort_values().reset_index(drop=True)
    y = (s.index + 1) / len(s)
    plt.plot(s, y, label=label)

plt.figure()
plot_cdf(plain2["proc_ms"], "PLAIN")
plot_cdf(enc2["proc_ms"], "ENC")
plt.xlabel("proc_ms (ms)")
plt.ylabel("CDF")
plt.title("Processing time per message (CDF)")
plt.legend()
plt.tight_layout()
plt.savefig("proc_ms_cdf.png", dpi=200)

# 3) Percentile bar chart
labels = ["p50", "p95", "p99", "mean"]
plain_vals = [pstats[k] for k in labels]
enc_vals   = [estats[k] for k in labels]

x = range(len(labels))
plt.figure()
plt.bar([i - 0.2 for i in x], plain_vals, width=0.4, label="PLAIN")
plt.bar([i + 0.2 for i in x], enc_vals,   width=0.4, label="ENC")
plt.xticks(list(x), labels)
plt.ylabel("proc_ms (ms)")
plt.title("proc_ms summary statistics")
plt.legend()
plt.tight_layout()
plt.savefig("proc_ms_stats.png", dpi=200)

print("Saved: proc_ms_hist.png, proc_ms_cdf.png, proc_ms_stats.png")
