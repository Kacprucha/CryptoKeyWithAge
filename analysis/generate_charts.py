#!/usr/bin/env python3
"""
analysis/generate_charts.py

Input data:
  --pgp        results/pgp_bench.csv      ← bench_pgp.c
  --age        results/age_raw.txt        ← go test -bench (ns/op)
  --age-sizes  results/age_sizes.csv      ← go test -run TestFileSizes (optional)
  --out        results/
"""

import argparse
import csv
import re
import sys
from pathlib import Path

MISSING = []
for _pkg in ("pandas", "matplotlib", "openpyxl", "numpy"):
    try:
        __import__(_pkg)
    except ImportError:
        MISSING.append(_pkg)

if MISSING:
    print(f"[ERR] Missing packages: {', '.join(MISSING)}")
    print("      pip install " + " ".join(MISSING))
    sys.exit(1)

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

# Style

COLORS = {
    "pgp_soft": "#1565C0",   # ciemny niebieski
    "pgp_hw":   "#B71C1C",   # ciemny czerwony
    "age_soft": "#2E7D32",   # ciemny zielony
    "age_hw":   "#E65100",   # pomarańczowy
}
HATCH = {"pgp_soft": "", "pgp_hw": "///", "age_soft": "", "age_hw": "///"}

SIZE_ORDER = ["100B", "1KB", "64KB", "1MB", "10MB", "100MB"]

SIZE_BYTES_MAP = {
    100: "100B",
    1024: "1KB",
    65536: "64KB",
    1048576: "1MB",
    10485760: "10MB",
    104857600: "100MB",
}

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linestyle": "--",
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "savefig.bbox": "tight",
    "legend.framealpha": 0.92,
})

# Helpers 

def _bytes_label(x, _=None):
    if x >= 1024**3: return f"{x/1024**3:.1f} GB"
    if x >= 1024**2: return f"{x/1024**2:.0f} MB"
    if x >= 1024: return f"{x/1024:.0f} KB"
    return f"{int(x)} B"

def _bytes_short(x):
    if x >= 1024**2: return f"{x/1024**2:.1f}M"
    if x >= 1024: return f"{x/1024:.0f}K"
    return f"{int(x)}B"

def _ms_label(y, _=None):
    if y >= 1e6: return f"{y/1e6:.1f} ks"
    if y >= 1000: return f"{y/1000:.1f} s"
    if y >= 1: return f"{y:.0f} ms"
    if y >= 0.01: return f"{y:.2f} ms"
    return f"{y:.3f} ms"

def _save(fig, path, label=""):
    fig.savefig(path)
    plt.close(fig)
    tag = f" ({label})" if label else ""
    print(f"\tSaved: {Path(path).name}{tag}")

def _bar_annotate(ax, x, y, fmt="{:.1f}"):
    for xi, yi in zip(x, y):
        if yi <= 0:
            continue
        ax.text(xi, yi * 1.06, fmt.format(yi),
                ha="center", va="bottom", fontsize=8.5, fontweight="bold")

# Parsers

def parse_pgp_csv(path: Path) -> pd.DataFrame:
    rows = []

    def _f(v, default=0.0): return float(v) if v not in (None, "", "0") else default
    def _fi(v, default=0.0): return float(v) if v not in (None, "") else default
    def _i(v, default=0):   return int(float(v)) if v not in (None, "") else default

    with open(path, newline="") as f:
        raw = f.read()

    lines = [l.strip() for l in raw.splitlines() if l.strip()]

    for line in lines:
        if line.startswith("#") or line.lower().startswith("benchmark,"):
            continue

        parts = line.split(",")
        if len(parts) < 2:
            continue

        name = parts[0].strip()
        if not name:
            continue

        is_filesize = "FileSize" in name

        try:
            if is_filesize and len(parts) == 4:
                plaintext = _i(parts[1])
                pgp_size = _i(parts[2])
                overhead = _i(parts[3])
                rows.append({
                    "source": "pgp",
                    "benchmark": name,
                    "median_ms": 0.0,
                    "min_ms": 0.0,
                    "max_ms": 0.0,
                    "n_runs": 0,
                    "bytes": plaintext,
                    "encrypted_bytes": pgp_size,
                    "overhead_bytes": overhead,
                    "header_bytes": 0,
                    "payload_bytes": 0,
                })
            else:
                rows.append({
                    "source": "pgp",
                    "benchmark": name,
                    "median_ms": _fi(parts[1] if len(parts) > 1 else None),
                    "min_ms": _fi(parts[2] if len(parts) > 2 else None),
                    "max_ms": _fi(parts[3] if len(parts) > 3 else None),
                    "n_runs": _i(parts[4]  if len(parts) > 4 else None),
                    "bytes":  _i(parts[5]  if len(parts) > 5 else None),
                    "encrypted_bytes": _i(parts[6]  if len(parts) > 6 else None),
                    "overhead_bytes": _i(parts[7]  if len(parts) > 7 else None),
                    "header_bytes": _i(parts[8]  if len(parts) > 8 else None),
                    "payload_bytes": _i(parts[9]  if len(parts) > 9 else None),
                })
        except (ValueError, IndexError) as e:
            print(f"\t[warn] pgp row skip ({e}): {line[:80]}")

    df = pd.DataFrame(rows)
    print(f"\tPGP: {len(df)} rows parsed"
          f"\t({len(df[df['benchmark'].str.contains('FileSize')])} FileSize,"
          f"\t{len(df[~df['benchmark'].str.contains('FileSize')])} timing)")
    
    return df


def parse_age_raw(path: Path) -> pd.DataFrame:
    rows = []

    pat = re.compile(
        r'^(Benchmark[A-Za-z0-9_/]+)-\d+\s+(\d+)\s+([\d.]+)\s+ns/op')
    
    with open(path) as f:
        for line in f:
            m = pat.match(line.strip())
            if not m:
                continue
            
            name = m.group(1)
            ms = float(m.group(3)) / 1_000_000.0
            size_bytes = 0
            
            for b, lbl in SIZE_BYTES_MAP.items():
                if lbl in name:
                    size_bytes = b
                    break
            
            rows.append({
                "source": "age",
                "benchmark": name,
                "median_ms": ms,
                "min_ms": ms,
                "max_ms": ms,
                "n_runs": int(m.group(2)),
                "bytes": size_bytes,
            })
    
    df = pd.DataFrame(rows)
    print(f"  age timing: {len(df)} rows parsed")
    
    return df


def parse_age_sizes(path: Path) -> pd.DataFrame:
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                rows.append({
                    "source": "age",
                    "variant": row["variant"].strip(),
                    "size_name": row["size_name"].strip(),
                    "bytes": int(row["plaintext_bytes"]),
                    "encrypted_bytes": int(row["encrypted_bytes"]),
                    "overhead_bytes": int(row["overhead_bytes"]),
                    "header_bytes": int(row["header_bytes"]),
                    "payload_bytes": int(row["payload_bytes"]),
                })
            except (ValueError, KeyError) as e:
                print(f"  [warn] age sizes skip ({e})")
    
    df = pd.DataFrame(rows)
    print(f"  age sizes: {len(df)} rows parsed")
    
    return df


def categorize(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    cats = []
    for _, row in df.iterrows():
        name = row["benchmark"]

        if   "ECDH_Software" in name: cat, var = "ECDH", "Software"
        elif "ECDH_Hardware" in name: cat, var = "ECDH", "Hardware"
        elif "Encrypt_Hard" in name: cat, var = "Encrypt", "Hardware"
        elif "Encrypt_Hard" in name: cat, var = "Encrypt", "Hardware" 
        elif "Decrypt_HW" in name: cat, var = "Decrypt", "Hardware"
        elif "Decrypt_Hard" in name: cat, var = "Decrypt", "Hardware"
        elif "FileSize" in name:  cat, var = "FileSize", "Hardware"
        else: cat, var = "Other", "Unknown"

        sz = int(row.get("bytes", 0))
        sl = SIZE_BYTES_MAP.get(sz, "")
        
        if not sl:
            for b, lbl in SIZE_BYTES_MAP.items():
                if lbl in name:
                    sl = lbl
                    sz = b
                    break
        if not sl:
            sl = "–"

        ckey = f"{row['source']}_{'soft' if var == 'Software' else 'hw'}"
        cats.append({
            "category": cat,
            "variant": var,
            "size_label": sl,
            "size_bytes": sz,
            "color_key": ckey,
        })

    return pd.concat([df.reset_index(drop=True),
                      pd.DataFrame(cats)], axis=1)

# Chart 01: ECDH

def chart_ecdh(df: pd.DataFrame, out_dir: Path):
    sub = df[df["category"] == "ECDH"].copy()
    if sub.empty:
        print("\t[warn] No ECDH data"); return
 

    COLORS_ECDH = {
        "pgp_soft": "#1565C0",  
        "pgp_hw": "#90CAF9",  
        "age_soft": "#2E7D32",  
        "age_hw": "#81C784",   
    }
    entries = [
        ("pgp", "Software", "pico-pgp\nSoftware", "pgp_soft"),
        ("pgp", "Hardware", "pico-pgp\nHardware", "pgp_hw"),
        ("age", "Software", "age\nSoftware", "age_soft"),
        ("age", "Hardware", "age\nHardware", "age_hw"),
    ]
 
    x_pos, heights, err_lo, err_hi, colors, hatches, xlabels = \
        [], [], [], [], [], [], []
 
    for i, (src, var, lbl, ckey) in enumerate(entries):
        row = sub[(sub["source"] == src) & (sub["variant"] == var)]
        
        if row.empty:
            continue
        
        med = row["median_ms"].values[0]
        lo = med - row["min_ms"].values[0]
        hi = row["max_ms"].values[0] - med
        x_pos.append(i)
        heights.append(med)
        err_lo.append(max(lo, 0))
        err_hi.append(max(hi, 0))
        colors.append(COLORS_ECDH.get(ckey, "#888"))
        hatches.append(HATCH.get(ckey, ""))
        xlabels.append(lbl)
 
    if not heights:
        print("\t[warn] ECDH — empty after filtering"); return
 
    fig, ax = plt.subplots(figsize=(9, 5.5))
    bars = ax.bar( x_pos, heights, color=colors, width=0.55, yerr=[err_lo, err_hi], capsize=6, error_kw={"linewidth": 1.5, "ecolor": "black"}, edgecolor="black", linewidth=0.8)
    for bar, hatch in zip(bars, hatches):
        if hatch:
            bar.set_hatch(hatch)
            bar.set_edgecolor("black")
 
    y_max = max(heights)
    y_min = min(heights)
    for xi, yi in zip(x_pos, heights):
        label_y = yi * (y_max / y_min) ** 0.06
        ax.text(xi, label_y, f"{yi:.2f} ms" if yi < 10 else f"{yi:.1f} ms", ha="center", va="bottom", fontsize=9, fontweight="bold")
 
    ax.set_yscale("log")
    ax.set_ylim(y_min * 0.15, y_max * 8)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(_ms_label))
    ax.set_xticks(x_pos)
    ax.set_xticklabels(xlabels, fontsize=10)
    ax.set_ylabel("Median time [ms] (log scale)")
    ax.set_title("ECDH P-256: Software vs Hardware — pico-pgp vs age")
 
    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(facecolor=COLORS["pgp_soft"], edgecolor="black", label="pico-pgp"),
        Patch(facecolor=COLORS["age_soft"], edgecolor="black", label="age"),
        Patch(facecolor="#ccc", edgecolor="black", label="Software"),
        Patch(facecolor="#ccc", edgecolor="black", hatch="///", label="Hardware"),
    ], loc="upper left", fontsize=9)
 
    _save(fig, out_dir / "01_ecdh_comparison.png", "ECDH log-bar")


# Chart 02 and 03: Encrypt / Decrypt time vs size 

def _time_vs_size(df: pd.DataFrame, category: str, ax: plt.Axes, show_legend: bool = True):
    sub = df[(df["category"] == category) &
             (df["variant"]  == "Hardware") &
             (df["size_label"].isin(SIZE_ORDER))].copy()

    if sub.empty:
        print(f"\t[warn] No {category} data"); return

    order_map = {k: i for i, k in enumerate(SIZE_ORDER)}
    sub["_o"] = sub["size_label"].map(order_map)
    sub = sub.sort_values("_o")

    for src in ["pgp", "age"]:
        grp = sub[sub["source"] == src]
        
        if grp.empty:
            continue
        
        ckey  = f"{src}_hw"
        label = f"{'pico-pgp' if src == 'pgp' else 'age'}  Hardware"
        style = "-o" if src == "pgp" else "--s"

        ax.plot(grp["size_label"].values, grp["median_ms"].values, style, label=label, color=COLORS.get(ckey, "#888"), linewidth=2.4, markersize=8)

    yvals = sub["median_ms"].values
    if len(yvals) > 0:
        ymin, ymax = yvals.min(), yvals.max()
        span_decades = np.log10(ymax / ymin) if ymin > 0 else 0
        if span_decades < 0.5:
            ax.set_ylim(ymin * 0.5, ymax * 2.0)
        else:
            ax.set_ylim(ymin * 0.3, ymax * 3.0)

    ax.set_yscale("log")
    ax.yaxis.set_major_locator(ticker.LogLocator(base=10, numticks=15))
    ax.yaxis.set_minor_locator(ticker.LogLocator(base=10, subs=np.arange(2,10)*0.1, numticks=30))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(_ms_label))
    ax.yaxis.set_minor_formatter(ticker.NullFormatter())
    ax.set_xlabel("File size")
    ax.set_ylabel("Median time [ms] (log scale)")
    ax.set_title(f"{category} — pico-pgp vs age")
    if show_legend:
        ax.legend(loc="upper left", fontsize=9)


def chart_encrypt_time(df: pd.DataFrame, out_dir: Path):
    fig, ax = plt.subplots(figsize=(10, 5.5))
    _time_vs_size(df, "Encrypt", ax)
    _save(fig, out_dir / "02_encrypt_time.png", "Encrypt log-line")


def chart_decrypt_time(df: pd.DataFrame, out_dir: Path):
    fig, ax = plt.subplots(figsize=(10, 5.5))
    _time_vs_size(df, "Decrypt", ax)
    _save(fig, out_dir / "03_decrypt_time.png", "Decrypt log-line")


def chart_encrypt_decrypt_combined(df: pd.DataFrame, out_dir: Path):
    fig, axes = plt.subplots(1, 2, figsize=(18, 5.5), sharey=False)
    for ax, cat in zip(axes, ["Encrypt", "Decrypt"]):
        _time_vs_size(df, cat, ax, show_legend=True)

    fig.suptitle("Encryption and Decryption Time - Pico-Pgp vs Age", fontsize=14, fontweight="bold", y=1.01)
    plt.tight_layout()
    _save(fig, out_dir / "04_encrypt_decrypt_combined.png", "combined log")


# Chart 05: Total file size

def chart_file_size_total(pgp_df: pd.DataFrame, age_sizes_df: pd.DataFrame, out_dir: Path):
    fig, ax = plt.subplots(figsize=(10, 6))

    ref_x = np.logspace(2, 8, 200)
    ax.plot(ref_x, ref_x, "k:", linewidth=1.2, alpha=0.6, label="plaintext (no overhead)")

    pgp_sub = pgp_df[
        (pgp_df["category"].isin(["FileSize", "Encrypt"])) &
        (pgp_df["encrypted_bytes"] > 0)
    ].copy().sort_values("bytes")

    if not pgp_sub.empty:
        grp = pgp_sub.groupby("bytes")["encrypted_bytes"].first().reset_index()
        ax.plot(grp["bytes"].values, grp["encrypted_bytes"].values, "-o", color=COLORS["pgp_hw"], linewidth=2.4, markersize=9, label="pico-pgp  (.pgp)")
        
        for bx, by in zip(grp["bytes"].values, grp["encrypted_bytes"].values):
            ax.annotate(f"+{_bytes_short(by - bx)}", xy=(bx, by), xytext=(4, 4), textcoords="offset points", fontsize=7.5, color=COLORS["pgp_hw"])

    if not age_sizes_df.empty:
        hw_variants = age_sizes_df[age_sizes_df["variant"].str.contains("Hardware|soft-ECDH")]
        for var in sorted(hw_variants["variant"].unique()):
            grp = hw_variants[hw_variants["variant"] == var].sort_values("bytes")
            if grp.empty:
                continue
            lbl = f"age (.age) — {var}"
            ax.plot(grp["bytes"].values, grp["encrypted_bytes"].values, "--s", color=COLORS["age_hw"], linewidth=2.4, markersize=8, label=lbl)

    ax.set_xscale("log"); ax.set_yscale("log")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(_bytes_label))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(_bytes_label))
    ax.set_xlabel("Plaintext size")
    ax.set_ylabel("Encrypted file size")
    ax.set_title("File size after encryption — pico-pgp vs age")
    ax.legend(fontsize=9, loc="upper left")
    _save(fig, out_dir / "05_file_size_total.png", "size log/log")


# Chart 06: Overhead bytes

def chart_overhead_bytes(pgp_df: pd.DataFrame, age_sizes_df: pd.DataFrame, out_dir: Path):
    fig, ax = plt.subplots(figsize=(10, 5.5))

    pgp_sub = pgp_df[ 
        (pgp_df["category"].isin(["FileSize", "Encrypt"])) &
        (pgp_df["overhead_bytes"] > 0)
    ].copy().sort_values("bytes")

    if not pgp_sub.empty:
        grp = pgp_sub.groupby("bytes")["overhead_bytes"].first().reset_index()
        ax.plot(grp["bytes"].values, grp["overhead_bytes"].values, "-o", color=COLORS["pgp_hw"], linewidth=2.4, markersize=9, label="pico-pgp  (PKESK + SEIPD header ≈ stały)")

    if not age_sizes_df.empty:
        hw_variants = age_sizes_df[age_sizes_df["variant"].str.contains("Hardware|soft-ECDH")]
        for var in sorted(hw_variants["variant"].unique()):
            grp = hw_variants[hw_variants["variant"] == var].sort_values("bytes")
            
            if grp.empty:
                continue
            
            ax.plot(grp["bytes"].values, grp["overhead_bytes"].values, "--s", color=COLORS["age_hw"], linewidth=2.4, markersize=8, label=f"age — {var}  (nagłówek + 16 B/64 KB)")

    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(_bytes_label))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(_bytes_label))
    ax.set_xlabel("Plaintext size")
    ax.set_ylabel("Overhead [bytes]  (encrypted − plaintext)")
    ax.set_title("Overhead size — pico-pgp vs age")
    ax.legend(fontsize=9)
    _save(fig, out_dir / "06_overhead_bytes.png", "overhead bytes")


# Chart 07: Overhead percent

def chart_overhead_pct(pgp_df: pd.DataFrame, age_sizes_df: pd.DataFrame, out_dir: Path):
    fig, ax = plt.subplots(figsize=(10, 5.5))

    pgp_sub = pgp_df[
        (pgp_df["category"].isin(["FileSize", "Encrypt"])) &
        (pgp_df["overhead_bytes"] > 0) &
        (pgp_df["bytes"] > 0)
    ].copy().sort_values("bytes")

    if not pgp_sub.empty:
        grp = pgp_sub.groupby("bytes")[["overhead_bytes"]].first().reset_index()
        pct = grp["overhead_bytes"].values / grp["bytes"].values * 100
        ax.plot(grp["bytes"].values, pct, "-o", color=COLORS["pgp_hw"], linewidth=2.4, markersize=9, label="pico-pgp")

    if not age_sizes_df.empty:
        hw_variants = age_sizes_df[
            age_sizes_df["variant"].str.contains("Hardware|soft-ECDH") &
            (age_sizes_df["bytes"] > 0)
        ]
        for var in sorted(hw_variants["variant"].unique()):
            grp = hw_variants[hw_variants["variant"] == var].sort_values("bytes")
            
            if grp.empty:
                continue
            
            pct = grp["overhead_bytes"].values / grp["bytes"].values * 100
            ax.plot(grp["bytes"].values, pct, "--s", color=COLORS["age_hw"], linewidth=2.4, markersize=8, label=f"age — {var}")

    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(_bytes_label))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, _: f"{y:.1f}%" if y < 1 else f"{y:.0f}%"))
    ax.set_xlabel("Plaintext size")
    ax.set_ylabel("Overhead  [%  plaintext]")
    ax.set_title("Percentage overhead — pico-pgp vs age")
    ax.legend(fontsize=9)
    _save(fig, out_dir / "07_overhead_pct.png", "overhead %")

# Excel export 

def _style_ws(ws, hex_color: str):
    from openpyxl.styles import Font, PatternFill, Alignment
    fill  = PatternFill("solid", fgColor=hex_color)
    font  = Font(color="FFFFFF", bold=True)
    align = Alignment(horizontal="center", vertical="center")
    
    for cell in ws[1]:
        cell.fill = fill; cell.font = font; cell.alignment = align
    
    ws.row_dimensions[1].height = 20
    
    for col in ws.columns:
        mx = max((len(str(c.value or "")) for c in col), default=10)
        ws.column_dimensions[col[0].column_letter].width = min(mx + 3, 42)


def write_excel(pgp_df: pd.DataFrame, age_df: pd.DataFrame, age_sizes_df: pd.DataFrame, combined: pd.DataFrame, out_dir: Path):
    path = out_dir / "comparison.xlsx"

    cols = [
        "Operation", "Size",
        "PGP HW [ms]", "PGP min [ms]", "PGP max [ms]",
        "age HW [ms]",
        "PGP enc [B]", "PGP overhead [B]", "PGP header [B]", "PGP payload [B]",
        "age enc [B]", "age overhead [B]", "age header [B]", "age payload [B]",
    ]

    ops = [
        ("ECDH", "–"),
        *[("Encrypt", sz) for sz in SIZE_ORDER],
        *[("Decrypt", sz) for sz in SIZE_ORDER],
    ]

    rows = []
    for cat, sz in ops:
        row: dict = {"Operation": cat, "Size": sz}

        for src, prefix in [("pgp", "PGP"), ("age", "age")]:
            var = "Software" if cat == "ECDH" else "Hardware"

            mask = (
                (combined["source"]     == src) &
                (combined["category"]   == cat) &
                (combined["variant"]    == var) &
                (combined["size_label"] == sz)
            )

            v = combined[mask]["median_ms"]
            if v.empty and cat == "ECDH":
                # fallback: Software
                mask2 = (
                    (combined["source"]   == src) &
                    (combined["category"] == "ECDH")
                )
                v = combined[mask2]["median_ms"]

            row[f"{prefix} HW [ms]"] = round(float(v.values[0]), 4) if not v.empty else ""
            if src == "pgp":
                row["PGP min [ms]"] = ""
                row["PGP max [ms]"] = ""
                v_min = combined[mask]["min_ms"]
                v_max = combined[mask]["max_ms"]
                if not v_min.empty:
                    row["PGP min [ms]"] = round(float(v_min.values[0]), 4)
                    row["PGP max [ms]"] = round(float(v_max.values[0]), 4)

        pm_all = pgp_df[
            (pgp_df["category"].isin(["FileSize", "Encrypt"])) &
            (pgp_df["size_label"] == sz) &
            (pgp_df["encrypted_bytes"] > 0)
        ]

        pm_enc = pm_all[pm_all["category"] == "Encrypt"]
        pm = pm_enc if not pm_enc.empty else pm_all
        
        for col, field in [
            ("PGP enc [B]", "encrypted_bytes"),
            ("PGP overhead [B]", "overhead_bytes"),
            ("PGP header [B]", "header_bytes"),
            ("PGP payload [B]", "payload_bytes"),
        ]:
            row[col] = (int(pm[field].values[0])
                        if not pm.empty and pm[field].values[0] > 0 else "")

        if not age_sizes_df.empty:
            ar = age_sizes_df[
                (age_sizes_df["variant"].str.contains("Software")) &
                (age_sizes_df["size_name"] == sz)
            ]
            for col, field in [
                ("age enc [B]", "encrypted_bytes"),
                ("age overhead [B]", "overhead_bytes"),
                ("age header [B]", "header_bytes"),
                ("age payload [B]", "payload_bytes"),
            ]:
                row[col] = int(ar[field].values[0]) if not ar.empty else ""
        else:
            for col in ["age enc [B]","age overhead [B]","age header [B]","age payload [B]"]:
                row[col] = ""

        rows.append(row)

    summary_df = pd.DataFrame(rows, columns=cols)

    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, sheet_name="Summary", index=False)
        _style_ws(writer.sheets["Summary"], "37474F")

        if not pgp_df.empty:
            pgp_df.to_excel(writer, sheet_name="PGP Raw", index=False)
            _style_ws(writer.sheets["PGP Raw"], "1565C0")

        if not age_df.empty:
            age_df.to_excel(writer, sheet_name="age Raw", index=False)
            _style_ws(writer.sheets["age Raw"], "1B5E20")

        if not age_sizes_df.empty:
            age_sizes_df.to_excel(writer, sheet_name="age Sizes", index=False)
            _style_ws(writer.sheets["age Sizes"], "4A148C")

        from openpyxl.styles import PatternFill as PF
        alt = PF("solid", fgColor="ECEFF1")
        ws  = writer.sheets["Summary"]
        for ri in range(2, len(rows) + 2):
            if ri % 2 == 0:
                for cell in ws[ri]:
                    cell.fill = alt

    print(f"  Saved: {path.name}")


# main 

def main():
    ap = argparse.ArgumentParser(
        description="Generate comparison charts: pico-pgp vs age")
    ap.add_argument("--pgp", default=None, help="pgp_bench.csv")
    ap.add_argument("--age", default=None, help="age_raw.txt")
    ap.add_argument("--age-sizes", default=None, help="age_sizes.csv (optional)")
    ap.add_argument("--out", required=True, help="output directory")
    args = ap.parse_args()

    out_dir = Path(args.out)
    charts_dir = out_dir / "charts"
    out_dir.mkdir(parents=True, exist_ok=True)
    charts_dir.mkdir(parents=True, exist_ok=True)

    print("\n[1/4] Parsing data...")

    pgp_df = age_df = age_sizes_df = pd.DataFrame()

    if args.pgp and Path(args.pgp).exists():
        pgp_df = categorize(parse_pgp_csv(Path(args.pgp)))
    else:
        print(f"\t[warn] No PGP CSV: {args.pgp}")

    if args.age and Path(args.age).exists():
        age_df = categorize(parse_age_raw(Path(args.age)))
        age_df.to_csv(out_dir / "age_bench.csv", index=False)
        print("  age parsed CSV → age_bench.csv")
    else:
        print(f"\t[warn] No age raw: {args.age}")

    szpath = args.age_sizes
    if not szpath and args.age:
        cand = Path(args.age).parent / "age_sizes.csv"
        if cand.exists():
            szpath = str(cand)
            print(f"\tAuto-detect age sizes: {cand}")

    if szpath and Path(szpath).exists():
        age_sizes_df = parse_age_sizes(Path(szpath))
    else:
        print(f"\t[info] No age_sizes.csv — size charts will skip age data")

    if pgp_df.empty and age_df.empty:
        print("[ERR] No timing data loaded — aborting.")
        sys.exit(1)

    combined = pd.concat([pgp_df, age_df], ignore_index=True)
    print(f"\tTotal timing rows: {len(combined)}")

    print("\n[2/4] Generating charts...")
    chart_ecdh(combined, charts_dir)
    chart_encrypt_time(combined, charts_dir)
    chart_decrypt_time(combined, charts_dir)
    chart_encrypt_decrypt_combined(combined, charts_dir)
    chart_file_size_total(pgp_df, age_sizes_df, charts_dir)
    chart_overhead_bytes(pgp_df, age_sizes_df, charts_dir)
    chart_overhead_pct(pgp_df, age_sizes_df, charts_dir)

    print("\n[3/4] Generating Excel...")
    write_excel(pgp_df, age_df, age_sizes_df, combined, out_dir)

    print("\n[4/4] Done.\n")
    print(f"Output: {out_dir}/")
    for p in sorted(out_dir.rglob("*")):
        if p.is_file():
            s = p.stat().st_size
            sstr = f"{s/1024:.1f} KB" if s > 1024 else f"{s} B"
            print(f"  {str(p.relative_to(out_dir)):<52}  {sstr}")
    print()


if __name__ == "__main__":
    main()