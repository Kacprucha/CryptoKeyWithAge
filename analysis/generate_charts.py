#!/usr/bin/env python3
"""
analysis/generate_charts.py

Input data:
  --pgp        results/pgp_bench.csv      ← bench_pgp.c (10 columns)
  --age        results/age_raw.txt        ← go test -bench (ns/op)
  --age-sizes  results/age_sizes.csv      ← go test -run TestFileSizes (opctional)
  --out        results/
"""

import argparse
import csv
import os
import re
import sys
from pathlib import Path

MISSING = []
for pkg in ("pandas", "matplotlib", "openpyxl", "numpy"):
    try:
        __import__(pkg)
    except ImportError:
        MISSING.append(pkg)

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

# Styl
COLORS = {
    "pgp_soft": "#1565C0",
    "pgp_hw":   "#B71C1C",
    "age_soft": "#2E7D32",
    "age_hw":   "#E65100",
}
HATCH = {"pgp_soft": "", "pgp_hw": "///", "age_soft": "", "age_hw": "///"}

SIZE_ORDER_ALL = ["100B", "1 KB", "64 KB", "1 MB", "10 MB", "100 MB"]
SIZE_BYTES_MAP = {
    100: "100B", 1024: "1 KB", 65536: "64 KB",
    1048576: "1 MB", 10485760: "10 MB", 104857600: "100 MB",
}

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 11,
    "axes.titlesize": 13, "axes.labelsize": 11,
    "axes.grid": True, "grid.alpha": 0.35, "grid.linestyle": "--",
    "figure.dpi": 150, "savefig.dpi": 150, "savefig.bbox": "tight",
    "legend.framealpha": 0.9,
})

#  Helpers

def _bytes_fmt(x, _):
    if x >= 1024**3: return f"{x/1024**3:.1f} GB"
    if x >= 1024**2: return f"{x/1024**2:.1f} MB"
    if x >= 1024:    return f"{x/1024:.0f} KB"
    return f"{int(x)} B"

def _bytes_fmt_short(x):
    if x >= 1024**2: return f"{x/1024**2:.1f}M"
    if x >= 1024:    return f"{x/1024:.1f}K"
    return f"{int(x)}B"

def _save(fig, path):
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved: {Path(path).name}")

def _label_bar(ax, bar, value, fmt="{:.2f} ms"):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height()*1.04,
            fmt.format(value), ha="center", va="bottom",
            fontsize=8.5, fontweight="bold")

#  Parsers

def parse_pgp_csv(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row.get("benchmark", "").strip()
            if not name or name.startswith("#"):
                continue
            try:
                rows.append({
                    "source": "pgp", "benchmark": name,
                    "median_ms": float(row["median_ms"]),
                    "min_ms":    float(row["min_ms"]),
                    "max_ms":    float(row["max_ms"]),
                    "n_runs":    int(row["n_runs"]),
                    "bytes":     int(row.get("bytes") or 0),
                    "encrypted_bytes": int(row.get("encrypted_bytes") or 0),
                    "overhead_bytes":  int(row.get("overhead_bytes") or 0),
                    "header_bytes":    int(row.get("header_bytes") or 0),
                    "payload_bytes":   int(row.get("payload_bytes") or 0),
                })
            except (ValueError, KeyError) as e:
                print(f"  [warn] PGP row skip ({e}): {name}")
    df = pd.DataFrame(rows)
    print(f"  PGP: {len(df)} rows")
    return df


def parse_age_raw(path):
    rows = []
    pat = re.compile(
        r'^(Benchmark[A-Za-z0-9_/]+)-\d+\s+(\d+)\s+([\d.]+)\s+ns/op')
    with open(path) as f:
        for line in f:
            m = pat.match(line.strip())
            if not m:
                continue
            name = m.group(1)
            ms   = float(m.group(3)) / 1e6
            size = 0
            for b, lbl in SIZE_BYTES_MAP.items():
                if lbl.replace(" ", "") in name:
                    size = b; break
            rows.append({
                "source": "age", "benchmark": name,
                "median_ms": ms, "min_ms": ms, "max_ms": ms,
                "n_runs": int(m.group(2)), "bytes": size,
                "encrypted_bytes": 0, "overhead_bytes": 0,
                "header_bytes": 0, "payload_bytes": 0,
            })
    df = pd.DataFrame(rows)
    print(f"  age timing: {len(df)} rows")
    return df


def parse_age_sizes(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                rows.append({
                    "source":          "age",
                    "size_name":       row["size_name"].strip(),
                    "variant":         row["variant"].strip(),
                    "bytes":           int(row["plaintext_bytes"]),
                    "encrypted_bytes": int(row["encrypted_bytes"]),
                    "overhead_bytes":  int(row["overhead_bytes"]),
                    "header_bytes":    int(row["header_bytes"]),
                    "payload_bytes":   int(row["payload_bytes"]),
                })
            except (ValueError, KeyError) as e:
                print(f"  [warn] age sizes skip ({e})")
    df = pd.DataFrame(rows)
    reverse = {v.replace(" ", ""): v for v in SIZE_ORDER_ALL}
    df["size_label"] = df["size_name"].map(reverse).fillna("–")
    print(f"  age sizes: {len(df)} rows")
    return df


def categorize(df):
    if df.empty:
        return df
    cats = []
    for _, row in df.iterrows():
        name = row["benchmark"]
        if   "ECDH_Software" in name: cat, var = "ECDH",     "Software"
        elif "ECDH_Hardware"  in name: cat, var = "ECDH",     "Hardware"
        elif "Encrypt_Soft"   in name: cat, var = "Encrypt",  "Software"
        elif "Encrypt_Hard"   in name: cat, var = "Encrypt",  "Hardware"
        elif "Decrypt_Soft"   in name: cat, var = "Decrypt",  "Software"
        elif "Decrypt_Hard"   in name: cat, var = "Decrypt",  "Hardware"
        elif "FileSize"        in name: cat, var = "FileSize", "Software"
        else:                          cat, var = "Other",    "Unknown"
        sz = int(row.get("bytes", 0))
        sl = SIZE_BYTES_MAP.get(sz, "–")
        if sl == "–":
            for b, lbl in SIZE_BYTES_MAP.items():
                if lbl.replace(" ", "") in name:
                    sl = lbl; break
        ckey = f"{row['source']}_{'soft' if var == 'Software' else 'hw'}"
        cats.append({"category": cat, "variant": var,
                     "size_label": sl, "color_key": ckey})
    return pd.concat([df.reset_index(drop=True), pd.DataFrame(cats)], axis=1)

#  Charts

def chart_ecdh(df, out_dir):
    sub = df[df["category"] == "ECDH"].copy()
    if sub.empty:
        print("  [warn] No ECDH"); return

    entries = [
        ("pgp", "Software", "pico-pgp\nSoftware"),
        ("pgp", "Hardware", "pico-pgp\nHardware"),
        ("age", "Software", "age\nSoftware"),
        ("age", "Hardware", "age\nHardware"),
    ]
    x_pos, heights, colors, hatches, xlabels, errors = [], [], [], [], [], []
    for i, (src, var, lbl) in enumerate(entries):
        row = sub[(sub["source"] == src) & (sub["variant"] == var)]
        if row.empty: continue
        med = row["median_ms"].values[0]
        err = abs(row["max_ms"].values[0] - row["min_ms"].values[0]) / 2
        ckey = f"{src}_{'soft' if var == 'Software' else 'hw'}"
        x_pos.append(i); heights.append(med); errors.append(err)
        colors.append(COLORS.get(ckey, "#888"))
        hatches.append(HATCH.get(ckey, ""))
        xlabels.append(lbl)

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(x_pos, heights, color=colors, width=0.55,
                  yerr=errors, capsize=6,
                  error_kw={"linewidth": 1.5, "ecolor": "black"},
                  edgecolor="black", linewidth=0.7)
    for bar, h, hatch in zip(bars, heights, hatches):
        bar.set_hatch(hatch)
        _label_bar(ax, bar, h)
    ax.set_xticks(x_pos); ax.set_xticklabels(xlabels)
    ax.set_ylabel("Mediana time [ms]")
    ax.set_title("ECDH P-256: Software vs Hardware — pico-pgp vs age")
    ax.set_ylim(0, max(heights) * 1.45 if heights else 1)
    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(facecolor="#aaa", edgecolor="black", label="Software"),
        Patch(facecolor="#aaa", edgecolor="black", hatch="///", label="Hardware"),
    ], loc="upper right")
    _save(fig, out_dir / "ecdh_comparison.png")


def chart_time_by_size(df, category, out_dir, filename, title,
                        age_hw_note=False):
    sub = df[(df["category"] == category) &
             (df["size_label"].isin(SIZE_ORDER_ALL))].copy()
    if sub.empty:
        print(f"  [warn] No {category}"); return
    sub["_o"] = sub["size_label"].map({k: i for i, k in enumerate(SIZE_ORDER_ALL)})
    sub = sub.sort_values("_o")

    fig, ax = plt.subplots(figsize=(10, 5.5))
    for src in ["pgp", "age"]:
        for var in ["Software", "Hardware"]:
            grp = sub[(sub["source"] == src) & (sub["variant"] == var)]
            if grp.empty: continue
            ckey  = f"{src}_{'soft' if var == 'Software' else 'hw'}"
            label = f"{'pico-pgp' if src == 'pgp' else 'age'} {var}"
            if age_hw_note and src == "age" and var == "Hardware" \
                    and category == "Encrypt":
                label += "\nECDH soft"
            style = "-o" if var == "Software" else "--s"
            ax.plot(grp["size_label"].values, grp["median_ms"].values,
                    style, label=label, color=COLORS.get(ckey, "#888"),
                    linewidth=2.2, markersize=8)
            if src == "pgp" and not all(
                    grp["min_ms"].values == grp["max_ms"].values):
                ax.fill_between(grp["size_label"].values,
                                grp["min_ms"].values, grp["max_ms"].values,
                                alpha=0.15, color=COLORS.get(ckey, "#888"))
    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(
        lambda y, _: f"{y:.0f}" if y >= 1 else f"{y:.2f}"))
    ax.set_xlabel("File size")
    ax.set_ylabel("Mediana time [ms]  (skala log)")
    ax.set_title(title)
    ax.legend(loc="upper left", fontsize=9)
    _save(fig, out_dir / filename)


def chart_file_size_total(pgp_df, age_sizes_df, out_dir):
    pgp_sub = pgp_df[(pgp_df["category"].isin(["Encrypt", "FileSize"])) &
                     (pgp_df["encrypted_bytes"] > 0) &
                     (pgp_df["size_label"].isin(SIZE_ORDER_ALL))].copy()
    pgp_sub = pgp_sub.sort_values("bytes")

    fig, ax = plt.subplots(figsize=(10, 5.5))

    if not pgp_sub.empty:
        x_ref = pgp_sub["bytes"].values
        ax.plot(x_ref, x_ref, "k:", linewidth=1.2, label="plaintext (brak overhead)")
        grp = pgp_sub.groupby("bytes")["encrypted_bytes"].first().reset_index()
        ax.plot(grp["bytes"].values, grp["encrypted_bytes"].values,
                "-o", color=COLORS["pgp_soft"], linewidth=2.2, markersize=8,
                label="pico-pgp (.pgp)")

    if not age_sizes_df.empty:
        for var in age_sizes_df["variant"].unique():
            grp = age_sizes_df[age_sizes_df["variant"] == var].sort_values("bytes")
            if grp.empty: continue
            is_hw = "Hardware" in var
            ckey  = "age_hw" if is_hw else "age_soft"
            style = "--s" if is_hw else "-^"
            lbl   = ("age (.age) — Hardware\nECDH soft, chip only for decrypt"
                     if "soft-ECDH" in var else f"age (.age) — {var}")
            ax.plot(grp["bytes"].values, grp["encrypted_bytes"].values,
                    style, color=COLORS.get(ckey, "#888"),
                    linewidth=2.2, markersize=8, label=lbl)

    ax.set_xscale("log"); ax.set_yscale("log")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(_bytes_fmt))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(_bytes_fmt))
    ax.set_xlabel("Plaintext size")
    ax.set_ylabel("Encrypted file size")
    ax.set_title("Total encrypted file size: pico-pgp vs age")
    ax.legend(fontsize=9)
    _save(fig, out_dir / "file_size_total.png")


def chart_overhead_bytes(pgp_df, age_sizes_df, out_dir):
    pgp_sub = pgp_df[(pgp_df["category"].isin(["Encrypt", "FileSize"])) &
                     (pgp_df["overhead_bytes"] > 0) &
                     (pgp_df["size_label"].isin(SIZE_ORDER_ALL))].copy()
    pgp_sub = pgp_sub.sort_values("bytes")

    fig, ax = plt.subplots(figsize=(10, 5.5))

    if not pgp_sub.empty:
        grp = pgp_sub.groupby("bytes")["overhead_bytes"].first().reset_index()
        ax.plot(grp["bytes"].values, grp["overhead_bytes"].values,
                "-o", color=COLORS["pgp_soft"], linewidth=2.2, markersize=8,
                label="pico-pgp  (constant overhead ≈ 163B)")

    if not age_sizes_df.empty:
        for var in age_sizes_df["variant"].unique():
            grp = age_sizes_df[age_sizes_df["variant"] == var].sort_values("bytes")
            if grp.empty: continue
            is_hw = "Hardware" in var
            ax.plot(grp["bytes"].values, grp["overhead_bytes"].values,
                    "--s" if is_hw else "-^",
                    color=COLORS.get("age_hw" if is_hw else "age_soft", "#888"),
                    linewidth=2.2, markersize=8,
                    label="age  (≈170B header + 16B/64KB chunk)")

    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(_bytes_fmt))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(_bytes_fmt))
    ax.set_xlabel("Plaintext size")
    ax.set_ylabel("Overhead [bytes]  (encrypted − plaintext)")
    ax.set_title("Encryption overhead: pico-pgp vs age")
    ax.legend(fontsize=9)
    _save(fig, out_dir / "file_size_overhead.png")


def chart_header_vs_payload(pgp_df, age_sizes_df, out_dir):
    show = ["100B", "1 KB", "64 KB", "1 MB"]
    pgp_sub = pgp_df[(pgp_df["category"].isin(["Encrypt", "FileSize"])) &
                     (pgp_df["header_bytes"] > 0) &
                     (pgp_df["size_label"].isin(show))].copy()

    age_sub = pd.DataFrame()
    if not age_sizes_df.empty:
        age_sub = age_sizes_df[
            (age_sizes_df["variant"].str.contains("Software")) &
            (age_sizes_df["size_label"].isin(show))
        ].copy()

    if pgp_sub.empty and age_sub.empty:
        print("  [warn] Brak danych header vs payload"); return

    labels, pgp_h, pgp_p, age_h, age_p = [], [], [], [], []
    for sz in show:
        pr = pgp_sub[pgp_sub["size_label"] == sz]
        ar = age_sub[age_sub["size_label"] == sz] if not age_sub.empty \
             else pd.DataFrame()
        if pr.empty and ar.empty: continue
        labels.append(sz)
        pgp_h.append(int(pr["header_bytes"].values[0]) if not pr.empty else 0)
        pgp_p.append(int(pr["payload_bytes"].values[0]) if not pr.empty else 0)
        age_h.append(int(ar["header_bytes"].values[0]) if not ar.empty else 0)
        age_p.append(int(ar["payload_bytes"].values[0]) if not ar.empty else 0)

    if not labels: return

    x = np.arange(len(labels)); w = 0.35
    fig, ax = plt.subplots(figsize=(10, 5.5))

    b1 = ax.bar(x - w/2, pgp_h, w, label="pico-pgp Header (PKESK)",
                color=COLORS["pgp_soft"], alpha=0.9, edgecolor="black", lw=0.7)
    ax.bar(x - w/2, pgp_p, w, bottom=pgp_h,
           label="pico-pgp Payload (SEIPD)",
           color=COLORS["pgp_soft"], alpha=0.4, edgecolor="black",
           lw=0.7, hatch="...")
    b3 = ax.bar(x + w/2, age_h, w, label="age Header (stanza)",
                color=COLORS["age_soft"], alpha=0.9, edgecolor="black", lw=0.7)
    ax.bar(x + w/2, age_p, w, bottom=age_h,
           label="age Payload (ciphertext)",
           color=COLORS["age_soft"], alpha=0.4, edgecolor="black",
           lw=0.7, hatch="...")

    for ph, pp, ah, ap_val in zip(pgp_h, pgp_p, age_h, age_p):
        pass  
    for i, (ph, pp, ah, ap_v, lbl) in enumerate(
            zip(pgp_h, pgp_p, age_h, age_p, labels)):
        for xoff, h, p in [(i - w/2, ph, pp), (i + w/2, ah, ap_v)]:
            total = h + p
            if total > 0:
                ax.text(xoff, total * 1.03, _bytes_fmt_short(total),
                        ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylabel("Size [bytes]")
    ax.set_title("Encrypted file structure: header vs payload\npico-pgp vs age")
    ax.legend(fontsize=9, loc="upper left")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(_bytes_fmt))
    _save(fig, out_dir / "header_vs_payload.png")


def chart_overhead_ratio(df, out_dir):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5), sharey=True)
    for ax, cat in zip(axes, ["Encrypt", "Decrypt"]):
        sub = df[(df["category"] == cat) &
                 (df["size_label"].isin(SIZE_ORDER_ALL))].copy()
        if sub.empty:
            ax.set_title(f"{cat} — brak danych"); continue
        x = np.arange(len(SIZE_ORDER_ALL)); w = 0.35
        for i, src in enumerate(["pgp", "age"]):
            ratios, valid_x = [], []
            for j, sz in enumerate(SIZE_ORDER_ALL):
                soft = sub[(sub["source"] == src) & (sub["variant"] == "Software") &
                           (sub["size_label"] == sz)]["median_ms"]
                hw   = sub[(sub["source"] == src) & (sub["variant"] == "Hardware") &
                           (sub["size_label"] == sz)]["median_ms"]
                if soft.empty or hw.empty or soft.values[0] == 0: continue
                ratios.append(hw.values[0] / soft.values[0])
                valid_x.append(j)
            if not ratios: continue
            ckey  = f"{src}_hw"
            label = f"{'pico-pgp' if src == 'pgp' else 'age'}"
            if src == "age" and cat == "Encrypt":
                label += "\nECDH soft"
            bars = ax.bar([x[j] + (i - 0.5) * w for j in range(len(valid_x))],
                          ratios, w, label=label,
                          color=COLORS.get(ckey, "#888"),
                          alpha=0.85, edgecolor="black", lw=0.7,
                          hatch=HATCH.get(ckey, ""))
            for bar, r in zip(bars, ratios):
                ax.text(bar.get_x() + bar.get_width()/2,
                        bar.get_height() + 0.05, f"{r:.1f}×",
                        ha="center", va="bottom", fontsize=8.5)
        ax.axhline(1.0, color="black", linestyle="--", lw=1.2,
                   label="baseline (1×)")
        ax.set_xticks(x)
        ax.set_xticklabels(SIZE_ORDER_ALL, rotation=15, ha="right")
        ax.set_title(cat); ax.set_ylabel("hw / software"); ax.legend(fontsize=8.5)
    fig.suptitle("Overhead hardware vs software", fontsize=14, fontweight="bold")
    plt.tight_layout()
    _save(fig, out_dir / "overhead_ratio.png")

#  Excel

def chart_hw_encrypt_comparison(df, out_dir):
    """
    Hardware encrypt comparison: pico-pgp vs age — time vs file size.

    pico-pgp Hardware Encrypt = CMD_GET_PUBLIC_KEY (I2C) + soft ECDH + SEIPD
    age Hardware Encrypt = soft ECDH with pub key from Pico + ChaCha20
                                (chip is NOT used for encryption in age)

    The chart shows the realistic encryption time when the public key
    comes from a hardware device — for both systems.
    """
    sub = df[(df["category"] == "Encrypt") &
             (df["variant"]   == "Hardware") &
             (df["size_label"].isin(SIZE_ORDER_ALL))].copy()

    if sub.empty:
        print("  [warn] No Hardware Encrypt data - skipping chart")
        return

    sub["_o"] = sub["size_label"].map(
        {k: i for i, k in enumerate(SIZE_ORDER_ALL)})
    sub = sub.sort_values("_o")

    fig, ax = plt.subplots(figsize=(10, 5.5))

    for src in ["pgp", "age"]:
        grp = sub[sub["source"] == src]
        if grp.empty:
            continue

        ckey = f"{src}_hw"
        if src == "pgp":
            label = "pico-pgp Hardware\n(CMD_GET_PUBLIC_KEY + soft ECDH + SEIPD)"
            style = "-o"
        else:
            label = "age Hardware\nECDH soft — chip only for decryption"
            style = "--s"

        ax.plot(grp["size_label"].values, grp["median_ms"].values,
                style, label=label,
                color=COLORS.get(ckey, "#888"),
                linewidth=2.2, markersize=8)

        if src == "pgp" and not all(
                grp["min_ms"].values == grp["max_ms"].values):
            ax.fill_between(grp["size_label"].values,
                            grp["min_ms"].values,
                            grp["max_ms"].values,
                            alpha=0.15, color=COLORS.get(ckey, "#888"))
    
    for src in ["pgp", "age"]:
        soft = df[(df["category"]   == "Encrypt") &
                  (df["variant"]    == "Software") &
                  (df["source"]     == src) &
                  (df["size_label"].isin(SIZE_ORDER_ALL))].copy()
        soft["_o"] = soft["size_label"].map(
            {k: i for i, k in enumerate(SIZE_ORDER_ALL)})
        soft = soft.sort_values("_o")
        if soft.empty:
            continue
        name = "pico-pgp" if src == "pgp" else "age"
        ax.plot(soft["size_label"].values, soft["median_ms"].values,
                ":", color=COLORS.get(f"{src}_soft", "#aaa"),
                linewidth=1.4, alpha=0.6,
                label=f"{name} Software (referencja)")

    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(
        lambda y, _: f"{y:.0f}" if y >= 1 else f"{y:.3f}"))
    ax.set_xlabel("File Size")
    ax.set_ylabel("Median Time [ms]  (log scale)")
    ax.set_title(
        "Hardware Encryption: pico-pgp vs age\n(dashed lines = software baseline)")
    ax.legend(loc="upper left", fontsize=9)
    _save(fig, out_dir / "hw_encrypt_comparison.png")


def chart_hw_decrypt_comparison(df, out_dir):
    """
    Hardware decrypt comparison: pico-pgp vs age — time vs file size.

    It shows three lines:
      - pico-pgp Hardware Decrypt (hardware ECDH + AES-CFB)
      - age Hardware Decrypt (hardware ECDH + ChaCha20)
      - pico-pgp Software Decrypt (soft ECDH + AES-CFB) - as a reference

    For small files ECDH dominates (~79ms constant), for large files it increases
    the cost of decrypting the data itself.
    """
    dec = df[df["category"] == "Decrypt"].copy()
    if dec.empty:
        print("  [warn] Brak danych Decrypt — pomijam wykres hw_decrypt")
        return

    dec["_o"] = dec["size_label"].map(
        {k: i for i, k in enumerate(SIZE_ORDER_ALL)})
    dec = dec.sort_values("_o")

    fig, ax = plt.subplots(figsize=(10, 5.5))

    plot_specs = [
        # (source, variant, label, style, color_key, linewidth)
        ("pgp", "Hardware", "pico-pgp Hardware\n(chip ECDH + AES-CFB + SHA-1 MDC)",
         "-o",  "pgp_hw",  2.2),
        ("age", "Hardware", "age Hardware\n(chip ECDH + ChaCha20-Poly1305)",
         "--s", "age_hw",  2.2),
        ("pgp", "Software", "pico-pgp Software (reference)",
         ":",   "pgp_soft", 1.4),
        ("age", "Software", "age Software (reference)",
         ":",   "age_soft", 1.4),
    ]

    has_data = False
    for src, var, label, style, ckey, lw in plot_specs:
        grp = dec[(dec["source"] == src) & (dec["variant"] == var) &
                  (dec["size_label"].isin(SIZE_ORDER_ALL))]
        if grp.empty:
            continue
        has_data = True
        alpha = 0.5 if "reference" in label else 1.0
        ax.plot(grp["size_label"].values, grp["median_ms"].values,
                style, label=label,
                color=COLORS.get(ckey, "#888"),
                linewidth=lw, markersize=8, alpha=alpha)
        if src == "pgp" and var == "Hardware" and not all(
                grp["min_ms"].values == grp["max_ms"].values):
            ax.fill_between(grp["size_label"].values,
                            grp["min_ms"].values,
                            grp["max_ms"].values,
                            alpha=0.12, color=COLORS.get(ckey, "#888"))

    if not has_data:
        print("  [warn] No Hardware Decrypt data - skipping chart")
        plt.close(fig)
        return

    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(
        lambda y, _: f"{y:.0f}" if y >= 1 else f"{y:.3f}"))
    ax.set_xlabel("File Size")
    ax.set_ylabel("Median Time [ms]  (log scale)")
    ax.set_title(
        "Hardware Decrypt: pico-pgp vs age\n"
        "(dashed lines = software baseline)")
    ax.legend(loc="upper left", fontsize=9)

    ax.annotate(
        "Hardware time = ECDH (~79ms constant) + decryption of data\n"
        "For small files ECDH dominates, for large files — the data",
        xy=(0.97, 0.03), xycoords="axes fraction",
        ha="right", va="bottom", fontsize=8,
        bbox=dict(boxstyle="round,pad=0.3", facecolor="lightyellow",
                  edgecolor="#ccc", alpha=0.9),
    )

    _save(fig, out_dir / "hw_decrypt_comparison.png")


def _style_ws(ws, hex_color):
    from openpyxl.styles import Font, PatternFill, Alignment
    fill  = PatternFill("solid", fgColor=hex_color)
    font  = Font(color="FFFFFF", bold=True)
    align = Alignment(horizontal="center", vertical="center")
    for cell in ws[1]:
        cell.fill = fill; cell.font = font; cell.alignment = align
    ws.row_dimensions[1].height = 20
    for col in ws.columns:
        mx = max((len(str(c.value or "")) for c in col), default=10)
        ws.column_dimensions[col[0].column_letter].width = min(mx + 3, 40)


def write_excel(pgp_df, age_df, age_sizes_df, combined, out_dir):
    path = out_dir / "comparison.xlsx"
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        if not pgp_df.empty:
            pgp_df.to_excel(writer, sheet_name="PGP Raw", index=False)
            _style_ws(writer.sheets["PGP Raw"], "1565C0")
        if not age_df.empty:
            age_df.to_excel(writer, sheet_name="age Raw", index=False)
            _style_ws(writer.sheets["age Raw"], "1B5E20")
        if not age_sizes_df.empty:
            age_sizes_df.to_excel(writer, sheet_name="age Sizes", index=False)
            _style_ws(writer.sheets["age Sizes"], "4A148C")

        cols = [
            "Operation", "Size",
            "PGP Soft [ms]", "PGP HW [ms]",
            "age Soft [ms]", "age HW [ms]",
            "PGP enc [B]", "PGP overhead [B]", "PGP header [B]", "PGP payload [B]",
            "age enc [B]", "age overhead [B]", "age header [B]", "age payload [B]",
            "Overhead PGP hw/soft", "Overhead age hw/soft",
        ]

        ops = [("ECDH","–"),
               ("Encrypt","100B"),("Encrypt","1 KB"),("Encrypt","64 KB"),
               ("Encrypt","1 MB"),("Encrypt","10 MB"),("Encrypt","100 MB"),
               ("Decrypt","100B"),("Decrypt","1 KB"),("Decrypt","64 KB"),
               ("Decrypt","1 MB"),("Decrypt","10 MB"),("Decrypt","100 MB")]

        rows = []
        for cat, sz in ops:
            row = {"Operation": cat, "Size": sz}
            for src, sl in [("pgp","PGP"),("age","age")]:
                for var, vl in [("Software","Soft"),("Hardware","HW")]:
                    mask = ((combined["source"]==src)&(combined["category"]==cat)&
                            (combined["variant"]==var)&(combined["size_label"]==sz))
                    v = combined[mask]["median_ms"]

                    if v.empty and src == "age" and cat == "Decrypt" and var == "Hardware" and sz == "1 KB":
                        v_fb = combined[(combined["source"]=="age") &
                                        (combined["category"]=="Decrypt") &
                                        (combined["variant"]=="Hardware") &
                                        (combined["size_label"]=="–")]["median_ms"]
                        v = v_fb

                    row[f"{sl} {vl} [ms]"] = (round(float(v.values[0]),4)
                                               if not v.empty else "")
                # PGP sizes
                if src == "pgp":
                    pm = ((pgp_df["category"].isin(["Encrypt","FileSize","Decrypt"]))&
                          (pgp_df["size_label"]==sz))
                    pr = pgp_df[pm]
                    for col,field in [(f"PGP enc [B]","encrypted_bytes"),
                                      (f"PGP overhead [B]","overhead_bytes"),
                                      (f"PGP header [B]","header_bytes"),
                                      (f"PGP payload [B]","payload_bytes")]:
                        row[col] = (int(pr[field].values[0])
                                    if not pr.empty and pr[field].values[0]>0 else "")
                # age sizes
                elif src == "age" and not age_sizes_df.empty:
                    ar = age_sizes_df[(age_sizes_df["variant"].str.contains("Software"))&
                                      (age_sizes_df["size_label"]==sz)]
                    for col,field in [(f"age enc [B]","encrypted_bytes"),
                                      (f"age overhead [B]","overhead_bytes"),
                                      (f"age header [B]","header_bytes"),
                                      (f"age payload [B]","payload_bytes")]:
                        row[col] = (int(ar[field].values[0])
                                    if not ar.empty else "")
                else:
                    for col in ["age enc [B]","age overhead [B]",
                                "age header [B]","age payload [B]"]:
                        row[col] = ""
            for sl in ["PGP","age"]:
                s = row.get(f"{sl} Soft [ms]","")
                h = row.get(f"{sl} HW [ms]","")
                row[f"Overhead {sl} hw/soft"] = (
                    round(h/s,2) if isinstance(s,float) and
                    isinstance(h,float) and s>0 else "")
            rows.append(row)

        from openpyxl.styles import PatternFill
        summary_df = pd.DataFrame(rows, columns=cols)
        summary_df.to_excel(writer, sheet_name="Summary", index=False)
        ws = writer.sheets["Summary"]
        _style_ws(ws, "37474F")
        alt = PatternFill("solid", fgColor="ECEFF1")
        for ri in range(2, len(rows)+2):
            if ri % 2 == 0:
                for cell in ws[ri]: cell.fill = alt

    print(f"  Saved: {path.name}")

#  main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pgp",       default=None)
    ap.add_argument("--age",       default=None)
    ap.add_argument("--age-sizes", default=None)
    ap.add_argument("--out",       required=True)
    args = ap.parse_args()

    out_dir    = Path(args.out)
    charts_dir = out_dir / "charts"
    out_dir.mkdir(parents=True, exist_ok=True)
    charts_dir.mkdir(parents=True, exist_ok=True)

    print("\n[1/4] Parsing data...")

    pgp_df = age_df = age_sizes_df = pd.DataFrame()

    if args.pgp and Path(args.pgp).exists():
        pgp_df = categorize(parse_pgp_csv(args.pgp))
    else:
        print(f"  [warn] No PGP CSV: {args.pgp}")

    if args.age and Path(args.age).exists():
        age_df = categorize(parse_age_raw(args.age))
        age_df.to_csv(out_dir / "age_bench.csv", index=False)
        print("  age CSV → age_bench.csv")
    else:
        print(f"  [warn] No age raw: {args.age}")

    szpath = args.age_sizes
    if not szpath and args.age:
        cand = str(Path(args.age).parent / "age_sizes.csv")
        if Path(cand).exists():
            szpath = cand
            print(f"  Auto-detect age sizes: {cand}")

    if szpath and Path(szpath).exists():
        age_sizes_df = parse_age_sizes(szpath)
    else:
        print("  [info] No age_sizes.csv — age size charts will be empty")
        print("         Generate: go test ./benchmarks/... -run TestFileSizes -v \\")
        print("                      2>&1 | grep -E 'age,' > results/age_sizes.csv")

    if pgp_df.empty and age_df.empty:
        print("[ERR] No data available."); sys.exit(1)

    combined = pd.concat([pgp_df, age_df], ignore_index=True)
    print(f"  Total timing entries: {len(combined)}")
    print("\n[2/4] Generating charts...")
    chart_ecdh(combined, charts_dir)
    chart_time_by_size(combined, "Encrypt", charts_dir,
                       "encrypt_time_comparison.png",
                       "Encryption time vs size — pico-pgp vs age",
                       age_hw_note=True)
    chart_time_by_size(combined, "Decrypt", charts_dir,
                       "decrypt_time_comparison.png",
                       "Decryption time vs size — pico-pgp vs age")
    chart_hw_encrypt_comparison(combined, charts_dir)
    chart_hw_decrypt_comparison(combined, charts_dir)
    chart_file_size_total(pgp_df, age_sizes_df, charts_dir)
    chart_overhead_bytes(pgp_df, age_sizes_df, charts_dir)
    chart_header_vs_payload(pgp_df, age_sizes_df, charts_dir)
    chart_overhead_ratio(combined, charts_dir)

    print("\n[3/4] Generating Excel...")
    write_excel(pgp_df, age_df, age_sizes_df, combined, out_dir)

    print("\n[4/4] Done.\n")
    print(f"Files in: {out_dir}/")
    for p in sorted(out_dir.rglob("*")):
        if p.is_file():
            s = p.stat().st_size
            print(f"  {str(p.relative_to(out_dir)):<50}"
                  f"  {s/1024:.1f} KB" if s > 1024 else
                  f"  {str(p.relative_to(out_dir)):<50}  {s} B")
    print()


if __name__ == "__main__":
    main()