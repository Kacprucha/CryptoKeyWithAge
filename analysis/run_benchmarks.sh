#!/usr/bin/env bash
# analysis/run_benchmarks.sh
#
# Collects benchmarks from pico-pgp (C) and age-go-client (Go),
# and then runs the visualization in an isolated Python venv.
#
# Directory structure (script located in analysis/):
# ../pico-pgp/ ← C CLI
# ../age-go-client/ ← Go CLI
# ./results/ ← Generated CSV and charts
# ./venv/ ← Isolated Python environment
#
# Usage:
# ./run_benchmarks.sh [options]
#
# Options:
# --port PORT Pico port (default /dev/ttyACM0)
# --slot N Slot number (default 0)
# --runs N Number of PGP benchmark repetitions (default 20)
# --no-hw Skip hardware benchmarks (non-Pico)
# --no-pgp Skip PGP benchmarks (C)
# --no-age Skip age benchmarks (Go)
# --no-charts Skip graph and Excel generation
# --benchtime DUR Duration of each Go benchmark (default 10s)
# -h, --help This help
 
set -euo pipefail
 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'
 
log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()      { echo -e "${GREEN}[ OK ]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERR ]${NC} $*" >&2; }
log_section() { echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; \
                echo -e "${BOLD}  $*${NC}"; \
                echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRYPTO_DIR="$(dirname "$SCRIPT_DIR")" 
PGP_DIR="$CRYPTO_DIR/pico-pgp"
AGE_DIR="$CRYPTO_DIR/age-go-client"
RESULTS_DIR="$SCRIPT_DIR/results"
VENV_DIR="$SCRIPT_DIR/venv"
CHARTS_DIR="$RESULTS_DIR/charts"
 
PORT="/dev/ttyACM0"
SLOT=0
RUNS=20
BENCHTIME="10s"
DO_HW=1
DO_PGP=1
DO_AGE=1
DO_CHARTS=1
 
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)      PORT="$2";      shift 2 ;;
        --slot)      SLOT="$2";      shift 2 ;;
        --runs)      RUNS="$2";      shift 2 ;;
        --benchtime) BENCHTIME="$2"; shift 2 ;;
        --no-hw)     DO_HW=0;        shift   ;;
        --no-pgp)    DO_PGP=0;       shift   ;;
        --no-age)    DO_AGE=0;       shift   ;;
        --no-charts) DO_CHARTS=0;    shift   ;;
        -h|--help)
            sed -n '/^# Użycie/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) log_error "Nieznana opcja: $1"; exit 1 ;;
    esac
done
 
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║      pico-pgp + pico-age  –  Benchmarks          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
log_info "Port:      $PORT"
log_info "Slot:      $SLOT"
log_info "Runs PGP:  $RUNS"
log_info "Benchtime: $BENCHTIME (age)"
log_info "Hardware:  $([ $DO_HW -eq 1 ] && echo 'YES' || echo 'NO')"
log_info "PGP (C):   $([ $DO_PGP -eq 1 ] && echo 'YES' || echo 'NO (--no-pgp)')"
log_info "age (Go):  $([ $DO_AGE -eq 1 ] && echo 'YES' || echo 'NO (--no-age)')"
echo ""
 
mkdir -p "$RESULTS_DIR" "$CHARTS_DIR"
 
#  STEP 1 – Benchmarki PGP (C)

if [[ $DO_PGP -eq 1 ]]; then
    log_section "1/3 pico-pgp (C) benchmarks"
 
    if [[ ! -d "$PGP_DIR" ]]; then
        log_error "pico-pgp directory not found: $PGP_DIR"
        log_error "Adjust the PGP_DIR variable in the script."
        exit 1
    fi
 
    log_info "Compiling bench_pgp..."
    cd "$PGP_DIR"
    if ! make bench -s 2>&1; then
        log_error "Failed to compile bench_pgp. Check the Makefile and dependencies."
        exit 1
    fi
    log_ok "bench_pgp compiled."
 
    PGP_BENCH="$PGP_DIR/benchmarks/bench_pgp"
    if [[ ! -x "$PGP_BENCH" ]]; then
        log_error "Executable file not found: $PGP_BENCH"
        exit 1
    fi
 
    PGP_CSV="$RESULTS_DIR/pgp_bench.csv"
 
    HW_FLAG=""
    if [[ $DO_HW -eq 0 ]]; then
        HW_FLAG="--no-hw"
        log_warn "Hardware benchmarks skipped (--no-hw):"
        log_warn "  BenchmarkECDH_Hardware, BenchmarkEncrypt_Hardware/*, BenchmarkDecrypt_HW/*"
    else
        log_warn "Hardware benchmarks require:"
        log_warn "  1. Pico connected on $PORT"
        log_warn "  2. gpg key pico@device imported (python3 gen_cert.py && gpg --import pico_cert.pgp)"
        log_warn "  3. BenchmarkDecrypt_HW uses bypass TUP — no button press needed"
        echo ""
    fi
    
    log_info "Running bench_pgp (runs=$RUNS)..."
    "$PGP_BENCH" \
        --runs  "$RUNS"  \
        --port  "$PORT"  \
        --slot  "$SLOT"  \
        $HW_FLAG         \
        > "$PGP_CSV"
 
    LINES=$(wc -l < "$PGP_CSV")
    log_ok "Zapisano $((LINES - 1)) wyników → $PGP_CSV"
fi
 
#  STEP 2 – Benchmarki age (Go)

if [[ $DO_AGE -eq 1 ]]; then
    log_section "2/3  age-go-client (Go) benchmarks"
 
    if [[ ! -d "$AGE_DIR" ]]; then
        log_error "age-go-client directory not found: $AGE_DIR"
        log_error "Adjust the AGE_DIR variable in the script."
        exit 1
    fi
 
    if ! command -v go &>/dev/null; then
        log_error "Go is not installed. Install it: sudo pacman -S go"
        exit 1
    fi
    log_info "Go: $(go version)"
 
    AGE_RAW="$RESULTS_DIR/age_raw.txt"
 
    cd "$AGE_DIR"
 
    if [[ $DO_HW -eq 1 ]]; then
        BENCH_FILTER="."
        log_info "Running all benchmarks (Software + Hardware)."
        log_warn "BenchmarkECDH_Hardware and BenchmarkEncrypt_Hardware"
        log_warn "  require Pico on $PORT with key in slot $SLOT."
        log_warn "BenchmarkDecrypt_Hardware uses BypassTUP=true — no button press needed."
        echo ""
    else
        BENCH_FILTER="BenchmarkECDH_Software"
        log_warn "Hardware benchmarks skipped (--no-hw):"
        log_warn "  BenchmarkECDH_Hardware, BenchmarkEncrypt_Hardware/*, BenchmarkDecrypt_Hardware/*"
    fi
 
    log_info "Running go test -bench (benchtime=$BENCHTIME)..."
 
    go test ./benchmarks/... \
        -bench       "$BENCH_FILTER" \
        -benchtime   "$BENCHTIME"    \
        -benchmem                    \
        -count       1               \
        -v                           \
        2>&1 | tee "$AGE_RAW"
 
    log_ok "Raw output saved → $AGE_RAW"
 
    # File size measurements age (TestFileSizes)

    AGE_SIZES="$RESULTS_DIR/age_sizes.csv"
    log_info "Collecting file sizes age (TestFileSizes)..."
 
    echo "format,variant,size_name,plaintext_bytes,encrypted_bytes,overhead_bytes,header_bytes,payload_bytes" \
        > "$AGE_SIZES"
 
    go test ./benchmarks/... \
        -run "TestFileSizes" \
        -v                   \
        2>&1 \
        | grep -E "^age," \
        >> "$AGE_SIZES"
 
    LINES_SIZES=$(wc -l < "$AGE_SIZES")
    if [[ $LINES_SIZES -le 1 ]]; then
        log_warn "TestFileSizes did not return data - check bench_test.go"
        AGE_SIZES=""
    else
        log_ok "Saved $((LINES_SIZES - 1)) file size measurements → $AGE_SIZES"
    fi
fi
 
#  STEP 3 – Python environment and visualization

if [[ $DO_CHARTS -eq 1 ]]; then
    log_section "3/3  Visualization (Python venv)"
 
    if ! command -v python3 &>/dev/null; then
        log_error "python3 is not installed."
        exit 1
    fi
    log_info "Python: $(python3 --version)"
 
    if [[ ! -d "$VENV_DIR" ]]; then
        log_info "Creating isolated Python environment: $VENV_DIR"
        python3 -m venv "$VENV_DIR"
        log_ok "venv created."
    else
        log_info "venv already exists: $VENV_DIR"
    fi
 
    VENV_PYTHON="$VENV_DIR/bin/python"
    VENV_PIP="$VENV_DIR/bin/pip"
 
    log_info "venv Python: $($VENV_PYTHON --version 2>&1)"
 
    # log_info "Installing/updating Python dependencies..."
    # "$VENV_PIP" install --quiet --upgrade pip
    # "$VENV_PIP" install --quiet \
    #     pandas       \
    #     matplotlib   \
    #     openpyxl     \
    #     numpy
 
    DEPS_OK=1
    for pkg in pandas matplotlib openpyxl numpy; do
        if ! "$VENV_PYTHON" -c "import $pkg" 2>/dev/null; then
            log_error "Package $pkg did not install correctly."
            DEPS_OK=0
        fi
    done
 
    if [[ $DEPS_OK -eq 0 ]]; then
        log_error "Error installing dependencies. Check your internet connection."
        exit 1
    fi
    log_ok "All dependencies installed."
 
    PGP_CSV="$RESULTS_DIR/pgp_bench.csv"
    AGE_RAW="$RESULTS_DIR/age_raw.txt"
 
    MISSING=0
    [[ ! -f "$PGP_CSV" ]] && { log_warn "No: $PGP_CSV (run without --no-pgp)"; MISSING=1; }
    [[ ! -f "$AGE_RAW" ]] && { log_warn "No: $AGE_RAW (run without --no-age)"; MISSING=1; }
 
    if [[ $MISSING -eq 1 ]]; then
        log_warn "Some input files do not exist."
        log_warn "The visualization script will attempt to work with the available data."
    fi
 
    CHART_SCRIPT="$SCRIPT_DIR/generate_charts.py"
 
    if [[ ! -f "$CHART_SCRIPT" ]]; then
        log_error "File not found: $CHART_SCRIPT"
        exit 1
    fi
 
    AGE_SIZES="${RESULTS_DIR}/age_sizes.csv"
 
    log_info "Generating charts and Excel sheet..."
    AGE_SIZES_ARG=""
    [[ -f "$AGE_SIZES" ]] && AGE_SIZES_ARG="--age-sizes $AGE_SIZES"
 
    "$VENV_PYTHON" "$CHART_SCRIPT" \
        --pgp  "$PGP_CSV"           \
        --age  "$AGE_RAW"           \
        $AGE_SIZES_ARG              \
        --out  "$RESULTS_DIR"
 
    log_ok "Visualization completed."
fi
 
log_section "Done!"
 
echo ""
log_ok "Output files in: $RESULTS_DIR/"
echo ""
 
if [[ -d "$RESULTS_DIR" ]]; then
    find "$RESULTS_DIR" -maxdepth 2 -type f \
        \( -name "*.csv" -o -name "*.xlsx" -o -name "*.png" -o -name "*.txt" \) \
        | sort \
        | while read -r f; do
            SIZE=$(du -h "$f" 2>/dev/null | cut -f1)
            printf "  %-50s %s\n" "$(realpath --relative-to="$RESULTS_DIR" "$f")" "$SIZE"
        done
fi
 
echo ""
echo -e "${BOLD}To regenerate charts without re-running benchmarks:${NC}"
echo "  $VENV_DIR/bin/python $SCRIPT_DIR/generate_charts.py \\"
echo "    --pgp       $RESULTS_DIR/pgp_bench.csv \\"
echo "    --age       $RESULTS_DIR/age_raw.txt \\"
echo "    --age-sizes $RESULTS_DIR/age_sizes.csv \\"
echo "    --out       $RESULTS_DIR"
echo ""