"""
Sentinel DDoS Core - ML model training with real-world datasets.

Loads CICDDoS2019, UNSW-NB15, and CAIDA-style CSV/JSON; trains RandomForest
(n_estimators=100, max_depth=15) on >= 100k samples; exports decisionengine/ml_model.h.

Feature order (20): packets_per_second, bytes_per_second, syn_ratio, rst_ratio,
  dst_port_entropy, payload_byte_entropy, unique_dst_ports, avg_packet_size,
  stddev_packet_size, http_request_count, fin_ratio, src_port_entropy,
  unique_src_ports, avg_ttl, stddev_ttl, avg_iat_us, stddev_iat_us,
  src_total_flows, src_packets_per_second, dns_query_count.
Label: 0 = Normal, 1 = Attack.
"""

import os
import sys
import json
import glob

try:
    from sklearn.ensemble import RandomForestClassifier
    import numpy as np
    import m2cgen as m2c
except ImportError:
    print("WARNING: Required libraries missing. Please run: pip install scikit-learn m2cgen numpy")
    sys.exit(1)

NUM_FEATURES = 20

# Feature names in order for the C model (must match sentinel_feature_vector_t)
FEATURE_NAMES = [
    "packets_per_second", "bytes_per_second", "syn_ratio", "rst_ratio",
    "dst_port_entropy", "payload_byte_entropy", "unique_dst_ports",
    "avg_packet_size", "stddev_packet_size", "http_request_count",
    "fin_ratio", "src_port_entropy", "unique_src_ports", "avg_ttl", "stddev_ttl",
    "avg_iat_us", "stddev_iat_us", "src_total_flows", "src_packets_per_second",
    "dns_query_count",
]

# STRICT CICDDoS2019 mappings. Missing feature = 0.0.
# CICDDoS2019 does NOT contain TTL; avg_ttl/stddev_ttl are always 0.0 for CIC.
CIC_ALIASES = {
    "packets_per_second": ["Flow Packets/s"],
    "bytes_per_second": ["Flow Bytes/s"],
    "syn_ratio": ["SYN Flag Count", "SYN Flag Cnt"],   # ratio computed as count / Total Fwd Packets in loader
    "fin_ratio": ["FIN Flag Count", "FIN Flag Cnt"],
    "rst_ratio": ["RST Flag Count", "RST Flag Cnt"],
    "dst_port_entropy": [],   # no direct entropy in CIC; use 0.0 if no column
    "payload_byte_entropy": [],
    "unique_dst_ports": ["Destination Port"],
    "avg_packet_size": ["Packet Length Mean", "Fwd Packet Length Mean"],
    "stddev_packet_size": ["Packet Length Std", "Fwd Packet Length Std"],
    "http_request_count": ["Fwd Header Length"],   # proxy for application data
    "src_port_entropy": [],
    "unique_src_ports": ["Source Port"],
    "avg_ttl": [],   # CICDDoS2019 does not contain TTL - always 0.0
    "stddev_ttl": [],
    "avg_iat_us": ["Flow IAT Mean"],
    "stddev_iat_us": ["Flow IAT Std", "Fwd IAT Std"],
    "src_total_flows": [],
    "src_packets_per_second": ["Fwd Packets/s", "Flow Packets/s"],
    "dns_query_count": [],
}
# CIC columns used for ratio denominators (Total Fwd Packets)
CIC_RATIO_DENOM = ["Total Fwd Packets", "Total Fwd Packet"]

# STRICT UNSW-NB15 mappings. Missing = 0.0.
UNSW_ALIASES = {
    "packets_per_second": ["rate"],
    "bytes_per_second": ["sload"],
    "syn_ratio": [],
    "rst_ratio": ["ct_rst_srv"],
    "dst_port_entropy": ["dsport", "ct_dst_sport_ltm"],
    "payload_byte_entropy": [],
    "unique_dst_ports": ["dsport"],
    "avg_packet_size": ["smean", "dmean"],
    "stddev_packet_size": [],
    "http_request_count": ["ct_flw_http_mthd", "ct_http_cmd"],
    "fin_ratio": [],
    "src_port_entropy": ["sport", "ct_src_sport_ltm"],
    "unique_src_ports": ["sport"],
    "avg_ttl": ["sttl"],
    "stddev_ttl": ["dttl"],
    "avg_iat_us": ["sinpkt"],   # source inter-packet arrival
    "stddev_iat_us": [],
    "src_total_flows": [],
    "src_packets_per_second": [],
    "dns_query_count": ["ct_dns_query"],
}


def _row_val(row, keys, default=0.0):
    """Get first matching key from row (case-insensitive); return default if missing or empty."""
    for k in keys:
        if k not in row:
            for h in row:
                if h and k.strip().lower() in h.strip().lower():
                    try:
                        v = float(row[h])
                        return v if v == v else default
                    except (ValueError, TypeError):
                        return default
            continue
        try:
            v = float(row[k])
            return v if v == v else default
        except (ValueError, TypeError):
            return default
    return default


def load_csv_generic(path, feature_cols, label_col="Label", label_normal=("BENIGN", "Normal", "0", "normal"), max_rows=None):
    """Load CSV. feature_cols = list of column names or None per feature (length NUM_FEATURES).
    Missing features (None or column absent in row) are set to 0.0. No guess; model integrity only."""
    import csv
    X_rows = []
    y_list = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        for i, row in enumerate(r):
            if max_rows and i >= max_rows:
                break
            try:
                vals = []
                for c in feature_cols:
                    if c is None:
                        vals.append(0.0)
                        continue
                    raw = row.get(c, 0)
                    try:
                        v = float(raw) if raw != "" and raw is not None else 0.0
                        vals.append(v if v == v else 0.0)  # NaN -> 0.0
                    except (ValueError, TypeError):
                        vals.append(0.0)
                x = vals
                lab = row.get(label_col, "")
                y = 0 if str(lab).strip() in label_normal else 1
                X_rows.append(x)
                y_list.append(y)
            except (ValueError, KeyError, TypeError):
                continue
    if not X_rows:
        return None, None
    return np.array(X_rows, dtype=np.float64), np.array(y_list, dtype=np.int64)


def load_csv_with_aliases(path, aliases, label_col="Label", max_rows=200000):
    """Strict: match only listed aliases. If no mapping exists for a feature, use 0.0 (do NOT use headers[0])."""
    import csv
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        headers = list(r.fieldnames or [])
    feature_cols = []
    for name in FEATURE_NAMES:
        chosen = None
        for alias in aliases.get(name, []):
            a = alias.strip().lower()
            for h in headers:
                if h and a == h.strip().lower():
                    chosen = h
                    break
                if h and a in h.strip().lower():
                    chosen = h
                    break
            if chosen:
                break
        feature_cols.append(chosen)  # None if no mapping -> 0.0 in load_csv_generic
    if len(feature_cols) != NUM_FEATURES:
        return None, None
    return load_csv_generic(path, feature_cols, label_col=label_col, max_rows=max_rows)


def _resolve_col(headers, aliases):
    """First header that matches any alias (case-insensitive)."""
    for a in aliases:
        a = a.strip().lower()
        for h in headers:
            if h and (a == h.strip().lower() or a in h.strip().lower()):
                return h
    return None


def load_cic_strict(path, label_col="Label", label_normal=("BENIGN", "Normal", "0", "normal"), max_rows=150000):
    """CICDDoS2019 strict: only real columns; ratios from count/Total Fwd Packets; avg_ttl/stddev_ttl = 0.0 (not in CIC)."""
    import csv
    X_rows = []
    y_list = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        headers = list(r.fieldnames or [])
        total_fwd_col = _resolve_col(headers, CIC_RATIO_DENOM)
        syn_col = _resolve_col(headers, ["SYN Flag Count", "SYN Flag Cnt"])
        fin_col = _resolve_col(headers, ["FIN Flag Count", "FIN Flag Cnt"])
        rst_col = _resolve_col(headers, ["RST Flag Count", "RST Flag Cnt"])
        flow_pps_col = _resolve_col(headers, ["Flow Packets/s"])
        flow_bps_col = _resolve_col(headers, ["Flow Bytes/s"])
        dst_port_col = _resolve_col(headers, ["Destination Port"])
        pkt_mean_col = _resolve_col(headers, ["Packet Length Mean", "Fwd Packet Length Mean"])
        pkt_std_col = _resolve_col(headers, ["Packet Length Std", "Fwd Packet Length Std"])
        fwd_hl_col = _resolve_col(headers, ["Fwd Header Length"])
        src_port_col = _resolve_col(headers, ["Source Port"])
        subflow_col = _resolve_col(headers, ["Subflow Fwd Bytes"])
        iat_mean_col = _resolve_col(headers, ["Flow IAT Mean"])
        iat_std_col = _resolve_col(headers, ["Flow IAT Std", "Fwd IAT Std"])
        fwd_pps_col = _resolve_col(headers, ["Fwd Packets/s", "Flow Packets/s"])
        for i, row in enumerate(r):
            if max_rows and i >= max_rows:
                break
            try:
                total_fwd = max(_row_val(row, [total_fwd_col] if total_fwd_col else [], 0), 1)
                syn_cnt = _row_val(row, [syn_col] if syn_col else [], 0)
                fin_cnt = _row_val(row, [fin_col] if fin_col else [], 0)
                rst_cnt = _row_val(row, [rst_col] if rst_col else [], 0)
                x = [
                    _row_val(row, [flow_pps_col] if flow_pps_col else [], 0),
                    _row_val(row, [flow_bps_col] if flow_bps_col else [], 0),
                    syn_cnt / total_fwd,
                    rst_cnt / total_fwd,
                    _row_val(row, [dst_port_col] if dst_port_col else [], 0),
                    _row_val(row, [subflow_col] if subflow_col else [], 0),
                    _row_val(row, [dst_port_col] if dst_port_col else [], 0),
                    _row_val(row, [pkt_mean_col] if pkt_mean_col else [], 0),
                    _row_val(row, [pkt_std_col] if pkt_std_col else [], 0),
                    _row_val(row, [fwd_hl_col] if fwd_hl_col else [], 0),
                    fin_cnt / total_fwd,
                    _row_val(row, [src_port_col] if src_port_col else [], 0),
                    _row_val(row, [src_port_col] if src_port_col else [], 0),
                    0.0,   # avg_ttl - CICDDoS2019 does not contain TTL
                    0.0,   # stddev_ttl
                    _row_val(row, [iat_mean_col] if iat_mean_col else [], 0),
                    _row_val(row, [iat_std_col] if iat_std_col else [], 0),
                    _row_val(row, [total_fwd_col] if total_fwd_col else [], 0),
                    _row_val(row, [fwd_pps_col] if fwd_pps_col else [], 0),
                    _row_val(row, [fwd_hl_col] if fwd_hl_col else [], 0),
                ]
                lab = row.get(label_col, "")
                y = 0 if str(lab).strip() in label_normal else 1
                X_rows.append(x)
                y_list.append(y)
            except (ValueError, KeyError, TypeError, ZeroDivisionError):
                continue
    if not X_rows:
        return None, None
    return np.array(X_rows, dtype=np.float64), np.array(y_list, dtype=np.int64)


def load_cic(path, max_rows=150000):
    """Load CICDDoS2019-style CSV. Prefer strict mapping; fallback to alias-based load."""
    X, y = load_cic_strict(path, max_rows=max_rows)
    if X is not None and len(X) > 0:
        return X, y
    return load_csv_with_aliases(path, CIC_ALIASES, label_col="Label", max_rows=max_rows)


def load_unsw(path, max_rows=150000):
    """Load UNSW-NB15-style CSV (label column often 'label' or 'attack')."""
    for label_col in ("label", "Label", "attack", "Attack"):
        X, y = load_csv_with_aliases(path, UNSW_ALIASES, label_col=label_col, max_rows=max_rows)
        if X is not None and len(X) > 100:
            return X, y
    return None, None


def load_caida(path, max_rows=100000):
    """Load CAIDA-style CSV or JSON. Expect columns/keys for all 20 features or JSON array of objects."""
    if path.lower().endswith(".json"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            if isinstance(data, list):
                rows = data[:max_rows]
            elif isinstance(data, dict) and "samples" in data:
                rows = data["samples"][:max_rows]
            else:
                return None, None
            X_rows = []
            y_list = []
            for r in rows:
                if isinstance(r, dict):
                    x = [
                        float(r.get("packets_per_second", r.get("pps", 0))),
                        float(r.get("bytes_per_second", r.get("bps", 0))),
                        float(r.get("syn_ratio", 0)),
                        float(r.get("rst_ratio", 0)),
                        float(r.get("dst_port_entropy", r.get("entropy", 0))),
                        float(r.get("payload_byte_entropy", 0)),
                        float(r.get("unique_dst_ports", 0)),
                        float(r.get("avg_packet_size", 0)),
                        float(r.get("stddev_packet_size", 0)),
                        float(r.get("http_request_count", 0)),
                        float(r.get("fin_ratio", 0)),
                        float(r.get("src_port_entropy", 0)),
                        float(r.get("unique_src_ports", 0)),
                        float(r.get("avg_ttl", 0)),
                        float(r.get("stddev_ttl", 0)),
                        float(r.get("avg_iat_us", r.get("avg_iat", 0))),
                        float(r.get("stddev_iat_us", 0)),
                        float(r.get("src_total_flows", 0)),
                        float(r.get("src_packets_per_second", 0)),
                        float(r.get("dns_query_count", 0)),
                    ]
                    y = 0 if str(r.get("label", r.get("attack", 0))).lower() in ("0", "normal", "benign", "false") else 1
                    X_rows.append(x)
                    y_list.append(y)
            if not X_rows:
                return None, None
            return np.array(X_rows, dtype=np.float64), np.array(y_list, dtype=np.int64)
        except Exception:
            return None, None
    return load_csv_with_aliases(path, {k: [k] for k in FEATURE_NAMES}, max_rows=max_rows)


def gather_datasets(data_dirs=None, min_total=100000):
    """Collect X, y from CICDDoS2019, UNSW-NB15, CAIDA under data_dirs."""
    if data_dirs is None:
        base = os.path.join(os.path.dirname(__file__), "data")
        data_dirs = [base, os.path.join(os.path.dirname(__file__), "..", "data"), "."]
    X_all = []
    y_all = []
    for d in data_dirs:
        if not os.path.isdir(d):
            continue
        for path in glob.glob(os.path.join(d, "**", "*.csv"), recursive=True)[:20]:
            X, y = load_cic(path)
            if X is not None:
                X_all.append(X)
                y_all.append(y)
                print(f"  Loaded CIC-style: {path} ({len(X)} rows)")
            if X is None:
                X, y = load_unsw(path)
                if X is not None:
                    X_all.append(X)
                    y_all.append(y)
                    print(f"  Loaded UNSW-style: {path} ({len(X)} rows)")
        for path in glob.glob(os.path.join(d, "**", "*.json"), recursive=True)[:10]:
            X, y = load_caida(path)
            if X is not None:
                X_all.append(X)
                y_all.append(y)
                print(f"  Loaded CAIDA-style JSON: {path} ({len(X)} rows)")
    if not X_all:
        raise RuntimeError("No dataset CSV/JSON found under data/ or current dir. Real datasets are required.")
    X = np.vstack(X_all)
    y = np.concatenate(y_all)
    if len(X) < min_total:
        raise RuntimeError(f"Insufficient real samples: {len(X)} < required {min_total}.")
    return X, y




def train_and_export_model():
    print("Gathering training data (CICDDoS2019, UNSW-NB15, CAIDA-style)...")
    X, y = gather_datasets(min_total=100000)
    print(f"Total samples: {len(X)} (min 100000 required)")


    # Replace inf/nan for robustness
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=0.0)
    X = np.clip(X, 0, 1e10)

    print("Training RandomForestClassifier (n_estimators=100, max_depth=15)...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    clf.fit(X, y)

    print("Exporting model to C code using m2cgen...")
    code = m2c.export_to_c(clf)

    c_header = """/*
 * AUTO-GENERATED MACHINE LEARNING MODEL
 * Generated by train_ml.py (scikit-learn + m2cgen).
 * Do not edit manually.
 */

#ifndef SENTINEL_ML_MODEL_H
#define SENTINEL_ML_MODEL_H

#include <math.h>

"""
    c_footer = """

/*
 * Wrapper for Sentinel 20-feature vector.
 * Maps sentinel_feature_vector_t to the model input array.
 * Returns probability of attack [0.0 - 1.0].
 */
static inline double run_ml_inference(const sentinel_feature_vector_t *f, ml_scratch_t *scr) {
    double input[20];
    double output[2];

    input[0]  = f->packets_per_second;
    input[1]  = f->bytes_per_second;
    input[2]  = f->syn_ratio;
    input[3]  = f->rst_ratio;
    input[4]  = f->dst_port_entropy;
    input[5]  = f->payload_byte_entropy;
    input[6]  = (double)f->unique_dst_ports;
    input[7]  = f->avg_packet_size;
    input[8]  = f->stddev_packet_size;
    input[9]  = (double)f->http_request_count;
    input[10] = f->fin_ratio;
    input[11] = f->src_port_entropy;
    input[12] = (double)f->unique_src_ports;
    input[13] = f->avg_ttl;
    input[14] = f->stddev_ttl;
    input[15] = f->avg_iat_us;
    input[16] = f->stddev_iat_us;
    input[17] = (double)f->src_total_flows;
    input[18] = f->src_packets_per_second;
    input[19] = (double)f->dns_query_count;

    score(input, output, scr);
    return output[1];
}

#endif /* SENTINEL_ML_MODEL_H */
"""
    output_path = os.path.join(os.path.dirname(__file__), "decisionengine", "ml_model.h")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f_out:
        f_out.write(c_header)
        f_out.write(code)
        f_out.write(c_footer)
    print(f"Successfully generated ML model: {output_path}")


if __name__ == "__main__":
    train_and_export_model()
