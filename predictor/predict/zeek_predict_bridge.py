
#!/usr/bin/env python3
import argparse, json, sys, os, re
import joblib
import pandas as pd
import numpy as np
from datetime import datetime

BRIDGE_NUM = ["dur","sbytes","dbytes","spkts","dpkts"]
BRIDGE_CAT = ["proto","state","service"]

def load_model(path):
    obj = joblib.load(path)
    return obj["pipeline"], obj.get("meta", {})

def parse_zeek_json(path):
    # Zeek JSON: one JSON object per line
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue

def zeek_to_bridge(rec: dict):
    # Map Zeek conn.log fields to UNSW bridge columns
    # Zeek fields reference: ts, uid, id.orig_h, id.resp_h, id.orig_p, id.resp_p, proto, service, duration,
    # orig_bytes, resp_bytes, orig_pkts, resp_pkts, conn_state
    out = {}
    out["dur"] = rec.get("duration")
    out["sbytes"] = rec.get("orig_bytes")
    out["dbytes"] = rec.get("resp_bytes")
    out["spkts"] = rec.get("orig_pkts")
    out["dpkts"] = rec.get("resp_pkts")
    out["proto"] = (rec.get("proto") or "").lower() or None
    # conn_state like "S0","S1","SF", etc. Keep as-is (lowercased) to let OHE handle unknowns
    cs = rec.get("conn_state")
    out["state"] = cs.lower() if isinstance(cs, str) else None
    svc = rec.get("service")
    # Zeek uses "-" for unknown service
    if svc == "-":
        svc = None
    out["service"] = (svc or "").lower() or None
    return out

def batch_dataframe(json_path):
    rows = []
    meta = []
    for rec in parse_zeek_json(json_path):
        bridge = zeek_to_bridge(rec)
        rows.append(bridge)
        meta.append({
            "ts": rec.get("ts"),
            "uid": rec.get("uid"),
            "src": rec.get("id.orig_h"),
            "dst": rec.get("id.resp_h"),
            "sport": rec.get("id.orig_p"),
            "dport": rec.get("id.resp_p"),
        })
    if not rows:
        return pd.DataFrame(), pd.DataFrame()
    X = pd.DataFrame(rows)
    M = pd.DataFrame(meta)
    # coerce numerics
    for c in BRIDGE_NUM:
        if c in X.columns:
            X[c] = pd.to_numeric(X[c], errors="coerce")
    for c in BRIDGE_CAT:
        if c in X.columns:
            X[c] = X[c].astype(object)
    return X, M

def main():
    ap = argparse.ArgumentParser(description="Predict malice from Zeek conn.log (JSON) using UNSW bridge model")
    ap.add_argument("--model", required=True, help="Path to unsw_bridge_model.joblib")
    ap.add_argument("--conn_json", required=True, help="Path to Zeek conn.log in JSON")
    ap.add_argument("--out", help="Optional CSV to write predictions")
    args = ap.parse_args()

    pipe, meta = load_model(args.model)
    X, M = batch_dataframe(args.conn_json)
    if X.empty:
        print("[WARN] No Zeek records parsed.")
        sys.exit(0)

    # Align expected columns (missing cats/numerics will be imputed/ignored by OHE/imputer)
    preds = pipe.predict(X)
    try:
        proba = pipe.predict_proba(X)[:,1]
    except Exception:
        proba = None

    out_df = M.copy()
    out_df["pred"] = preds
    if proba is not None:
        out_df["score"] = proba

    if args.out:
        out_df.to_csv(args.out, index=False)
        print(f"[OK] Wrote predictions to {args.out}")
    else:
        # print a few top suspicious
        show = out_df.sort_values("score", ascending=False) if "score" in out_df.columns else out_df
        print(show.head(20).to_string(index=False))

if __name__ == "__main__":
    main()