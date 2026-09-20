
#!/usr/bin/env python3
import argparse, time, os, json, joblib, pandas as pd, numpy as np
from zeek_predict_bridge import zeek_to_bridge, BRIDGE_NUM, BRIDGE_CAT
from ipaddress import ip_address, IPv4Address
import json
from datetime import datetime, timezone


def wait_for_file(path, interval=1.0):
    while not os.path.isfile(path):
        print(f"[wait] esperando {path} ...")
        time.sleep(interval)

def is_public_ipv4(ip_str: str) -> bool:
    """True solo si es IPv4 pública enrutables."""
    try:
        ip = ip_address(ip_str)
    except ValueError:
        return False  # no es IP válida
    if not isinstance(ip, IPv4Address):
        return False  # ignorar IPv6 en esta PoC
    # descartar privadas, loopback, link-local, multicast, reservadas, sin especificar
    return not (ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip.is_private)


def tail_f(path):
    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def normalize_ip(val):
    """Convierte cualquier cosa (tuple/list/str/None) a string 'ip' o '' """
    if val is None:
        return ""
    if isinstance(val, (list, tuple)) and val:
        return str(val[0])
    return str(val)

def jsonl_log(path, ts, ip, score, classification):
    event = {
        "@timestamp": datetime.fromtimestamp(
            ts, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),

        "source": {
            "ip": ip
        },

        "network": {
            "transport": "tcp",
            "service": "http"
        },

        "ml": {
            "score": float(score),
            "threshold": 0.75,
            "classification": classification
        }
    }

    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")





def append_ip_once(path, ip):
    ip = (ip or "").strip()
    if not ip or not is_public_ipv4(ip):
        return
    try:
        # lee existente una vez y evita duplicados
        existing = set()
        if os.path.exists(path):
            with open(path, "r") as r:
                existing = {l.strip() for l in r if l.strip()}
        if ip not in existing:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a") as w:
                w.write(ip + "\n")
    except Exception:
        # PoC: ignorar errores de E/S para que el contenedor no muera
        pass

def main():
    ap = argparse.ArgumentParser(description="Tail Zeek conn.log (JSON) and live-predict")
    ap.add_argument("--model", required=True)
    ap.add_argument("--conn_json", required=True)
    ap.add_argument("--malicious-threshold",
        type=float, default=0.75, 
        help="Alert threshold for malicious classification"
    )
    ap.add_argument(
        "--suspicious-threshold",
        type=float,
        default=0.65,
        help="Threshold for suspicious classification"
    )
    ap.add_argument(
        "--out_ips",
        default="/data/detected_ips.txt",
        help="Path to file where detected source IPs will be saved"
    )

    args = ap.parse_args()
    
    obj = joblib.load(args.model)
    
    pipe = obj["pipeline"]
    
    pred=None

    buf = []
    for line in tail_f(args.conn_json):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        bridge = zeek_to_bridge(rec)
        X = pd.DataFrame([bridge])
        for c in BRIDGE_NUM:
            X[c] = pd.to_numeric(X[c], errors="coerce")
        for c in BRIDGE_CAT:
            X[c] = X[c].astype(object)
        try:
            proba = pipe.predict_proba(X)[:,1][0]
        except Exception:
            pred = pipe.predict(X)[0]
            proba = None
        uid = rec.get("uid")
        src = rec.get("id.orig_h")
        dst = rec.get("id.resp_h")

        if proba is not None:
            if proba >= args.malicious_threshold and is_public_ipv4(src):
                classification = "malicious"

                print(json.dumps({
                    "uid": uid,
                    "src": src,
                    "dst": dst,
                    "score": proba,
                    "classification": classification,
                    "alert": True
                }))

                append_ip_once(args.out_ips, src)

            elif proba >= args.suspicious_threshold and is_public_ipv4(src):
                classification = "suspicious"

                print(json.dumps({
                    "uid": uid,
                    "src": src,
                    "dst": dst,
                    "score": proba,
                    "classification": classification,
                    "alert": False
                }))

            else:
                classification = "normal"

            jsonl_log(
            "/data/predictions.jsonl",
            rec.get("ts"),
            src,
            proba,
            classification
            )



        # if proba is not None and proba >= args.threshold:
        #     classification = "malicious"
        #     print(json.dumps({"uid": uid, "src": src, "dst": dst, "score": proba, "alert": True}))
        #     append_ip_once(args.out_ips, src)
        #     jsonl_log("/data/predictions.jsonl",rec.get("ts"),src,proba,classification)

        # elif proba is None and pred == 1:
        #     print(json.dumps({"uid": uid, "src": src, "dst": dst, "pred": int(pred), "alert": True}))
        #     append_ip_once(args.out_ips, src)
            

if __name__ == "__main__":
    main()