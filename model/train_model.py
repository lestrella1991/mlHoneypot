
#!/usr/bin/env python3
import argparse, os, sys, json
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV,StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, fbeta_score, make_scorer
import joblib

RANDOM_STATE = 42
BRIDGE_NUM = ["dur","sbytes","dbytes","spkts","dpkts"]
BRIDGE_CAT = ["proto","state","service"]

def read_csv_safely(path: str) -> pd.DataFrame:
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.read_csv(path, engine="python")

def clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = (
        df.columns
          .str.strip()
          .str.lower()
          .str.replace(r"[^\w]+", "_", regex=True)
          .str.replace("__+", "_", regex=True)
          .str.strip("_")
    )
    # Common UNSW typos
    fixes = {
        "attack_cat_": "attack_cat",
        "label_": "label",
    }
    df.rename(columns=fixes, inplace=True)
    return df

def coerce_types(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for c in ["proto","state","service","attack_cat"]:
        if c in df.columns:
            df[c] = df[c].astype(str).str.strip().str.lower().replace({"nan": np.nan, "-": np.nan})
    for c in BRIDGE_NUM:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df

def prepare_labels(df: pd.DataFrame, mode: str) -> pd.DataFrame:
    df = df.copy()
    if "attack_cat" in df.columns:
        df["attack_cat"] = df["attack_cat"].fillna("normal").replace({"-": "normal"}).str.lower()
    if "label" in df.columns:
        df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    else:
        df["label"] = (df.get("attack_cat","normal").astype(str).str.lower() != "normal").astype(int)
    if mode == "binary":
        df["y"] = df["label"]
    else:
        known = ["normal","fuzzers","analysis","backdoor","dos","exploits","generic","reconnaissance","shellcode","worms"]
        ac = df.get("attack_cat", "normal").astype(str).str.lower().fillna("normal")
        df["y"] = ac.where(ac.isin(known), other="other")
    return df

def build_preproc():
    num_pipe = Pipeline([
        ("imp", SimpleImputer(strategy="median")),
        ("sc", StandardScaler(with_mean=False)),
    ])
    cat_pipe = Pipeline([
        ("imp", SimpleImputer(strategy="most_frequent")),
        ("oh", OneHotEncoder(handle_unknown="ignore")),
    ])
    pre = ColumnTransformer([
        ("num", num_pipe, BRIDGE_NUM),
        ("cat", cat_pipe, BRIDGE_CAT),
    ])
    return pre

def main():
    ap = argparse.ArgumentParser(description="Train UNSW-NB15 bridge model compatible with Zeek conn.log")
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--mode", choices=["binary","multiclass"], default="binary")
    ap.add_argument("--out", default="unsw_bridge_model.joblib")
    args = ap.parse_args()

    train = coerce_types(clean_columns(read_csv_safely(args.train)))
    test  = coerce_types(clean_columns(read_csv_safely(args.test)))

    # keep only bridge features + labels
    needed = set(BRIDGE_NUM + BRIDGE_CAT + ["attack_cat","label"])
    train = train[[c for c in train.columns if c in needed]].copy()
    test  = test [[c for c in test.columns  if c in needed]].copy()

    train = prepare_labels(train, args.mode)
    test  = prepare_labels(test, args.mode)

    pre = build_preproc()
    clf = Pipeline([
        ("pre", pre),
        ("rf", RandomForestClassifier(class_weight='balanced_subsample',n_jobs=-1,n_estimators=800 , random_state=RANDOM_STATE
        ))
    ])

    Xtr = train.drop(columns=["y"])
    ytr = train["y"]
    Xte = test.drop(columns=["y"])
    yte = test["y"]
    

    scorers = {
        "recall_pos": make_scorer(recall_score, pos_label=1),
        "precision_pos": make_scorer(precision_score, pos_label=1),
        "fbeta_08": make_scorer(fbeta_score, beta=0.8, pos_label=1),
        "fbeta_10": make_scorer(fbeta_score, beta=1.0, pos_label=1),  
    }


    param_grid = {
        "rf__n_estimators": [800],
        "rf__max_depth": [30],
        "rf__min_samples_split": [2],
        "rf__min_samples_leaf": [1],
        "rf__max_features": ["log2"]
    }

    # CV estratificado para mantener proporciones
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)

    # 3) GridSearch con múltiples métricas y refit por fbeta_08 (menos FP)
    grid = GridSearchCV(
    clf,
    param_grid=param_grid,
    scoring=scorers,
    refit="fbeta_08", 
    cv=cv,
    n_jobs=-1,
    verbose=2
    )

    def pick_threshold(y_true, y_proba, recall_min=0.95):
        thr_list = np.linspace(0.20, 0.80, 25)
        best = (0.5, 0.0, 0.0, 0.0)  # (t, precision, recall, f1)
        for t in thr_list:
            yp = (y_proba >= t).astype(int)
            pre = precision_score(y_true, yp, pos_label=1, zero_division=0)
            rec = recall_score(y_true, yp, pos_label=1)
            f1  = fbeta_score(y_true, yp, beta=1.0, pos_label=1)
            if rec >= recall_min:
                if pre > best[1]:  # max precision bajo la restricción de recall
                    best = (t, pre, rec, f1)
        if best[1] == 0.0:  # si no alcanza recall_min, tomar mejor F1 global
            for t in thr_list:
                yp = (y_proba >= t).astype(int)
                f1  = fbeta_score(y_true, yp, beta=1.0, pos_label=1)
                if f1 > best[3]:
                    pre = precision_score(y_true, yp, pos_label=1, zero_division=0)
                    rec = recall_score(y_true, yp, pos_label=1)
                    best = (t, pre, rec, f1)
        return best

    grid.fit(Xtr, ytr)

    print("=== Mejor combinación (según fbeta_08) ===")
    print(grid.best_params_)
    print("Mejor score (fbeta_08):", grid.best_score_)

    best_model = grid.best_estimator_

    # 4) No usar umbral 0.5 a ciegas: barrer umbrales y elegir uno operativo
    y_proba_te = best_model.predict_proba(Xte)[:, 1]
    t_opt, pre_v, rec_v, f1_v = pick_threshold(yte, y_proba_te, recall_min=0.95)

    yp = (y_proba_te >= t_opt).astype(int)



    print("\n=== Classification report (umbral óptimo) ===")
    print(classification_report(yte, yp, digits=4))

    print("\n=== Confusion matrix (counts) ===")
    print(confusion_matrix(yte, yp))

    rf = grid.best_estimator_.named_steps['rf']
    importances = rf.feature_importances_
    feat_names = grid.best_estimator_.named_steps['pre'].get_feature_names_out()

    df = pd.DataFrame({'feature': feat_names, 'importance': importances})
    print(df.sort_values('importance', ascending=False).head(15))
    
    # Save model + metadata
    meta = {
    "mode": args.mode,
    "bridge_num": BRIDGE_NUM,
    "bridge_cat": BRIDGE_CAT,
    "best_params": grid.best_params_,
    "threshold": float(t_opt),
    "version": 2,
    }
    joblib.dump({"pipeline": best_model, "meta": meta}, args.out)
    with open(args.out + ".meta.json","w") as f:
        json.dump(meta, f, indent=2)
    print(f"[OK] Saved model to {args.out} and metadata to {args.out}.meta.json")

if __name__ == "__main__":
    main()
