import json, csv, datetime, time, os, requests
import numpy as np
from sklearn.preprocessing import RobustScaler
from feature_fill import fill_missing
import tensorflow as tf

# === TF-Serving endpoints ===
TF_BASE    = "http://192.168.0.104:8501/v1/models"
BIN_URL    = f"{TF_BASE}/binary_classifier:predict"
ATTACK_URL = f"{TF_BASE}/attack_classifier:predict"
APP_URL    = f"{TF_BASE}/app_classifier:predict"

# === Load expected feature order ===
with open("expected_features.json") as f:
    expected_features = json.load(f)     # 77-feature order

# === Load TSMixer imputer model (local, not TF-Serving) ===
imputer_model = tf.keras.models.load_model("./imputer/imputer_nn.keras")

# === Scalers ===
scaler77 = RobustScaler()
scaler78 = RobustScaler()

# === Policy thresholds & logfile ===
TH_BIN  = 0.8
TH_ATK  = 0.7
LOGFILE = "predictions.csv"


# -------------------------------------------------
# 1. Build + Impute Feature Vector
# -------------------------------------------------
def build_vector77(flow, expected_features):
    """
    Step 1: Zeek-native Group A + NaN for Group C.
    Step 2: Impute missing (Group C) using TSMixer model.
    Step 3: Return ordered 77-dim vector.
    """
    base = {
        "destinationport": int(flow.get("id.resp_p", 0)),
        "flowduration": float(flow.get("duration", 0.0)),
        "totalfwdpackets": int(flow.get("orig_pkts", 0)),
        "totalbackwardpackets": int(flow.get("resp_pkts", 0)),
        "totallengthoffwdpackets": int(flow.get("orig_ip_bytes", 0)),
        "totallengthofbwdpackets": int(flow.get("resp_ip_bytes", 0)),
    }

    # Fill Group A + NaNs for Group B
    synth = fill_missing(flow)
    merged = {**base, **synth}

    # Order features consistently
    raw_vec = np.array([merged.get(f, np.nan) for f in expected_features], dtype=float)

    # === Imputation ===
    # Reshape: (1, 77, 1) → TSMixer 3D input
    inp = np.expand_dims(np.expand_dims(raw_vec, axis=0), axis=-1)
    imputed = imputer_model.predict(inp, verbose=0)
    imputed_vec = imputed[0, :, 0]  # back to (77,)

    return imputed_vec.tolist()


def extract_l7(flow):
    """Convert Zeek's service/protocol string to numeric code if needed."""
    return 0  # placeholder


# -------------------------------------------------
# 2. Helper to POST to TF-Serving
# -------------------------------------------------
def post_tf(url, arr):
    payload = {"instances": arr.tolist()}
    try:
        r = requests.post(url, json=payload, timeout=3)
        js = r.json()
        if "predictions" not in js:
            print("Missing predictions field:", r.text)
            return {}
        return js
    except Exception as e:
        print(f"TF-Serving error: {e}")
        return {}


# -------------------------------------------------
# 3. CSV logging
# -------------------------------------------------
def log_result(flow, result):
    with open(LOGFILE, "a", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            datetime.datetime.now().isoformat(),
            flow.get("id.orig_h"), flow.get("id.resp_h"),
            result.get("decision"),
            result.get("binary_score"),
            result.get("attack_label", ""),
            result.get("app_label", "")
        ])


# -------------------------------------------------
# 4. Classification pipeline
# -------------------------------------------------
def classify(flow):
    # --- Step A: Build + impute + scale 77 feats ---
    raw77 = build_vector77(flow, expected_features)
    scaled77 = scaler77.fit_transform([raw77])
    scaled77 = np.expand_dims(scaled77, axis=-1)  

    # --- Binary classification ---
    resp = post_tf(BIN_URL, scaled77)
    prob = resp.get("predictions", [[0]])[0][0]
    label = "attack" if prob > 0.5 else "normal"

    if label == "attack":
        atk = post_tf(ATTACK_URL, scaled77)
        return {
            "binary_score": prob,
            "attack_label": atk.get("predictions", [["?"]])[0],
            "decision": "ATTACK"
        }

    # --- Normal → build 78 feats (add L7 protocol) ---
    raw78 = raw77 + [extract_l7(flow)]
    scaled78 = scaler78.fit_transform([raw78])
    scaled78 = np.expand_dims(scaled78, axis=-1)

    app = post_tf(APP_URL, scaled78)
    return {
        "binary_score": prob,
        "app_label": app.get("predictions", [["?"]])[0],
        "decision": "NORMAL"
    }


# -------------------------------------------------
# 5. Optional: Ryu block stub
# -------------------------------------------------
def push_block(src_ip, dst_ip, duration=60):
    """Call Ryu REST to drop traffic."""
    data = {
        "dpid": 1,
        "priority": 100,
        "match": {"ipv4_src": src_ip, "ipv4_dst": dst_ip, "eth_type": 2048},
        "actions": []
    }
    try:
        r = requests.post("http://127.0.0.1:8080/stats/flowentry/add", json=data)
        print("→ SDN rule installed:", r.status_code)
    except Exception as e:
        print("SDN push failed:", e)


# -------------------------------------------------
# 6. Tail conn.log + classify
# -------------------------------------------------
def follow_connlog(logfile):
    last_size = 0
    while True:
        try:
            size = os.path.getsize(logfile)
            if size > last_size:
                with open(logfile, "r") as f:
                    f.seek(last_size)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            flow   = json.loads(line)
                            result = classify(flow)
                            log_result(flow, result)

                            src, dst = flow.get("id.orig_h"), flow.get("id.resp_h")
                            score    = result.get("binary_score", 0.0)

                            if result["decision"] == "ATTACK":
                                lbl = result.get("attack_label", "?")
                                print(f"[{src}->{dst}] ATTACK ({lbl}) score={score:.2f}")

                                if score >= TH_BIN:
                                    print(f"Would block flow {src}->{dst} (score {score:.2f})")
                                    # push_block(src, dst)
                            else:
                                lbl = result.get("app_label", "?")
                                print(f"[{src}->{dst}] NORMAL (App={lbl}) score={score:.2f}")

                        except Exception as e:
                            print("Parse/classify error:", e)
                last_size = size
            time.sleep(2)
        except KeyboardInterrupt:
            print("Stopped.")
            break


# -------------------------------------------------
# 7. Entrypoint
# -------------------------------------------------
if __name__ == "__main__":
    follow_connlog("conn.log")
