import json
import joblib
import numpy as np
import requests
from sklearn.preprocessing import RobustScaler 

# === Step 1: Load files ===
with open("one_conn.jsonl") as f:
    zeek_flow = json.loads(f.readline().strip())

with open("expected_features.json") as f:
    expected_features = json.load(f)  # must be ordered list of 77 feature names

# scaler = joblib.load("scaler_pipeline.joblib")

scaler = RobustScaler()

# === Step 2: Map Zeek flow into features ===
def build_feature_vector(flow, expected_features):
    feature_vector = []

    for feat in expected_features:
        value = None

        # Map Zeek fields → your features
        if feat == "destinationport":
            value = int(flow.get("id.resp_p", 0))
        elif feat == "flowduration":
            # Zeek duration is in seconds, convert to ms
            value = float(flow.get("duration", 0.0)) * 1000
        elif feat == "totalfwdpackets":
            value = int(flow.get("orig_pkts", 0))
        elif feat == "totalbackwardpackets":
            value = int(flow.get("resp_pkts", 0))
        elif feat == "totallengthoffwdpackets":
            value = int(flow.get("orig_ip_bytes", 0))
        elif feat == "totallengthofbwdpackets":
            value = int(flow.get("resp_ip_bytes", 0))
        elif feat == "l7protocol":
            # Zeek logs don't have direct l7 info → set to 0 for now
            value = 0
        else:
            # TODO: implement more mappings (flowiat*, flags, etc.)
            value = 0

        feature_vector.append(value)

    return feature_vector


# === Step 3: Build + scale vector ===
raw_vector = build_feature_vector(zeek_flow, expected_features)
scaled_vector = scaler.fit_transform([raw_vector])  # [[...77 values...]]
scaled_vector = np.expand_dims(scaled_vector, axis=-1)


# === Step 4: Send to TensorFlow Serving ===
url = "http://192.168.0.104:8501/v1/models/binary_classifier:predict"
payload = {"instances": scaled_vector.tolist()}

response = requests.post(url, json=payload)
print("Response:", response.json())

