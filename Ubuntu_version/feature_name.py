import joblib, json
scaler = joblib.load("./scaler_pipeline.joblib")     
# Try to read feature names from the pipeline
names = getattr(scaler, "feature_names_in_", None)
if names is None:
    # If your scaler is inside a Pipeline:
    # names = [...]
    raise SystemExit("Put your ordered 77 feature names list here and re-run.")
print("Feature count:", len(names))
open("expected_features.json","w").write(json.dumps(list(names), indent=2))
print("Wrote expected_features.json")

