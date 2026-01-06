import requests
import time
import numpy as np

data = {
    "instances": [[[0.1],[0.2],[0.3]] + [[0.0]]*71]  
}

def time_model(url, name, runs=200):
    times = []
    # Warmup
    for _ in range(10):
        requests.post(url, json=data)
    # Timed runs
    for _ in range(runs):
        t0 = time.perf_counter()
        requests.post(url, json=data)
        times.append(time.perf_counter() - t0)
    times = np.array(times)
    print(f"{name}: mean={times.mean():.4f}s, median={np.median(times):.4f}s, p95={np.percentile(times,95):.4f}s")

time_model("http://localhost:8501/v1/models/binary_classifier:predict", "Binary")
time_model("http://localhost:8501/v1/models/attack_classifier:predict", "Malicious")

time_model("http://localhost:8501/v1/models/application_classifier:predict", "Application")
