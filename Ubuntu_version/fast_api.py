from fastapi import FastAPI
from fastapi.responses import JSONResponse
import pandas as pd
from pathlib import Path
import math

app = FastAPI()
CSV_PATH = Path("/home/danger/Desktop/network_project/predictions.csv")

@app.get("/latest")
def latest(limit: int = 50):
    if not CSV_PATH.exists():
        return JSONResponse({"flows": []})

    df = pd.read_csv(
        CSV_PATH,
        header=None,
        names=["timestamp","src_ip","dst_ip","decision","binary_score","attack_label","app_label"]
    )

    df = df.tail(limit)

    # Ensure no bad floats
    flows = []
    for row in df.to_dict(orient="records"):
        clean_row = {}
        for k, v in row.items():
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                clean_row[k] = None
            else:
                clean_row[k] = v
        flows.append(clean_row)

    return {"flows": flows}

