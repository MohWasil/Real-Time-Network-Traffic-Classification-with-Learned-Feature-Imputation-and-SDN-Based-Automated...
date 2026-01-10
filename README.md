# Real-Time Network Traffic Classification with Learned Feature Imputation and SDN-Based Automated Response.

This repository provides the complete implementation of a **real-time network traffic classification framework** with learned **feature imputation and SDN-based automated response**. The system is designed to bridge the gap between production network monitoring tools and flow-based machine learning models that rely on richer feature representations.

The framework integrates **Zeek** for live network flow monitoring, a **neural feature imputation module** to approximate and reconstruct the full **CICFlowMeter 77-feature schema**, TensorFlow Serving for low-latency traffic classification, and the Ryu SDN controller for real-time policy enforcement in OpenFlow-enabled networks. A Gradio-based dashboard is included to support real-time visualization and operational monitoring of classification outcomes.

The implementation demonstrates how flow-based deep learning models trained on **CICIDS2017/2018, ToN-IoT, and 75 app application traffic** datasets can be deployed in a hybrid Windows–Ubuntu testbed. The system enables dynamic traffic classification and confidence-aware security enforcement, providing a reproducible reference architecture for research and practical experimentation in **software-defined networking** and network security.


## System Architecture
![Diagram Description](https://github.com/user-attachments/assets/183be9e4-dafe-4a19-a78a-a73066436b37)

---

---

### 📂 Project Structure

```text
.
├── notebooks/ 
│   ├── binary_cnn_training.ipynb
│   ├── attack_cnn_training.ipynb
│   └── app_lstm_training.ipynb
├── main_Models/
│   ├── binary.keras
│   ├── attack_type.keras
│   └── app_type.keras
├── windows/ 
│   ├── tf_models/ 
│   │   ├── binary_classifier/1/
│   │   ├── attack_classifier/1/
│   │   └── app_classifier/1/
│   ├── dashboard.py               # Gradio real-time monitoring UI
│   └── models.config 
├── ubuntu/ 
│   ├── zeek_ids_orchestrator.py    # Pipeline (Zeek → Imputer → Scaler → TF-Serving)
│   ├── feature_fill.py            # Math-based feature approximation
│   ├── imputers.pkl 
│   ├── scaler_pipeline.joblib
│   ├── fast_api.py                # FastAPI server
│   ├── internet_topo.py 
│   ├── classified.csv
│   └── log_files/                 # Directory for logs
├── requirements.txt 
├── measure_models_latency.py
├── policy.md 
└── README.md


----

# 1. Ubuntu Backend Setup
     ┌────────────────────────── Ubuntu VM (Backend) ───────────────────────┐
     │                                                                      │
     │   Mininet → Zeek → Step3/Step4 ML → Predictions.csv → FastAPI        │
     │                                                                      │
     │   ● Mininet (virtual network)                                        │
     │   ● Zeek IDS capturing packets                                       │
     │   ● Python feature extractor (Step3)                                 │
     │   ● ML model inference (Step4)                                       │
     │   ● predictions.csv (append-only log)                                │
     │   ● FastAPI service exposes results to Windows                       │
     │                                                                      │
     └──────────────────────────────────────────────────────────────────────┘

### Install Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git mininet zeek
```

### Create environment:
```bash
python3 -m venv my_env
source my_env/bin/activate
pip install -r requirements.txt
```

### Mininet Topology (Simple 2 hosts → switch → controller)
```bash
sudo mn --topo single,2 --controller=remote,ip=127.0.0.1 --switch ovsk
```

### Start Zeek for Packet Capture

Zeek cannot monitor multiple -i interfaces; use a bridge or single interface such as the switch port:
``` bash
sudo zeek -i s1-eth1
```

Zeek logs appear in:
``` bash
/usr/local/zeek/logs/current/
```


### Step4 Machine Learning Inference Script

Your Step4 script:

loads trained model

processes features → predicts attack/benign

appends results to:
``` bash
predictions.csv
```
This file is used by both FastAPI and the Windows dashboard.
-----

### FastAPI Backend Service (Ubuntu)
``` bash
uvicorn service:app --host 0.0.0.0 --port 8000
```
----

# 2. Windows Host — Frontend & Model Serving

This directory contains all components running on the Windows host responsible for:

Serving the three deep-learning models using TensorFlow Serving (Docker)

Providing a real-time monitoring dashboard using Gradio

Receiving classification requests from the Ubuntu VM preprocessor

Returning predictions (label + probability) to the Ubuntu SDN controller

This part of the system completes the inference and monitoring stages of the real-time pipeline.

### 1. Components Overview
#### ✔ TensorFlow Serving (Docker)

Hosts the three exported models:

binary_classifier (CNN)

attack_classifier (CNN)

app_classifier (LSTM)

Each model uses the SavedModel directory structure:
```bash
model_name/
   └── 1/
       └── saved_model.pb
       └── variables/
```

#### ✔ Gradio Dashboard

A lightweight monitoring UI that:

* polls the Ubuntu FastAPI service (/latest)

* updates a real-time table of flows

* displays label, attack probability, and SDN action applied

### 2. Directory Structure
```bash
windows/
│
├── tf_models/
│   ├── binary_classifier/1/
│   ├── attack_classifier/1/
│   └── app_classifier/1/
│
├── models.config        
├── dashboard.py         
├── start_tf_serving.bat 

```

### 3. Requirements
**Prerequisites**
* Windows 10 Pro / 11 Pro
* Docker Desktop installed and running
* Python 3.10+
* Stable LAN connection to the Ubuntu VM

**Python dependencies**
Install Gradio and utilities:
```bash
pip install -r requirements.txt
```

This installs:

* gradio
* requests
* pandas
* uvicorn (optional for local testing)

### 4. Running TensorFlow Serving (Docker)

Docker launch command:
```bash
docker run -p 8501:8501 -p 8500:8500 ^
  -v %cd%/tf_models/binary_classifier:/models/binary ^
  -v %cd%/tf_models/attack_classifier:/models/attack ^
  -v %cd%/tf_models/app_classifier:/models/app ^
  -v %cd%/models.config:/models/models.config ^
  tensorflow/serving:latest ^
  --model_config_file=/models/models.config
```

### 5. After Launching TF-Serving

Verify that the models are running:

Open browser:
```bash
http://localhost:8501/v1/models/binary
http://localhost:8501/v1/models/attack
http://localhost:8501/v1/models/app
```

You should see:
```bash
{"model_version_status":[{"version":"1","state":"AVAILABLE"}]}
```

### 6. Running the Gradio Dashboard

Once TF-Serving and Ubuntu preprocessing are running:
```bash
python dashboard.py
```

The dashboard will:

* auto-refresh using /latest endpoint from Ubuntu FastAPI
* show table with:
- timestamps
- source/destination IP
- predicted class
- model probability
- SDN action (allowed / paused / dropped)

You can access the UI at:
```bash
http://127.0.0.1:7860/
```

### 7. Data Flow (Windows Perspective)
```bash
Ubuntu VM (Zeek + Preprocessing)
          ↓
REST Request
          ↓
TensorFlow Serving (Windows Docker)
          ↓
Prediction JSON (label + probability)
          ↓
Ubuntu SDN Controller (decision: allow / pause / drop)
          ↓
FastAPI (/latest)
          ↓
Gradio Dashboard (Windows)
```

### 8. Troubleshooting
❗ TF-Serving cannot find model

Check folder structure — must be:
```bash
model_name/1/saved_model.pb
```
❗ Ubuntu cannot reach TF-Serving

* Ensure Windows firewall allows port 8501
* Ensure both systems are on the same bridged network

❗ Dashboard not updating

* Check Ubuntu FastAPI is running
* Check the IP in dashboard.py is correct
