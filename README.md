# Real-Time Network Traffic Classification with Learned Feature Imputation and SDN-Based Automated Response.

This repository contains the full implementation of our **real-time machine learning–based intrusion detection and mitigation framework**.  
The system integrates **Zeek** for live flow monitoring, **feature approximation and neural network imputation** to complete the CICFlowMeter 77-feature schema, **TensorFlow Serving** for classification, and the **Ryu SDN controller** for real-time enforcement.  
A **Gradio-based dashboard** provides real-time monitoring of traffic classification outcomes.  

The work demonstrates how flow-based deep learning models, trained on CICIDS2017/2018, ToN-IoT, and application datasets, can be **deployed in a hybrid Windows–Ubuntu testbed** to classify network traffic and enforce security policies dynamically.

---

## 🔹 High-Level Architecture
### project-root

│

├── notebooks/ 

│ ├── binary_cnn_training.ipynb

│ ├── attack_cnn_training.ipynb

│ └── app_lstm_training.ipynb

|

├── main_Models

│ ├── binary.keras

│ ├── attack_type.keras

│ └── app_type.keras

|

├── windows/ 

│ ├── tf_models/ 

│ │ ├── binary_classifier/1/

│ │ ├── attack_classifier/1/

│ │ └── app_classifier/1/

│ │

│ ├── dashboard.py # Gradio real-time monitoring UI

│ ├── models.config 

│ ├── Dockerfile / scripts # Docker TF-Serving launch configs

│

├── ubuntu/ 

│ ├── preprocess.py # Main pipeline (Zeek → imputer → scaler → TF-Serving)

│ ├── feature_fill.py # Math-based feature approximation module

│ ├── imputers.pkl 

│ ├── scaler_pipeline.joblib

│ ├── service.py # FastAPI server exposing /latest endpoint

│ ├── ml_sdn_firewall.py 

│ ├── classified.csv 

│

├── requirements.txt 

├── measure_models_latency.py 

├── README.md 

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
