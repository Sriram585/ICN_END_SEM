import subprocess
import joblib
import streamlit as st
import pandas as pd
import time
import platform
import shutil

# ============================
# LOAD TRAINED MODEL
# ============================
model = joblib.load("model/ids_model_randomforest.pkl")

st.set_page_config(page_title="Live AI IDS", layout="wide")
st.title("Live AI Intrusion Detection System (UNSW-NB15)")

status_box = st.empty()
table = st.empty()
rows = []

# ============================
# TSHARK COMMAND
# Interface 5 = Wi-Fi (from tshark -D)
# ============================
# Detect OS
if platform.system() == "Windows":
    # Your local Windows path
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
else:
    # Linux (Streamlit Cloud) - assumes tshark is in the system path
    tshark_path = shutil.which("tshark") or "tshark"
tshark_cmd = [
    tshark_path,   # <--- This must be the variable, not the string "tshark"
    "-i", "5", 
    "-l",
    "-T", "fields",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "frame.len"
]
process = subprocess.Popen(
    tshark_cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

# ============================
# LIVE PACKET PROCESSING
# ============================
for line in process.stdout:
    try:
        parts = line.strip().split("\t")
        if len(parts) != 3:
            continue

        src_ip, dst_ip, length = parts
        length = int(length)

        # Approximate features (same as training)
        dur = 1
        sbytes = length
        dbytes = length
        spkts = 1
        dpkts = 1

        X = [[dur, sbytes, dbytes, spkts, dpkts]]

        # Probability-based detection (IMPORTANT)
        attack_prob = model.predict_proba(X)[0][1]

        if attack_prob > 0.5:
            label = "Attack"
            color = "red"
        else:
            label = "Normal"
            color = "green"

        status_box.markdown(
            f"### **Current Traffic Status:** "
            f"<span style='color:{color}'>{label}</span> "
            f"(Attack probability: {attack_prob:.2f})",
            unsafe_allow_html=True
        )

        rows.append({
            "Time": time.strftime("%H:%M:%S"),
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Length": length,
            "Attack Probability": round(attack_prob, 2),
            "Status": label
        })

        table.dataframe(pd.DataFrame(rows).tail(20))

    except:
        continue
