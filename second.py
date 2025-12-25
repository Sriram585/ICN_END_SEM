import streamlit as st
import pandas as pd
import joblib
import subprocess
import shutil
import os
import time

# ============================
# 1. PAGE CONFIG & TITLE
# ============================
st.set_page_config(page_title="AI IDS Analysis", layout="wide")
st.title("🛡️ AI Intrusion Detection System (UNSW-NB15)")
st.markdown("""
**Note for Cloud Users:** Live packet capture is not permitted on Streamlit Cloud due to security restrictions. 
Please upload a captured network file (**`.pcap`**) to analyze traffic for attacks.
""")

# ============================
# 2. LOAD TRAINED MODEL
# ============================
# specific caching to prevents reloading model on every interaction
@st.cache_resource 
def load_model():
    try:
        return joblib.load("model/ids_model_randomforest.pkl")
    except FileNotFoundError:
        st.error("Model file not found! Please ensure 'ids_model_randomforest.pkl' is inside the 'model' folder.")
        return None

model = load_model()

# ============================
# 3. FILE UPLOADER LOGIC
# ============================
uploaded_file = st.file_uploader("Upload Network Traffic (.pcap)", type=["pcap", "pcapng"])

# UI Elements for results
status_box = st.empty()
table_placeholder = st.empty()
rows = []

if uploaded_file is not None and model is not None:
    # Save uploaded file to a temporary file so Tshark can read it
    temp_filename = "temp_capture.pcap"
    with open(temp_filename, "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.success(f"File '{uploaded_file.name}' uploaded! Analyzing traffic...")

    # ============================
    # 4. TSHARK COMMAND SETUP
    # ============================
    # Locate Tshark automatically (works on Windows & Linux)
    tshark_path = shutil.which("tshark")
    
    # Fallback for local Windows if not in PATH
    if tshark_path is None and os.name == 'nt':
        possible_path = r"C:\Program Files\Wireshark\tshark.exe"
        if os.path.exists(possible_path):
            tshark_path = possible_path

    if tshark_path is None:
        st.error("Tshark not found! If on Cloud, ensure 'packages.txt' contains 'tshark'.")
        st.stop()

    # Command to read the FILE (-r) instead of live interface (-i)
    tshark_cmd = [
        tshark_path,
        "-r", temp_filename,     # Read the saved file
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len"
    ]

    # ============================
    # 5. EXECUTE ANALYSIS
    # ============================
    try:
        process = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        # Process the output line by line to simulate "streaming" analysis
        progress_bar = st.progress(0)
        
        for i, line in enumerate(process.stdout):
            try:
                parts = line.strip().split("\t")
                
                # Skip incomplete lines
                if len(parts) < 3:
                    continue

                src_ip = parts[0]
                dst_ip = parts[1]
                length = int(parts[2])

                # --- FEATURE ENGINEERING (Must match training logic) ---
                # These are approximations since we are using raw packet data
                dur = 0.1      # Dummy duration
                sbytes = length
                dbytes = length
                spkts = 1
                dpkts = 1
                
                # Create input vector for model
                X = [[dur, sbytes, dbytes, spkts, dpkts]]

                # --- PREDICTION ---
                # Get probability of attack (class 1)
                attack_prob = model.predict_proba(X)[0][1]

                if attack_prob > 0.7:
                    label = "Attack"
                    color = "red"
                    icon = "⚠️"
                else:
                    label = "Normal"
                    color = "green"
                    icon = "✅"

                # Update Status Box
                status_box.markdown(
                    f"### Status: {icon} <span style='color:{color}'>{label}</span> "
                    f"(Prob: {attack_prob:.2f})",
                    unsafe_allow_html=True
                )

                # Add to data table
                rows.append({
                    "Source IP": src_ip,
                    "Dst IP": dst_ip,
                    "Length": length,
                    "Prob": f"{attack_prob:.2f}",
                    "Status": label
                })

                # Refresh table every 10 packets to improve performance
                if i % 10 == 0:
                    df = pd.DataFrame(rows)
                    table_placeholder.dataframe(df.tail(15), use_container_width=True)
                    # Small sleep to visualize the "Live" feel (optional)
                    time.sleep(0.01) 

            except ValueError:
                continue

        # Final update
        if rows:
            table_placeholder.dataframe(pd.DataFrame(rows), use_container_width=True)
            st.success("Analysis Complete!")
        else:
            st.warning("No IPv4 packets found in this capture file.")

    except Exception as e:
        st.error(f"An error occurred during execution: {e}")
