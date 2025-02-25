# wifi-pentst2.py
import streamlit as st
import subprocess
import os
from datetime import datetime

# Function to execute terminal commands
def run_command(command):
    result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = result.communicate()
    return output.decode(), error.decode()

# Function to save logs
def save_logs(tool_name, output):
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(logs_dir, f"{tool_name}_{timestamp}.log")
    with open(file_path, "w") as log_file:
        log_file.write(output)
    return file_path

# Streamlit App
st.title("Penetration Testing & Network Monitoring Dashboard")

# Sidebar for tool selection
tool = st.sidebar.selectbox("Select Tool", [
    "Nmap", "Metasploit Framework", "Hydra", "John the Ripper", "Burp Suite", "SQLMap",
    "Ettercap", "DirBuster", "Nikto", "Wireshark", "OWASP ZAP", "Snort", "Aircrack-ng"
])

# Tool Interfaces
if tool == "Nmap":
    st.header("Nmap Network Scanner")
    target = st.text_input("Enter Target IP or Hostname:")
    options = st.text_input("Enter Nmap Options (e.g., -sV -A):")
    if st.button("Run Nmap"):
        command = f"nmap {options} {target}"
        output, error = run_command(command)
        st.text_area("Output", output if output else error, height=300)
        log_file = save_logs("nmap", output if output else error)
        st.success(f"Log saved: {log_file}")
        st.download_button("Download Log", output if output else error)

elif tool == "Hydra":
    st.header("Hydra Brute Force")
    target = st.text_input("Target (IP or Hostname):")
    service = st.text_input("Service (e.g., ssh, ftp):")
    username = st.text_input("Username:")
    password_list = st.text_input("Path to Password List:")
    if st.button("Run Hydra"):
        command = f"hydra -l {username} -P {password_list} {target} {service}"
        output, error = run_command(command)
        st.text_area("Output", output if output else error, height=300)
        log_file = save_logs("hydra", output if output else error)
        st.success(f"Log saved: {log_file}")
        st.download_button("Download Log", output if output else error)

# Add similar sections for other tools following the same structure

# Monitoring Section
st.sidebar.header("Real-Time Monitoring")
if st.sidebar.button("Show Connected Devices (Nmap Ping Sweep)"):
    local_network = st.text_input("Enter your Local Network (e.g., 192.168.1.0/24):")
    if local_network:
        command = f"nmap -sn {local_network}"
        output, error = run_command(command)
        st.text_area("Connected Devices", output if output else error, height=300)
        log_file = save_logs("connected_devices", output if output else error)
        st.success(f"Log saved: {log_file}")
        st.download_button("Download Log", output if output else error)

# Real-time IDS Alerts from Snort
st.sidebar.header("Intrusion Detection (Snort)")
if st.sidebar.button("Run Snort (IDS)"):
    interface = st.text_input("Enter Interface for Snort (e.g., eth0):")
    if interface:
        command = f"snort -i {interface} -A console"
        output, error = run_command(command)
        st.text_area("Snort Alerts", output if output else error, height=300)
        log_file = save_logs("snort_alerts", output if output else error)
        st.success(f"Log saved: {log_file}")
        st.download_button("Download Log", output if output else error)

# Logs Directory
if st.sidebar.button("View All Logs"):
    logs_dir = "logs"
    if os.path.exists(logs_dir):
        logs = os.listdir(logs_dir)
        st.write("Logs:")
        for log in logs:
            log_path = os.path.join(logs_dir, log)
            with open(log_path, "r") as file:
                st.download_button(f"Download {log}", file.read())
                
