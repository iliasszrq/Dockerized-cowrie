import streamlit as st
import pandas as pd
import re
import plotly.express as px

st.set_page_config(page_title="Cowrie Log Forensics", layout="wide")
st.title("🕵️ Cowrie Honeypot: Raw Log Analysis")

@st.cache_data
def parse_cowrie_log(file_path):
    data = []
    
    # REGEX PATTERNS
    # 1. Catch: b'root' failed auth b'password'
    auth_pattern = re.compile(r"b'(.+?)' failed auth b'(.+?)'")
    
    # 2. Catch: login attempt [root/password] (Older cowrie versions)
    legacy_pattern = re.compile(r"login attempt \[(.*)/(.*)\]")
    
    # 3. Catch: CMD: ls -la
    cmd_pattern = re.compile(r"CMD: (.*)")
    
    # 4. Catch IPs from: [HoneyPotSSHTransport,12,192.168.1.5]
    ip_pattern = re.compile(r"HoneyPotSSHTransport,\d+,([\d\.]+)")

    try:
        with open(file_path, 'r') as f:
            for line in f:
                # Extract timestamp (First 23 chars)
                timestamp = line[:23]
                
                # CHECK FOR PASSWORDS
                match_auth = auth_pattern.search(line)
                match_legacy = legacy_pattern.search(line)
                
                if match_auth:
                    data.append({
                        "timestamp": timestamp,
                        "type": "Login Attempt",
                        "user": match_auth.group(1),
                        "password": match_auth.group(2),
                        "command": None
                    })
                    continue
                elif match_legacy:
                    data.append({
                        "timestamp": timestamp, 
                        "type": "Login Attempt", 
                        "user": match_legacy.group(1), 
                        "password": match_legacy.group(2), 
                        "command": None
                    })
                    continue

                # CHECK FOR COMMANDS
                cmd_match = cmd_pattern.search(line)
                if cmd_match:
                    data.append({
                        "timestamp": timestamp,
                        "type": "Command Execution",
                        "user": None,
                        "password": None,
                        "command": cmd_match.group(1)
                    })
                    continue

                # CHECK FOR CONNECTIONS (To get IPs)
                ip_match = ip_pattern.search(line)
                if ip_match:
                     data.append({
                        "timestamp": timestamp,
                        "type": "New Connection",
                        "user": None, 
                        "password": None, 
                        "command": None,
                        "src_ip": ip_match.group(1)
                    })

        df = pd.DataFrame(data)
        return df

    except FileNotFoundError:
        st.error(f"Could not find file: {file_path}")
        return pd.DataFrame()

# LOAD DATA
# Ensure this points to where your log file actually is
df = parse_cowrie_log("logs/cowrie.log") 

if not df.empty:
    # KPI METRICS
    st.success(f"Loaded {len(df)} events.")
    
    logins = df[df['type'] == "Login Attempt"]
    cmds = df[df['type'] == "Command Execution"]
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Events", len(df))
    col2.metric("Brute Force Attempts", len(logins))
    col3.metric("Commands Executed", len(cmds))

    st.divider()

    # CHARTS
    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("Top Attacked Usernames")
        if not logins.empty:
            st.bar_chart(logins['user'].value_counts().head(10))
        else:
            st.info("No logins captured yet.")

    with c2:
        st.subheader("Top Passwords Tried")
        if not logins.empty:
            st.bar_chart(logins['password'].value_counts().head(10))
            
    # COMMANDS TABLE
    st.divider()
    st.subheader("🚨 Attacker Commands")
    if not cmds.empty:
        st.table(cmds[['timestamp', 'command']])
    else:
        st.info("No shell commands executed.")

else:
    st.warning("Log file is empty or not found.")
