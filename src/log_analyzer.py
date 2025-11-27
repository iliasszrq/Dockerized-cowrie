import streamlit as st
import pandas as pd
import re
import plotly.express as px
import subprocess

# --- Page Config ---
st.set_page_config(page_title="Cowrie SIEM", layout="wide")
st.title(" Cowrie Honeypot: Custom SIEM Dashboard")

# Cache data for 10 seconds (Simple cache reset)
@st.cache_data(ttl=10)
def parse_cowrie_log_from_docker():
    data = []
    
    # Regex patterns
    auth_pattern = re.compile(r"b'(.+?)' failed auth b'(.+?)'")
    legacy_pattern = re.compile(r"login attempt \[(.*)/(.*)\]")
    cmd_pattern = re.compile(r"CMD: (.*)")
    new_conn_ip_pattern = re.compile(r"New connection: ([\d\.]+):") 
    transport_ip_pattern = re.compile(r"HoneyPotSSHTransport,\d+,([\d\.]+)") 

    try:
        # Read logs from Docker
        result = subprocess.run(
            ['docker', 'logs', 'cowrie', '--since', '24h'], # Read last 24h of logs
            capture_output=True,
            text=True,
            check=True
        )
        
        logs = result.stdout + result.stderr 
        
        for line in logs.split('\n'):
            if not line.strip():
                continue
                
            timestamp = line[:23] if len(line) >= 23 else ""
            
            # 1. IP Capture (Priority)
            conn_match = new_conn_ip_pattern.search(line)
            if conn_match:
                data.append({
                    "timestamp": timestamp, 
                    "type": "New Connection", 
                    "user": None, 
                    "password": None, 
                    "src_ip": conn_match.group(1), 
                    "command": None
                })
                continue

            transport_match = transport_ip_pattern.search(line)
            if transport_match:
                data.append({
                    "timestamp": timestamp, 
                    "type": "Transport IP", 
                    "user": None, 
                    "password": None, 
                    "src_ip": transport_match.group(1), 
                    "command": None
                })
                # Don't continue here, sometimes transport lines have other info

            # 2. Login Attempts
            match_auth = auth_pattern.search(line)
            match_legacy = legacy_pattern.search(line)
            
            if match_auth:
                data.append({
                    "timestamp": timestamp, 
                    "type": "Login Attempt", 
                    "user": match_auth.group(1), 
                    "password": match_auth.group(2), 
                    "src_ip": None, 
                    "command": None
                })
                continue
            elif match_legacy:
                data.append({
                    "timestamp": timestamp, 
                    "type": "Login Attempt", 
                    "user": match_legacy.group(1), 
                    "password": match_legacy.group(2), 
                    "src_ip": None, 
                    "command": None
                })
                continue

            # 3. Commands
            cmd_match = cmd_pattern.search(line)
            if cmd_match:
                data.append({
                    "timestamp": timestamp, 
                    "type": "Command Execution", 
                    "user": None, 
                    "password": None, 
                    "src_ip": None, 
                    "command": cmd_match.group(1)
                })
                continue

        df = pd.DataFrame(data)
        
        # --- Data Cleaning ---
        if not df.empty:
            # Fix timestamps
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True).dt.tz_localize(None)
            
            # Clean byte strings
            for col in ['user', 'password']:
                if col in df.columns:
                    df[col] = df[col].astype(str).str.replace("b'", "").str.replace("'", "").replace("None", None)
            
            # Fill IP addresses forward
            if 'src_ip' in df.columns:
                df['src_ip'] = df['src_ip'].fillna(method='ffill') 

        return df

    except subprocess.CalledProcessError as e:
        st.error(f"Error reading Docker logs: {e}")
        return pd.DataFrame()
    except FileNotFoundError:
        st.error("Docker command not found. Make sure Docker is installed and you have permission to use it.")
        return pd.DataFrame()

# --- Load Data ---
df = parse_cowrie_log_from_docker() 

if not df.empty:
    # Sidebar
    st.sidebar.header("Controls & Filters")
    
    if st.sidebar.button(" Refresh Logs"):
        st.cache_data.clear()
        st.rerun()

    event_types = df['type'].unique()
    selected_types = st.sidebar.multiselect("Event Types", event_types, default=event_types)
    filtered_df = df[df['type'].isin(selected_types)]

    # Metrics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events", len(filtered_df))
    c2.metric("Unique Attackers", df['src_ip'].nunique())
    c3.metric("Login Attempts", len(df[df['type'] == "Login Attempt"]))
    c4.metric("Commands Captured", len(df[df['type'] == "Command Execution"]))

    st.divider()

    # Timeline
    st.subheader(" Attack Volume Over Time")
    if 'timestamp' in filtered_df.columns:
        timeline = filtered_df.set_index('timestamp').resample('H').size().reset_index(name='Count')
        fig_time = px.line(timeline, x='timestamp', y='Count', title="Hourly Activity", markers=True)
        st.plotly_chart(fig_time, use_container_width=True)

    # Charts
    c1, c2 = st.columns(2)
    with c1:
        st.subheader(" Top Attacker IPs")
        ip_counts = df['src_ip'].value_counts().head(10)
        if not ip_counts.empty: 
             fig_ip = px.bar(ip_counts, x=ip_counts.index, y=ip_counts.values,
                            labels={'x': 'Source IP', 'y': 'Total Events'})
             st.plotly_chart(fig_ip, use_container_width=True)
        else: st.info("No IP data.")

    with c2:
        st.subheader("Top Passwords")
        pass_counts = df[df['type'] == "Login Attempt"]['password'].value_counts().head(10)
        if not pass_counts.empty: st.bar_chart(pass_counts)
        else: st.info("No passwords.")

    st.divider()

    # Tables
    c3, c4 = st.columns([1, 2])
    with c3:
        st.subheader(" Top Usernames")
        user_counts = df[df['type'] == "Login Attempt"]['user'].value_counts().head(10)
        if not user_counts.empty: st.dataframe(user_counts, use_container_width=True)
        else: st.info("No usernames.")

    with c4:
        st.subheader(" Forensic Timeline (Commands)")
        commands = df[df['type'] == "Command Execution"][['timestamp', 'command']].sort_values(by='timestamp', ascending=False)
        if not commands.empty: st.dataframe(commands, use_container_width=True, hide_index=True)
        else: st.success("No commands executed.")

else:
    st.warning("Log file is empty or missing.")
