cowrie-honeypot-project/
├── attacker_vm/                    # Files used on the attacker VM
│   ├── README.md                  # Instructions for attacker VM setup
│   ├── nmap_scan.sh               # Example scanning script
│   ├── hydra_bruteforce.sh        # Example Hydra brute‑force script
│   └── wordlists/                 # Optional custom wordlists
│
├── victim_vm/                     # Files used on the victim (honeypot) VM
│   ├── README.md                  # Instructions for victim VM setup
│   ├── docker-compose.yml         # Cowrie deployment (port 2222)
│   ├── cowrie.cfg                 # Cowrie configuration (JSON logging enabled)
│   ├── iptables_rules.sh          # iptables commands used to redirect ports, if any
│   └── scripts/
│       ├── check_env.sh           # Diagnostic script to verify the honeypot status
│       └── start_honeypot.sh      # Helper script to run Cowrie container
│
├── zerotier/                      # ZeroTier setup scripts (optional)
│   ├── join_network.sh            # Commands to join a ZeroTier network
│   └── network_info.md            # Notes about network IDs and authorisation
│
├── elastic_kibana/                # (Optional) Log analysis with ELK stack
│   ├── elastic_install.md         # Commands to install Elasticsearch, Logstash, Kibana, Filebeat
│   ├── logstash-cowrie.conf       # Example Logstash pipeline for Cowrie JSON logs
│   └── kibana_usage.md            # How to create an index pattern and view Cowrie data
│
├── docs/                          # Project documentation
│   ├── report.md                  # Detailed report (the file you generated earlier)
│   └── demo_placeholder.md        # Section where you can embed screenshots or recordings of your demo
│
├── .gitignore                     # Ignore logs, large files, secrets
└── README.md                      # Top‑level overview and instructions
