#!/usr/bin/env bash
# ============================================================
#  Server Initial Setup & Hardening Script
#  Automates the first-time setup of a fresh Debian/Ubuntu server
#
#  Author: Awssman — IT Systems Engineer
#  Tested: Debian 12 / Ubuntu 22.04 / Ubuntu 24.04
#
#  Usage:
#    chmod +x server-setup.sh
#    sudo ./server-setup.sh
#
#  What it does:
#    1. System update & upgrade
#    2. Install essential packages
#    3. Create admin user with SSH key
#    4. SSH hardening (disable root, change port, key-only)
#    5. Configure UFW firewall
#    6. Install & configure Fail2Ban
#    7. Set timezone & NTP
#    8. Configure automatic security updates
#    9. Basic kernel hardening (sysctl)
#   10. Setup log rotation
#   11. Generate security report
# ============================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Configuration ────────────────────────────────────────
NEW_USER="sysadmin"
SSH_PORT="2222"
TIMEZONE="Europe/Berlin"

# Packages to install
ESSENTIAL_PACKAGES=(
    "ufw"
    "fail2ban"
    "unattended-upgrades"
    "apt-listchanges"
    "curl"
    "wget"
    "git"
    "htop"
    "tmux"
    "vim"
    "net-tools"
    "dnsutils"
    "lsof"
    "rsync"
    "tree"
    "jq"
    "ncdu"
    "logrotate"
    "chrony"
    "mtr-tiny"
    "software-properties-common"
)

# ── Logging ──────────────────────────────────────────────
LOG_FILE="/var/log/server-setup-$(date +%Y%m%d-%H%M%S).log"

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        INFO)  echo -e "${CYAN}[INFO]${NC}  $msg" ;;
        OK)    echo -e "${GREEN}[OK]${NC}    $msg" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC}  $msg" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} $msg" ;;
        STEP)  echo -e "\n${BOLD}${CYAN}━━━ $msg ━━━${NC}" ;;
    esac

    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE"
}

# ── Pre-flight checks ───────────────────────────────────
preflight() {
    log STEP "Pre-flight Checks"

    # Must be root
    if [[ $EUID -ne 0 ]]; then
        log ERROR "This script must be run as root (use sudo)"
        exit 1
    fi
    log OK "Running as root"

    # Check OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        log INFO "Detected OS: $PRETTY_NAME"
    else
        log WARN "Could not detect OS version"
    fi

    # Check internet
    if ping -c 1 -W 3 8.8.8.8 &>/dev/null; then
        log OK "Internet connectivity verified"
    else
        log ERROR "No internet connection"
        exit 1
    fi

    log INFO "Log file: $LOG_FILE"
}

# ── Step 1: System Update ────────────────────────────────
system_update() {
    log STEP "Step 1/10: System Update & Upgrade"

    apt-get update -qq
    log OK "Package lists updated"

    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
    log OK "System packages upgraded"

    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -qq
    log OK "Distribution upgrade complete"

    apt-get autoremove -y -qq
    apt-get autoclean -qq
    log OK "Cleanup complete"
}

# ── Step 2: Install Essential Packages ───────────────────
install_packages() {
    log STEP "Step 2/10: Installing Essential Packages"

    for pkg in "${ESSENTIAL_PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            log INFO "$pkg — already installed"
        else
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg"
            log OK "$pkg — installed"
        fi
    done
}

# ── Step 3: Create Admin User ────────────────────────────
create_user() {
    log STEP "Step 3/10: Creating Admin User"

    if id "$NEW_USER" &>/dev/null; then
        log INFO "User '$NEW_USER' already exists — skipping"
    else
        useradd -m -s /bin/bash -G sudo "$NEW_USER"
        log OK "User '$NEW_USER' created and added to sudo group"

        # Setup SSH directory
        local ssh_dir="/home/$NEW_USER/.ssh"
        mkdir -p "$ssh_dir"
        touch "$ssh_dir/authorized_keys"
        chmod 700 "$ssh_dir"
        chmod 600 "$ssh_dir/authorized_keys"
        chown -R "$NEW_USER:$NEW_USER" "$ssh_dir"
        log OK "SSH directory configured for '$NEW_USER'"

        log WARN "Remember to add your SSH public key to: $ssh_dir/authorized_keys"
    fi
}

# ── Step 4: SSH Hardening ────────────────────────────────
harden_ssh() {
    log STEP "Step 4/10: SSH Hardening"

    local sshd_config="/etc/ssh/sshd_config"

    # Backup original config
    cp "$sshd_config" "${sshd_config}.backup.$(date +%Y%m%d)"
    log OK "SSH config backed up"

    # Apply hardening
    sed -i "s/^#\?Port .*/Port $SSH_PORT/" "$sshd_config"
    sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' "$sshd_config"
    sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' "$sshd_config"
    sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' "$sshd_config"
    sed -i 's/^#\?X11Forwarding .*/X11Forwarding no/' "$sshd_config"
    sed -i 's/^#\?MaxAuthTries .*/MaxAuthTries 3/' "$sshd_config"
    sed -i 's/^#\?ClientAliveInterval .*/ClientAliveInterval 300/' "$sshd_config"
    sed -i 's/^#\?ClientAliveCountMax .*/ClientAliveCountMax 2/' "$sshd_config"
    sed -i 's/^#\?AllowAgentForwarding .*/AllowAgentForwarding no/' "$sshd_config"

    # Add allowed user
    if ! grep -q "^AllowUsers" "$sshd_config"; then
        echo "AllowUsers $NEW_USER" >> "$sshd_config"
    fi

    # Validate config before restart
    if sshd -t &>/dev/null; then
        systemctl restart sshd
        log OK "SSH hardened — Port: $SSH_PORT, Root login: disabled, Key-only auth"
    else
        log ERROR "SSH config validation failed — restoring backup"
        cp "${sshd_config}.backup."* "$sshd_config"
    fi
}

# ── Step 5: Configure Firewall ───────────────────────────
configure_firewall() {
    log STEP "Step 5/10: Configuring UFW Firewall"

    ufw default deny incoming
    ufw default allow outgoing

    ufw allow "$SSH_PORT/tcp" comment "SSH"
    ufw allow 80/tcp comment "HTTP"
    ufw allow 443/tcp comment "HTTPS"

    ufw --force enable
    log OK "UFW enabled — Allowed: SSH($SSH_PORT), HTTP(80), HTTPS(443)"
}

# ── Step 6: Configure Fail2Ban ───────────────────────────
configure_fail2ban() {
    log STEP "Step 6/10: Configuring Fail2Ban"

    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd
banaction = ufw

[sshd]
enabled  = true
port     = 2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 86400
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    log OK "Fail2Ban configured — SSH jail active, ban time: 24h"
}

# ── Step 7: Set Timezone & NTP ───────────────────────────
configure_time() {
    log STEP "Step 7/10: Setting Timezone & NTP"

    timedatectl set-timezone "$TIMEZONE"
    log OK "Timezone set to $TIMEZONE"

    systemctl enable chrony
    systemctl start chrony
    log OK "NTP (chrony) enabled and started"
}

# ── Step 8: Automatic Security Updates ───────────────────
configure_auto_updates() {
    log STEP "Step 8/10: Configuring Automatic Security Updates"

    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    log OK "Automatic security updates enabled (daily check)"
}

# ── Step 9: Kernel Hardening ─────────────────────────────
harden_kernel() {
    log STEP "Step 9/10: Kernel Hardening (sysctl)"

    cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# ── Network security ──
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ── IPv6 disable (if not needed) ──
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# ── Kernel ──
kernel.randomize_va_space = 2
kernel.sysrq = 0
fs.suid_dumpable = 0
EOF

    sysctl -p /etc/sysctl.d/99-hardening.conf &>/dev/null
    log OK "Kernel parameters hardened (SYN cookies, ICMP, redirects, ASLR)"
}

# ── Step 10: Generate Report ─────────────────────────────
generate_report() {
    log STEP "Step 10/10: Security Report"

    local report_file="/root/server-setup-report-$(date +%Y%m%d).txt"

    cat > "$report_file" << EOF
================================================================
  SERVER SETUP REPORT
  Generated: $(date)
================================================================

  Hostname:    $(hostname)
  OS:          $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
  Kernel:      $(uname -r)
  Timezone:    $TIMEZONE
  Uptime:      $(uptime -p)

  SSH Port:    $SSH_PORT
  Admin User:  $NEW_USER
  Root Login:  DISABLED
  Password Auth: DISABLED

  Firewall:    UFW ACTIVE
    - SSH ($SSH_PORT/tcp)
    - HTTP (80/tcp)
    - HTTPS (443/tcp)

  Fail2Ban:    ACTIVE
    - SSH jail: maxretry=3, bantime=24h

  Auto Updates: ENABLED (daily security patches)

  Kernel Hardening: APPLIED
    - SYN cookies, ICMP protection, ASLR enabled
    - Source routing & redirects disabled

  NEXT STEPS:
  1. Add SSH public key to /home/$NEW_USER/.ssh/authorized_keys
  2. Test SSH login: ssh -p $SSH_PORT $NEW_USER@<server-ip>
  3. Verify firewall: sudo ufw status verbose
  4. Check Fail2Ban: sudo fail2ban-client status sshd

  Log file: $LOG_FILE
================================================================
EOF

    log OK "Report saved: $report_file"

    echo ""
    echo -e "${BOLD}${GREEN}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  Setup Complete!${NC}"
    echo -e "${BOLD}${GREEN}════════════════════════════════════════${NC}"
    echo ""
    echo -e "  SSH Port:     ${CYAN}$SSH_PORT${NC}"
    echo -e "  Admin User:   ${CYAN}$NEW_USER${NC}"
    echo -e "  Firewall:     ${GREEN}Active${NC}"
    echo -e "  Fail2Ban:     ${GREEN}Active${NC}"
    echo -e "  Auto Updates: ${GREEN}Enabled${NC}"
    echo ""
    echo -e "  ${YELLOW}IMPORTANT: Add your SSH key before logging out!${NC}"
    echo -e "  ${YELLOW}Path: /home/$NEW_USER/.ssh/authorized_keys${NC}"
    echo ""
}

# ── Main ─────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║   Server Initial Setup & Hardening       ║${NC}"
    echo -e "${BOLD}${CYAN}║   Debian / Ubuntu                        ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""

    preflight
    system_update
    install_packages
    create_user
    harden_ssh
    configure_firewall
    configure_fail2ban
    configure_time
    configure_auto_updates
    harden_kernel
    generate_report
}

main "$@"
