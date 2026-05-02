# Server Initial Setup and Hardening Script

Bash script that automates the first-time setup and security hardening of a fresh Debian/Ubuntu server.

Built as a portfolio project to demonstrate Linux administration and security hardening skills.

## What It Does

| Step | Task | Details |
|------|------|---------|
| 1 | System Update | Full update, upgrade, dist-upgrade, cleanup |
| 2 | Essential Packages | 20+ tools including htop, tmux, curl, git, jq, ncdu |
| 3 | Admin User | Creates sudo user with SSH directory |
| 4 | SSH Hardening | Custom port, disable root, key-only auth, max 3 attempts |
| 5 | UFW Firewall | Default deny, allow SSH/HTTP/HTTPS only |
| 6 | Fail2Ban | SSH jail with 24h ban, 3 max retries |
| 7 | Timezone and NTP | Chrony NTP sync, configurable timezone |
| 8 | Auto Updates | Daily unattended security patches |
| 9 | Kernel Hardening | SYN cookies, ICMP protection, ASLR, disable redirects |
| 10 | Security Report | Full text report with next steps |

## Usage

    chmod +x server-setup.sh
    sudo ./server-setup.sh

## Features

- Single script runs all 10 steps in sequence
- Color-coded terminal output (INFO, OK, WARN, ERROR)
- Full logging to /var/log/server-setup.log
- Pre-flight checks (root, OS detection, internet)
- SSH config backup before changes
- SSH config validation before restart
- Generates post-setup security report

## Customization

Edit the variables at the top of the script:

    NEW_USER="sysadmin"
    SSH_PORT="2222"
    TIMEZONE="Europe/Berlin"

## Tested On

- Debian 12 (Bookworm)
- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS

## Requirements

- Root access (sudo)
- Debian or Ubuntu based system
- Internet connection

## Author

Awssman — IT Systems Administrator
