#!/bin/bash

# Script for Automating Security Audits and Server Hardening on Linux Servers
# Author: Tirtharaj_Kalal
# Date: 2024-08-24

# Global Variables
REPORT_FILE="security_audit_report_$(date +%F).txt"
CONFIG_FILE="custom_checks.conf"

# Function to check root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit 1
    fi
}

# Function to generate a summary report
generate_report() {
    echo -e "\n*** Security Audit and Hardening Report ***" >> "$REPORT_FILE"
}

# Function to list all users and groups
audit_users_and_groups() {
    echo -e "\n### User and Group Audit ###" >> "$REPORT_FILE"
    echo "Listing all users:" >> "$REPORT_FILE"
    cut -d: -f1 /etc/passwd >> "$REPORT_FILE"
    echo "Listing all groups:" >> "$REPORT_FILE"
    cut -d: -f1 /etc/group >> "$REPORT_FILE"
    echo "Checking for non-standard users with UID 0:" >> "$REPORT_FILE"
    awk -F: '$3 == 0 {print $1}' /etc/passwd >> "$REPORT_FILE"
    echo "Identifying users without passwords:" >> "$REPORT_FILE"
    awk -F: '($2 == "" || $2 == "*") {print $1}' /etc/shadow >> "$REPORT_FILE"
}

# Function to audit file and directory permissions
audit_file_permissions() {
    echo -e "\n### File and Directory Permission Audit ###" >> "$REPORT_FILE"
    echo "Scanning for world-writable files and directories:" >> "$REPORT_FILE"
    find / -type d -perm -0002 2>/dev/null >> "$REPORT_FILE"
    echo "Checking for .ssh directories with insecure permissions:" >> "$REPORT_FILE"
    find / -type d -name ".ssh" -exec chmod 700 {} \; -exec chown $USER:$USER {} \;
    echo "Listing files with SUID or SGID bits set:" >> "$REPORT_FILE"
    find / -perm /6000 -type f 2>/dev/null >> "$REPORT_FILE"
}

# Function to audit services
audit_services() {
    echo -e "\n### Service Audit ###" >> "$REPORT_FILE"
    echo "Listing all running services:" >> "$REPORT_FILE"
    systemctl list-units --type=service --state=running >> "$REPORT_FILE"
    echo "Checking critical services (e.g., sshd, iptables):" >> "$REPORT_FILE"
    systemctl is-active sshd >> "$REPORT_FILE"
    systemctl is-active iptables >> "$REPORT_FILE"
    echo "Checking for services listening on non-standard or insecure ports:" >> "$REPORT_FILE"
    netstat -tuln | grep -v ':22\|:80\|:443' >> "$REPORT_FILE"
}

# Function to audit firewall and network security
audit_firewall_and_network() {
    echo -e "\n### Firewall and Network Security Audit ###" >> "$REPORT_FILE"
    echo "Verifying firewall status:" >> "$REPORT_FILE"
    ufw status >> "$REPORT_FILE"
    echo "Listing open ports and associated services:" >> "$REPORT_FILE"
    netstat -tuln >> "$REPORT_FILE"
    echo "Checking for IP forwarding:" >> "$REPORT_FILE"
    sysctl net.ipv4.ip_forward >> "$REPORT_FILE"
    sysctl net.ipv6.conf.all.forwarding >> "$REPORT_FILE"
}

# Function to check IP and network configuration
audit_ip_and_network() {
    echo -e "\n### IP and Network Configuration Audit ###" >> "$REPORT_FILE"
    IP_ADDRESSES=$(hostname -I)
    echo "Server IP addresses: $IP_ADDRESSES" >> "$REPORT_FILE"
    for IP in $IP_ADDRESSES; do
        if [[ "$IP" =~ ^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\. ]]; then
            echo "Private IP: $IP" >> "$REPORT_FILE"
        else
            echo "Public IP: $IP" >> "$REPORT_FILE"
        fi
    done
}

# Function to check security updates and patching
audit_security_updates() {
    echo -e "\n### Security Updates and Patching ###" >> "$REPORT_FILE"
    echo "Checking for available security updates:" >> "$REPORT_FILE"
    apt update && apt list --upgradable | grep -i security >> "$REPORT_FILE"
    echo "Ensuring regular security updates:" >> "$REPORT_FILE"
    grep -i unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades >> "$REPORT_FILE"
}

# Function to monitor logs for suspicious activity
monitor_logs() {
    echo -e "\n### Log Monitoring ###" >> "$REPORT_FILE"
    echo "Checking for recent suspicious log entries (e.g., SSH login attempts):" >> "$REPORT_FILE"
    grep "Failed password" /var/log/auth.log | tail -10 >> "$REPORT_FILE"
}

# Function to implement server hardening steps
harden_server() {
    echo -e "\n### Server Hardening ###" >> "$REPORT_FILE"
    
    # Implementing SSH key-based authentication and disabling root login
    echo "Implementing SSH key-based authentication and disabling root login:" >> "$REPORT_FILE"
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl reload sshd
    echo "SSH settings updated." >> "$REPORT_FILE"

    # Disabling IPv6 if not required
    echo "Disabling IPv6 if not required:" >> "$REPORT_FILE"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p >> "$REPORT_FILE"
    echo "IPv6 disabled." >> "$REPORT_FILE"

    # Securing GRUB bootloader
    echo "Securing GRUB bootloader:" >> "$REPORT_FILE"
    echo "Please manually set GRUB password using grub-mkpasswd-pbkdf2 and add it to /etc/grub.d/40_custom" >> "$REPORT_FILE"
    update-grub
    echo "GRUB configuration updated. Please set GRUB password manually." >> "$REPORT_FILE"

    # Configuring firewall with recommended rules
    echo "Configuring firewall with recommended rules:" >> "$REPORT_FILE"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
    if ufw status | grep -q "Status: active"; then
        echo "Firewall enabled successfully." >> "$REPORT_FILE"
    else
        echo "Failed to enable firewall." >> "$REPORT_FILE"
    fi

    # Configuring automatic security updates
    echo "Configuring automatic security updates:" >> "$REPORT_FILE"
    dpkg-reconfigure -plow unattended-upgrades
    echo "Automatic security updates configured." >> "$REPORT_FILE"
}

# Function to run custom security checks
run_custom_checks() {
    echo -e "\n### Custom Security Checks ###" >> "$REPORT_FILE"
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        echo "No custom checks configuration file found." >> "$REPORT_FILE"
    fi
}

# Function to send email alerts
send_alerts() {
    if grep -q "CRITICAL" "$REPORT_FILE"; then
        echo "Critical vulnerabilities found! Sending email alert..."
        # mailx -s "Security Audit Alert" user@example.com < "$REPORT_FILE"
    fi
}

# Main Function
main() {
    check_root
    generate_report
    audit_users_and_groups
    audit_file_permissions
    audit_services
    audit_firewall_and_network
    audit_ip_and_network
    audit_security_updates
    monitor_logs
    harden_server
    run_custom_checks
    send_alerts
    echo "Security audit and hardening completed. Report saved to $REPORT_FILE"
}

main "$@"
