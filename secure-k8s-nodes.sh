#!/bin/bash
set -e

# Secure Kubernetes Nodes - Zero Downtime Security Enhancement Script
# This script implements best practices for securing Linux nodes in a Kubernetes cluster
# and performs rolling updates to avoid service disruption
# It also creates an admin user for future SSH access

# Default configuration
SSH_PORT=22 # Default SSH port, change if needed
MAX_CONCURRENT_UPGRADES=1 # Maximum nodes to upgrade concurrently
WORKER_DRAIN_TIMEOUT="300s" # Time to wait for pods to evict during drain
LOG_FILE="k8s-security-upgrade-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="security-upgrade-backup-$(date +%Y%m%d)"
ADMIN_USER="admin"
SSH_KEY_PATH=""
INVENTORY_PATH="./cloud/hetzner/kubespray/inventory.ini"
K8S_UPGRADE=true
ROOT_SSH_KEY="$HOME/.ssh/id_ed25519" # Default root SSH key path

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Display help message
usage() {
  echo "Usage: $0 [options]"
  echo "Options:"
  echo "  -u, --user USERNAME       Admin username to create (default: admin)"
  echo "  -i, --inventory PATH      Path to inventory.ini file (default: ./cloud/hetzner/kubespray/inventory.ini)"
  echo "  -k, --k8s-upgrade BOOL    Enable/disable Kubernetes upgrade (default: true)"
  echo "  -s, --ssh-key PATH        Path to root SSH key for node access (default: $HOME/.ssh/id_ed25519)"
  echo "  -h, --help                Display this help message"
  echo ""
  echo "Example:"
  echo "  $0 --user admin2023 --inventory /path/to/inventory.ini --k8s-upgrade false --ssh-key $HOME/.ssh/id_ed25519"
  exit 1
}

# Parse command line arguments
parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case $1 in
      -u|--user)
        ADMIN_USER="$2"
        shift 2
        ;;
      -i|--inventory)
        INVENTORY_PATH="$2"
        shift 2
        ;;
      -k|--k8s-upgrade)
        K8S_UPGRADE="$2"
        shift 2
        ;;
      -s|--ssh-key)
        ROOT_SSH_KEY="$2"
        shift 2
        ;;
      -h|--help)
        usage
        ;;
      *)
        echo "Unknown parameter: $1"
        usage
        ;;
    esac
  done
  
  # Set SSH key path based on username
  SSH_KEY_PATH="$HOME/.ssh/${ADMIN_USER}_id_ed25519"
  
  # Validate k8s-upgrade parameter
  if [[ "$K8S_UPGRADE" != "true" && "$K8S_UPGRADE" != "false" ]]; then
    echo "Error: k8s-upgrade must be 'true' or 'false'"
    usage
  fi
  
  # Verify root SSH key exists
  if [ ! -f "$ROOT_SSH_KEY" ]; then
    echo "Error: Root SSH key not found at $ROOT_SSH_KEY"
    echo "Please provide a valid SSH key path with --ssh-key"
    usage
  fi
  
  # Print configuration
  echo "Configuration:"
  echo "  Admin user: $ADMIN_USER"
  echo "  SSH key path: $SSH_KEY_PATH"
  echo "  Root SSH key: $ROOT_SSH_KEY"
  echo "  Inventory path: $INVENTORY_PATH"
  echo "  K8s upgrade: $K8S_UPGRADE"
  echo ""
}

# Helper functions
log() {
  echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_FILE
}

log_success() {
  echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_FILE
}

log_warning() {
  echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_FILE
}

log_error() {
  echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_FILE
}

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Create backup directory
setup_environment() {
  mkdir -p $BACKUP_DIR
  log "Created backup directory: $BACKUP_DIR"
  
  # Check if kubectl is available
  if ! command_exists kubectl; then
    log_error "kubectl not found. Please install kubectl before running this script."
    exit 1
  fi
  
  # Verify inventory file exists
  if [ ! -f "$INVENTORY_PATH" ]; then
    log_error "Could not find Kubernetes inventory file at $INVENTORY_PATH"
    exit 1
  fi
}

# Extract node IP addresses from inventory
get_node_ips() {
  grep -E "ansible_host=" $INVENTORY_PATH | grep -oP 'ansible_host=\K[^ ]+'
}

# Create SSH key if it doesn't exist
create_ssh_key() {
  log "Checking for SSH key at $SSH_KEY_PATH"
  
  if [ ! -f "$SSH_KEY_PATH" ]; then
    log "Generating new ED25519 SSH key for $ADMIN_USER user"
    ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -C "$ADMIN_USER@k8s-admin"
    log_success "SSH key generated at $SSH_KEY_PATH"
  else
    log "SSH key already exists at $SSH_KEY_PATH"
  fi
  
  # Display public key
  SSH_PUB_KEY=$(cat "${SSH_KEY_PATH}.pub")
  log "Using public key: $SSH_PUB_KEY"
}

# Setup admin user on node
setup_admin_user() {
  local node_ip=$1
  log "Setting up $ADMIN_USER user on $node_ip"
  
  # Connect to node as root and create admin user
  ssh -o StrictHostKeyChecking=no -i "$ROOT_SSH_KEY" root@$node_ip "
    set -e
    
    # Create user if it doesn't exist
    if ! id -u $ADMIN_USER >/dev/null 2>&1; then
      useradd -m -s /bin/bash $ADMIN_USER
      echo '$ADMIN_USER ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/$ADMIN_USER
      chmod 440 /etc/sudoers.d/$ADMIN_USER
    fi
    
    # Setup SSH directory and authorized_keys
    mkdir -p /home/$ADMIN_USER/.ssh
    echo '$SSH_PUB_KEY' > /home/$ADMIN_USER/.ssh/authorized_keys
    chmod 700 /home/$ADMIN_USER/.ssh
    chmod 600 /home/$ADMIN_USER/.ssh/authorized_keys
    chown -R $ADMIN_USER:$ADMIN_USER /home/$ADMIN_USER/.ssh
    
    echo 'User $ADMIN_USER setup complete'
  "
  
  log_success "User $ADMIN_USER setup complete on $node_ip"
}

# SECURITY ENHANCEMENT FUNCTIONS
# ------------------------------

enhance_ssh_security() {
  local node_ip=$1
  log "Enhancing SSH security on $node_ip..."
  
  ssh -o StrictHostKeyChecking=no -i "$ROOT_SSH_KEY" root@$node_ip "
    # Back up SSH config
    mkdir -p /root/security-backup
    cp /etc/ssh/sshd_config /root/security-backup/sshd_config.backup
    
    # Secure SSH configuration
    sed -i.bak \\
      -e 's/^#\?PermitRootLogin .*/PermitRootLogin prohibit-password/' \\
      -e 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' \\
      -e 's/^#\?X11Forwarding .*/X11Forwarding no/' \\
      -e 's/^#\?MaxAuthTries .*/MaxAuthTries 3/' \\
      -e 's/^#\?ClientAliveInterval .*/ClientAliveInterval 300/' \\
      -e 's/^#\?ClientAliveCountMax .*/ClientAliveCountMax 2/' \\
      -e 's/^#\?Protocol .*/Protocol 2/' \\
      /etc/ssh/sshd_config
    
    # Add additional security options
    if ! grep -q '^AllowAgentForwarding' /etc/ssh/sshd_config; then
      echo 'AllowAgentForwarding no' >> /etc/ssh/sshd_config
    fi
    
    if ! grep -q '^AllowTcpForwarding' /etc/ssh/sshd_config; then
      echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config
    fi
    
    systemctl restart sshd
    echo 'SSH security enhanced and service restarted'
  "
  
  log_success "SSH security enhanced on $node_ip"
}

configure_firewall() {
  local node_ip=$1
  log "Configuring firewall on $node_ip..."
  
  ssh -o StrictHostKeyChecking=no -i "$ROOT_SSH_KEY" root@$node_ip "
    # Check if ufw is installed
    if ! command -v ufw >/dev/null 2>&1; then
      apt-get update
      apt-get install -y ufw
    fi
    
    # Configure ufw for Kubernetes
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow $SSH_PORT/tcp
    
    # Kubernetes required ports
    # Control plane nodes
    ufw allow 6443/tcp # Kubernetes API server
    ufw allow 2379:2380/tcp # etcd server client API
    ufw allow 10250/tcp # Kubelet API
    ufw allow 10259/tcp # kube-scheduler
    ufw allow 10257/tcp # kube-controller-manager
    
    # Worker nodes
    ufw allow 10250/tcp # Kubelet API
    ufw allow 30000:32767/tcp # NodePort Services
    
    # Cilium CNI specific ports
    ufw allow 4240/tcp # Cilium health checks
    ufw allow 4244/tcp # Hubble server
    ufw allow 4245/tcp # Hubble relay
    ufw allow 51871/udp # Cilium VXLAN tunnel
    
    # Enable firewall
    ufw --force enable
    
    echo 'Firewall configured and enabled'
  "
  
  log_success "Firewall configured on $node_ip"
}

harden_kernel_parameters() {
  local node_ip=$1
  log "Hardening kernel parameters on $node_ip..."
  
  ssh -o StrictHostKeyChecking=no -i "$ROOT_SSH_KEY" root@$node_ip "
    # Back up sysctl conf
    cp /etc/sysctl.conf /root/security-backup/sysctl.conf.backup
    
    # Configure kernel parameters
    cat > /etc/sysctl.d/99-kubernetes-security.conf << EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IP forwarding unless needed (required for Kubernetes)
net.ipv4.ip_forward = 1

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable ICMP redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Increase system file descriptors
fs.file-max = 65535

# Cilium-specific kernel parameters
net.core.bpf_jit_limit = 1000000000
net.ipv4.conf.lxc*.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
    
    # Apply changes
    sysctl --system
    
    echo 'Kernel parameters hardened'
  "
  
  log_success "Kernel parameters hardened on $node_ip"
}

setup_auditd() {
  local node_ip=$1
  log "Setting up auditd for system auditing on $node_ip..."
  
  ssh -o StrictHostKeyChecking=no -i "$ROOT_SSH_KEY" root@$node_ip "
    # Install auditd if needed
    if ! command -v auditd >/dev/null 2>&1; then
      apt-get update
      apt-get install -y auditd audispd-plugins
    fi
    
    # Back up audit rules
    if [ -f /etc/audit/rules.d/audit.rules ]; then
      cp /etc/audit/rules.d/audit.rules /root/security-backup/audit.rules.backup
    fi
    
    # Configure audit rules
    cat > /etc/audit/rules.d/audit.rules << EOF
# Delete all existing rules
-D

# Set buffer size to reduce likelihood of lost events
-b 8192

# Monitor file system for changes to key Kubernetes files
-w /etc/kubernetes/ -p wa -k kubernetes_configs
-w /var/lib/kubelet/ -p wa -k kubelet_configs
-w /etc/cni/ -p wa -k cni_configs
-w /etc/cilium/ -p wa -k cilium_configs

# Monitor for privilege escalation
-w /bin/su -p x -k privileged
-w /usr/bin/sudo -p x -k privileged

# Monitor SSH key usage
-w /etc/ssh/ -p wa -k sshd
-w /root/.ssh/ -p wa -k ssh_root_keys
-w /home/$ADMIN_USER/.ssh/ -p wa -k ssh_admin_keys

# Monitor unsuccessful accesses
-a always,exit -F arch=b64 -S open,openat,open_by_handle_at -F exit=-EACCES -F key=access
-a always,exit -F arch=b64 -S open,openat,open_by_handle_at -F exit=-EPERM -F key=access

# Critical commands to monitor
-w /usr/bin/curl -p x -k command_execution
-w /usr/bin/wget -p x -k command_execution
-w /usr/bin/nc -p x -k command_execution
-w /usr/bin/ncat -p x -k command_execution
-w /usr/bin/ssh -p x -k command_execution
-w /usr/bin/scp -p x -k command_execution

# Monitor containerd files and directories
-w /etc/containerd/ -p wa -k containerd_conf
-w /var/lib/containerd/ -p wa -k containerd_data

# Disallow modification of audit configurations
-w /etc/audit/ -p wa -k audit_config_change
-w /etc/libaudit.conf -p wa -k audit_config_change
-w /etc/audisp/ -p wa -k audisp_config_change

# Make audit config immutable - requires reboot to change audit rules
-e 2
EOF
    
    # Restart auditd
    service auditd restart
    
    echo 'System auditing configured with auditd'
  "
  
  log_success "System auditing configured on $node_ip"
}

secure_root_account() {
  local node_ip=$1
  log "Securing root account on $node_ip..."
  
  ssh -o StrictHostKeyChecking=no -i "$ROOT_SSH_KEY" root@$node_ip "
    # Set strong password policies
    if command -v pwquality >/dev/null 2>&1; then
      # Backup first
      cp /etc/security/pwquality.conf /root/security-backup/pwquality.conf.backup
      
      # Set strong password policies
      sed -i 's/# minlen = 8/minlen = 14/' /etc/security/pwquality.conf
      sed -i 's/# dcredit = 0/dcredit = -1/' /etc/security/pwquality.conf 
      sed -i 's/# ucredit = 0/ucredit = -1/' /etc/security/pwquality.conf
      sed -i 's/# ocredit = 0/ocredit = -1/' /etc/security/pwquality.conf
      sed -i 's/# lcredit = 0/lcredit = -1/' /etc/security/pwquality.conf
    fi
    
    echo 'Root account secured'
  "
  
  log_success "Root account secured on $node_ip"
}

install_fail2ban() {
  local node_ip=$1
  log "Installing and configuring Fail2ban on $node_ip..."
  
  ssh -o StrictHostKeyChecking=no -i "$ROOT_SSH_KEY" root@$node_ip "
    # Install fail2ban
    apt-get update
    apt-get install -y fail2ban
    
    # Configure fail2ban for SSH
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    
    # Enable and start fail2ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    echo 'Fail2ban installed and configured'
  "
  
  log_success "Fail2ban installed and configured on $node_ip"
}

secure_containerd() {
  local node_ip=$1
  log "Securing containerd runtime on $node_ip..."
  
  ssh -o StrictHostKeyChecking=no -i "$ROOT_SSH_KEY" root@$node_ip "
    # Backup containerd config
    if [ -f /etc/containerd/config.toml ]; then
      cp /etc/containerd/config.toml /root/security-backup/config.toml.backup
    fi
    
    # Generate default config if it doesn't exist
    if [ ! -f /etc/containerd/config.toml ]; then
      containerd config default > /etc/containerd/config.toml
    fi
    
    # Update containerd configuration for security
    
    # Ensure we have a version with no_new_privileges support
    if grep -q 'SystemdCgroup' /etc/containerd/config.toml; then
      # Enable systemd cgroup driver
      sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
      
      # Set no_new_privileges for default runtime
      if ! grep -q 'no_new_privileges' /etc/containerd/config.toml; then
        sed -i '/\[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options\]/a \        NoNewPrivileges = true' /etc/containerd/config.toml
      fi
    else
      # Older format or custom config - be more careful
      echo 'Containerd config does not match expected format. Manual review recommended.'
    fi
    
    # Restrict permissions on containerd socket
    if [ -S /run/containerd/containerd.sock ]; then
      chmod 0600 /run/containerd/containerd.sock
    fi
    
    # Restart containerd
    systemctl restart containerd
    
    echo 'Containerd security enhanced'
  "
  
  log_success "Containerd secured on $node_ip"
}

update_system() {
  local node_ip=$1
  log "Updating system packages on $node_ip..."
  
  ssh -o StrictHostKeyChecking=no -i "$ROOT_SSH_KEY" root@$node_ip "
    # Update package lists
    apt-get update
    
    # Upgrade packages
    DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::=\"--force-confdef\" -o Dpkg::Options::=\"--force-confold\" upgrade -y
    
    # Clean up
    apt-get autoremove -y
    apt-get autoclean
    
    echo 'System packages updated successfully'
  "
  
  log_success "System packages updated on $node_ip"
}

cordon_node() {
  local node=$1
  log "Cordoning node ${node}..."
  kubectl cordon $node
  log_success "Node ${node} cordoned"
}

drain_node() {
  local node=$1
  log "Draining node ${node}..."
  kubectl drain $node --ignore-daemonsets --delete-emptydir-data --force --timeout=$WORKER_DRAIN_TIMEOUT
  log_success "Node ${node} drained"
}

uncordon_node() {
  local node=$1
  log "Uncordoning node ${node}..."
  kubectl uncordon $node
  log_success "Node ${node} is now schedulable again"
}

verify_node_health() {
  local node=$1
  log "Verifying health of node ${node}..."
  
  # Check if node is Ready
  local status=$(kubectl get node $node -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
  if [ "$status" != "True" ]; then
    log_error "Node ${node} is not in Ready state after upgrade"
    return 1
  fi
  
  # Check if kubelet is running
  local node_ip=$(grep $node $INVENTORY_PATH | grep -oP 'ansible_host=\K[^ ]+')
  ssh -o StrictHostKeyChecking=no -i "$ROOT_SSH_KEY" root@$node_ip systemctl is-active kubelet
  
  log_success "Node ${node} is healthy"
  return 0
}

# Node upgrade function with k8s upgrade flag check
upgrade_node() {
  local node_ip=$1
  local node_name=$2
  local is_control_plane=$3
  
  # Security enhancements
  enhance_ssh_security $node_ip
  configure_firewall $node_ip
  harden_kernel_parameters $node_ip
  setup_auditd $node_ip
  secure_root_account $node_ip
  install_fail2ban $node_ip
  secure_containerd $node_ip
  
  # Conditionally perform system upgrade if k8s_upgrade is enabled
  if [[ "$K8S_UPGRADE" == "true" ]]; then
    log "K8s upgrade enabled - performing system update on $node_name"
    update_system $node_ip
    
    if ! verify_node_health $node_name; then
      log_error "Node ${node_name} failed health check after upgrade. Manual intervention required."
      exit 1
    fi
  else
    log "K8s upgrade disabled - skipping system update on $node_name"
  fi
}

# MAIN EXECUTION SCRIPT
# --------------------

# Parse command line arguments
parse_args "$@"

# Setup environment
setup_environment

log "Starting Kubernetes security enhancement"
log "Using inventory from: $INVENTORY_PATH"

# Create the SSH key for admin user
create_ssh_key

# Parse inventory to get nodes
CONTROL_PLANE_NODES=$(grep -A 100 '\[kube_control_plane\]' $INVENTORY_PATH | grep -B 100 -m 1 '\[' | grep -v '\[' | grep -v '^$' | awk '{print $1}')
WORKER_NODES=$(grep -A 100 '\[kube_node\]' $INVENTORY_PATH | grep -B 100 -m 1 '\[' | grep -v '\[' | grep -v '^$' | awk '{print $1}')

# Print cluster info
log "Control plane nodes: ${CONTROL_PLANE_NODES}"
log "Worker nodes: ${WORKER_NODES}"

# Get all node IPs
NODE_IPS=$(get_node_ips)

# First, setup admin user on all nodes
log "Setting up admin user on all nodes..."
for node_ip in $NODE_IPS; do
  setup_admin_user $node_ip
done

# Process worker nodes first
log "Starting worker node security enhancements..."

for worker in $WORKER_NODES; do
  log "Processing worker node: ${worker}"
  node_ip=$(grep $worker $INVENTORY_PATH | grep -oP 'ansible_host=\K[^ ]+')
  
  # Only cordon/drain if we're doing a k8s upgrade
  if [[ "$K8S_UPGRADE" == "true" ]]; then
    cordon_node $worker
    drain_node $worker
  fi
  
  # Perform security enhancements and conditionally upgrade
  upgrade_node $node_ip $worker false
  
  # Uncordon only if we cordoned
  if [[ "$K8S_UPGRADE" == "true" ]]; then
    uncordon_node $worker
  fi
  
  log_success "Worker node ${worker} successfully processed"
  
  # Wait between nodes to ensure cluster stability
  if [[ "$K8S_UPGRADE" == "true" && "$worker" != "$(echo $WORKER_NODES | awk '{print $NF}')" ]]; then
    log "Waiting 60 seconds before processing next node..."
    sleep 60
  fi
done

log_success "All worker nodes processed successfully"

# Process control plane nodes one at a time
log "Starting control plane node security enhancements..."

for master in $CONTROL_PLANE_NODES; do
  log "Processing control plane node: ${master}"
  node_ip=$(grep $master $INVENTORY_PATH | grep -oP 'ansible_host=\K[^ ]+')
  
  # Only cordon/drain if we're doing a k8s upgrade
  if [[ "$K8S_UPGRADE" == "true" ]]; then
    cordon_node $master
    drain_node $master
  fi
  
  # Perform security enhancements and conditionally upgrade
  upgrade_node $node_ip $master true
  
  # Uncordon only if we cordoned
  if [[ "$K8S_UPGRADE" == "true" ]]; then
    uncordon_node $master
  fi
  
  log_success "Control plane node ${master} successfully processed"
  
  # Wait between control plane nodes to ensure cluster stability
  if [[ "$K8S_UPGRADE" == "true" && "$master" != "$(echo $CONTROL_PLANE_NODES | awk '{print $NF}')" ]]; then
    log "Waiting 120 seconds before processing next control plane node..."
    sleep 120
  fi
done

log_success "All control plane nodes processed successfully"

# Verify overall cluster health
log "Verifying overall cluster health..."
kubectl get nodes -o wide
kubectl get pods -A

log_success "Security enhancement completed successfully!"
log_success "Log file available at: $LOG_FILE"
log_success "Backup files stored in: $BACKUP_DIR"
log_success "User $ADMIN_USER created on all nodes with SSH key access"

# Provide additional security recommendations
cat << EOF

${GREEN}=================================${NC}
${GREEN}  SECURITY RECOMMENDATIONS       ${NC}
${GREEN}=================================${NC}

1. Implement network policies to restrict pod-to-pod communication with Cilium
   - Use CiliumNetworkPolicy resources for more granular control

2. Use Pod Security Standards to enforce security contexts
   https://kubernetes.io/docs/concepts/security/pod-security-standards/

3. Regularly scan container images for vulnerabilities
   Consider deploying Trivy or Clair

4. Regularly rotate all certificates and credentials:
   - kubeadm certs renew (for kubeadm clusters)
   - Service account tokens
   - Secrets

5. Consider implementing a secrets management solution like HashiCorp Vault

6. Set up regular automated backups of etcd data and Kubernetes resources
   - velero install
   - etcdctl snapshot save

7. Implement proper RBAC policies and regularly review access permissions

8. Consider setting up Cilium's Hubble for network observability

9. Configure Fluentbit via Helm chart for centralized logging

10. Setup regular security audits and compliance checks

EOF

exit 0 