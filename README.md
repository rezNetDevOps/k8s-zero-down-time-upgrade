# k8s-zero-down-time-upgrade
Secure Kubernetes Nodes - Zero Downtime Security Enhancement Script

```bash
$./secure-k8s-nodes.sh --help
Usage: ./secure-k8s-nodes.sh [options]
Options:
  -u, --user USERNAME       Admin username to create (default: admin)
  -i, --inventory PATH      Path to inventory.ini file (default: ./cloud/hetzner/kubespray/inventory.ini)
  -k, --k8s-upgrade BOOL    Enable/disable Kubernetes upgrade (default: true)
  -h, --help                Display this help message

Example:
  ./secure-k8s-nodes.sh --user admin2023 --inventory /path/to/inventory.ini --k8s-upgrade false
```