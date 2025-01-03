import subprocess
import ipaddress
from pathlib import Path
import qrcode
import logging
from rich.console import Console
import json
import socket
import sys
import yaml
import requests

logger = logging.getLogger(__name__)
console = Console()

DEFAULT_CONFIG = {
    'ipv4_subnet': '10.0.0.0/24',
    'ipv6_subnet': 'fd00::/64',
    'wg_interface': 'wg0',
    'server_port': 51820,
    'config_dir': '/etc/wireguard',
    'interface_name': 'eth0',
    'server_public_key': '',  # Will be populated when server is initialized
    'server_private_key': '',  # Will be populated when server is initialized
    'full_tunnel': False,  # Default to split tunnel
}

def load_config(config_path=None):
    """Load configuration from file or use defaults."""
    config = DEFAULT_CONFIG.copy()
    
    if config_path and Path(config_path).exists():
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    config.update(user_config)
        except Exception as e:
            logger.error(f"Failed to load config file: {e}")
            sys.exit(1)
    
    return config

def save_config(config, config_path):
    """Save current configuration to file."""
    try:
        with open(config_path, 'w') as f:
            yaml.safe_dump(config, f)
    except Exception as e:
        logger.error(f"Failed to save config file: {e}")
        sys.exit(1)

def get_config():
    """Get the configuration."""
    return load_config('config.yaml')

def get_clients():
    """Get the clients."""
    clients_file = Path('clients.json')
    return json.loads(clients_file.read_text()) if clients_file.exists() else {}

def client_exists(name):
    """Check if the client exists."""
    clients = get_clients()
    return name in clients

def get_server_ips():
    """Get the server IP."""
    cfg = get_config()
    
    ipv4_subnet = cfg.get('ipv4_subnet')
    ipv4_netmask = ipv4_subnet.split('/')[1]
    first_ipv4_ip = f"{str(list(ipaddress.ip_network(ipv4_subnet).hosts())[0])}/{ipv4_netmask}"
        
    ipv6_subnet = cfg.get('ipv6_subnet')
    ipv6_netmask = ipv6_subnet.split('/')[1]
    network = ipaddress.ip_network(ipv6_subnet)
    # Get the first IP by adding 1 to the network address
    first_ipv6_ip = f"{str(network.network_address + 1)}/{network.prefixlen}"

    return {
        'ipv4': first_ipv4_ip,
        'ipv6': first_ipv6_ip
    }

def get_allowed_ips(tunnel_type=None):
    """Get allowed IPs based on tunnel type."""
    cfg = get_config()
    if tunnel_type is None:
        tunnel_type = cfg.get('full_tunnel', False)
    if tunnel_type:
        return ['0.0.0.0/0', '::/0']
    else:
        return [cfg['ipv4_subnet'], cfg['ipv6_subnet']]

def install_wireguard():
    """Install and configure WireGuard."""
    try:
        # Check if wireguard is installed
        if not Path('/usr/bin/wg').exists():
            logger.info("Installing WireGuard...")
            subprocess.run(['apt', 'update'], check=True, timeout=60)
            subprocess.run(['apt', 'install', '-y', 'wireguard'], check=True, timeout=120)
            
        # Create wireguard directory if it doesn't exist
        Path('/etc/wireguard').mkdir(mode=0o700, parents=True, exist_ok=True)
        
        # Initialize wg0.conf if it doesn't exist or is empty
        wg0_conf = Path('/etc/wireguard/wg0.conf')
        if not wg0_conf.exists() or wg0_conf.stat().st_size == 0:
            logger.info("Generating new WireGuard keys...")
            private_key, public_key = generate_keypair()
            
            cfg = get_config()
            interface_name = cfg.get('interface_name', 'eth0')
            port = cfg.get('server_port', 51820)
            ipv4 = get_server_ips()['ipv4']
            ipv6 = get_server_ips()['ipv6']
            
            # Create basic configuration
            config_content = f"""[Interface]
PrivateKey = {private_key}
Address = {ipv4}, {ipv6}
ListenPort = {port}

# Enable IP forwarding and NAT
PostUp = sysctl -w net.ipv4.ip_forward=1; sysctl -w net.ipv6.conf.all.forwarding=1; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {interface_name} -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o {interface_name} -j MASQUERADE; iptables -A INPUT -p udp --dport {port} -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {interface_name} -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o {interface_name} -j MASQUERADE; iptables -D INPUT -p udp --dport {port} -j ACCEPT
"""
            wg0_conf.write_text(config_content)
            wg0_conf.chmod(0o600)
            
            logger.info("WireGuard server configuration initialized")
            return private_key, public_key
            
        logger.debug("WireGuard already installed and configured")
        return None, None
        
    except subprocess.TimeoutExpired:
        logger.error("Timeout while installing WireGuard")
        raise
    except Exception as e:
        logger.error(f"Failed to install WireGuard: {e}")
        raise
    
def get_server_endpoint():
    """Get the server endpoint (FQDN or IP)."""
    try:
        # Try to get FQDN first
        fqdn = socket.getfqdn()
        if fqdn and fqdn != 'localhost' and '.' in fqdn:
            return fqdn
            
        # Fallback to public IP
        ip_address = requests.get('https://api.ipify.org/?format=json', timeout=5).json()['ip']
        return ip_address
            
    except Exception as e:
        logger.warning(f"Failed to get server endpoint: {e}")
        # Final fallback: use local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception as e:
            logger.error(f"Failed to get local IP: {e}")
            raise ValueError("Could not determine server endpoint")

def generate_keypair():
    """Generate a WireGuard private/public keypair."""
    try:
        # Generate private key
        private_key = subprocess.check_output(['wg', 'genkey'], timeout=10).decode().strip()
        
        # Generate public key from private key
        public_key = subprocess.check_output(['wg', 'pubkey'], 
                                           input=private_key.encode(),
                                           timeout=10).decode().strip()
        
        return private_key, public_key
    except subprocess.TimeoutExpired:
        logger.error("Timeout while generating keypair")
        raise
    except Exception as e:
        logger.error(f"Failed to generate keypair: {e}")
        raise

def get_next_available_ips():
    """Get next available IPv4 and IPv6 addresses from subnets."""
    cfg = get_config()
    clients = get_clients()
    ipv4_subnet = cfg.get('ipv4_subnet')
    ipv6_subnet = cfg.get('ipv6_subnet')
    
    # Extract netmasks
    ipv4_netmask = ipv4_subnet.split('/')[1]
    ipv6_netmask = ipv6_subnet.split('/')[1]
    
    used_ipv4s = [client['ipv4'] for client in clients.values()]
    used_ipv6s = [client.get('ipv6') for client in clients.values() if client.get('ipv6')]
    
    logger.info(f"IPv4 Subnet: {ipv4_subnet}")
    logger.info(f"Used IPv4s: {used_ipv4s}")
    
    # Get next IPv4
    ipv4_network = ipaddress.ip_network(ipv4_subnet)
    # Skip the first IP as it's reserved for the server
    ipv4_hosts = list(ipv4_network.hosts())[1:]
    next_ipv4 = None
    for ip in ipv4_hosts:
        if str(ip) not in [ip.split('/')[0] for ip in used_ipv4s]:  # Strip CIDR for comparison
            next_ipv4 = f"{str(ip)}/{ipv4_netmask}"  # Add CIDR notation
            break
    if not next_ipv4:
        raise ValueError(f"No available IPv4s in subnet {ipv4_subnet}")
        
    # Get next IPv6
    ipv6_network = ipaddress.ip_network(ipv6_subnet)
    if not used_ipv6s:
        # If no IPs used yet, take first available after server
        next_ipv6 = str(ipv6_network.network_address + 2)
    else:
        # Find the highest used IP and add 1
        highest_ipv6 = max(ipaddress.ip_address(ip.split('/')[0]) for ip in used_ipv6s)
        next_ipv6_addr = highest_ipv6 + 1
        if next_ipv6_addr not in ipv6_network:
            raise ValueError(f"No available IPv6s in subnet {ipv6_subnet}")
        next_ipv6 = str(next_ipv6_addr)
    
    return {
        'ipv4': f"{next_ipv4}",
        'ipv6': f"{next_ipv6}/{ipv6_netmask}"
    }

def create_client_config(name, client_private_key, client_public_key, server_public_key,
                        client_ipv4, client_ipv6, server_endpoint, server_port, allowed_ips=None):
    """Create client configuration file content."""
    cfg = get_config()
    # Add /32 to IPv4 if not present
    if '/' not in client_ipv4:
        client_ipv4 = f"{client_ipv4}/32"
        
    
    config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ipv4}, {client_ipv6}
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {server_public_key}
AllowedIPs = {', '.join(allowed_ips)}
Endpoint = {server_endpoint}:{server_port}
PersistentKeepalive = 25
"""
    return config

def save_client_config(config_dir, name, config_content):
    """Save client configuration to file."""
    config_path = Path(config_dir) / f"{name}.conf"
    try:
        config_path.write_text(config_content)
        logger.info(f"Saved client config to {config_path}")
    except Exception as e:
        logger.error(f"Failed to save client config: {e}")
        raise

def generate_qr_code(config_content, output_path):
    """Generate QR code for client configuration."""
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(config_content)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        qr_image.save(output_path)
        logger.info(f"Generated QR code at {output_path}")
    except Exception as e:
        logger.error(f"Failed to generate QR code: {e}")
        raise

def update_server_config(interface, clients):
    """Update WireGuard server configuration."""
    try:
        # Validate required fields
        if not interface.get('private_key'):
            raise ValueError("Server private key is missing or empty")
            
        interface_name = interface.get('interface_name', 'eth0')
        port = interface.get('port', 51820)
        ipv4 = get_server_ips()['ipv4']
        ipv6 = get_server_ips()['ipv6']
        
        config_content = f"""[Interface]
PrivateKey = {interface['private_key'].strip()}
Address = {ipv4}, {ipv6}
ListenPort = {port}

# Enable IP forwarding and NAT
PostUp = sysctl -w net.ipv4.ip_forward=1; sysctl -w net.ipv6.conf.all.forwarding=1; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {interface_name} -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o {interface_name} -j MASQUERADE; iptables -A INPUT -p udp --dport {port} -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {interface_name} -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o {interface_name} -j MASQUERADE; iptables -D INPUT -p udp --dport {port} -j ACCEPT
"""
        for client in clients:
            if not client.get('public_key'):
                logger.warning(f"Skipping client with missing public key: {client}")
                continue
                
            # Ensure IP addresses are in correct format (IP/32 for IPv4, IP/128 for IPv6)
            ipv4_addr = client['ipv4'].split('/')[0] + '/32'  # Changed from 'ip' to 'ipv4'
            ipv6_addr = client.get('ipv6', '').split('/')[0] + '/128'
                
            config_content += f"""
[Peer]
PublicKey = {client['public_key'].strip()}
AllowedIPs = {ipv4_addr}, {ipv6_addr}
"""
        
        # Clean up any existing NAT rules
        try:
            subprocess.run(['iptables', '-t', 'nat', '-F', 'POSTROUTING'], check=False)
            subprocess.run(['iptables', '-F', 'FORWARD'], check=False)
            subprocess.run(['ip6tables', '-t', 'nat', '-F', 'POSTROUTING'], check=False)
            subprocess.run(['ip6tables', '-F', 'FORWARD'], check=False)
        except Exception as e:
            logger.warning(f"Failed to clean rules: {e}")
        
        # Write config
        config_path = Path(f"/etc/wireguard/{interface['name']}.conf")
        config_path.write_text(config_content)
        config_path.chmod(0o600)
        
        # Enable IP forwarding
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True, capture_output=True)
        subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.forwarding=1'], check=True, capture_output=True)
        
        # Restart WireGuard interface
        subprocess.run(['systemctl', 'restart', f'wg-quick@{interface["name"]}'], check=True)
        
        logger.debug(f"Updated server configuration for {interface['name']}")
    except Exception as e:
        logger.error(f"Failed to update server config: {e}")
        raise

def manage_firewall_rules(client_ipv4, client_ipv6, allowed_ips=None, peer_ips=None, action='add'):
    """Manage iptables rules for client."""
    try:
        # Strip CIDR notation if present
        client_ipv4 = client_ipv4.split('/')[0] if '/' in client_ipv4 else client_ipv4
        client_ipv6 = client_ipv6.split('/')[0] if '/' in client_ipv6 else client_ipv6
        
        if action == 'add':
            # IPv4 rules
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'wg0', '-j', 'ACCEPT'], check=False)
            subprocess.run(['iptables', '-A', 'FORWARD', '-o', 'wg0', '-j', 'ACCEPT'], check=False)
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', 
                          '-s', client_ipv4, '-o', 'eth0', '-j', 'MASQUERADE'], 
                         check=False)
            
            # IPv6 rules
            subprocess.run(['ip6tables', '-A', 'FORWARD', '-i', 'wg0', '-j', 'ACCEPT'], check=False)
            subprocess.run(['ip6tables', '-A', 'FORWARD', '-o', 'wg0', '-j', 'ACCEPT'], check=False)
            subprocess.run(['ip6tables', '-t', 'nat', '-A', 'POSTROUTING', 
                          '-s', client_ipv6, '-o', 'eth0', '-j', 'MASQUERADE'], 
                         check=False)
            
            # Allow specific IPs if provided
            if allowed_ips:
                for ip in allowed_ips:
                    if ':' in ip:  # IPv6
                        subprocess.run(['ip6tables', '-A', 'FORWARD', '-s', client_ipv6, 
                                     '-d', ip, '-j', 'ACCEPT'], check=False)
                    else:  # IPv4
                        subprocess.run(['iptables', '-A', 'FORWARD', '-s', client_ipv4, 
                                     '-d', ip, '-j', 'ACCEPT'], check=False)
            
            # Allow peer access if provided
            if peer_ips:
                for ip in peer_ips:
                    subprocess.run(['iptables', '-A', 'FORWARD', '-s', client_ipv4,
                                 '-d', ip, '-j', 'ACCEPT'], check=False)
        
        elif action == 'remove':
            # Clean up client-specific rules
            rules = subprocess.check_output(['iptables', '-S'], text=True).splitlines()
            for rule in rules:
                if client_ipv4 in rule or client_ipv6 in rule:
                    remove_rule = rule.replace('-A', '-D', 1)
                    subprocess.run(['iptables'] + remove_rule.split()[1:], check=False)
        
        logger.info(f"Updated firewall rules for {client_ipv4}, {client_ipv6}")
    except Exception as e:
        logger.warning(f"Failed to manage firewall rules: {e}")
        # Continue anyway as this is not critical

def initialize_server_config():
    """Initialize server configuration if it doesn't exist."""
    try:
        private_key, public_key = generate_keypair()
        ipv4 = get_server_ips()['ipv4']
        ipv6 = get_server_ips()['ipv6']
        ip_addresses = f"{ipv4}, {ipv6}"
        config_content = f"""[Interface]
PrivateKey = {private_key}
Address = {ip_addresses}
ListenPort = 51820
SaveConfig = true

# Enable IP forwarding
PostUp = sysctl -w net.ipv4.ip_forward=1; sysctl -w net.ipv6.conf.all.forwarding=1; iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
"""
        config_path = Path('/etc/wireguard/wg0.conf')
        config_path.write_text(config_content)
        return private_key, public_key
    except Exception as e:
        logger.error(f"Failed to initialize server config: {e}")
        raise

