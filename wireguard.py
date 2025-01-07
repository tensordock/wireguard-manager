#!/usr/bin/env python3
import subprocess
import ipaddress
from pathlib import Path
import qrcode
import logging
import json
import socket
import sys
import yaml
import requests
from typing import Dict, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, asdict, field
from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
console = Console()

@dataclass
class WireGuardConfig:
    """WireGuard server configuration."""
    ipv4_subnet: str = '10.0.0.0/24'
    ipv6_subnet: str = 'fd00::/64'
    wg_interface: str = 'wg0'
    server_port: int = 51820
    config_dir: str = '/etc/wireguard'
    interface_name: str = 'eth0'
    server_public_key: str = ''
    server_private_key: str = ''
    endpoint: str = ''
    full_tunnel: bool = False

    @classmethod
    def from_dict(cls, config_dict: Dict) -> 'WireGuardConfig':
        return cls(**{k: v for k, v in config_dict.items() if k in cls.__annotations__})

@dataclass
class WireGuardClient:
    """WireGuard client configuration."""
    name: str
    public_key: str
    ipv4: str
    ipv6: str
    allowed_ips: List[str]
    restricted_ips: List[str] = field(default_factory=list)  # IPv4 restrictions
    restricted_ip6s: List[str] = field(default_factory=list)  # IPv6 restrictions
    created_at: str = ''

class WireGuardManager:
    """Manages WireGuard VPN server and clients."""
    
    def __init__(self, config_path: str = 'config.yaml'):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.clients_file = Path('clients.json')
        self.clients: Dict[str, WireGuardClient] = {}
        self._load_clients()

    def _load_config(self) -> WireGuardConfig:
        """Load configuration from file or create default."""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    return WireGuardConfig.from_dict(yaml.safe_load(f) or {})
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
                sys.exit(1)
        return WireGuardConfig()

    def _save_config(self) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                yaml.safe_dump(asdict(self.config), f)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            sys.exit(1)

    def _load_clients(self) -> None:
        """Load clients from JSON file."""
        if self.clients_file.exists():
            try:
                clients_data = json.loads(self.clients_file.read_text())
                self.clients = {
                    name: WireGuardClient(**data)
                    for name, data in clients_data.items()
                }
            except Exception as e:
                logger.error(f"Failed to load clients: {e}")
                self.clients = {}

    def _save_clients(self) -> None:
        """Save clients to JSON file."""
        try:
            clients_data = {
                name: asdict(client)
                for name, client in self.clients.items()
            }
            self.clients_file.write_text(json.dumps(clients_data, indent=2))
        except Exception as e:
            logger.error(f"Failed to save clients: {e}")

    def _run_command(self, cmd: List[str], input_data: str = None, 
                    timeout: int = 30) -> str:
        """Run system command with timeout."""
        try:
            if input_data:
                result = subprocess.run(
                    cmd,
                    input=input_data.encode(),
                    capture_output=True,
                    timeout=timeout
                )
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout
                )
            
            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode, cmd, result.stdout, result.stderr
                )
            
            return result.stdout.decode().strip()
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            raise
        except Exception as e:
            logger.error(f"Command failed: {' '.join(cmd)}, Error: {e}")
            raise

    def _generate_keypair(self) -> Tuple[str, str]:
        """Generate WireGuard keypair."""
        private_key = self._run_command(['wg', 'genkey'])
        public_key = self._run_command(['wg', 'pubkey'], input_data=private_key)
        return private_key, public_key

    def _get_server_endpoint(self) -> str:
        """Get server endpoint (FQDN or IP)."""
        try:
            # Try FQDN first
            fqdn = socket.getfqdn()
            if fqdn and fqdn != 'localhost' and '.' in fqdn:
                return fqdn

            # Fallback to public IP
            response = requests.get(
                'https://api.ipify.org/?format=json',
                timeout=5
            )
            return response.json()['ip']
        except Exception as e:
            logger.warning(f"Failed to get server endpoint: {e}")
            # Final fallback to local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip

    def _get_next_available_ips(self) -> Dict[str, str]:
        """Get next available IPs for a new client."""
        ipv4_net = ipaddress.ip_network(self.config.ipv4_subnet)
        ipv6_net = ipaddress.ip_network(self.config.ipv6_subnet)
        
        used_ipv4s = {client.ipv4.split('/')[0] for client in self.clients.values()}
        used_ipv6s = {client.ipv6.split('/')[0] for client in self.clients.values()}
        
        # Skip first IP (reserved for server)
        for ip in list(ipv4_net.hosts())[1:]:
            if str(ip) not in used_ipv4s:
                next_ipv4 = f"{ip}/{ipv4_net.prefixlen}"
                break
        else:
            raise ValueError(f"No available IPv4s in subnet {self.config.ipv4_subnet}")
        
        next_ip = ipv6_net.network_address + 2
        while str(next_ip) in used_ipv6s:
            next_ip += 1
            if next_ip not in ipv6_net:
                raise ValueError(f"No available IPv6s in subnet {self.config.ipv6_subnet}")
        
        next_ipv6 = f"{next_ip}/{ipv6_net.prefixlen}"
        return {'ipv4': next_ipv4, 'ipv6': next_ipv6}

    def initialize(self) -> None:
        """Initialize WireGuard server."""
        try:
            # Install WireGuard if needed
            if not Path('/usr/bin/wg').exists():
                self._run_command(['apt', 'update'])
                self._run_command(['apt', 'install', '-y', 'wireguard'])

            # Create config directory
            Path(self.config.config_dir).mkdir(mode=0o700, parents=True, exist_ok=True)

            # Generate server keys if needed
            if not self.config.server_private_key:
                private_key, public_key = self._generate_keypair()
                self.config.server_private_key = private_key
                self.config.server_public_key = public_key

            # Set endpoint if not configured
            if not self.config.endpoint:
                self.config.endpoint = self._get_server_endpoint()

            # Ensure forwarding is enabled
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n')
            with open('/proc/sys/net/ipv6/conf/all/forwarding', 'w') as f:
                f.write('1\n')

            # Make forwarding persistent
            sysctl_conf = Path('/etc/sysctl.d/99-wireguard.conf')
            sysctl_conf.write_text(
                "net.ipv4.ip_forward=1\n"
                "net.ipv6.conf.all.forwarding=1\n"
            )
            
            self._ensure_persistent_firewall()
            self._save_config()
            self._update_server_config()
            
            # Verify interface is up
            if not Path(f"/sys/class/net/{self.config.wg_interface}").exists():
                raise RuntimeError("Failed to create WireGuard interface")
                
            console.print("[green]Server initialized successfully[/green]")
        except Exception as e:
            logger.error(f"Failed to initialize server: {e}")
            sys.exit(1)

    def _ensure_persistent_firewall(self) -> None:
        """Ensure firewall rules persist across reboots."""
        rules_file = Path('/etc/iptables/rules.v4')
        rules_file6 = Path('/etc/iptables/rules.v6')

        try:
            # Install iptables-persistent if needed
            if not rules_file.parent.exists():
                self._run_command(['apt', 'install', '-y', 'iptables-persistent'])
                rules_file.parent.mkdir(parents=True, exist_ok=True)

            # Save current rules
            self._run_command(['iptables-save'], timeout=5)
            self._run_command(['ip6tables-save'], timeout=5)

        except Exception as e:
            logger.warning(f"Failed to ensure persistent firewall: {e}")

    def _update_client_firewall_rules(self, client: WireGuardClient) -> None:
        """Update firewall rules for a specific client."""
        try:
            client_ip = client.ipv4.split('/')[0]
            client_ip6 = client.ipv6.split('/')[0]
            
            # Clean up existing IPv4 rules
            try:
                iptables_list = self._run_command(['iptables', '-L', 'FORWARD', '--line-numbers'])
                for line in reversed(iptables_list.split('\n')):
                    if client_ip in line:
                        rule_num = line.split()[0]
                        self._run_command(['iptables', '-D', 'FORWARD', rule_num])
            except Exception as e:
                logger.warning(f"Error cleaning up old IPv4 rules: {e}")

            # Clean up existing IPv6 rules
            try:
                ip6tables_list = self._run_command(['ip6tables', '-L', 'FORWARD', '--line-numbers'])
                for line in reversed(ip6tables_list.split('\n')):
                    if client_ip6 in line:
                        rule_num = line.split()[0]
                        self._run_command(['ip6tables', '-D', 'FORWARD', rule_num])
            except Exception as e:
                logger.warning(f"Error cleaning up old IPv6 rules: {e}")

            # Add IPv4 restrictions
            if client.restricted_ips:
                for dest_ip in client.restricted_ips:
                    self._run_command([
                        'iptables', '-A', 'FORWARD',
                        '-i', self.config.wg_interface,
                        '-s', client_ip,
                        '-d', dest_ip,
                        '-j', 'ACCEPT'
                    ])
                
                self._run_command([
                    'iptables', '-A', 'FORWARD',
                    '-i', self.config.wg_interface,
                    '-s', client_ip,
                    '-j', 'DROP'
                ])

            # Add IPv6 restrictions
            if client.restricted_ip6s:
                for dest_ip in client.restricted_ip6s:
                    self._run_command([
                        'ip6tables', '-A', 'FORWARD',
                        '-i', self.config.wg_interface,
                        '-s', client_ip6,
                        '-d', dest_ip,
                        '-j', 'ACCEPT'
                    ])
                
                self._run_command([
                    'ip6tables', '-A', 'FORWARD',
                    '-i', self.config.wg_interface,
                    '-s', client_ip6,
                    '-j', 'DROP'
                ])

        except Exception as e:
            logger.error(f"Failed to update firewall rules for client {client.name}: {e}")
            raise

    def _update_server_config(self) -> None:
        """Update WireGuard server configuration."""
        try:
            # First try to clean up existing interface
            if Path(f"/sys/class/net/{self.config.wg_interface}").exists():
                try:
                    # Stop interface if running
                    self._run_command(['wg-quick', 'down', self.config.wg_interface])
                except Exception as e:
                    logger.warning(f"Failed to bring down interface: {e}")

            # Build server config
            config_lines = [
                '[Interface]',
                f'PrivateKey = {self.config.server_private_key}',
                f'Address = {self._get_server_ips()}',
                f'ListenPort = {self.config.server_port}',
                '# Enable IP forwarding and NAT',
                'PostUp = sysctl -w net.ipv4.ip_forward=1; '
                'sysctl -w net.ipv6.conf.all.forwarding=1; '
                f'iptables -t nat -A POSTROUTING -o {self.config.interface_name} -j MASQUERADE; '
                f'ip6tables -t nat -A POSTROUTING -o {self.config.interface_name} -j MASQUERADE',
                'PostDown = '
                f'iptables -t nat -D POSTROUTING -o {self.config.interface_name} -j MASQUERADE; '
                f'ip6tables -t nat -D POSTROUTING -o {self.config.interface_name} -j MASQUERADE'
            ]

            # Add peer configs if any clients exist
            if self.clients:
                for client in self.clients.values():
                    config_lines.extend([
                        '',
                        '[Peer]',
                        f'PublicKey = {client.public_key}',
                        f'AllowedIPs = {client.ipv4.split("/")[0]}/32, {client.ipv6.split("/")[0]}/128',
                        'PersistentKeepalive = 25'
                    ])

            # Add final newline
            config_lines.append('')

            # Write config file
            config_path = Path(self.config.config_dir) / f"{self.config.wg_interface}.conf"
            config_path.write_text('\n'.join(config_lines))
            config_path.chmod(0o600)

            # Start interface
            self._run_command(['wg-quick', 'up', self.config.wg_interface])

            # Add default forward rules (only for unrestricted clients)
            unrestricted_clients = [client for client in self.clients.values() 
                                  if not client.restricted_ips and not client.restricted_ip6s]
            
            for client in unrestricted_clients:
                client_ip = client.ipv4.split('/')[0]
                client_ip6 = client.ipv6.split('/')[0]
                
                # Add IPv4 rules
                self._run_command([
                    'iptables', '-A', 'FORWARD',
                    '-i', self.config.wg_interface,
                    '-s', client_ip,
                    '-j', 'ACCEPT'
                ])
                self._run_command([
                    'iptables', '-A', 'FORWARD',
                    '-o', self.config.wg_interface,
                    '-d', client_ip,
                    '-j', 'ACCEPT'
                ])
                
                # Add IPv6 rules
                self._run_command([
                    'ip6tables', '-A', 'FORWARD',
                    '-i', self.config.wg_interface,
                    '-s', client_ip6,
                    '-j', 'ACCEPT'
                ])
                self._run_command([
                    'ip6tables', '-A', 'FORWARD',
                    '-o', self.config.wg_interface,
                    '-d', client_ip6,
                    '-j', 'ACCEPT'
                ])

            # Update firewall rules for all restricted clients
            restricted_clients = [client for client in self.clients.values() 
                                if client.restricted_ips or client.restricted_ip6s]
            for client in restricted_clients:
                self._update_client_firewall_rules(client)

            # Verify interface is up
            if not Path(f"/sys/class/net/{self.config.wg_interface}").exists():
                raise RuntimeError("Failed to create WireGuard interface")

        except Exception as e:
            logger.error(f"Failed to update server config: {e}")
            raise
        
    def _get_server_ips(self) -> str:
        """Get server IPs from subnet."""
        ipv4_net = ipaddress.ip_network(self.config.ipv4_subnet)
        ipv6_net = ipaddress.ip_network(self.config.ipv6_subnet)
        
        return (
            f"{next(ipv4_net.hosts())}/{ipv4_net.prefixlen}, "
            f"{ipv6_net.network_address + 1}/{ipv6_net.prefixlen}"
        )

    def update_client_restrictions(self, name: str, 
                                 add_ips: Optional[List[str]] = None,
                                 remove_ips: Optional[List[str]] = None,
                                 add_ip6s: Optional[List[str]] = None,
                                 remove_ip6s: Optional[List[str]] = None,
                                 clear_all: bool = False) -> None:
        """Update IP restrictions for a client."""
        try:
            if name not in self.clients:
                console.print(f"[red]Client {name} not found[/red]")
                return

            client = self.clients[name]

            if clear_all:
                client.restricted_ips = []
                client.restricted_ip6s = []
                console.print(f"[yellow]Cleared all restrictions for client {name}[/yellow]")
            else:
                # Handle IPv4 restrictions
                if add_ips:
                    for ip in add_ips:
                        try:
                            ipaddress.ip_network(ip)
                            if ip not in client.restricted_ips:
                                client.restricted_ips.append(ip)
                        except ValueError as e:
                            console.print(f"[red]Invalid IPv4 address/network: {ip}[/red]")

                if remove_ips:
                    client.restricted_ips = [ip for ip in client.restricted_ips if ip not in remove_ips]

                # Handle IPv6 restrictions
                if add_ip6s:
                    for ip in add_ip6s:
                        try:
                            ipaddress.ip_network(ip)
                            if ip not in client.restricted_ip6s:
                                client.restricted_ip6s.append(ip)
                        except ValueError as e:
                            console.print(f"[red]Invalid IPv6 address/network: {ip}[/red]")

                if remove_ip6s:
                    client.restricted_ip6s = [ip for ip in client.restricted_ip6s if ip not in remove_ip6s]

            # Update firewall rules and save changes
            self._update_client_firewall_rules(client)
            self._save_clients()

            console.print(f"[green]Successfully updated restrictions for client {name}[/green]")
            if client.restricted_ips or client.restricted_ip6s:
                if client.restricted_ips:
                    console.print("[yellow]IPv4 restrictions: " + ", ".join(client.restricted_ips))
                if client.restricted_ip6s:
                    console.print("[yellow]IPv6 restrictions: " + ", ".join(client.restricted_ip6s))
            else:
                console.print("[yellow]No IP restrictions active[/yellow]")

        except Exception as e:
            logger.error(f"Failed to update client restrictions: {e}")
            raise

    def add_client(self, name: str, full_tunnel: Optional[bool] = None, 
                  restricted_ips: Optional[List[str]] = None,
                  restricted_ip6s: Optional[List[str]] = None) -> None:
        """Add a new WireGuard client."""
        try:
            if name in self.clients:
                console.print(f"[red]Client {name} already exists[/red]")
                return

            # Validate IP restrictions if provided
            if restricted_ips:
                for ip in restricted_ips:
                    try:
                        ipaddress.ip_network(ip)
                    except ValueError as e:
                        raise ValueError(f"Invalid IPv4 address/network: {ip}")

            if restricted_ip6s:
                for ip in restricted_ip6s:
                    try:
                        ipaddress.ip_network(ip)
                    except ValueError as e:
                        raise ValueError(f"Invalid IPv6 address/network: {ip}")

            # Generate client keys and get IPs
            private_key, public_key = self._generate_keypair()
            ips = self._get_next_available_ips()
            
            # Set tunnel mode
            use_full_tunnel = full_tunnel if full_tunnel is not None else self.config.full_tunnel
            allowed_ips = ['0.0.0.0/0', '::/0'] if use_full_tunnel else [
                self.config.ipv4_subnet,
                self.config.ipv6_subnet
            ]

            # Create client
            client = WireGuardClient(
                name=name,
                public_key=public_key,
                ipv4=ips['ipv4'],
                ipv6=ips['ipv6'],
                allowed_ips=allowed_ips,
                restricted_ips=restricted_ips or [],
                restricted_ip6s=restricted_ip6s or [],
                created_at=datetime.now().isoformat()
            )

            # Generate client config
            config_content = self._create_client_config(client, private_key)
            
            # Save client config
            config_path = Path(self.config.config_dir) / f"{name}.conf"
            config_path.write_text(config_content)
            config_path.chmod(0o600)

            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(config_content)
            qr.make(fit=True)
            qr.make_image(fill_color="black", back_color="white").save(f"{name}_qr.png")

            # Update clients
            self.clients[name] = client
            self._save_clients()
            
            # Update firewall rules
            self._update_client_firewall_rules(client)
            
            # Update server config
            self._update_server_config()

            console.print(f"[green]Successfully created client {name}[/green]")
            console.print(f"Configuration saved to: {config_path}")
            console.print(f"QR code saved to: {name}_qr.png")
            if client.restricted_ips:
                console.print("[yellow]IPv4 restrictions: " + ", ".join(client.restricted_ips))
            if client.restricted_ip6s:
                console.print("[yellow]IPv6 restrictions: " + ", ".join(client.restricted_ip6s))

        except Exception as e:
            logger.error(f"Failed to add client: {e}")
            raise

    def _create_client_config(self, client: WireGuardClient, private_key: str) -> str:
        """Create client configuration."""
        return '\n'.join([
            '[Interface]',
            f'PrivateKey = {private_key}',
            f'Address = {client.ipv4}, {client.ipv6}',
            'DNS = 8.8.8.8, 8.8.4.4',
            '',
            '[Peer]',
            f'PublicKey = {self.config.server_public_key}',
            f'AllowedIPs = {", ".join(client.allowed_ips)}',
            f'Endpoint = {self.config.endpoint}:{self.config.server_port}',
            'PersistentKeepalive = 25',
            ''  # Add empty string to create final newline
        ])

    def remove_client(self, name: str) -> None:
        """Remove a WireGuard client."""
        try:
            if name not in self.clients:
                console.print(f"[red]Client {name} not found[/red]")
                return

            # Confirm deletion
            if not Confirm.ask(f"Are you sure you want to remove client {name}?"):
                return

            # Clean up firewall rules before removing client
            self._update_client_firewall_rules(self.clients[name])

            # Remove client config file
            config_path = Path(self.config.config_dir) / f"{name}.conf"
            if config_path.exists():
                config_path.unlink()

            # Remove QR code if exists
            qr_path = Path(f"{name}_qr.png")
            if qr_path.exists():
                qr_path.unlink()

            # Remove client and update
            del self.clients[name]
            self._save_clients()
            self._update_server_config()

            console.print(f"[green]Successfully removed client {name}[/green]")

        except Exception as e:
            logger.error(f"Failed to remove client: {e}")
            raise

    def list_clients(self) -> None:
        """List all WireGuard clients."""
        try:
            if not self.clients:
                console.print("[yellow]No clients found[/yellow]")
                return

            table = Table(
                title="WireGuard Clients",
                show_header=True,
                header_style="bold",
                show_lines=True
            )
            
            table.add_column("Name", style="cyan")
            table.add_column("IPv4", style="green")
            table.add_column("IPv6", style="green")
            table.add_column("Tunnel Mode", style="yellow")
            table.add_column("Restrictions", style="red", max_width=40)
            table.add_column("Created", style="blue")

            for name, client in sorted(self.clients.items()):
                tunnel_mode = "Full" if "0.0.0.0/0" in client.allowed_ips else "Split"
                created = datetime.fromisoformat(client.created_at).strftime("%Y-%m-%d %H:%M") if client.created_at else "Unknown"
                
                restrictions = []
                if client.restricted_ips:
                    restrictions.append("IPv4: " + ", ".join(client.restricted_ips))
                if client.restricted_ip6s:
                    restrictions.append("IPv6: " + ", ".join(client.restricted_ip6s))
                
                restriction_text = "\n".join(restrictions) if restrictions else "None"
                
                table.add_row(
                    name,
                    client.ipv4,
                    client.ipv6,
                    tunnel_mode,
                    restriction_text,
                    created
                )

            console.print(table)

        except Exception as e:
            logger.error(f"Failed to list clients: {e}")
            raise
        
def main():
    parser = argparse.ArgumentParser(description="WireGuard VPN Manager")
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to config file")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Initialize command
    subparsers.add_parser("init", help="Initialize WireGuard server")
    
    # Add client command
    add_parser = subparsers.add_parser("add", help="Add a new client")
    add_parser.add_argument("name", help="Client name")
    add_parser.add_argument("--full-tunnel", action="store_true", help="Use full tunnel mode")
    add_parser.add_argument("--split-tunnel", action="store_true", help="Use split tunnel mode")
    add_parser.add_argument("--restrict-to", nargs="+", metavar="IP", 
        help="List of IP addresses/networks this client can access (both IPv4 and IPv6)")
    
    # Remove client command
    remove_parser = subparsers.add_parser("remove", help="Remove a client")
    remove_parser.add_argument("name", help="Client name")
    
    # List clients command
    subparsers.add_parser("list", help="List all clients")
    
    # Manage restrictions command
    restrict_parser = subparsers.add_parser("restrict", 
        help="Manage client IP restrictions")
    restrict_parser.add_argument("name", help="Client name")
    restrict_parser.add_argument("--allow", nargs="+", metavar="IP",
        help="Add IP addresses/networks to allowed list")
    restrict_parser.add_argument("--deny", nargs="+", metavar="IP",
        help="Remove IP addresses/networks from allowed list")
    restrict_parser.add_argument("--clear", action="store_true",
        help="Remove all IP restrictions")
    
    args = parser.parse_args()

    try:
        manager = WireGuardManager(args.config)
        
        if args.command == "init":
            manager.initialize()
        
        elif args.command == "add":
            if args.full_tunnel and args.split_tunnel:
                console.print("[red]Cannot specify both --full-tunnel and --split-tunnel[/red]")
                sys.exit(1)
            full_tunnel = True if args.full_tunnel else False if args.split_tunnel else None
            
            # Split IPs into v4 and v6 automatically
            if args.restrict_to:
                ipv4_list = []
                ipv6_list = []
                for ip in args.restrict_to:
                    try:
                        parsed_ip = ipaddress.ip_network(ip)
                        if parsed_ip.version == 4:
                            ipv4_list.append(ip)
                        else:
                            ipv6_list.append(ip)
                    except ValueError as e:
                        console.print(f"[red]Invalid IP address/network: {ip}[/red]")
                        sys.exit(1)
                manager.add_client(args.name, full_tunnel, ipv4_list, ipv6_list)
            else:
                manager.add_client(args.name, full_tunnel)
        
        elif args.command == "remove":
            manager.remove_client(args.name)
        
        elif args.command == "list":
            manager.list_clients()
            
        elif args.command == "restrict":
            if not any([args.allow, args.deny, args.clear]):
                console.print("[red]Please specify at least one action: --allow, --deny, or --clear[/red]")
                sys.exit(1)
                
            # Process restrictions
            add_ipv4 = []
            add_ipv6 = []
            remove_ipv4 = []
            remove_ipv6 = []
            
            if args.allow:
                for ip in args.allow:
                    try:
                        parsed_ip = ipaddress.ip_network(ip)
                        if parsed_ip.version == 4:
                            add_ipv4.append(ip)
                        else:
                            add_ipv6.append(ip)
                    except ValueError as e:
                        console.print(f"[red]Invalid IP address/network: {ip}[/red]")
                        sys.exit(1)
                        
            if args.deny:
                for ip in args.deny:
                    try:
                        parsed_ip = ipaddress.ip_network(ip)
                        if parsed_ip.version == 4:
                            remove_ipv4.append(ip)
                        else:
                            remove_ipv6.append(ip)
                    except ValueError as e:
                        console.print(f"[red]Invalid IP address/network: {ip}[/red]")
                        sys.exit(1)
            
            manager.update_client_restrictions(
                args.name,
                add_ips=add_ipv4,
                remove_ips=remove_ipv4,
                add_ip6s=add_ipv6,
                remove_ip6s=remove_ipv6,
                clear_all=args.clear
            )

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()