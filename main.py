#!/usr/bin/env python3
import click
from rich.console import Console
from rich.table import Table
import json
from pathlib import Path
import logging
import utils
import config

console = Console()
logger = logging.getLogger(__name__)

def initialize_server(cfg):
    """Initialize WireGuard server if not already configured."""
    try:
        # Install WireGuard and get keys if needed
        private_key, public_key = utils.install_wireguard()
        
        if not cfg:
            cfg = {}
        
        # If we got new keys from installation, use them
        if private_key and public_key:
            cfg['server_private_key'] = private_key
            cfg['server_public_key'] = public_key
            
        endpoint = utils.get_server_endpoint()
        
        # Set default values if not present
        cfg.setdefault('wg_interface', 'wg0')
        cfg.setdefault('endpoint', endpoint)
        cfg.setdefault('ipv4_subnet', '10.0.0.0/24')
        cfg.setdefault('ipv6_subnet', 'fd00::/64')
        cfg.setdefault('server_port', 51820)
        cfg.setdefault('config_dir', '/etc/wireguard')
        cfg.setdefault('interface_name', 'eth0')
        
        ipv4 = utils.get_server_ips()['ipv4']
        ipv6 = utils.get_server_ips()['ipv6']
        
        # Ensure we have server keys
        if 'server_private_key' not in cfg or 'server_public_key' not in cfg:
            private_key, public_key = utils.generate_keypair()
            cfg['server_private_key'] = private_key
            cfg['server_public_key'] = public_key
        
        # Create initial server config
        interface = {
            'name': cfg['wg_interface'],
            'private_key': cfg['server_private_key'],
            'port': cfg['server_port'],
            'interface_name': cfg['interface_name']
        }
        utils.update_server_config(interface, [])
        
        config.save_config(cfg, 'config.yaml')
        return cfg
    except Exception as e:
        logger.error(f"Failed to initialize server: {e}")
        raise

@click.group()
@click.option('--config-file', '-c', type=str, default='config.yaml',
              help='Path to config file')
@click.pass_context
def cli(ctx, config_file):
    """WireGuard VPN Manager"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config.load_config(config_file)
    ctx.obj['config'] = initialize_server(ctx.obj['config'])

@cli.command(name='add')
@click.argument('name')
@click.option('--allowed-ips', '-a', multiple=True, 
              help='Allowed IP addresses for this client')
@click.option('--peer-access/--no-peer-access', default=False,
              help='Allow access to other clients')
@click.option('--full-tunnel/--split-tunnel', default=None,
              help='Route all traffic through VPN or only VPN subnet traffic')
@click.pass_context
def add_client(ctx, name, allowed_ips, peer_access, full_tunnel):
    """Add a new WireGuard client."""
    try:
        cfg = ctx.obj['config']
        
        # If full_tunnel not specified on command line, use config default
        if full_tunnel is None:
            full_tunnel = cfg.get('full_tunnel', False)

        # If full tunnel is requested, route all traffic through VPN
        if full_tunnel:
            allowed_ips = ['0.0.0.0/0', '::/0']
        elif not allowed_ips:
            # Default to VPN subnets only for split tunnel
            allowed_ips = [cfg['ipv4_subnet'], cfg['ipv6_subnet']]

        clients_file = Path('clients.json')
        clients = json.loads(clients_file.read_text()) if clients_file.exists() else {}
        
        if utils.client_exists(name):
            logger.error(f"Client {name} already exists")
            return

        # Generate client keys first
        private_key, public_key = utils.generate_keypair()

        # Get next available IP
        next_ips = utils.get_next_available_ips()
        client_ipv4 = next_ips['ipv4']
        client_ipv6 = next_ips['ipv6']
        
        # Save client information first
        clients[name] = {
            'public_key': public_key,
            'ipv4': client_ipv4,
            'ipv6': client_ipv6,
            'allowed_ips': list(allowed_ips) if allowed_ips else [],
            'peer_access': peer_access
        }
        clients_file.write_text(json.dumps(clients, indent=2))

        # Update server configuration
        interface = {
            'name': cfg['wg_interface'],
            'private_key': cfg['server_private_key'],
            'address': f"{cfg['ipv4_subnet']}, {cfg['ipv6_subnet']}",
            'port': cfg['server_port'],
            'interface_name': cfg['interface_name']
        }
        utils.update_server_config(interface, [
            {'public_key': c['public_key'], 'ipv4': c['ipv4'], 'ipv6': c['ipv6']}
            for c in clients.values()
        ])

        # Create and save client config
        client_config = utils.create_client_config(
            name, private_key, public_key,
            cfg['server_public_key'],
            client_ipv4,
            client_ipv6,
            utils.get_server_endpoint(),
            cfg['server_port'],
            allowed_ips
        )
        
        utils.save_client_config(cfg['config_dir'], name, client_config)
        utils.generate_qr_code(client_config, f"{name}_qr.png")

        # Setup firewall rules last (non-critical)
        peer_ips = [c['ipv4'] for c in clients.values()] if peer_access else None
        utils.manage_firewall_rules(
            client_ipv4=client_ipv4.split('/')[0],  # Remove CIDR notation
            client_ipv6=client_ipv6.split('/')[0],  # Remove CIDR notation
            allowed_ips=allowed_ips,
            peer_ips=peer_ips
        )

        console.print(f"[green]Successfully created client {name}[/green]")
        console.print(f"Configuration saved to: {cfg['config_dir']}/{name}.conf")
        console.print(f"QR code saved to: {name}_qr.png")

    except Exception as e:
        console.print(f"[red]Error creating client: {e}[/red]")

@cli.command(name='remove')
@click.argument('name')
@click.pass_context
def remove_client(ctx, name):
    """Remove a WireGuard client."""
    try:
        cfg = ctx.obj['config']
        clients_file = Path('clients.json')
        clients = utils.get_clients()
        
        if not utils.client_exists(name):
            logger.error(f"Client {name} not found")
            return

        clients = json.loads(clients_file.read_text())
        if name not in clients:
            console.print(f"[red]Client {name} not found[/red]")
            return

        # Remove client config file
        client_config = Path(cfg['config_dir']) / f"{name}.conf"
        if client_config.exists():
            client_config.unlink()

        # Remove firewall rules
        utils.manage_firewall_rules(
            client_ipv4=clients[name]['ipv4'].split('/')[0],
            client_ipv6=clients[name]['ipv6'].split('/')[0],
            action='remove'
        )

        # Remove from clients list
        del clients[name]
        clients_file.write_text(json.dumps(clients, indent=2))

        # Update server configuration
        interface = {
            'name': cfg['wg_interface'],
            'private_key': cfg['server_private_key'],
            'port': cfg['server_port'],
            'interface_name': cfg['interface_name']
        }
        # Make sure to pass both IPv4 and IPv6 for remaining clients
        utils.update_server_config(interface, [
            {
                'public_key': c['public_key'],
                'ipv4': c['ipv4'],
                'ipv6': c['ipv6']
            }
            for c in clients.values()
        ])

        console.print(f"[green]Successfully removed client {name}[/green]")

    except Exception as e:
        console.print(f"[red]Error removing client: {e}[/red]")

@cli.command(name='list')
@click.pass_context
def list_clients(ctx):
    """List all WireGuard clients."""
    try:
        clients_file = Path('clients.json')
        if not clients_file.exists():
            console.print("[yellow]No clients found[/yellow]")
            return

        clients = json.loads(clients_file.read_text())
        if not clients:
            console.print("[yellow]No clients found[/yellow]")
            return
        # separator between items
        table = Table(title="WireGuard Clients", show_header=True, header_style="bold", show_lines=True)
        table.add_column("Name")
        table.add_column("IPv4")
        table.add_column("IPv6")
        table.add_column("Allowed IPs")
        table.add_column("Peer Access")

        for name, client in clients.items():
            table.add_row(
                name,
                client['ipv4'],
                client['ipv6'],
                '\n'.join(client['allowed_ips'] or ['All']),
                'Yes' if client['peer_access'] else 'No'
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error listing clients: {e}[/red]")

if __name__ == '__main__':
    cli()