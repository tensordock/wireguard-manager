import yaml
from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler
import logging
import sys

# Configure Rich logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("wireguard_manager")

DEFAULT_CONFIG = {
    'ipv4_subnet': '10.0.0.0/24',
    'ipv6_subnet': 'fd00::/80',
    'wg_interface': 'wg0',
    'server_port': 51820,
    'config_dir': '/etc/wireguard',
    'interface_name': 'eth0',
    'server_public_key': '',  # Will be populated when server is initialized
    'server_private_key': '',  # Will be populated when server is initialized
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