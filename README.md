# Wireguard Manager

```
# Add client with restrictions to specific IPs (both IPv4 and IPv6 automatically handled)
sudo python3 wireguard.py add client1 --restrict-to 192.168.1.100 2001:db8::1

# Add client with full tunnel mode
sudo python3 wireguard.py add client1 --full-tunnel
```

```
# Allow access to additional IPs
sudo python3 wireguard.py restrict client1 --allow 192.168.1.200 2001:db8::2

# Remove access to specific IPs
sudo python3 wireguard.py restrict client1 --deny 192.168.1.100 2001:db8::1

# Clear all restrictions
sudo python3 wireguard.py restrict client1 --clear

# You can combine operations
sudo python3 wireguard.py restrict client1 --allow 10.0.0.1 --deny 192.168.1.100
```