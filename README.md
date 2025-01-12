# Wireguard Manager

```
wgm list
wgm add ian
wgm remove ian
wgm config ian
```

```
# Add client with restrictions to specific IPs (both IPv4 and IPv6 automatically handled)
wgm add client1 --restrict-to 192.168.1.100 2001:db8::1

# Add client with full tunnel mode
wgm add client1 --full-tunnel
```

```
# Allow access to additional IPs
wgm restrict client1 --allow 192.168.1.200 2001:db8::2

# Remove access to specific IPs
wgm restrict client1 --deny 192.168.1.100 2001:db8::1

# Clear all restrictions
wgm restrict client1 --clear

# You can combine operations
wgm restrict client1 --allow 10.0.0.1 --deny 192.168.1.100
```
