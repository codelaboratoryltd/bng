# ZTP (Zero Touch Provisioning) Deployment Guide

The Nexus ZTP server is a DHCP server that automatically provisions OLT-BNG devices on a management network. When a new device boots, ZTP assigns it a management IP and tells it how to reach Nexus via DHCP options, enabling fully automated device registration.

## How It Works

```
New OLT-BNG device boots
    |
    v
1. DHCP DISCOVER  --->  ZTP Server (port 67)
    |
    v
2. DHCP OFFER     <---  Management IP + Nexus URL (Option 43/224)
    |
    v
3. DHCP REQUEST   --->  ZTP Server
    |
    v
4. DHCP ACK       <---  Lease confirmed
    |
    v
5. POST /api/v1/bootstrap  --->  Nexus API
    |                              (serial + MAC)
    v
6. Device receives node_id, polls until configured
```

### DHCP Message Flow

**DISCOVER**: The device broadcasts a DHCP DISCOVER on the management interface. The ZTP server extracts the device's hostname (Option 12) and Vendor Class Identifier (Option 60) for logging.

**OFFER**: The server offers a management IP from the configured pool. If the device has an existing lease (by MAC), it re-offers the same IP.

**REQUEST**: The device requests the offered IP. The server creates or updates the lease. If the device requests an IP that conflicts with its existing lease, a NAK is sent.

**ACK**: The server confirms the lease and includes:
- Standard DHCP options: subnet mask, default gateway, DNS servers, lease time
- **Option 43** (Vendor-Specific Information): Nexus URL in TLV format (Type=1, Length, Value)
- **Option 224** (Private Use): Nexus URL as a plain string for simpler parsing

**RELEASE**: When a device releases its lease, the IP is returned to the pool.

### Nexus URL Discovery

The Nexus API URL is delivered to devices via two DHCP options for compatibility:

- **Option 43** uses a TLV (Type-Length-Value) encoding: byte 0 is the type (1 = Nexus URL), byte 1 is the length, followed by the URL bytes
- **Option 224** contains the URL as a plain UTF-8 string

Devices should check Option 224 first (simpler to parse), falling back to Option 43.

## Configuration

The ZTP server is configured with the following parameters:

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `Interface` | yes | - | Network interface to listen on (e.g. `eth0`) |
| `Network` | yes | - | Management network CIDR (e.g. `192.168.100.0/24`) |
| `RangeStart` | no | auto | Start of IP allocation range |
| `RangeEnd` | no | auto | End of IP allocation range |
| `Gateway` | no | - | Default gateway for management network |
| `DNS` | no | - | DNS servers |
| `LeaseTime` | no | 24h | DHCP lease duration |
| `NexusURL` | yes | - | URL of the Nexus API (e.g. `http://nexus.local:9000`) |

When `RangeStart` and `RangeEnd` are not specified, the server uses the full network range excluding the network address, broadcast address, gateway, and its own IP.

### Lease Management

- Leases are stored in memory (not persisted across restarts)
- Expired leases are cleaned up every 5 minutes
- IPs from expired or released leases are returned to the pool

## Privilege Requirements

The ZTP DHCP server binds to **UDP port 67**, which is a privileged port (below 1024). This means the Nexus process needs elevated privileges to start the ZTP server.

### Option 1: Run as root (not recommended for production)

```bash
sudo /usr/local/bin/nexus --ztp-enabled
```

### Option 2: Linux capabilities (recommended)

Grant only the specific capability needed to bind privileged ports:

```bash
sudo setcap cap_net_bind_service=+ep /usr/local/bin/nexus
```

This allows the binary to bind to port 67 without running as root. The capability persists across executions but must be re-applied after recompiling or replacing the binary.

To verify the capability is set:

```bash
getcap /usr/local/bin/nexus
# Expected output: /usr/local/bin/nexus cap_net_bind_service=ep
```

### Option 3: systemd socket activation

If running under systemd, you can configure the service to receive the socket from systemd:

```ini
# /etc/systemd/system/nexus-ztp.socket
[Socket]
ListenDatagram=0.0.0.0:67
BindIPv6Only=default

[Install]
WantedBy=sockets.target
```

```ini
# /etc/systemd/system/nexus-ztp.service
[Service]
ExecStart=/usr/local/bin/nexus --ztp-enabled
User=nexus
Group=nexus
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

### Option 4: Container deployment

When running in a container (Docker/Kubernetes), add the capability:

```yaml
# Kubernetes securityContext
securityContext:
  capabilities:
    add: ["NET_BIND_SERVICE"]
  runAsNonRoot: true
```

```bash
# Docker
docker run --cap-add=NET_BIND_SERVICE nexus --ztp-enabled
```

## Security Considerations

### Network Isolation

The ZTP server should run on a **dedicated management VLAN** that is isolated from subscriber traffic:

- Management VLAN carries only device provisioning and control traffic
- Subscriber VLANs carry customer data
- Firewall rules should prevent cross-VLAN access from subscriber networks to the management network

### DHCP Security

- The ZTP server only responds on the configured interface -- it does not listen on all interfaces
- Leases are tracked by MAC address to prevent IP exhaustion from rogue devices
- The server validates DHCP message types and ignores malformed packets

### Bootstrap Security

Devices that register via the bootstrap API start in `"pending"` status and cannot receive configuration until an administrator explicitly assigns them to a site via `PUT /api/v1/devices/{node_id}`. This two-step process prevents unauthorized devices from joining the network automatically.

For additional security:

- **Inventory pre-registration**: Use `POST /api/v1/devices/import` to pre-register known device serial numbers. When a device bootstraps, it matches against the inventory by serial or MAC.
- **mTLS (future)**: The bootstrap request includes an optional `public_key` field for future mutual TLS authentication between devices and Nexus.

### Credential Protection

The Nexus URL provided via DHCP options should use HTTPS in production. The URL is transmitted in cleartext over DHCP, so the management network must be trusted or encrypted at a lower layer (e.g. MACsec).

## Callbacks

The ZTP server provides two event callbacks for integration with monitoring or logging:

- `OnDeviceDiscovered(mac, hostname, vendorInfo)` -- called when a DHCP DISCOVER is received
- `OnDeviceLeased(mac, ip)` -- called when a DHCP ACK is sent (new lease or renewal)

These can be used to trigger alerts for unknown devices or to feed a real-time device inventory.
