# Nexus API Reference

Nexus exposes an HTTP API for managing IP pools, subscriber allocations, cluster nodes, and device bootstrap/registration.

All API endpoints are served under the `/api/v1` prefix. Request bodies must be JSON with a maximum size of 1 MB. Responses use `Content-Type: application/json`.

## Table of Contents

- [Health Endpoints](#health-endpoints)
  - [GET /health](#get-health)
  - [GET /ready](#get-ready)
- [Pools](#pools)
  - [GET /api/v1/pools](#list-pools)
  - [POST /api/v1/pools](#create-pool)
  - [GET /api/v1/pools/{id}](#get-pool)
  - [DELETE /api/v1/pools/{id}](#delete-pool)
- [Allocations](#allocations)
  - [GET /api/v1/allocations](#list-allocations)
  - [POST /api/v1/allocations](#create-allocation)
  - [GET /api/v1/allocations/{subscriber_id}](#get-allocation)
  - [DELETE /api/v1/allocations/{subscriber_id}](#delete-allocation)
  - [POST /api/v1/allocations/{subscriber_id}/renew](#renew-allocation)
  - [GET /api/v1/allocations/expiring](#list-expiring-allocations)
- [Backup Allocations](#backup-allocations)
  - [POST /api/v1/pools/{pool_id}/backup-allocations](#create-backup-allocations)
  - [GET /api/v1/nodes/{node_id}/backup-allocations](#list-node-backup-allocations)
- [Nodes](#nodes)
  - [GET /api/v1/nodes](#list-nodes)
  - [GET /api/v1/nodes/{node_id}/allocations](#list-node-allocations)
- [Bootstrap (Device Registration)](#bootstrap)
  - [POST /api/v1/bootstrap](#bootstrap-device)
  - [GET /api/v1/devices](#list-devices)
  - [GET /api/v1/devices/{node_id}](#get-device)
  - [PUT /api/v1/devices/{node_id}](#assign-device)
  - [DELETE /api/v1/devices/{node_id}](#delete-device)
  - [POST /api/v1/devices/import](#import-devices)
- [Error Format](#error-format)
- [Validation Rules](#validation-rules)

---

## Health Endpoints

### GET /health

Returns server health status. Always returns `200 OK` if the process is running.

**Response:**

| Status | Body |
|--------|------|
| `200 OK` | `ok` (plain text) |

```bash
curl http://localhost:9000/health
```

### GET /ready

Returns readiness status. In standalone mode, always returns ready. In P2P cluster mode (with DNS discovery), returns `503` until peer discovery completes.

**Response:**

| Status | Body |
|--------|------|
| `200 OK` | `ready` or `ready (peers: N)` (plain text) |
| `503 Service Unavailable` | `waiting for peer discovery` (plain text) |

```bash
curl http://localhost:9000/ready
```

---

## Pools

### List Pools

**GET /api/v1/pools**

Returns all configured IP pools.

**Response: `200 OK`**

```json
{
  "pools": [
    {
      "id": "residential-v4",
      "cidr": "10.0.0.0/16",
      "prefix": 24,
      "exclusions": ["10.0.0.0/24"],
      "metadata": {"region": "east"},
      "sharding_factor": 4,
      "backup_ratio": 0.1,
      "gateway": "10.0.0.1",
      "dns": ["8.8.8.8", "8.8.4.4"]
    }
  ],
  "count": 1
}
```

```bash
curl http://localhost:9000/api/v1/pools
```

### Create Pool

**POST /api/v1/pools**

Creates a new IP pool and adds it to the hashring for immediate use.

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Pool identifier (alphanumeric, hyphens, underscores, dots; max 128 chars) |
| `cidr` | string | yes | Pool CIDR (must be a network address, e.g. `10.0.0.0/16`) |
| `prefix` | int | no | Delegated prefix length for subnet sharding (must be >= CIDR mask) |
| `exclusions` | string[] | no | IP addresses or CIDRs to exclude (max 100 entries) |
| `metadata` | object | no | Key-value metadata (keys: letters/digits/hyphens/underscores, max 64 chars; values: max 512 chars) |
| `sharding_factor` | int | no | Sharding factor for hashring distribution (0-256) |
| `backup_ratio` | float | no | Fraction of pool reserved for backup allocations (0.0-1.0) |
| `gateway` | string | no | Default gateway IP address |
| `dns` | string[] | no | DNS server IP addresses |

**Response: `201 Created`**

```json
{
  "id": "residential-v4",
  "cidr": "10.0.0.0/16",
  "prefix": 24,
  "exclusions": [],
  "metadata": null,
  "sharding_factor": 0,
  "backup_ratio": 0,
  "gateway": "",
  "dns": null
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Validation failure (invalid CIDR, pool ID, prefix, etc.) |
| `413 Request Entity Too Large` | Request body exceeds 1 MB |
| `500 Internal Server Error` | Storage failure |

```bash
curl -X POST http://localhost:9000/api/v1/pools \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "residential-v4",
    "cidr": "10.0.0.0/16",
    "prefix": 24,
    "gateway": "10.0.0.1",
    "dns": ["8.8.8.8"]
  }'
```

### Get Pool

**GET /api/v1/pools/{id}**

Returns a single pool by ID.

**Response: `200 OK`**

```json
{
  "id": "residential-v4",
  "cidr": "10.0.0.0/16",
  "prefix": 24,
  "exclusions": [],
  "metadata": null,
  "sharding_factor": 0,
  "backup_ratio": 0,
  "gateway": "10.0.0.1",
  "dns": ["8.8.8.8"]
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Invalid pool ID format |
| `404 Not Found` | Pool does not exist |

```bash
curl http://localhost:9000/api/v1/pools/residential-v4
```

### Delete Pool

**DELETE /api/v1/pools/{id}**

Removes a pool from storage and the hashring.

**Response: `204 No Content`**

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Invalid pool ID format |
| `500 Internal Server Error` | Storage failure |

```bash
curl -X DELETE http://localhost:9000/api/v1/pools/residential-v4
```

---

## Allocations

### List Allocations

**GET /api/v1/allocations?pool_id={pool_id}**

Returns all allocations for a pool. The `pool_id` query parameter is required.

**Query Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `pool_id` | yes | Pool ID to list allocations for |

**Response: `200 OK`**

```json
{
  "allocations": [
    {
      "pool_id": "residential-v4",
      "subscriber_id": "sub-001",
      "ip": "10.0.1.5",
      "timestamp": "2025-01-15T10:30:00Z",
      "node_id": "node-abc123",
      "backup_node_id": "",
      "is_backup": false,
      "ttl": 3600,
      "epoch": 42,
      "expires_at": "2025-01-15T11:30:00Z",
      "last_renewed": "2025-01-15T10:30:00Z",
      "alloc_type": "session"
    }
  ],
  "count": 1
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Missing or invalid `pool_id` |
| `500 Internal Server Error` | Storage failure |

```bash
curl 'http://localhost:9000/api/v1/allocations?pool_id=residential-v4'
```

### Create Allocation

**POST /api/v1/allocations**

Creates a new IP allocation for a subscriber. If no `ip` is specified, one is allocated from the hashring.

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pool_id` | string | yes | Pool to allocate from |
| `subscriber_id` | string | yes | Subscriber identifier (alphanumeric, hyphens, underscores, colons, dots, @; max 256 chars) |
| `ip` | string | no | Specific IP to assign (if omitted, allocated automatically) |
| `node_id` | string | no | Primary node that owns this allocation |
| `ttl` | int | no | TTL in seconds (0 = permanent) |
| `alloc_type` | string | no | Allocation type: `"session"`, `"sticky"`, or `"permanent"` |

**Response: `201 Created`**

```json
{
  "pool_id": "residential-v4",
  "subscriber_id": "sub-001",
  "ip": "10.0.1.5",
  "timestamp": "2025-01-15T10:30:00Z",
  "node_id": "node-abc123",
  "ttl": 3600,
  "epoch": 42,
  "expires_at": "2025-01-15T11:30:00Z",
  "last_renewed": "2025-01-15T10:30:00Z",
  "alloc_type": "session"
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Validation failure (invalid pool ID, subscriber ID, IP, etc.) |
| `409 Conflict` | Subscriber already has an allocation |
| `413 Request Entity Too Large` | Request body exceeds 1 MB |
| `500 Internal Server Error` | Storage failure |
| `503 Service Unavailable` | No IPs available in pool |

```bash
curl -X POST http://localhost:9000/api/v1/allocations \
  -H 'Content-Type: application/json' \
  -d '{
    "pool_id": "residential-v4",
    "subscriber_id": "sub-001",
    "node_id": "node-abc123",
    "ttl": 3600,
    "alloc_type": "session"
  }'
```

### Get Allocation

**GET /api/v1/allocations/{subscriber_id}**

Returns the allocation for a specific subscriber.

**Response: `200 OK`**

Returns an allocation object (same schema as in the list response).

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Invalid subscriber ID format |
| `404 Not Found` | No allocation for this subscriber |

```bash
curl http://localhost:9000/api/v1/allocations/sub-001
```

### Delete Allocation

**DELETE /api/v1/allocations/{subscriber_id}?pool_id={pool_id}**

Removes a subscriber's IP allocation. If `pool_id` is not provided, the system looks up the allocation first to determine the pool.

**Query Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `pool_id` | no | Pool ID (speeds up deletion if known) |

**Response: `204 No Content`**

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Invalid subscriber ID or pool ID format |
| `404 Not Found` | No allocation for this subscriber |
| `500 Internal Server Error` | Storage failure |

```bash
curl -X DELETE 'http://localhost:9000/api/v1/allocations/sub-001?pool_id=residential-v4'
```

### Renew Allocation

**POST /api/v1/allocations/{subscriber_id}/renew**

Renews an allocation's TTL. Used for session keepalives.

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ttl` | int | no | New TTL in seconds (0 = use original TTL) |

**Response: `200 OK`**

Returns the renewed allocation object.

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Invalid subscriber ID or malformed JSON |
| `404 Not Found` | No allocation for this subscriber |
| `413 Request Entity Too Large` | Request body exceeds 1 MB |
| `500 Internal Server Error` | Storage failure |

```bash
curl -X POST http://localhost:9000/api/v1/allocations/sub-001/renew \
  -H 'Content-Type: application/json' \
  -d '{"ttl": 7200}'
```

### List Expiring Allocations

**GET /api/v1/allocations/expiring?within={seconds}**

Returns allocations that will expire within the specified time window. Defaults to 3600 seconds (1 hour).

**Query Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `within` | no | `3600` | Seconds from now to check for expiring allocations |

**Response: `200 OK`**

```json
{
  "allocations": [],
  "count": 0,
  "expiring_before": "2025-01-15T11:30:00Z"
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Invalid `within` parameter (not a number) |
| `500 Internal Server Error` | Storage failure |

```bash
curl 'http://localhost:9000/api/v1/allocations/expiring?within=1800'
```

---

## Backup Allocations

### Create Backup Allocations

**POST /api/v1/pools/{pool_id}/backup-allocations**

Assigns backup copies of a pool's allocations to a standby node for HA failover. Skips allocations that already have a backup or are owned by the backup node itself. If the pool has a `backup_ratio`, limits the number of backup assignments accordingly.

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `backup_node_id` | string | yes | Standby node to receive backup allocations |

**Response: `201 Created`**

```json
{
  "pool_id": "residential-v4",
  "backup_node_id": "node-standby-1",
  "allocations_count": 150
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Invalid pool ID or node ID |
| `404 Not Found` | Pool does not exist |
| `413 Request Entity Too Large` | Request body exceeds 1 MB |
| `500 Internal Server Error` | Storage failure |

```bash
curl -X POST http://localhost:9000/api/v1/pools/residential-v4/backup-allocations \
  -H 'Content-Type: application/json' \
  -d '{"backup_node_id": "node-standby-1"}'
```

### List Node Backup Allocations

**GET /api/v1/nodes/{node_id}/backup-allocations**

Returns all backup allocations held by a specific node (allocations where this node is the backup).

**Response: `200 OK`**

```json
{
  "allocations": [],
  "count": 0,
  "backup_node_id": "node-standby-1"
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Invalid node ID format |
| `500 Internal Server Error` | Storage failure |

```bash
curl http://localhost:9000/api/v1/nodes/node-standby-1/backup-allocations
```

---

## Nodes

### List Nodes

**GET /api/v1/nodes**

Returns all cluster nodes with their status. A node is "active" if the current time is before its `best_before` timestamp, otherwise "expired".

**Response: `200 OK`**

```json
{
  "nodes": [
    {
      "id": "node-abc123",
      "best_before": "2025-01-15T12:00:00Z",
      "metadata": {"address": "10.1.0.5:9000"},
      "status": "active"
    }
  ],
  "count": 1
}
```

```bash
curl http://localhost:9000/api/v1/nodes
```

### List Node Allocations

**GET /api/v1/nodes/{node_id}/allocations**

Returns all primary allocations owned by a specific node.

**Response: `200 OK`**

```json
{
  "allocations": [],
  "count": 0,
  "node_id": "node-abc123"
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Invalid node ID format |
| `500 Internal Server Error` | Storage failure |

```bash
curl http://localhost:9000/api/v1/nodes/node-abc123/allocations
```

---

## Bootstrap

The bootstrap endpoints manage OLT-BNG device registration and site assignment. They are only available when the device store is enabled on the server.

### Bootstrap Device

**POST /api/v1/bootstrap**

Registers a new device or re-registers an existing one. New devices start in `"pending"` status until assigned to a site. Re-registering updates `last_seen` and mutable fields (firmware, public key).

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `serial` | string | yes | Hardware serial number (4-32 uppercase alphanumeric chars) |
| `mac` | string | yes | Primary MAC address (any common format, normalized to `AA:BB:CC:DD:EE:FF`) |
| `model` | string | no | Device model identifier (max 64 chars) |
| `firmware` | string | no | Current firmware version (max 64 chars) |
| `public_key` | string | no | Device public key for mTLS (max 4096 chars) |

The `node_id` is generated deterministically from `serial` and `mac` using SHA-256: `node-{first 16 hex chars of sha256(serial:MAC)}`.

**Response: `201 Created` (new device) or `200 OK` (re-registration)**

Pending device response:

```json
{
  "node_id": "node-a1b2c3d4e5f6a7b8",
  "status": "pending",
  "retry_after": 30,
  "message": "Device registered, awaiting configuration"
}
```

Configured device response:

```json
{
  "node_id": "node-a1b2c3d4e5f6a7b8",
  "status": "configured",
  "site_id": "london-1",
  "role": "active",
  "partner": {
    "node_id": "node-f1e2d3c4b5a69788",
    "status": "unknown"
  },
  "pools": [
    {
      "pool_id": "residential-v4",
      "cidr": "10.0.0.0/16",
      "subnets": ["10.0.1.0/24", "10.0.2.0/24"]
    }
  ],
  "cluster": {
    "peers": ["10.1.0.5:9000", "10.1.0.6:9000"],
    "sync_endpoint": ""
  },
  "message": "Device configured successfully"
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Missing or invalid serial/MAC, field too long |
| `413 Request Entity Too Large` | Request body exceeds 1 MB |
| `500 Internal Server Error` | Storage failure |

```bash
curl -X POST http://localhost:9000/api/v1/bootstrap \
  -H 'Content-Type: application/json' \
  -d '{
    "serial": "GPON12345678",
    "mac": "AA:BB:CC:DD:EE:FF",
    "model": "HUAWEI-MA5800",
    "firmware": "V800R021C10"
  }'
```

### List Devices

**GET /api/v1/devices?site_id={site_id}&status={status}**

Returns all registered devices, optionally filtered by site or status.

**Query Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `site_id` | no | Filter by site ID |
| `status` | no | Filter by status: `"pending"` or `"configured"` |

**Response: `200 OK`**

```json
{
  "devices": [
    {
      "node_id": "node-a1b2c3d4e5f6a7b8",
      "serial": "GPON12345678",
      "mac": "AA:BB:CC:DD:EE:FF",
      "model": "HUAWEI-MA5800",
      "firmware": "V800R021C10",
      "status": "configured",
      "site_id": "london-1",
      "role": "active",
      "partner_node_id": "node-f1e2d3c4b5a69788",
      "assigned_pools": ["residential-v4"],
      "first_seen": "2025-01-15T10:00:00Z",
      "last_seen": "2025-01-15T10:30:00Z",
      "metadata": {}
    }
  ],
  "count": 1
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `500 Internal Server Error` | Storage failure |

```bash
# List all devices
curl http://localhost:9000/api/v1/devices

# Filter by site
curl 'http://localhost:9000/api/v1/devices?site_id=london-1'

# Filter by status
curl 'http://localhost:9000/api/v1/devices?status=pending'
```

### Get Device

**GET /api/v1/devices/{node_id}**

Returns a single device by node ID.

**Response: `200 OK`**

Returns a device object (same schema as in the list response).

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Missing node ID |
| `404 Not Found` | Device does not exist |
| `500 Internal Server Error` | Storage failure |

```bash
curl http://localhost:9000/api/v1/devices/node-a1b2c3d4e5f6a7b8
```

### Assign Device

**PUT /api/v1/devices/{node_id}**

Assigns a device to a site. Auto-pairing logic applies:

- **First device at site**: assigned as `"active"`.
- **Second device at site**: assigned as `"standby"`, automatically paired with the first device.
- **Third+ device**: rejected with `409 Conflict`.

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `site_id` | string | yes | Site identifier (alphanumeric, hyphens, underscores; max 64 chars) |

**Response: `200 OK`**

```json
{
  "node_id": "node-a1b2c3d4e5f6a7b8",
  "site_id": "london-1",
  "role": "active",
  "status": "configured",
  "message": "Device assigned as active (first device at site)"
}
```

Paired response:

```json
{
  "node_id": "node-f1e2d3c4b5a69788",
  "site_id": "london-1",
  "role": "standby",
  "partner_node_id": "node-a1b2c3d4e5f6a7b8",
  "status": "configured",
  "message": "Device assigned as standby, paired with node-a1b2c3d4e5f6a7b8"
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Missing node ID or invalid site ID |
| `404 Not Found` | Device does not exist |
| `409 Conflict` | Site already has 2 devices |
| `413 Request Entity Too Large` | Request body exceeds 1 MB |
| `500 Internal Server Error` | Storage failure |

```bash
curl -X PUT http://localhost:9000/api/v1/devices/node-a1b2c3d4e5f6a7b8 \
  -H 'Content-Type: application/json' \
  -d '{"site_id": "london-1"}'
```

### Delete Device

**DELETE /api/v1/devices/{node_id}**

Removes a device from the system. If the device has an HA partner, the partner is unpaired and promoted to `"active"`.

**Response: `200 OK`**

```json
{
  "message": "device deleted successfully",
  "node_id": "node-a1b2c3d4e5f6a7b8"
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | Missing node ID |
| `404 Not Found` | Device does not exist |
| `500 Internal Server Error` | Storage failure |

```bash
curl -X DELETE http://localhost:9000/api/v1/devices/node-a1b2c3d4e5f6a7b8
```

### Import Devices

**POST /api/v1/devices/import**

Bulk import devices from a CSV file. Each device is pre-registered and assigned to a site. Auto-pairing logic applies (two devices at the same site are paired).

**CSV Format:**

```
serial,site_id
GPON12345678,london-1
GPON87654321,london-1
GPON11111111,manchester-1
```

The header row (`serial,site_id`) is optional and auto-detected. Devices that don't yet exist are created with a placeholder MAC and `"pending"` status, then immediately assigned to the specified site.

**Content Types:**

- `multipart/form-data` with a `file` field (max 10 MB)
- `text/csv` or `application/octet-stream` with CSV in the request body

**Response: `200 OK`**

```json
{
  "imported": 3,
  "paired": 1,
  "errors": []
}
```

**Errors:**

| Status | Cause |
|--------|-------|
| `400 Bad Request` | CSV parse error, empty file, or invalid form data |

```bash
# Upload as multipart form
curl -X POST http://localhost:9000/api/v1/devices/import \
  -F 'file=@devices.csv'

# Upload as raw CSV body
curl -X POST http://localhost:9000/api/v1/devices/import \
  -H 'Content-Type: text/csv' \
  --data-binary @devices.csv
```

---

## Error Format

All error responses use a consistent JSON format:

```json
{
  "error": "descriptive error message"
}
```

Validation errors include the field name:

```json
{
  "error": "validation error for field 'pool_id': pool ID is required"
}
```

---

## Validation Rules

The following validation rules are enforced on all inputs:

| Field | Rules |
|-------|-------|
| `pool_id` | Required; max 128 chars; alphanumeric, hyphens, underscores, dots; must start and end with alphanumeric |
| `subscriber_id` | Required; max 256 chars; alphanumeric, hyphens, underscores, colons, dots, @; must start and end with alphanumeric |
| `node_id` | Required; max 128 chars; same format as pool_id |
| `cidr` | Required; valid CIDR notation; must be the network address (not a host) |
| `ip` | Valid IPv4 or IPv6 address |
| `mac` | Valid MAC address (accepts `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`, `AABBCCDDEEFF` formats) |
| `serial` | Required; 4-32 uppercase alphanumeric characters |
| `site_id` | Required; max 64 chars; alphanumeric, hyphens, underscores |
| `prefix` | Must be >= CIDR mask size; IPv4: 8-32, IPv6: 16-128 |
| `sharding_factor` | 0-256 |
| `backup_ratio` | 0.0-1.0 |
| `gateway` | Valid IPv4 or IPv6 address (or empty) |
| `dns` | Each entry must be a valid IP address |
| `metadata` keys | Start with letter; alphanumeric, hyphens, underscores; max 64 chars |
| `metadata` values | Max 512 chars |
| `exclusions` | Max 100 entries; each must be a valid IP or CIDR |

All string fields are checked for SQL injection, path traversal, and script injection patterns.
