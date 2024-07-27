
# Kheper

[![codecov](https://codecov.io/gh/mikefero/kheper/graph/badge.svg?token=OXHR0SBZR6)](https://codecov.io/gh/mikefero/kheper)

Kheper is a tool designed to mock Kong Gateway data plane nodes for testing and
developing your control plane. It simulates node behavior using standard and
JSON RPC protocols, handles WebSocket events, manages pings, and processes
configuration updates. Additionally, Kheper provides a RESTful API for
inspecting the configuration received by each node, eliminating the need for a
full Kong Gateway setup.

Features:

- Simulates Kong Gateway data plane node connections to a control plane using
  multiple WebSocket protocols
  - Supports both standard and JSON RPC protocols
- Manages connections, pings, and configuration updates
- Enables communication with multiple control planes for
  cross-region/environment testing
- Offers simple configuration through YAML files or environment variables
- Exposes a RESTful API for inspecting the configuration of each node
- Supports the simulation of extensive network loads by creating thousands of
  mock Kong Gateway data plane nodes
- Compatible with both OSS and Enterprise versions of Kong Gateway

## Getting Started

### Installation

To use Kheper, you'll need to have Go installed on your system. You can
[download and install Go from the official website].

#### Building Kheper

```bash
git clone https://github.com/mikefero/kheper.git
cd kheper
make build
```

## Usage

### Configuration

Kheper can be configured using a YAML file or environment variables. Below are
the configuration options available:

#### Configuration Options

##### Defaults

| YAML Key | Environment Variable | Description |
|---|---|---|
| `defaults.handshake_timeout` | `KHEPER_DEFAULTS_HANDSHAKE_TIMEOUT` | The amount of time allowed to complete the WebSocket handshake. (default: **15s**) |
| `defaults.node_creation_delay` | `KHEPER_DEFAULTS_NODE_CREATION_DELAY` | The amount of time to wait before creating the next node. (default: **20ms**) |
| `defaults.ping_interval` | `KHEPER_DEFAULTS_PING_INTERVAL` | The interval at which the node should ping the control plane. This interval must be greater than 0. (default: **15s**) |
| `defaults.ping_jitter` | `KHEPER_DEFAULTS_PING_JITTER` | The jitter to apply to the ping interval. This jitter must be greater than 0. (default: **5s**) |
| `defaults.reconnection_interval` | `KHEPER_DEFAULTS_RECONNECTION_INTERVAL` | The interval at which the node should attempt to reconnect to the control plane. This interval must be greater than 0.(default: **10s**) |
| `defaults.reconnection_jitter` | `KHEPER_DEFAULTS_RECONNECTION_JITTER` | The jitter to apply to the reconnection interval. This jitter must be greater than 0. (default: **5s**) |

##### Nodes

| YAML Key | Environment Variable | Description |
|---|---|---|
| `nodes.instances` | `KHEPER_NODES_INSTANCES` | The number of node instances to create. (default: 1) |
| `nodes.group` | `KHEPER_NODES_GROUP` | The name of the group to which the node instance belongs. |
| `nodes.hostname` | `KHEPER_NODES_HOSTNAME` | The RFC 1123 hostname of the node. This can be a `sequential` hostname or a specific hostname. when `sequential` is specified, a sequential hostname will be generated starting with `00000000-0000-4000-8000-000000000001` and incrementing by 1 hexadecimal digit for each node. (default: **sequential**) |
| `nodes.id` | `KHEPER_NODES_ID` | The unique ID of the node. This can be a `sequential`, `unique`, or a specific UUID. When `sequential` is specified, a sequential UUID will be generated starting with `00000000-0000-4000-8000-000000000001` and incrementing by 1 hexadecimal digit for each node. When `unique` is specified, a unique UUID will be generated. (default: **sequential**) |
| `nodes.versions` | `KHEPER_NODES_VERSIONS` | The Kong Gateway semantic versions of the node. This version can be represented as 3 or 4 integers separated by dots (e.g. 1.2.3 or 1.2.3.4). Each version in the slice will be "round-robin" across the nodes based on the number of instances. (default: **3.7.0.0**) |

###### Connection

| YAML Key | Environment Variable | Description |
|---|---|---|
| `nodes.connection.host` | `KHEPER_NODES_CONNECTION_HOST` | The RFC 1123 IP address or hostname of the control plane to connect to. |
| `nodes.connection.port` | `KHEPER_NODES_CONNECTION_PORT` | The port of the control plane to connect to (range 1-65535). |
| `nodes.connection.protocol` | `KHEPER_NODES_CONNECTION_PROTOCOL` | The protocol to use to communicate with the control plane. Supported values are 'standard' and 'jsonrpc'. (default: **standard**) |
| `nodes.connection.cipher_suites` | `KHEPER_NODES_CONNECTION_CIPHER_SUITES` | The OpenSSL or TLS cipher suites to use when connecting to the control plane. Each cipher suite in the slice will be "round-robin" across the nodes based on the number of instances. If not specified, the default cipher suite will be used. |
| `nodes.connection.tls_version` | `KHEPER_NODES_CONNECTION_TLS_VERSION` | The TLS version to use when connecting to the control plane. If not specified, TLS v1.3 will be used. |
| `nodes.connection.certificate` | `KHEPER_NODES_CONNECTION_CERTIFICATE` | The TLS certificate in PEM format to use when connecting to the control plane. |
| `nodes.connection.key` | `KHEPER_NODES_CONNECTION_KEY` | The TLS key in PEM format to use when connecting to the control plane. |

###### Kheper Admin API Server

| YAML Key | Environment Variable | Description |
|---|---|---|
| `server.port` | `KHEPER_SERVER_PORT` | The port to run the API server on. (default: **5000**) |
| `server.timeouts.read` | `KHEPER_SERVER_TIMEOUTS_READ` | The timeout for reading the request body. (default: **15s**) |
| `server.timeouts.read_header` | `KHEPER_SERVER_TIMEOUTS_READ_HEADER` | The timeout for reading the headers. (default: **15s**) |
| `server.timeouts.write` | `KHEPER_SERVER_TIMEOUTS_WRITE` | The timeout for writing the response. (default: **15s**) |

#### Cipher Suites

The Kheper application allows configuring various TLS cipher suites to ensure
secure communication. The cipher suites can be specified using either the
OpenSSL or TLS enumeration. Below is a table listing the supported cipher suites
and their corresponding identifiers.

For more details on OpenSSL cipher suites, you can refer to the
[Kong Gateway constants]. The mapping between OpenSSL cipher suites and their
TLS counterparts were taken from the [OpenSSL documentation].

##### Supported TLS Version

The Kheper application supports TLS versions 1.0 through 1.3. When configuring
the application, it is important to note the following:

- **TLS v1.0, TLS v1.1, and TLS v1.2**: Clients can specify the desired cipher
  suite.
- **TLS v1.3**: The cipher suites are predefined and cannot be specified by the
  client. This version uses a fixed set of cipher suites that are considered
  secure and efficient. As a result, attempting to configure specific cipher
  suite when using TLS v1.3 will not have any effect.

##### Supported Cipher Suites

| OpenSSL Identifier | TLS Identifier | Kong Gateway SSL Cipher Suite |
|---|---|---|
| ECDHE-RSA-AES128-GCM-SHA256 | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | intermediate |
| ECDHE-RSA-AES256-GCM-SHA384 | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | intermediate |
| ECDHE-RSA-CHACHA20-POLY1305 | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | intermediate |
| ECDHE-ECDSA-AES128-GCM-SHA256 | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | intermediate |
| ECDHE-ECDSA-AES256-GCM-SHA384 | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 | intermediate |
| ECDHE-ECDSA-CHACHA20-POLY1305 | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | intermediate |
| ECDHE-ECDSA-AES128-SHA256 | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 | old |
| ECDHE-RSA-AES128-SHA256 | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 | old |
| ECDHE-RSA-AES128-SHA | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA | old |
| ECDHE-RSA-AES256-SHA | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA | old |
| ECDHE-ECDSA-AES128-SHA | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA | old |
| ECDHE-ECDSA-AES256-SHA | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA | old |
| AES128-GCM-SHA256 | TLS_RSA_WITH_AES_128_GCM_SHA256 | old |
| AES256-GCM-SHA384 | TLS_RSA_WITH_AES_256_GCM_SHA384 | old |
| AES128-SHA256 | TLS_RSA_WITH_AES_128_CBC_SHA256 | old |
| AES128-SHA | TLS_RSA_WITH_AES_128_CBC_SHA | old |
| AES256-SHA | TLS_RSA_WITH_AES_256_CBC_SHA | old |

The application currently does not support certain Kong Gateway cipher suites in
Go, such as `AES256-SHA256`, `DES-CBC3-SHA`, `DHE-RSA-AES128-GCM-SHA256`,
`DHE-RSA-AES256-GCM-SHA384`, `DHE-RSA-CHACHA20-POLY1305`,
`DHE-RSA-AES128-SHA256`, `DHE-RSA-AES256-SHA256`. `ECDHE-ECDSA-AES256-SHA384`,
and `ECDHE-RSA-AES256-SHA384`

For any unsupported cipher suite, an error will be returned indicating the
unsupported status.

#### Example YAML Configuration

Here is an example YAML configuration file:

```yaml
# Admin API server configuration
server:
  port: 5000
  timeouts:
    read: 15s
    read_header: 15s
    write: 15s

# Node defaults configuration that are shared across all nodes
defaults:
  handshake_timeout: 15s
  node_creation_delay: 20ms
  ping_interval: 15s
  ping_jitter: 5s
  reconnection_interval: 10s
  reconnection_jitter: 5s

# Node configuration for single or multiple control planes
nodes:
  - instances: 6
    hostname: sequential
    id: sequential
    versions:
      - 3.7.1
      - 3.7.0
    connection:
      host: localhost
      port: 8005
      protocol: standard
      cipher_suites:
        - ECDHE-ECDSA-AES128-GCM-SHA256
        - ECDHE-ECDSA-AES256-GCM-SHA384
        - ECDHE-ECDSA-CHACHA20-POLY1305
        - ECDHE-ECDSA-AES128-SHA256
        - ECDHE-ECDSA-AES128-SHA
        - ECDHE-ECDSA-AES256-SHA
      tls_version: TLSv1.2
      certificate: |
        -----BEGIN CERTIFICATE-----
        MIIBkTCCATegAwIBAgIUNafcmtDPirW6BY512Kn4LVm49ggwCgYIKoZIzj0EAwIw
        HTEbMBkGA1UEAwwSa2hlcGVyLmV4YW1wbGUuY29tMCAXDTI0MDcxNTE1NTExNloY
        DzIxMjQwNjIxMTU1MTE2WjAdMRswGQYDVQQDDBJraGVwZXIuZXhhbXBsZS5jb20w
        WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARnfTV7waofWrgsN86ueBRl+HuF5+3B
        WQgRxu0s1XJqvEgTCsMObNo5c87PA9NpmP2t0O2S8mjonJ2VUOE896CPo1MwUTAd
        BgNVHQ4EFgQU5qSZisQi+Gg5b/W8ianbh9+f1DcwHwYDVR0jBBgwFoAU5qSZisQi
        +Gg5b/W8ianbh9+f1DcwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBF
        AiBxcYu26lPkyxqDjas6gAXIuyJLK4IlDkvkRQxU0Ko9zAIhAJF0vuSPLvp+4L/G
        rrfgvmrE10iZPEm0/Iq2vlF/hZ63
        -----END CERTIFICATE-----
      key: |
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgc5u/SwkNIuzrCMxr
        IxFc1FAzG1O4Rfm6lWxrFVrTAvahRANCAARnfTV7waofWrgsN86ueBRl+HuF5+3B
        WQgRxu0s1XJqvEgTCsMObNo5c87PA9NpmP2t0O2S8mjonJ2VUOE896CP
        -----END PRIVATE KEY-----
```

#### Example Environment Variables Configuration

You can override the YAML configuration using environment variables:

```bash
# Server
export KHEPER_SERVER_PORT=5000
export KHEPER_SERVER_TIMEOUTS_READ=15s
export KHEPER_SERVER_TIMEOUTS_READ_HEADER=15s
export KHEPER_SERVER_TIMEOUTS_WRITE=15s

# Defaults
export KHEPER_DEFAULTS_HANDSHAKE_TIMEOUT=15s
export KHEPER_DEFAULTS_NODE_CREATION_DELAY=20ms
export KHEPER_DEFAULTS_PING_INTERVAL=15s
export KHEPER_DEFAULTS_PING_JITTER=5s
export KHEPER_DEFAULTS_RECONNECTION_INTERVAL=10s
export KHEPER_DEFAULTS_RECONNECTION_JITTER=5s

# Nodes
export KHEPER_NODES_INSTANCES=6
export KHEPER_NODES_HOSTNAME=sequential
export KHEPER_NODES_ID=sequential
export KHEPER_NODES_VERSIONS=3.7.1,3.7.0
export KHEPER_NODES_CONNECTION_HOST=localhost
export KHEPER_NODES_CONNECTION_PORT=8005
export KHEPER_NODES_CONNECTION_PROTOCOL=standard
export KHEPER_NODES_CONNECTION_CIPHER_SUITE="ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-ECDSA-CHACHA20-POLY1305,ECDHE-ECDSA-AES128-SHA256,ECDHE-ECDSA-AES128-SHA,ECDHE-ECDSA-AES256-SHA"
export KHEPER_NODES_CONNECTION_TLS_VERSION=TLSv1.2
export KHEPER_NODES_CONNECTION_CERTIFICATE="-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIUNafcmtDPirW6BY512Kn4LVm49ggwCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSa2hlcGVyLmV4YW1wbGUuY29tMCAXDTI0MDcxNTE1NTExNloY
DzIxMjQwNjIxMTU1MTE2WjAdMRswGQYDVQQDDBJraGVwZXIuZXhhbXBsZS5jb20w
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARnfTV7waofWrgsN86ueBRl+HuF5+3B
WQgRxu0s1XJqvEgTCsMObNo5c87PA9NpmP2t0O2S8mjonJ2VUOE896CPo1MwUTAd
BgNVHQ4EFgQU5qSZisQi+Gg5b/W8ianbh9+f1DcwHwYDVR0jBBgwFoAU5qSZisQi
+Gg5b/W8ianbh9+f1DcwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBF
AiBxcYu26lPkyxqDjas6gAXIuyJLK4IlDkvkRQxU0Ko9zAIhAJF0vuSPLvp+4L/G
rrfgvmrE10iZPEm0/Iq2vlF/hZ63
-----END CERTIFICATE-----"
export KHEPER_NODES_CONNECTION_KEY="-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgc5u/SwkNIuzrCMxr
IxFc1FAzG1O4Rfm6lWxrFVrTAvahRANCAARnfTV7waofWrgsN86ueBRl+HuF5+3B
WQgRxu0s1XJqvEgTCsMObNo5c87PA9NpmP2t0O2S8mjonJ2VUOE896CP
-----END PRIVATE KEY-----"
```

### Hostname and ID

- `nodes.hostname` and `KHEPER_NODES_HOSTNAME`: The RFC 1123 hostname of the node.
  - If **sequential** is specified, a sequential hostname will be generated.

- `nodes.id` and `KHEPER_NODES_ID`: The unique ID of the node.
  - If **sequential** is specified, a sequential ID will be generated.
  - If **unique** is specified, a unique ID will be generated as a random UUID.

> **Note:** If a specific value is provided for `hostname` or `id`, it will be used as-is. However, if `instances` is greater than 1, the same `hostname` and `id` will be duplicated for each instance.

### Running Kheper

To run Kheper, use the following command:

```bash
./bin/kheper
```


#### Admin API for Kheper Mock Data Plane Node Application

The Kheper Mock Data Plane Node Application provides an Admin API to manage and retrieve information about hosts and nodes connected to control planes. This API allows users to list all hosts, nodes connected to a specific host, retrieve specific nodes, and access particular resources from a node's payload. Below are the available endpoints and their functionalities:

##### Endpoints

###### List All Hosts
- **Endpoint:** `/hosts`
- **Method:** `GET`
- **Summary:** Retrieve a list of all hosts for data plane nodes connected to control planes.

```json
[
  {
    "hostname": "example-host1.com"
  },
  {
    "groups": [
      "kong-gateway-oss",
    ],
    "hostname":"example-host2.com"
  }
]
```

###### List All Nodes Connected to a Host
- **Endpoint:** `/{host}`
- **Method:** `GET`
- **Summary:** Retrieve a list of all nodes connected to a specific host or address.
- **Parameters:**
  - `host`: The IP address or hostname of the control plane.

```json
[
  {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "group": "kong-gateway-oss",
    "hostname": "node1.example-host.com",
    "tls_version": "TLSv1.2",
    "version": "1.2.3"
  },
  {
    "id": "223e4567-e89b-12d3-a456-426614174001",
    "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "group": "kong-gateway-oss",
    "hostname": "node2.example-host.com",
    "tls_version": "TLSv1.2",
    "version": "1.2.3.1"
  }
]
```

###### Retrieve a Specific Node
- **Endpoint:** `/{host}/{node-id}`
- **Method:** `GET`
- **Summary:** Retrieve a specific node.
- **Parameters:**
  - `host`: The IP address or hostname of the control plane.
  - `node-id`: The node ID in UUID format.

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "group": "kong-gateway-oss",
  "hostname": "node1.example-host.com",
  "tls_version": "TLSv1.2",
  "version": "1.2.3",
  "payload": {
    "config_hash": "374d97a6cdede7dbe918d7e72c29e6c8",
    "config_table": {
      "_format_version": "3.0",
      "_transform": false,
      "parameters": [
        {
          "created_at": 1719610962,
          "key": "cluster_id",
          "value": "46956d6b-4d94-4621-8663-87302bf5b18e"
        }
      ],
      "workspaces": [
        {
          "comment": "default workspace",
          "config": {},
          "created_at": 1719610962,
          "id": "0b38010c-9279-4c3e-a669-9b4f977a1efa",
          "meta": {},
          "name": "default",
          "updated_at": 1719610962
        }
      ]
    },
    "hashes": {
      "config": "374d97a6cdede7dbe918d7e72c29e6c8",
      "plugins": "00000000000000000000000000000000",
      "routes": "00000000000000000000000000000000",
      "services": "00000000000000000000000000000000",
      "targets": "00000000000000000000000000000000"
    },
    "timestamp": 1719750771.23,
    "type": "reconfigure"
  }
}
```

###### Retrieve a Specific Resource from a Node Payload
- **Endpoint:** `/{host}/{node-id}/{resource}`
- **Method:** `GET`
- **Summary:** Retrieve a specific resource from the root level of the `config_table` in the payload JSON object of a node.
- **Parameters:**
  - `host`: The IP address or hostname of the control plane.
  - `node-id`: The node ID in UUID format.
  - `resource`: The resource name.

```json
{
  "data": [
    {
      "ca_certificates": null,
      "client_certificate": null,
      "connect_timeout": 60000,
      "created_at": 1719863489,
      "enabled": true,
      "host": "kheper.local",
      "id": "3ec50d85-808a-4ddc-9d72-d5a29fa30aa3",
      "name": "kheper",
      "path": null,
      "port": 80,
      "protocol": "http",
      "read_timeout": 60000,
      "retries": 5,
      "tags": null,
      "tls_verify": null,
      "tls_verify_depth": null,
      "updated_at": 1719863489,
      "write_timeout": 60000
    }
  ],
  "next": null
}
```

### Generating a Certificate and Key Pair

Here is an example of how to generate a certificate and key pair using OpenSSL
for multiple cipher suites:

#### Elliptic Curve Key Pair

```bash
openssl req \
  -new \
  -newkey ec:<(openssl ecparam -name prime256v1) \
  -keyout docker/kong/cluster_ec.key \
  -nodes \
  -x509 \
  -days 36500 \
  -out docker/kong/cluster_ec.crt \
  -subj "/CN=kheper.example.com"
```

#### RSA Key Pair

```bash
openssl req \
  -new \
  -newkey rsa:2048 \
  -keyout docker/kong/cluster_rsa.key \
  -nodes \
  -x509 \
  -days 36500 \
  -out docker/kong/cluster_rsa.crt \
  -subj "/CN=kheper.example.com"
```

This command generates a new self-signed X.509 certificate valid for 100 years
using an elliptic curve key with the prime256v1 curve. It outputs the private
key to `cluster_ec.key` and the certificate to `cluster_ec.crt`, with the common
name (CN) set to `kheper.example.com`. This PEM-encoded certificate and key can
be used as the `certificate` and `key` values in the YAML configuration along
with the Kong Gateway control plane `cluster_cert` and `cluster_cert_key`
configuration fields.

**Note**: A [cluster_ec.crt] and [cluster_ec.key] file are included in the
          repository for convenience and are used in the yaml configuration file
          example. Additionally [cluster_rsa.crt] and [cluster_rsa.key] are
          included for completeness in order to utilize all cipher suites.

### Testing With Kong Gateway

To test Kheper with Kong Gateway, you can use the following commands to start
and stop Kong Gateway:

```
make kong-up
make kong-down
```

## TODO

- Develop a handler for the JSON-RPC protocol.
- Integrate observability metrics and create Grafana dashboards.
- Set default values in the configuration file for all versions of Kong Gateway.
- Incorporate a configuration section for both standard and custom plugins.

## License

Kheper is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for more information.

## Acknowledgements

- [Gorilla WebSocket] - A fast, well-tested, and widely used WebSocket library
  in Go.
- [golangci-lint] - A fast Go linters runner for Go. It runs linters in
  parallel, caching their results for much faster runs.
- [go-memdb] - Golang in-memory database built on immutable radix trees
- [kin-openapi] - OpenAPI 3.0 (and Swagger v2) implementation for Go (parsing,
  converting, validation, and more).
- [mockio] - A mocking framework for Go that helps in creating and using mocks
  for testing purposes.
- [viper] - Go configuration with fangs.
- [zap] - Blazing fast, structured, leveled logging in Go.

[cluster_ec.crt]: ./docker/kong/cluster_ec.crt
[cluster_ec.key]: ./docker/kong/cluster_ec.key
[cluster_rsa.crt]: ./docker/kong/cluster_rsa.crt
[cluster_rsa.key]: ./docker/kong/cluster_rsa.key
[download and install Go from the official website]: https://golang.org/dl/
[Gorilla WebSocket]: https://github.com/gorilla/websocket
[golangci-lint]: https://github.com/golangci/golangci-lint
[go-memdb]: https://github.com/hashicorp/go-memdb
[kin-openapi]: https://github.com/getkin/kin-openapi
[Kong Gateway constants]: https://github.com/Kong/kong/blob/master/kong/conf_loader/constants.lua#L14
[LICENSE]: LICENSE
[mockio]: https://github.com/ovechkin-dm/mockio/mock
[OpenSSL documentation]: https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
[viper]: https://github.com/spf13/viper
[zap]: https://github.com/uber-go/zap
