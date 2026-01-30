# Arnika - CTU fork
This is a fork of [Arnika](https://github.com/arnika-project/arnika) project. See documentation there for bigger picture, this readme will highlight the differences in our fork.

#### Abbreviations
- KMS - Key Management Service/Server
- WG - WireGuard
- PSK - pre-shared key, used in Wireguard protocol to provide post-quantum security


## Fork differences
- safe fallback mode
    - when KMS has an outage, use PQC and the last KMS key
- more robust Wireguard interface handling
    - race-free implementation during initialization; previously
        - it was possible that some unecrypted (just plain classical WG crypto) was sent before Arnika managed the WG interface
        - one can pass the Wireguard interface in deactivated state (see `contrib/arnika-wrapper`)
    - if proper PSK is not set during given interval, abort communication and set a random PSK
- ability to statically assign roles to each peer
    - currently, there are distinct `initiator`/master/client and `responder`/slave/server roles for each Arnika instance. Dynamic role assignment would require heavier protocol with timestamps.
    - (in original nomenclature master and backup)
- less coupled codebase - separate modules for different functionality (`net`, `peer`)
    - this allowed for more robust networking, original project had problems with some unclosed sockets etc.
- proper unit tests of networking and business logic
    - large refactoring was needed
- wrapper with sane defaults (`contrib/arnika-wrapper`)
    - starts all dependencies of Arnika properly
    - creates a place in RAM (without swap) to exchange the Rosenpass keys without using disk

## Tooling
There are Ansible and Docker deploy scripts available in `contrib`. See their README.md for more info.

There is also a script `contrib/arnika-wrapper` for running Arnika with all its dependencies in a safe and race-condition-free manner. Ideally, this script would be replaced integrated into the main Arnika Go codebase.

## Configuration
- via environment variables, the same as original
- `LISTEN_ADDRESS`, Address to listen on for incoming connections
- `SERVER_ADDRESS`, Address of the arnika server
- **new**, set one of `LISTEN_ADDRESS` or `SERVER_ADDRESS` to statically determine the peer to be master/slave
    - e.g. `SERVER_ADDRESS=""` means that the peer is slave and does not connect to any Arnika server, only receives
- `KMS_MODE`, **new**: specify behaviour on KMS errors - possible values: `STRICT` or `LAST_FALLBACK`
- `KEY_USAGE_LIMIT`, **new** limit how many times a given KMS key can be used; only applicable with KMS_MODE=LAST_FALLBACK; default to 720; a key is used on each INTERVAL tick; can be negative to allow for unlimited use
- `PSK_EXPIRATION_INTERVAL`, **new**, Interval; if PSK is not refreshed in this interval, deactivate peer; 0 to disable
- `CERTIFICATE`, Path to the client certificate file
- `PRIVATE_KEY`, Path to the client key file
- `CA_CERTIFICATE`, Path to the CA certificate file
- `KMS_URL`, URL of the KMS server
- `KMS_HTTP_TIMEOUT`, HTTP connection timeout
- `INTERVAL`, Interval between key updates
- `WIREGUARD_INTERFACE`, Name of the WireGuard interface to configure
- `WIREGUARD_PEER_PUBLIC_KEY`, Public key of the WireGuard peer
- `PQC_PSK_FILE`, Path to the PQC PSK file
