# Example configuration

## WARNING: only for testing!
- This is just an example for connecting two peers - Alice and Bob
    - there are two possible scenarios:
        - both are on the same host
        - one is on a remote host
- it contains fixed private keys for demonstrational purposes
- Wireguard config + keys must be generated separately - mainly so that you can specify your IP ranges and topology

## Requirements
- in order to properly build the container, you need to copy these binary files to `bin/`,
    - `arnika`: your build of arnika
    - `arnika-wrapper`: copy from `/contrib/ansible/files/bin/arnika-wrapper`
        - symlink is not possible as docker needs the files to be present under the `docker` folder
    - `rosenpass` and `rp`: some as for ansible deploy
- you can generate fresh PQC keys via `tools/gen-rosenpass.sh` for Rosenpass
- alice and bob pubkeys and generate fresh WG keys
- place your KMS certificates to `fit_connect`
