# Sample Ansible deploy scripts

- deploy to two servers, Alice and Bob, and provision arnika to connect them with a Wireguard+Rosenpass+Arnika tunnel
- this is not production-ready deploy script, some tinkering might be needed
- tested on two Ubuntu 24.04.3 LTS virtual machines

- WARNING: the script will open `tcp:9999` (for arnika) and `udp:9998` (for Rosenpass) ports in firewall (assuming `firewalld`)
    - if you do not want that, uncomment the corresponding functionality
- this script assumes you connect to KMS via **OpenVPN**
    - set credentials in `group_vars/all.yml`
    - in real scenario, the KMS is ready on the same host
- all other settings are configurable through `inventories/fit.yml`
    - such as KMS connection information


## Requirements
- in order to deploy sucessfully, you must:
    - put binaries into `files/bin` folder
        - copy `contrib/arnika-wrapper` to `files/bin/arnika/arnika-wrapper`
        - this means build of `arnika` to `files/bin/arnika/arnika`
        - release of `rosenpass` to `files/bin/rosenpass/{rosenpass,rp}`
            - this was tested with `rosenpass 0.2.2`
    - put OpenVPN configuration inside `files/openvpn`
        - this means your credentials and `kms.ovpn` file with configuration and certificates
    - place your KMS certificates in `files/certs`
    - generate Rosenpass keys
        - see `docker/README.md` on how to do that - the keys and structure will be generated automatically
        - place private `pqsk` and public `pqpk` keys to `rosenpass/{alice,bob}/my` for alice and bob respectively
        - place alice's public key to `bob/rosenpass/alice.pqpk` and vice versa
        - do not place the config TOML file there, it will be generated automatically from your config
    - generate Wireguard config + keys
        - this has to be done manually but is standard

## Deploy
- `ansible-playbook deploy-all.yml -i inventories/fit.yml`

## Running
- to start Arnika, run `systemctl start arnika` or to manually start it,
```bash
set -a && source /etc/arnika/arnika.env && set +a
/opt/arnika/arnika-wrapper
```


## Tips
- for debugging purposes or visualise the Wireguard keys, you can change `print_wg_keys=1` in `files/bin/arnika/arnika-wrapper`
    - this is of course unsafe as that will print your VPN keys to logs
