#!/bin/bash

# delete outer default routes
# add route only to KMSs
# echo "Deleting default routes..."
# ip route del default
# ip route add 10.40.0.0/20 via 10.100.1.1 dev eth0 
# ip route add 10.126.6.12/32 via 10.100.1.1 dev eth0 

export WG_CONF=/etc/wireguard/wg0.conf
export RP_CONF=/etc/rosenpass/rp.toml

# symlink scenarios when bob is local/remote (specified in alice's env)
if [ -n "$LOCAL_BOB" ] 
then
    [ "$LOCAL_BOB" -eq 1 ] && src="local"
    [ "$LOCAL_BOB" -eq 0 ] && src="remote"

    # delete when already symlinked
    [ -L "$RP_CONF" ] && rm "$RP_CONF"
    [ -L "$WG_CONF" ] && rm "$WG_CONF"

    # symlink files
    ln -s "/etc/rosenpass/rp-$src.toml" "$RP_CONF"
    ln -s "/etc/wireguard/wg0-$src.conf" "$WG_CONF"
fi

exec /app/bin/arnika-wrapper

# wg-quick up wg0
# while true; do
#     sleep 5
# done

# create wireguard interface and deactivate it
#echo "wg-quick & IF down"
#wg-quick up wg0 2>/dev/null && ip link set down dev wg0
#
### run pqc server
#rm -f "$PQC_PSK_FILE"
#rosenpass exchange-config /etc/rosenpass/rp.toml &
## block until PQC PSK is created
#echo "waiting for new PQC PSK..."
#while true; do if [ -f "$PQC_PSK_FILE" ]; then break; else sleep 1; fi; done
#echo "PQC PSK created: $(cat "$PQC_PSK_FILE")"
#
##export PQC_PSK_FILE=
#slp="$(echo "$RANDOM % 0.60 + .1" | bc)"
#echo "$slp"
#sleep "$slp" && arnika &
#echo "Activating interface in 10 s..." && sleep 10 && ip link set up dev wg0
#echo "IF up; pinging..."
#ping "$WIREGUARD_OTHER" & # works fine
#old_wg_key=0
#old_pqc_key=0
#while true
#do
#    wg_key="$(wg showconf wg0 | grep PresharedKey)"
#    [ "$old_wg_key" = "$wg_key" ] || { echo "WG PSK: $wg_key"; old_wg_key="$wg_key"; }
##    pqc_key="$(cat < "$PQC_PSK_FILE")"
##    [ "$old_pqc_key" = "$pqc_key" ] || { echo "PQC PSK: $pqc_key"; old_pqc_key="$pqc_key"; }
#    sleep 1
#done
