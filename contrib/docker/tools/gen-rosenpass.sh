#!/bin/bash
#
# generate PQC rosenpass keys for two peers - alice and bob - and pair them
# use to generate PQC keys in ../config/
#

peers=(alice bob)
mkdir -p {alice,bob}/rosenpass

# generates public & secret keys
rp genkey alice/rosenpass/my
rp genkey bob/rosenpass/my

# we do not use wireguard keys generated this way, remove them
rm -f {alice,bob}/rosenpass/my/wgsk

# distribute public keys to other peers
for d in "${peers[@]}"
do
    echo "$d"
    # copy one file to multiple files
    # to all peers except the current one
    other_peers=( ${peers[@]/$d} ) # remove this peer
    tee "${other_peers[@]/%/\/rosenpass\/$d.pqpk}" < "$d/rosenpass/my/pqpk" >/dev/null
done
