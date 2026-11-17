#!/usr/bin/env bash
# Creates a Proxmox LXC container that runs the daemon as a systemd service.
# Run it as root on the Proxmox host. For a new install:
#
#   CONTROLLER=10.0.0.5 OPNSENSE_HOST=10.0.0.1 \
#   OPNSENSE_API_KEY_FILE=/root/apikey.txt BRIDGE=vmbr1 ./create-lxc.sh
#
# CONTROLLER is the UniFi controller's address and OPNSENSE_API_KEY_FILE is
# the apikey.txt OPNsense downloads when you create a key. A new install
# starts in plan mode (APPLY_MODE), so it only logs what it would change.
#
# To move a daemon that is already adopted, set STATE_DIR to a copy of its
# state directory (/var/lib/opnsense-unifi) instead of the OPNSENSE_ settings.
# It keeps its adoption and settings. Stop the old copy first, because two
# copies would report the same gateway.
#
# Optional: CTID (default the next free ID), CT_HOSTNAME, STORAGE, IP (like
# 10.0.0.7/24, default DHCP) with GATEWAY, REPO, BRANCH.
set -euo pipefail

: "${CONTROLLER:?set CONTROLLER to the UniFi controller address}"
CTID=${CTID:-$(pvesh get /cluster/nextid)}
CT_HOSTNAME=${CT_HOSTNAME:-opnsense-unifi}
STORAGE=${STORAGE:-local-lvm}
BRIDGE=${BRIDGE:-vmbr0}
IP=${IP:-dhcp}
REPO=${REPO:-https://github.com/BobbyRadford/os-unifi-gateway.git}
BRANCH=${BRANCH:-bobby/opnsense-apply}
APPLY_MODE=${APPLY_MODE:-plan}
STATE=/var/lib/opnsense-unifi

if [ -n "${STATE_DIR:-}" ]; then
    [ -f "$STATE_DIR/unifi-gateway.conf" ] || { echo "no unifi-gateway.conf in $STATE_DIR" >&2; exit 1; }
else
    : "${OPNSENSE_HOST:?set OPNSENSE_HOST, or STATE_DIR to move an existing install}"
    : "${OPNSENSE_API_KEY_FILE:?set OPNSENSE_API_KEY_FILE to the apikey.txt from OPNsense}"
fi

# the newest Debian 13 template, downloaded if there isn't one yet
template=$(pveam list local | awk '/debian-13-standard/ {print $1}' | sort -V | tail -1)
if [ -z "$template" ]; then
    pveam update >/dev/null
    name=$(pveam available --section system | awk '/debian-13-standard_.*_amd64/ {print $2}' | sort -V | tail -1)
    pveam download local "$name"
    template=local:vztmpl/$name
fi

net="name=eth0,bridge=$BRIDGE,ip=$IP"
[ -n "${GATEWAY:-}" ] && net="$net,gw=$GATEWAY"

echo "Creating CT $CTID ($CT_HOSTNAME) from $template"
pct create "$CTID" "$template" \
    --hostname "$CT_HOSTNAME" --unprivileged 1 --features nesting=1 \
    --cores 1 --memory 512 --swap 512 --rootfs "$STORAGE:4" \
    --net0 "$net" --onboot 1 --timezone host --tags "unifi;opnsense"
pct set "$CTID" --description "## OPNsense as a UniFi gateway

This container runs [os-unifi-gateway]($(sed 's/\.git$//' <<<"$REPO")) (branch \`$BRANCH\`). The UniFi controller at $CONTROLLER sees the OPNsense router as a UXG-Pro gateway, and the daemon applies network changes made in UniFi to OPNsense through its API.

- Logs: \`journalctl -u opnsense-unifi -f\`
- Code: \`/opt/opnsense-unifi\`. To update, run \`git -C /opt/opnsense-unifi pull && systemctl restart opnsense-unifi\`.
- State: \`$STATE\` holds the config, the OPNsense API key, and the adoption keys.
- \`[apply] mode\` in \`unifi-gateway.conf\` is \`off\`, \`plan\` (log only), or \`apply\`.

Run only one copy, because two copies would report the same gateway. The UniFi speed test measures this host's connection."
pct start "$CTID"

for _ in $(seq 30); do
    pct exec "$CTID" -- getent hosts deb.debian.org >/dev/null 2>&1 && break
    sleep 2
done

pct exec "$CTID" -- bash -euc "
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git python3-requests python3-cryptography python3-dnspython >/dev/null
useradd --system --home-dir $STATE --shell /usr/sbin/nologin unifi-gw
install -d -o unifi-gw -g unifi-gw -m 700 $STATE
git clone -q --branch '$BRANCH' '$REPO' /opt/opnsense-unifi
sed 's|CONTROLLER-IP|$CONTROLLER|' /opt/opnsense-unifi/contrib/opnsense-unifi.service \
    > /etc/systemd/system/opnsense-unifi.service
"

if [ -n "${STATE_DIR:-}" ]; then
    tar -C "$STATE_DIR" -cf - . | pct exec "$CTID" -- tar -C "$STATE" -xf -
else
    pct push "$CTID" "$OPNSENSE_API_KEY_FILE" "$STATE/apikey.txt"
    pct exec "$CTID" -- bash -euc "cat > $STATE/unifi-gateway.conf" <<EOF
[opnsense]
host = $OPNSENSE_HOST
verify_ssl = False
api_key_file = $STATE/apikey.txt

[apply]
mode = $APPLY_MODE
EOF
fi

pct exec "$CTID" -- bash -euc "
chown -R unifi-gw:unifi-gw $STATE
chmod -R go= $STATE
systemctl daemon-reload
systemctl enable --now opnsense-unifi
sleep 5
systemctl --no-pager status opnsense-unifi | head -5
"
echo "CT $CTID is running. Logs: pct exec $CTID -- journalctl -u opnsense-unifi -f"
