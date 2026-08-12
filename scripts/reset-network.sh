#!/usr/bin/env bash
# No Linux analog yet: reset-network.ps1 drives the Windows binary's
# `cleanup` verb (WFP filter teardown + orphaned NRPT/DNS-redirect registry
# rule removal), and neither the WFP-equivalent enforcement backend nor a
# `cleanup` verb exist in nrr-serviced yet (enforcement is a stub pending the
# nftables backend).
#
# Best current option on a stuck host: `sudo systemctl stop netrulerouter`
# (or `sudo systemctl disable --now netrulerouter` to also stop it starting
# again on boot). Since the Linux daemon does not yet apply any firewall
# state of its own, stopping it does not leave anything behind to clean up.

set -euo pipefail

echo "reset-network.sh: no Linux equivalent yet — the enforcement backend" >&2
echo "  (nftables) and the daemon's cleanup verb are not implemented." >&2
echo "  If the machine is in a bad state, stop the service instead:" >&2
echo "    sudo systemctl stop netrulerouter" >&2
exit 1
