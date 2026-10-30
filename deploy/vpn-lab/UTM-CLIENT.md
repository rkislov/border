# Ubuntu VPN client in UTM

Verified 2026-10-29 with Ubuntu 24.04 ARM64, strongSwan 5.9.13 and MikroTik
CHR 7.23.8. RADIUS remains implemented by Border; domain passwords are
verified by the Samba helper.

VM: `Border VPN Client`, UUID `075827BE-15E4-43A0-BEEA-085731946AFA`,
2 vCPU, 1 GiB RAM. UTM QEMU/HVF, serial console, no shared directories.

- Internet NIC: emulated NAT, DHCP `10.0.2.15`; host SSH forward is bound
  only to `127.0.0.1:38023`.
- Lab NIC: host-only `192.168.128.20/24`; CHR is `192.168.128.10`.
- SSH user `lab`, key authentication only. Keys, passwords, CA and VM disk
  are stored outside Git in the local private lab directory.
- `cloud-init` installs strongSwan, swanctl, extra plugins and guest agent.
- `border-vpn-load.service` loads connections after charon is ready at boot.
  VPN initiation is manual: `sudo swanctl --initiate --child net`.
- Inspect: `sudo swanctl --list-sas`; test: `ping -c 3 10.182.0.1`;
  disconnect: `sudo swanctl --terminate --ike chr`.

Two CHR corrections were necessary:

```routeros
/ip ipsec identity set [find peer=border-vpn] my-id=fqdn:chr-vpn.lab.border.test
/ip route add dst-address=10.182.0.0/24 gateway=192.168.128.1 comment="Border VPN pool return route"
```

The identity must match the client's expected server identity. The route is
required before RouterOS applies the outbound IPsec policy to pool replies.
This isolated CHR has no default route. Add the pool route only if absent;
it is specific to this lab topology.

Verified results:

- Domain `domain-test`: EAP-MSCHAPv2 succeeds, VIP `10.182.0.20`, encrypted
  bidirectional traffic to `10.182.0.1` (3/3 ping replies).
- Local `local/chr-test`: succeeds, VIP `10.182.0.19`, 3/3 replies.
- Wrong domain password: EAP_FAILURE, no tunnel.
- Border receives Start/Stop for both users under NAS `127.0.0.2`, including
  the canonical domain username `samba-lab/domain-test`.

**Class-less accounting compatibility:** CHR IPsec omits Class. Border now
records the authenticated connection tuple for MikroTik EAP VPN grants and
matches a timestamped Start against a unique recent grant for the same NAS,
canonical user and exact tuple (NAS-IP, service, called/calling station,
NAS-Identifier, port type and binary port ID). The grant can be claimed by one
accounting session only. Later updates must match the claimed session and its
start time. Class-based accounting retains its previous rules.

The first Start must include Event-Timestamp and Acct-Session-Time <= 5 s;
the authorization window is 30 s with a 2 s timestamp tolerance. Events older
than 60 s or more than 5 s in the future are not correlated. Missing fields,
unknown Class, ambiguous unclaimed grants, and lost Start events are left unlinked rather than guessed. Previously
unlinked sessions need a new connection; there is no username-only backfill.
Synchronize NAS/server clocks. An unlinked session cannot receive policy-based
automatic revocation; inspect its grant association during deployment.

Live verification after migration 21:

- Domain VPN Start linked to its `lab-domain-vpn` grant. Blocking `domain-test`
  in Samba was detected by the normal background sync; automatic Disconnect
  returned ACK, recorded `user blocked`, and removed the client IKE/IPsec SAs.
- A separate local VPN session linked to `lab-local-vpn`. Its policy deadline
  was shortened after connection (the original Session-Timeout was still 600 s).
  At expiry the worker received Disconnect-ACK and recorded `policy expired`;
  the client SAs disappeared. This verifies server-driven revocation rather
  than relying on the NAS's original timeout.
- The domain user was re-enabled and the original policy restored after tests.

This proves Linux → CHR → Border → Samba interoperability. It does not establish
native macOS or Windows compatibility. macOS currently selects Wi-Fi for the
IKEv2 outer connection and fails to reach the host-only CHR address; the Linux
VM avoids that routing issue through a dedicated lab interface.

## Session isolation regression (2026-10-30)

Live tests found and fixed two issues: consumed grants previously prevented
rapid reconnects from binding, and the SSH adapter incorrectly compared the
wire username with the canonical domain identity. Claimed grants now remain
attached to their own session and do not compete for a fresh session. Only a
unique unclaimed grant may be assigned; reuse of the same accounting ID within
timestamp precision remains fail-closed. The SSH adapter validates the grant's
NAS, SSH policy and canonical or unqualified login before correlation/removal.

Verified after deployment:

- Three consecutive domain VPN connects/reconnects: three distinct grants;
  stopped predecessors remain stopped and the newest session is linked.
- Two domain VPNs from client addresses `.20` and `.21`, plus an SSH session
  of the same domain user: disconnecting VPN A returns Disconnect-ACK;
  VPN B remains established with working traffic, SSH keeps emitting heartbeats.
- Disconnecting the SSH session returns RouterOS-SSH-Disconnect; its SSH client
  receives `logout requested`. VPN B remains established, with 3/3 ping replies.
- Two VPNs from the same source IP `.20` with distinct IKE identities but the
  same EAP domain account: both have their own VIP and grant. Disconnecting A
  leaves B established and carrying traffic. Distinct IKE identities prevent
  strongSwan from reusing the first IKE SA; `unique=never` disables
  INITIAL_CONTACT replacement for this parallel-client test.

These are targeted session-disconnect tests through Border's authenticated
session-action API. Blocking an identity or expiring a shared policy is
intentionally broader and may revoke every matching grant; those automatic
scenarios were tested separately above. Test-only aliases/configurations and
sessions are cleaned up afterward; the original single-client profile remains.
