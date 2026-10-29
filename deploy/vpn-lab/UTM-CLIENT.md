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

**Unresolved accounting limitation:** these CHR IPsec sessions have an empty
`grant_token` in Border despite the access grant being created. Start/Stop
recording works, but policy-based automatic revocation has not been validated
for these VPN sessions. Investigate the Class attribute in RouterOS IPsec
accounting before claiming lifecycle enforcement. Do not correlate by username
alone: concurrent SSH and VPN sessions may share an identity.

This proves Linux → CHR → Border → Samba interoperability. It does not establish
native macOS or Windows compatibility. macOS currently selects Wi-Fi for the
IKEv2 outer connection and fails to reach the host-only CHR address; the Linux
VM avoids that routing issue through a dedicated lab interface.
