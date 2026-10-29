#!/usr/bin/env python3
"""Generate a password-free IKEv2 configuration profile with the lab public CA."""
import argparse
import pathlib
import plistlib
import ssl
import uuid

p = argparse.ArgumentParser()
p.add_argument('--ca', type=pathlib.Path, required=True)
p.add_argument('--output', type=pathlib.Path, required=True)
p.add_argument('--server', default='192.168.128.10')
p.add_argument('--username', default='domain-test')
a = p.parse_args()
def payload(kind, name):
    return dict(PayloadType=kind, PayloadVersion=1, PayloadIdentifier='ru.kislovs.border.lab.' + str(uuid.uuid4()), PayloadUUID=str(uuid.uuid4()), PayloadDisplayName=name)
ca = payload('com.apple.security.root', 'Border CHR VPN Lab CA')
ca['PayloadContent'] = ssl.PEM_cert_to_DER_cert(a.ca.read_text())
vpn = payload('com.apple.vpn.managed', 'Border CHR Lab')
vpn.update(UserDefinedName='Border CHR Lab', VPNType='IKEv2')
crypto = dict(EncryptionAlgorithm='AES-256', IntegrityAlgorithm='SHA2-256', DiffieHellmanGroup=14, LifeTimeInMinutes=60)
vpn['IKEv2'] = dict(RemoteAddress=a.server, RemoteIdentifier='chr-vpn.lab.border.test', LocalIdentifier=a.username, AuthenticationMethod='None', ExtendedAuthEnabled=1, AuthName=a.username, ServerCertificateCommonName='chr-vpn.lab.border.test', ServerCertificateIssuerCommonName='Border CHR VPN Lab CA', IncludeAllNetworks=0, OnDemandEnabled=0, EnablePFS=0, IKESecurityAssociationParameters=crypto, ChildSecurityAssociationParameters=crypto)
profile = payload('Configuration', 'Border CHR Lab IKEv2')
profile.update(PayloadContent=[ca, vpn], PayloadScope='User', PayloadDescription='Lab IKEv2 VPN using Border EAP-MSCHAPv2. Server provides only the 10.182.0.1/32 route. Password is entered on connection.')
with a.output.open('xb') as f:
    plistlib.dump(profile, f)
print(a.output)
