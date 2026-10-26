#!/usr/bin/env python3
"""Root-only initial host setup. Keeps generated credentials outside the repo."""
import os
from pathlib import Path
import pty
import secrets
import select
import subprocess
import time

ETC = Path('/etc/border')
DATA = Path('/var/lib/border')
BINARY = '/usr/local/bin/radiusd'
assert os.geteuid() == 0, 'Run as root'
ETC.mkdir(mode=0o750, exist_ok=True)
DATA.mkdir(mode=0o700, exist_ok=True)
if subprocess.run(['id', '-u', 'border'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
    subprocess.run(['useradd', '--system', '--home-dir', str(DATA), '--shell', '/usr/sbin/nologin', 'border'], check=True)
config = ETC / 'border.env'
if not config.exists():
    key = subprocess.check_output([BINARY, 'gen-key'], text=True).strip()
    config.write_text('BORDER_DB_DRIVER=sqlite\nBORDER_DB=/var/lib/border/border.db\nBORDER_MASTER_KEY=' + key + '\n')
    config.chmod(0o600)
env = dict(os.environ)
for line in config.read_text().splitlines():
    if line and not line.startswith('#'):
        key, value = line.split('=', 1)
        env[key] = value
subprocess.run([BINARY, 'init-db'], env=env, check=True)
certs = ETC / 'certs'
if not (certs / 'server.pem').exists():
    subprocess.run([BINARY, 'gen-certs', '--out', str(certs), '--host', 'dev.kislovs.ru'], check=True)
subprocess.run(['chown', 'root:border', str(ETC), str(certs)], check=True)
ETC.chmod(0o750)
certs.chmod(0o750)
subprocess.run(['chown', 'root:border', str(certs / 'server.key')], check=True)
(certs / 'server.key').chmod(0o640)
for name in ['server.pem', 'ca.pem', 'admin.pem']:
    (certs / name).chmod(0o644)
password_file = ETC / 'initial-admin-password'
# Existing installations must not silently reset an administrator.
import sqlite3
with sqlite3.connect(env['BORDER_DB']) as db:
    admins = db.execute('SELECT COUNT(*) FROM admins').fetchone()[0]
if not admins:
    password = secrets.token_urlsafe(24)
    fd = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(password + '\n')
    master, slave = pty.openpty()
    process = subprocess.Popen([BINARY, 'create-admin', 'admin'], env=env, stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    try:
        for prompt in [b'12', 'Повторите'.encode()]:
            buffer = b''
            deadline = time.monotonic() + 15
            while prompt not in buffer:
                if time.monotonic() > deadline:
                    raise RuntimeError('Administrator bootstrap timed out')
                if select.select([master], [], [], 0.1)[0]:
                    buffer += os.read(master, 4096)
            os.write(master, password.encode() + b'\n')
        if process.wait(timeout=15):
            raise RuntimeError('Administrator bootstrap failed')
    finally:
        os.close(master)
        if process.poll() is None:
            process.terminate()
    password = ''
subprocess.run(['chown', '-R', 'border:border', str(DATA)], check=True)
print('Border initialized. Initial administrator credential: /etc/border/initial-admin-password (root-only).')
