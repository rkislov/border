#!/usr/bin/env python3
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
"""Install per-user launchd supervision using a private JSON configuration.
Required fields: directory, python, ssh, proxy_command, destination, ssh_port.
Optional fields: local_address, router. No passwords are used by the tunnel.
"""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

config = json.loads(Path(sys.argv[1]).read_text())
base = Path(config['directory']).resolve()
base.mkdir(mode=0o700, parents=True, exist_ok=True)
shutil.copy2(Path(__file__).with_name('relay.py'), base / 'relay-supervised.py')
local = config.get('local_address', '192.168.128.1')
router = config.get('router', '192.168.128.10')
commands = {
    'ru.kislovs.border.lab-relay': [config['python'], '-u', str(base / 'relay-supervised.py'),
                                  'local', '--local-address', local, '--router', router],
    'ru.kislovs.border.lab-tunnel': [config['ssh'], '-N', '-T', '-p', str(config['ssh_port']),
        '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=15',
        '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3',
        '-o', 'ProxyCommand=' + config['proxy_command'],
        '-L', '127.0.0.1:31812:127.0.0.1:31812',
        '-R', '127.0.0.1:37990:127.0.0.1:37990',
        '-R', '127.0.0.1:38022:' + router + ':22', config['destination']],
}
folder = Path.home() / 'Library/LaunchAgents'
folder.mkdir(exist_ok=True)
domain = 'gui/' + str(os.getuid())
for label, args in commands.items():
    path = folder / (label + '.plist')
    body = {'Label': label, 'ProgramArguments': args, 'RunAtLoad': True, 'KeepAlive': True,
            'ThrottleInterval': 10, 'ProcessType': 'Background', 'WorkingDirectory': str(base),
            'StandardOutPath': str(base / (label + '.log')),
            'StandardErrorPath': str(base / (label + '.log'))}
    path.write_bytes(plistlib.dumps(body)); path.chmod(0o600)
    subprocess.run(['launchctl', 'bootout', domain + '/' + label], capture_output=True)
    subprocess.run(['launchctl', 'bootstrap', domain, str(path)], check=True)
    print('Supervised:', label)
