#!/usr/bin/env python3
"""Optional local interactive wrapper. Secrets go to vpnctl via stdin, never argv."""
import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['enroll', 'reset', 'confirm'])
    parser.add_argument('--login', required=True)
    parser.add_argument('--root', default='var/admin')
    parser.add_argument('--master-key', default='var/admin-secrets/master.key')
    parser.add_argument('--name', default='Администратор')
    args = parser.parse_args()
    if not sys.stdin.isatty():
        parser.error('Interactive terminal required; automation should pass JSON directly to vpnctl stdin.')
    if args.action == 'confirm':
        payload = {'code': getpass.getpass('Код TOTP (ввод скрыт): ')}
    else:
        password = getpass.getpass('Новый пароль (от 12 символов): ')
        if password != getpass.getpass('Повторите пароль: '):
            parser.error('Пароли не совпадают')
        payload = {'password': password}
    root = Path(__file__).resolve().parent.parent
    command = [str(root / 'build' / ('vpnctl.exe' if os.name == 'nt' else 'vpnctl')),
               'admin-' + args.action, '--login', args.login, '--root', args.root,
               '--master-key', args.master_key, '--name', args.name]
    # Enrollment prints the newly generated secret once, directly to the operator.
    result = subprocess.run(command, input=json.dumps(payload), text=True, cwd=root, check=False)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
