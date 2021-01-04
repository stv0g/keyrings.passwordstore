
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from keyring.errors import PasswordSetError, InitError
from keyring.util import properties

import subprocess
import re


class PasswordStoreBackend(KeyringBackend):
    """
    Password-store (https://www.passwordstore.org/)
    """

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        try:
            p = subprocess.run(['pass', 'version'],
                               capture_output=True,
                               check=True)

            m = re.match(r'v(\d+\.\d+\.\d+)', p.stdout.decode('ascii'))
            if m:
                _ = m.group(1)

        except subprocess.CalledProcessError:
            raise InitError('pass not installed')

        return 3

    def get_password(self, service, username):
        try:
            p = subprocess.run(['pass', 'show', f'{service}/{username}'],
                               capture_output=True,
                               check=True)
            return p.stdout.decode('utf-8').split('\n')[0]
        except subprocess.CalledProcessError as e:
            raise RuntimeError(e.output)

    def set_password(self, service, username, password):
        try:
            subprocess.run(['pass', 'insert', '--multiline',
                            f'{service}/{username}'],
                           capture_output=True,
                           check=True,
                           input=password.encode('utf-8'))
        except subprocess.CalledProcessError as e:
            raise PasswordSetError(e.output)

    def delete_password(self, service, username):
        try:
            subprocess.run(['pass', 'rm', f'{service}/{username}'],
                           capture_output=True,
                           check=True)
        except subprocess.CalledProcessError as e:
            raise PasswordDeleteError(e.output)
