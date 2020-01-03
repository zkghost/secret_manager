"""
A secret store for storing json/dict data. 
Secrets are encrypted with AES symetric encryption, and AES
keys are encrypted using RSA asymetric encryption. 

You can provide your own keys, or have the secret store
generate them for you. 

In a secure setting, this would be setup behind an HTTP server 
and would hold a user's public key. The user would then decrypt
responses from the server with their private key that lives on 
their machine. 

TODO: update the API later to not require the private key... it seems
      like my model is a little messed up. I shouldn't need the private key. 
      Or rather, decrypt should run locally and encrypt should run remotely, 
      so encryption shouldn't require the private key. Maybe breakout into a 
      client server architecture.
"""

import base64
from getpass import getpass
import hashlib
import importlib.resources as pkg_resources
import json
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    padding,
    rsa,
)
from cryptography.hazmat.primitives import serialization


logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s |%(levelname)s|] - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S')
_logger = logging.getLogger(__name__)


"""
{'secret_folder': '.secrets/',
 'symetric_key_location': 'path',
 'asymetric_priv_key_location': 'path',
 'asymetric_publ_key_location': 'path'}
"""

DEFAULT_SECRET_DIR_LOCATION = Path.home()
DEFAULT_SECRET_DIR_NAME     = '.secrets/'
DEFAULT_SECRET_DIR          = DEFAULT_SECRET_DIR_LOCATION/DEFAULT_SECRET_DIR_NAME
KEYS_DIR = 'keys/'
DEFAULT_SYM_KEY_NAME       = 'aes_key'
DEFAULT_ASYM_PUBL_KEY_NAME = 'rsa_publ.pem'
DEFAULT_ASYM_PRIV_KEY_NAME = 'rsa_priv.pem' 

class SecretStore():
    def __init__(self, 
                 secrets_dir_path = None,
                 secrets_dir_prefix = '',
                 sym_key_path = None,
                 asym_publ_key_path = None,
                 asym_priv_key_path = None,
                 password_protect_private_key = False,
                 obsfucate_file_names = True):
        """
        """
        self.secrets_dir_path = secrets_dir_path
        self.secrets_dir_base_path = self.secrets_dir_path
        self.secrets_dir_prefix = secrets_dir_prefix
        self.symetric_key_path = sym_key_path
        self.asymetric_pub_key_path = asym_publ_key_path
        self.asymetric_priv_key_path = asym_priv_key_path
        self.password_protect_private_key = password_protect_private_key
        self.obsfucate_file_names = obsfucate_file_names
        self._validate_paths()
        


    @staticmethod
    def _hash_strings(*args, consecutive_hashing=True):
        """
        The secrets dir prefix dir and secret name are stored on disk 
        hashed to preserve the nature of the secrets

        If consecutive_hashing is True, then the output of the first hash
        will be appended to the raw string when calculating the second hash, 
        and so on. This may be similar to a merkel tree. 
        """
        hashed_strings = []
        for i in range(len(args)):
            string=args[i]
            if i != 0 and consecutive_hashing:
                string += hashed_strings[i-1]
            hashed_strings.append(hashlib.sha3_224(base64.b64encode(string.encode('utf-8'))).hexdigest())
        return hashed_strings


    def _generate_obfsucated_path(self,  
                                  path,
                                  matching_existing,
                                  consecutive_hashing=True):
        """
        given a path like:
        <some_location>/<secrets_dir>/<some_location>,
        generates a similar path where everything after secrets dir is 
        obsfucated
        for example, input of :
            Path('/home/user/.secrets/my_app/my_sensitive_info')
        returns:
            Path('/home/user/.secrets/ZqkVm39/9xmPoel=')
        """
        secrets_dir_name = self.secrets_dir_base_path._parts[-1]
        path_parts = path._parts[path._parts.index(secrets_dir_name)+1:]
        obsfucated_path_parts = SecretStore._hash_strings(*path_parts, 
                                                          consecutive_hashing=consecutive_hashing)
        # determine location of the secrets dir

        # get all elements in path after the secrets dir
        return self.secrets_dir_path/'/'.join(obsfucated_path_parts)

        

    def _find_or_make_secrets_directory(self):
        if self.secrets_dir_base_path:
            if not self.secrets_dir_base_path.exists() or \
               not self.secrets_dir_base_path.is_dir():
                _logger.fatal('provided secrets dir doesnt exist or isnt dir')
        else:
            secrets_dir_base_path = DEFAULT_SECRET_DIR_LOCATION/DEFAULT_SECRET_DIR_NAME
            if not secrets_dir_base_path.exists():
                os.makedirs(secrets_dir_base_path, exist_ok=True)
            elif not secrets_dir_base_path.is_dir():
                _logger.fatal(f'{secrets_dir_base_path.__str__} exists but is not a dir!')
            self.secrets_dir_base_path = secrets_dir_base_path
            self.secrets_dir_path = secrets_dir_base_path


    def _find_or_make_secrets_prefix_directory(self):
        if self.secrets_dir_prefix == '':
            self.secrets_dir_path = self.secrets_dir_base_path
            return
        else:
            assert self.secrets_dir_base_path
            secrets_dir_path = self.secrets_dir_base_path/self.secrets_dir_prefix
            if self.obsfucate_file_names:
                secrets_dir_path = self._generate_obfsucated_path(secrets_dir_path, 
                                                                  matching_existing=False)
            if secrets_dir_path.exists() and not secrets_dir_path.is_dir():
                _logger.fatal(f'{secrets_dir_path} exists but is not a dir!')
            os.makedirs(secrets_dir_path, exist_ok=True)
            self.secrets_dir_path = secrets_dir_path
            self.secrets_dir_prefix = secrets_dir_path._parts[-1]
            

    def _find_or_make_secrets_key_directory(self):
        assert self.secrets_dir_path
        keys_dir_path = self.secrets_dir_path/KEYS_DIR
        if self.obsfucate_file_names:
            keys_dir_path = self._generate_obfsucated_path(keys_dir_path,
                                                           matching_existing=False)
        if keys_dir_path.exists() and not keys_dir_path.is_dir():
            _logger.fatal(f'key dir exists, but is not a directory: {keys_dir_path}')
        os.makedirs(keys_dir_path, exist_ok=True)


    def _validate_paths(self):
        self._find_or_make_secrets_directory()
        self._find_or_make_secrets_prefix_directory()
        self._find_or_make_secrets_key_directory()
        if self.symetric_key_path:
            if not self.symetric_key_path.exists():
                _logger.fatal(f'symetric aes key not found at location {self.symetric_key_path}')
        else:
            symetric_key_path = Path(self.secrets_dir_path/KEYS_DIR/DEFAULT_SYM_KEY_NAME)
            if self.obsfucate_file_names:
                symetric_key_path = self._generate_obfsucated_path(symetric_key_path, 
                                                                   matching_existing=False)
            self._write_symetric_key(self._generate_symetric_key(),
                                     symetric_key_path)
            self.symetric_key_path = symetric_key_path
        
        # we expect either to have both the asym pub priv keys, or neither
        # if we only have 1 we will fail, so check the xor first
        if bool(self.asymetric_pub_key_path) ^ bool(self.asymetric_priv_key_path):
            _logger.fatal('both rsa pub and priv keys must be specified, only got 1')
        if self.asymetric_pub_key_path and self.asymetric_priv_key_path:
            if not self.asymetric_pub_key_path.exists():
                _logger.fatal(f'asym rsa public key not found at {self.asymetric_pub_key_path}')
            if not self.asymetric_priv_key_path.exists():
                _logger.fatal(f'asym rsa priv key not found at {self.asymetrical_priv_key_path}')
        else:
            private_key, public_key = self._generate_asymetric_key()
            private_key_path = Path(self.secrets_dir_path/KEYS_DIR/DEFAULT_ASYM_PRIV_KEY_NAME)
            public_key_path = Path(self.secrets_dir_path/KEYS_DIR/DEFAULT_ASYM_PUBL_KEY_NAME)
            if self.obsfucate_file_names:
                private_key_path = self._generate_obfsucated_path(private_key_path,
                                                                  matching_existing=False)
                public_key_path = self._generate_obfsucated_path(public_key_path,
                                                                  matching_existing=False)
            self._write_private_key(private_key, private_key_path)
            self.asymetric_priv_key_path = private_key_path
            self._write_public_key(public_key, public_key_path)    
            self.asymetric_pub_key_path = public_key_path


    def _generate_symetric_key(self):
        return Fernet.generate_key()


    def _generate_asymetric_key(self):
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=4096,
                                               backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key


    def _write_symetric_key(self, sym_key, path):
        if not path.exists():
            with open(path, 'wb+') as f:
                f.write(sym_key)
            

    def _read_symetric_key(self):
        sym_key = ''
        with open(self.symetric_key_path, 'rb') as key_file:
            sym_key = key_file.read()
        if sym_key == '':
            _logger.fatal('failed to read symetric key')
        return sym_key


    def _write_private_key(self, private_key, path):
        if not path.exists():
            if self.password_protect_private_key:
                password = getpass('enter the password for your private key')  
                encryption = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption = serialization.NoEncryption()
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption)
            with open(path, 'wb+') as f:
                f.write(pem)    


    def _read_private_key(self):
        private_key = ''
        if self.password_protect_private_key:
            password = getpass('enter the password for your private key').encode()
        else:
            password=None
        with open(self.asymetric_priv_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )
        if private_key == '':
            _logger.fatal('failed to read private key from file')
        return private_key


    def _write_public_key(self, public_key, path):
        if not path.exists():
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            with open(path, 'wb+') as f:
                f.write(pem)

    def _read_public_key(self):
        public_key = ''
        with open(self.asymetric_pub_key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        if public_key == '':
            _logger.fatal('failed to read public key from file')
        return public_key

    """
    def _write_key_to_secret_store(self, 
                                   sym_key=None,
                                   public_key=None, 
                                   private_key=None):
        assert (public_key and private_key) or (sym_key), "Must pass either a single symetric key " \
                                                          "or public and private asymetric keys"
        if sym_key:
            self._write_symetric_key(sym_key)
        else:
            self._write_private_key(private_key)
            self._write_public_key(public_key)
    """


    def _encrypt_data(self, sym_key, data):
        f = Fernet(sym_key)
        return f.encrypt(data)


    def _decrypt_data(self, sym_key, encrypted_data):
        f = Fernet(sym_key)
        return f.decrypt(encrypted_data)


    def _encrypt_key(self, public_key, key):
        return public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


    def _decrypt_key(self, private_key, encrypted_key):
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )


    def _write_secret(self, name, data):
        path = self.secrets_dir_path/name
        if self.obsfucate_file_names:
            path = self._generate_obfsucated_path(path,
                                                  matching_existing=False)
        with open(path, 'wb+') as secret_file:
            secret_file.write(data)


    def _read_secret(self, name):
        path = self.secrets_dir_path/name
        if self.obsfucate_file_names:
            path = self._generate_obfsucated_path(path,
                                                  matching_existing=True)
        secret = ''
        with open(path, 'rb') as secret_file:
            secret =  secret_file.read()
        return secret


    def store_secret(self,
                     secret_name: str,
                     data: dict):
        """
        Given a dictionary, does the following:
            - serializes to json string
            - base 64 encodes result
            - encrypts that result with an aes key
            - encrypts the aes key with an rsa public key
            - stores the data in the secrets directory 

        It will check for the existance of the secrets folder
        and relevant keys and create them if they don't exist 
        each time.
        """
        data_json_str = json.dumps(data)
        data_encoded_str = base64.b64encode(data_json_str.encode())
        
        encrypted_data = self._encrypt_data(self._read_symetric_key(), data_encoded_str)
        encrypted_key = self._encrypt_key(self._read_public_key(), self._read_symetric_key())
        self._write_secret(secret_name,
                           encrypted_data)
                
        return encrypted_key


    def retrieve_secret(self,secret_name, encrypted_key):
        secret = self._read_secret(secret_name)
        private_key = self._read_private_key()
        decrypted_key = self._decrypt_key(private_key, encrypted_key)
        decrypted_data = self._decrypt_data(decrypted_key, secret)
        decrypted_data = json.loads(base64.b64decode(decrypted_data))
        return decrypted_data
