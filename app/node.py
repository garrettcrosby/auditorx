from netmiko import Netmiko
import os
import paramiko
import requests
import time
import re
import stat
import json

class Node(object):

    def __init__(self, metadata_dir=None, name=None, host=None, logger=None,
                password=None, known_hosts=None, user=None, ssh_port=22):
        self.metadata_dir = metadata_dir
        self.name = name
        self.host = host
        self.logger = logger
        self.files = []
        self.dirs = []
        self.skip = []
        self.except_dirs = []
        self.password = password
        self.known_hosts = known_hosts
        self.user = user
        self.port = ssh_port
        self.modified_files = {}
        self.metadata = {}
        #self.metadata_file not defined in init because metadata_dir might not be defined at init time

    def connect(self):
        try:
            client = paramiko.SSHClient()
            client.load_host_keys(self.known_hosts)
            client.connect(self.host, username=self.user, password=self.password, port=self.port)
            self.client = client
            self.sftp = client.open_sftp()
        except Exception as e:
            self.logger.error('There was an issue connecting to {0}! Exception: {1}'.format(self.host))

    def close_connection(self):
        self.client.close()
        self.sftp.close()

    def sftp_walk(self, rootdir):
        for obj in self.sftp.listdir(rootdir):
            remote_path = os.path.join(rootdir, obj)
            if remote_path in self.skip:
                continue
            remote_attr = self.sftp.lstat(remote_path)
            if stat.S_ISDIR(remote_attr.st_mode):
                self.sftp_walk(remote_path)
            else:
                self.files.append(remote_path)
                mtime = {remote_path: remote_attr.st_mtime}
                self.metadata.update(mtime)

    def check_files(self):
        for dir in self.dirs:
            self.sftp_walk(dir)
        for file in self.files:
            try:
                remote_attr = self.sftp.lstat(file)
                mtime = {file: remote_attr.st_mtime}
                self.metadata.update(mtime)
            except FileNotFoundError:
                self.logger.error('A file on {0} was not found.({1})'.format(self.name, file))

    def audit_files(self):
        self.metadata_file = '{}/metadata.json'.format(self.metadata_dir)
        #handle first run
        if not os.path.exists(self.metadata_file):
            for file in self.files:
                self.modified_files.update({file: 'add'})
            return
        with open(self.metadata_file, 'r') as f:
            current_meta = json.load(f)
        for file in self.files:
            try:
                current_mtime = current_meta[file]
            except:
                self.logger.warning('New file found on server {0} ({1}'.format(self.name, file))
                current_mtime = 0
            new_mtime = self.metadata[file]
            if new_mtime != current_mtime:
                self.modified_files.update({file: 'add'})

    def get_files(self, files):
        for file in files:
            local_path = '{0}{1}'.format(self.metadata_dir, file)
            local_dir = os.path.dirname(local_path)
            if not os.path.exists(local_dir):
                os.makedirs(local_dir, exist_ok=True)
            print('getting file {}'.format(file))
            with open(local_path, 'wb') as f:
                try:
                    self.sftp.getfo(file, f)
                except PermissionError:
                    self.logger.error('Permission error on {}'.format(file))
                except Exception as e:
                    self.logger.error('Error with file {0} on {1}. Exception: {2}'.format(file, self.name, e))

    def write_metadata(self):
        if not os.path.exists(self.metadata_dir):
            os.makedirs(self.metadata_dir)
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2)

    def reconcile(self):
        files_add = []
        local_files = []
        for file in self.modified_files:
            files_add.append(file)
        for root, dir, filenames in os.walk(self.metadata_dir):
            for file in filenames:
                #ignore metadata file
                if file == 'metadata.json':
                    continue
                else:
                    fullpath = os.path.join(root, file)
                    #need to slice off part of the path concerning the local machine
                    local_files.append(fullpath[len(self.metadata_dir):])
        for file in local_files:
            if file not in self.files:
                self.modified_files.update({file: 'delete'})
        self.get_files(files_add)

#inheritance is mostly for attributes. Node methods will not work on a networknode
class NetworkNode(Node):

    def __init__(self, cmd):
        self.cmd = cmd
        super().__init__(self)

    def get_new_config(self):
        args = {
            'ssh_strict': True,
            'alt_host_keys': True,
            'alt_key_file': self.known_hosts,
            'host': self.host,
            'username': self.user,
            'password': self.password,
            'device_type': self.type
        }
        connection = Netmiko(**args)
        self.new_config = connection.send_command(self.cmd)

    def get_current_config(self):
        current_config_file = '{}/config.txt'.format(self.metadata_dir)
        if os.path.exists(current_config_file):
            with open(current_config_file, 'r') as f:
                self.current_config = f.read()
        else:
            self.current_config = []

    def compare_config(self):
        if self.current_config != self.new_config:
            self.update_network_config()
            return True

    def update_network_config(self):
        config_file = self.metadata_dir + '/config.txt'
        #check that path exists
        if not os.path.exists(self.metadata_dir):
            os.makedirs(self.metadata_dir, exist_ok=True)
        with open(config_file, 'w') as f:
            f.write(self.new_config)
        self.modified_files.update({config_file: 'add'})

    #maybe move this up to node class, and expand functionality
    def sanitize_data(self):
        #create a regex that looks for hashes
        #hashes as defined here are going to strings only containing characters 0-9 and a-f
        #and longer than 16 characters
        secret = re.compile(r'[0-9a-f]{16,}')
        self.new_config = secret.sub('##SECRET DATA##', self.new_config)

class VaultConnection(object):

    def __init__(self, vault_server, role_id, secret_id, ca ):
        self.vault_server = vault_server
        self.role_id = role_id
        self.secret_id = secret_id
        self.ca = ca

    def login(self):
        auth_url = '{0}/v1/auth/approle/login'.format(self.vault_server)
        payload = '{{"role_id": "{0}", "secret_id": "{1}"}}'.format(self.role_id, self.secret_id)
        r = requests.post(auth_url, data=payload, verify=self.ca)
        response = r.json()
        self.token = response['auth']['client_token']

    def get_secret(self, secret_path):
        url = self.vault_server + secret_path
        r = requests.get(url, headers={'X-Vault-Token': self.token}, verify=self.ca)
        response = r.json()
        return response['data']
