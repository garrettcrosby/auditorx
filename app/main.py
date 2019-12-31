from git import Repo
import os
import yaml
import time
import json
import subprocess
import node
import logging
import logging.handlers
import socket
import sys

#sets env variables for testing
def testing():
    os.environ['HOSTS_FILE'] = ''
    os.environ['GIT_REPO'] = ''
    os.environ['VAULT_SERVER'] = ''
    os.environ['CA_FILE'] = ''
    os.environ['VAULT_ROLE_ID'] = ''
    os.environ['VAULT_SECRET_ID'] = ''
    os.environ['SYSLOG_SERVER'] = ''
    os.environ['SYSLOG_PORT'] = ''

class Auditor(object):

    def __init__(self):
        #grab environment vars
        self.syslog_server = os.getenv('SYSLOG_SERVER')
        self.syslog_port = os.getenv('SYSLOG_PORT')
        self.known_hosts = os.getenv('HOSTS_FILE')
        self.git_repo = os.getenv('GIT_REPO')
        self.vault_server = os.getenv('VAULT_SERVER')
        self.ca = os.getenv('CA_FILE')
        self.role_id = os.getenv('VAULT_ROLE_ID')
        self.secret_id = os.getenv('VAULT_SECRET_ID')
        self.node_file_dir = '{}/nodes'.format(self.git_repo)
        self.metadata_dir = '{}/metadata'.format(self.git_repo)
        # get other variables
        self.node_files = self.find_node_files()
        self.changed = False
        self.modified_files = {}

    def setup_logger(self):
        self.logger = logging.getLogger('syslog')
        self.logger.setLevel(logging.DEBUG)
        syslog_port = int(self.syslog_port)
        syslog_handler = logging.handlers.SysLogHandler(
            address=(self.syslog_server, syslog_port),
            socktype=socket.SOCK_DGRAM)
        self.logger.addHandler(syslog_handler)
        self.logger.info('AuditorX logging initialized.')

    def find_node_files(self):
        node_files = []
        for (dirpath, dirnames, filenames) in os.walk(self.node_file_dir):
            for file in filenames:
                if file[-4:] == 'yaml' or file[-3:] == 'yml':
                    node_files.append(os.path.join(dirpath, file))
        return node_files

    def run_audit(self):
        #auth to vault server, so we can retrieve secrets for each node
        self.logger.info('Beginning audit.')
        self.vault_access = node.VaultConnection(self.vault_server, self.role_id,
                                                 self.secret_id, self.ca)
        self.logger.info('Attempting to login to Vault server.')
        try:
            self.vault_access.login()
            self.logger.info('AuditorX successfully logged in to Vault server.')
        except:
            self.logger.error('AuditorX could not log in to Vault! Exiting.')
            sys.exit()
        for file in self.node_files:
            self.handle_node(file)

    def handle_node(self, node_file):
        with open(node_file, 'rb') as f:
            node_config = yaml.full_load(f)
        if node_config['type'].lower() == 'server':
            self.server_audit(node_config)
        else:
            self.network_audit(node_config)

    def server_audit(self, config):
        server = node.Node(self.metadata_dir)
        server.name = config['name']
        server.host = config['host']
        server.secret_path = config['secret_path']
        if 'files' in config:
            server.files = config['files']
        if 'dirs' in config:
            server.dirs = config['dirs']
        if 'port' in config:
            server.port = config['port']
        server.known_hosts = self.known_hosts
        login_info = self.vault_access.get_secret(server.secret_path)
        for key, value in login_info.items():
            server.user = key
            server.password = value

        self.logger.info('Instantiation complete. Beginning audit of {}'.format(server.name))
        server.connect()
        server.metadata_dir = '{0}/{1}'.format(self.metadata_dir, server.name)
        server.check_files()
        server.audit_files()
        server.reconcile()
        server.close_connection()
        server.write_metadata()
        if server.modified_files != {}:
            self.changed = True
            self.logger.warning('Found changed files on {}'.format(server.name))
        #dict comprehension to edit keys in modified files to paths friendly to git
        git_friendly = {('metadata/{0}/{1}'.format(server.name, k)): v for k, v in server.modified_files.items()}
        for file, action in git_friendly.items():
            self.modified_files.update({file: action})

    def network_audit(self, config):
        appliance = node.NetworkNode(config['cmd'])
        appliance.name = config['name']
        appliance.metadata_dir = '{0}/{1}'.format(self.metadata_dir, appliance.name)
        appliance.host = config['host']
        appliance.secret_path = config['secret_path']
        appliance.type = config['type']
        appliance.known_hosts = self.known_hosts
        #explain this below line...for future reference
        login_info = self.vault_access.get_secret(appliance.secret_path)
        for key, value in login_info.items():
            appliance.user = key
            appliance.password = value

        self.logger.info('Instantiation complete. Beginning audit of {}'.format(appliance.name))
        #generates new attr, appliance.config as result of get_new_config method
        appliance.get_new_config()
        appliance.sanitize_data()
        #generates new attr, appliance.current_config as a result of get_current_config method
        appliance.get_current_config()

        #compare returns false if the compared items are different
        compare = appliance.compare_config()
        if compare == True:
            self.changed = True
            self.logger.warning('Found changed files on {}'.format(server.name))

        for file in appliance.modified_files:
            self.modified_files.update({file: 'add'})

    def push_git(self):
        self.logger.warning('AudiorX beginning git operations.')
        repo = Repo(self.git_repo)
        untracked = repo.untracked_files
        tracked = self.git_tracked_files()
        #git returns files without the full path, which the git_tracked_files method does
        #so these shenanigans are necessary
        for file in tracked:
            for untracked_file in untracked:
                    if file.find(untracked_file) != -1:
                        repo.git.add(file)
        for file, action in self.modified_files.items():
            if action == 'add':
                repo.git.add(file)
            elif action == 'delete':
                repo.index.remove(file, working_tree=True, force=True)
        repo.git.commit(m='Automated commit from auditorx')
        self.logger.info('Sucessful git commit from AuditorX')
        origin = repo.remote(name='origin')
        origin.push()
        self.logger.info('Sucessful git push from AuditorX')

    def git_tracked_files(self):
        tracked_files = []
        tracked_dirs = [self.metadata_dir, self.node_file_dir]
        for dir in tracked_dirs:
            for (dirpath, dirnames, filenames) in os.walk(dir):
                for file in filenames:
                    tracked_files.append(os.path.join(dirpath, file))
        return tracked_files

def main():
    testing()
    auditor_instance = Auditor()
    auditor_instance.setup_logger()
    auditor_instance.run_audit()
    if auditor_instance.changed == True:
        auditor_instance.push_git()
    else:
        auditor_instance.logger.info('No changes found, skipping git operations.')

if __name__ == '__main__':
    main()
