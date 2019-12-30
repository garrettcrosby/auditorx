#!/bin/sh

#path to file with known ssh hosts
export HOSTS_FILE=''

#path to git repository where configs go
export GIT_REPO=''

#ip and listening port of vault secrets server
export VAULT_SERVER=''

#file containing trusted root certs
export CA_FILE=''

#role id for approle login to vault server
export VAULT_ROLE_ID='

#secret id for approle login to vault server
export VAULT_SECRET_ID=''
