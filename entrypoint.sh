#!/bin/bash

## Setup some variables
MSFDB=${MSFDB:-msf}
MSFUSER=${MSFUSER:-msf}
MSFPASS=${MSFPASS:-msf}
DBHOST=localhost
DBPORT=5432

## Start Postgres
/etc/init.d/postgresql start
if [[ $? -ne 0 ]]; then echo "Couldn't start PostgreSQL"; exit 1; fi

## Check if Postgres user and DB exists, If not create them
USEREXIST="$(sudo -u postgres psql postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='$MSFUSER'")"
if [[ $? -ne 0 ]]; then echo "Couldn't test PostgreSQL role"; exit 1; fi
if [[ ! $USEREXIST -eq 1 ]]; then
  echo "creating role"
  sudo -u postgres psql postgres -c "create role $MSFUSER login password '$MSFPASS'"
  if [[ $? -ne 0 ]]; then echo "Couldn't create PostgreSQL role"; exit 1; fi
fi
DBEXIST="$(sudo -u postgres psql postgres -l | grep $MSFDB)"
if [[ ! $DBEXIST ]]; then
  echo "creating DB"
  sudo -u postgres psql postgres -c "CREATE DATABASE $MSFDB OWNER $MSFUSER;"
  if [[ $? -ne 0 ]]; then echo "Couldn't create PostgreSQL DB"; exit 1; fi
fi

## Setup database.yml file
echo "creating database.yml"
sh -c "echo 'production:
  adapter:  postgresql
  database: $MSFDB
  username: $MSFUSER
  password: $MSFPASS
  host:     $DBHOST
  port:     $DBPORT
  pool:     75
  timeout:  5' > /usr/share/metasploit-framework/config/database.yml"
if [[ $? -ne 0 ]]; then echo "Couldn't create database.yml"; exit 1; fi

## Start msfrpcd
echo "starting msfrpcd"
/usr/bin/msfrpcd -U 'admin' -P 'mypass' -S -a 127.0.0.1 -p '3790' -u '/api/1.0'
if [[ $? -ne 0 ]]; then echo "msfrpcd exited unexpectedly"; exit 1; fi

## Start Sploit
echo "starting sploit"
cd /sploitinator
/sploit --config-file="/sploitinator/sploit.yml" --debug

