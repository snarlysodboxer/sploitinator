#!/bin/bash
MSFUSER=${MSFUSER:-postgres}
MSFPASS=${MSFPASS:-postgres}
if [[ ! -z "$DB_PORT_5432_TCP_ADDR" ]]; then
  # Check if user exists
  USEREXIST="$(psql -h $DB_PORT_5432_TCP_ADDR -p 5432 -U postgres postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='$MSFUSER'")"
  # If not create it
  if [[ ! $USEREXIST -eq 1 ]]; then
	 psql -h $DB_PORT_5432_TCP_ADDR -p 5432 -U postgres postgres -c "create role $MSFUSER login password '$MSFPASS'"
  fi

  DBEXIST="$(psql -h $DB_PORT_5432_TCP_ADDR -p 5432 -U postgres  postgres -l | grep msf)"
  if [[ ! $DBEXIST ]]; then
	 psql -h $DB_PORT_5432_TCP_ADDR -p 5432 -U postgres postgres -c "CREATE DATABASE msf OWNER $MSFUSER;"
  fi

sh -c "echo 'production:
  adapter: postgresql
  database: msf
  username: $MSFUSER
  password: $MSFPASS
  host: $DB_PORT_5432_TCP_ADDR
  port: 5432
  pool: 75
  timeout: 5' > /metasploit-framework/config/database.yml"
else
	echo "USAGE:"
	echo "	1. Setup a database:"
	echo "	   docker run -d --name=postgres postgres"
	echo "	2. Link containers:"
	echo "	   docker run -it --link postgres:db pandrew/metasploit"
	exit 0
fi

#/metasploit-framework/msfconsole -r /tmp/temp/setup.rc
/metasploit-framework/msfrpcd -P 'mypass' -S -U 'admin' -a 0.0.0.0 -f -p '3790' -u '/api/1.0'
