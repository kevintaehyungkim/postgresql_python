# -*- coding: utf-8 -*-
#!/usr/bin/python

import os
import sys
import psycopg2
import logging
import socket
import base64
from ConfigParser import SafeConfigParser

# logger
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger()

#config
config = SafeConfigParser()
filename = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.cfg')
found = config.readfp(open(filename))

# database
dbName = config.get('db', 'dbName')
dbUser = config.get('db', 'dbUser')
dbPassword = config.get('db', 'dbPassword')
dbHost = config.get('db', 'dbHost')
dbPort = config.get('db', 'dbPort')

# filepaths
KEA_FILEPATH = 'kea-leases4.csv'

lease_arr = []


def iptoint(ip):
    return int(socket.inet_aton(ip).encode('hex'), 16)


def inttoip(ip):
    return socket.inet_ntoa(hex(ip)[2:].decode('hex'))


def create_table(cur):
	try:
		cur.execute('''CREATE TABLE LEASES
			(ADDRESS INT NOT NULL,
			HWADDR TEXT NOT NULL,
			CLIENT_ID TEXT NOT NULL,
			VALID_LIFETIME INT NOT NULL,
			EXPIRE INT NOT NULL,
			SUBNET_ID INT NOT NULL,
			FQDN_FWD BOOLEAN NOT NULL,
			FQDN_REV BOOLEAN NOT NULL,
			HOSTNAME INT,
			STATE INT NOT NULL);''')
	except Exception as e:
		logger.exception(e)
		sys.exit(1)

	LOG.info("Table created")


def load_database(cur, conn):

	unique_leases = {}

	# process lease_arr and only keep rows with unique ip addresses
	for lease in lease_arr:
		ip = lease[0]
		if ip not in unique_leases.keys():
			unique_leases[ip] = lease

	# process each unique ip_address into database
	for ip_addr in unique_leases.keys():
		unique_lease = unique_leases[ip_addr]
		address = iptoint(unique_lease[0])
		hwaddr = unique_lease[1].encode('utf-8')
		client_id = unique_lease[2].encode('utf-8')
		valid_lifetime = unique_lease[3]
		expire = unique_lease[4]
		subnet_id = unique_lease[5]
		fqdn_fwd = unique_lease[6]
		fqdn_rev = unique_lease[7]
		hostname = unique_lease[8]
		state = unique_lease[9]

		try:
			columns = "ADDRESS, HWADDR, CLIENT_ID, VALID_LIFETIME, EXPIRE, SUBNET_ID, FQDN_FWD, FQDN_REV, HOSTNAME, STATE"
			query = '''INSERT INTO LEASE4 ({}) 
				VALUES ({}, '{}', '{}', {}, to_timestamp({}), {}, '{}', '{}', {}, {})'''.format(columns, address, hwaddr, client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev, 0, state)
			cur.execute(query)
		except Exception as e:
			LOG.info(e)
			sys.exit(1)

	LOG.info("Leases loaded successfully")


def drop_table(cur):
	query = "DROP TABLE LEASES"
	cur.execute(query)


def display_records(cur):
	cur.execute("SELECT * from LEASES")
	rows = cur.fetchall()
	for row in rows:
		print "ADDRESS = ", row[0]
		print "HWADDR = ", row[1]
		print "CLIENT ID = ", row[2]
		print "VALID_LIFETIME = ", row[3]
		print "EXPIRE = ", row[4]
		print "SUBNET_ID = ", row[5]
		print "FQDN_FWD = ", row[6]
		print "FQDN_REV = ", row[7]
		print "HOSTNAME = ", row[8]
		print "STATE = ", row[9], "\n"


def main():
	try:
		conn = psycopg2.connect(database=dbName, user=dbUser, password=dbPassword, host=dbHost, port=dbPort)
	except Exception as e:
		LOG.exception(e)
		sys.exit(1)

	LOG.info("Connected to database")

	cur = conn.cursor()

	with open(KEA_FILEPATH, "r") as f:
		lines = f.readlines()
		# for line in lines:
		for i in range(1, len(lines)):
			line = lines[i]
			line_arr = line.split(',')
			lease_arr.append(line_arr)

	# create_table(cur)
	load_database(cur, conn)
	# display_records(cur)
	# drop_table(cur)

	conn.commit()
	cur.close()
	conn.close()


if __name__ == '__main__':
	main()
