import pyshark
import argparse
import sys
import threading
import time
from datetime import datetime

parser = argparse.ArgumentParser(
	description="Monitoring tool for real time analysis"
)
parser.add_argument(
	"-i",
	"--interface",
	dest="nic",
	help="Interface to capture",
)
parser.add_argument(
	"-r",
	"--alertLimiter",
	dest="alertLimiter",
	action="store_true",
	help="Set an alert limiter to one event for IP",
)
parser.add_argument(
	"-s"
	"--statsTimer",
	dest="statsTimer",
	default=0.0,
	type=float,
	help="Enable stats every x seconds",
)

args = parser.parse_args()

if not args.nic:
	print("Interface required!")
	parser.print_help()
	sys.exit(1)
parser.set_defaults(alertLimiter=False)

if len(sys.argv) <= 1:
	parser.print_help()
	sys.exit(1)

print("Listening on interface {}".format(args.nic))

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'


capture = pyshark.LiveCapture(interface=args.nic,bpf_filter='tcp port 80')

syn_flag= "0x00000002"
fin_flag ="0x00000011"
ack_flag="0x00000010"
synAck_flag= "0x00000012"
rst_flag = "0x00000004"
clients = {} # database of all the connections states for each client and port
connections = {} # contains the number of connections for each client
stats={} # contains some stats on the clients
timestamps = {} # timestamp info on the connections
conn_duration = {}
blacklist = {}

#stats



# Alert limiter dictionary
anomalies = {}
end_without_connection = 0
double_syn = 1
ack_without_connection =2
more_concurrent_connections =3
syn_flood =4

def anomaly(ip,code):
	if code == end_without_connection:
		msg = "{}Anomaly detected from IP {} -> FIN/RST without connection.{}".format(WARNING,ip,ENDC)
		if args.alertLimiter == True:
			if not anomalies.get(ip,0):
				anomalies[ip] = {}
				anomalies[ip][end_without_connection] = 1
				print(msg)
			elif not anomalies[ip].get(end_without_connection,0):
				anomalies[ip][end_without_connection] = 1
				print(msg)
		else:
			print(msg)
	if code == double_syn:
		msg = "{}Anomaly detected from IP {} -> connection already tried.{}".format(WARNING,ip,ENDC)
		if args.alertLimiter == True:
			if not anomalies.get(ip,0):
				anomalies[ip] = {}
				anomalies[ip][double_syn] = 1
				print(msg)
			elif not anomalies[ip].get(double_syn,0):
				anomalies[ip][double_syn] = 1
				print(msg)
		else:
			print(msg)
	if code == ack_without_connection:
		msg = "{}Anomaly detected from IP {} -> ACK without connection.{}".format(WARNING,ip,ENDC)
		if args.alertLimiter == True:
			if not anomalies.get(ip,0):
				anomalies[ip] = {}
				anomalies[ip][ack_without_connection] = 1
				print(msg)
			elif not anomalies[ip].get(ack_without_connection,0):
				anomalies[ip][ack_without_connection] = 1
				print(msg)
		else:
			print(msg)
	if code == more_concurrent_connections:
		msg = "{}ATTACK DETECTED: IP {} is using {} concurrent connection.{}".format(FAIL,ip,connections[ip],ENDC)
		if args.alertLimiter == True:
			if not anomalies.get(ip,0):
				anomalies[ip] = {}
				anomalies[ip][more_concurrent_connections] = 1
				print(msg)
			elif not anomalies[ip].get(more_concurrent_connections,0):
				anomalies[ip][more_concurrent_connections] = 1
				print(msg)
		else:
			print(msg)
	if code == syn_flood:
		msg = "{}ATTACK DETECTED: IP {} is flooding with SYN.{}".format(FAIL,ip,ENDC)
		if args.alertLimiter == True:
			if not anomalies.get(ip,0):
				anomalies[ip] = {}
				anomalies[ip][syn_flood] = 1
				print(msg)
			elif not anomalies[ip].get(syn_flood,0):
				anomalies[ip][syn_flood] = 1
				print(msg)
		else:
			print(msg)


def removeConn(ip,port,time):
	if connections.get(ip,0) != 0:
		connections[ip] -= 1
		if connections[ip] == 0:
			del connections[ip]
	if args.statsTimer > 0:
		# Add stats on the timestamp
			if not conn_duration.get(ip,0):
				conn_duration[ip] = []
			#print("remove for {}".format(port))
			conn_duration[ip].append(round(float(time) - timestamps[ip][port],3))
			del timestamps[ip][port]


def addConn(ip,port,time):
	# Increase counter
	if not connections.get(ip,0):
		connections[ip] = 1
	else:
		connections[ip] += 1
		if connections[ip] > 3: # margin for latency and errors
			anomaly(ip,more_concurrent_connections)
			if blacklist.get(ip,0) == 2:
				blacklist[ip] = 3
			else:
				blacklist[ip] = 1
	
	if args.statsTimer > 0:
		# Add stats on the timestamp
		if not timestamps.get(ip,0):
			timestamps[ip] = {}
		if not timestamps[ip].get(port,0):
			timestamps[ip][port] = float(time)
			#print("add for {}".format(port))
	
	if args.statsTimer > 0:
		## Add the stats
		if not stats.get(ip,0):
			stats[ip] = {}
		if not stats[ip].get("established",0):
			stats[ip]["established"] = 0
		stats[ip]["established"] += 1

#### TODO: optimize check flood
def checkFlood(ip,port):
	if clients.get(ip,0) != 0:
		count = 0
		for key, val in clients[ip].items():
			# Check wheter the connection is not established yet
			if val == 1 or val == 0:
				count+=1
		if count > 5: # A little of head room! IT could be greater than 1!
			anomaly(ip,syn_flood)
			if blacklist.get(ip,0) == 1:
				blacklist[ip] = 3
			else:
				blacklist[ip] = 2
	
	if args.statsTimer > 0:
		## Add the stats
		if not stats.get(ip,0):
			stats[ip] = {}
		if not stats[ip].get("SYNs",0):
			stats[ip]["SYNs"] = 0
		stats[ip]["SYNs"] += 1



# TODO: timeout of the SYN


def print_callback(pkt):
	src=str(pkt.ip.src)
	flag=pkt.tcp.flags
	#print(dir(pkt.tcp))
	#if str(pkt.tcp.srcport) == 17767:
		#print("Flag: {} and Port: {}.".format(pkt.tcp.flags,pkt.tcp.srcport))
	if src != "10.1.5.2":
		sport=str(pkt.tcp.srcport)		
		if flag == syn_flag:
			# Start of the handshake with the server
			if not clients.get(src,0):
				clients[src] = {}
			if not clients[src].get(sport,0):
				# there isn't a connection with that port
				clients[src][sport]=0 
			else:
				#There is a connection with that port
				anomaly(src,double_syn)
			checkFlood(src,sport)
		elif flag == fin_flag or flag == rst_flag:
			# It's a FIN flag
			if not clients.get(src,0):
				anomaly(src,end_without_connection)
			elif not clients[src].get(sport,0):
				# there isn't a connection with that port
				#print("No connection on port {}: staus {}".format(sport,clients[src].get(sport,-1)))
				# TODO: fix this bug
				anomaly(src,end_without_connection)
			elif clients[src][sport] == 2:
				# connection it correctly terminated
				del clients[src][sport]
				#print("Conn {} terminated".format(sport))
				removeConn(src,sport,pkt.sniff_timestamp)
			else:
				#print("reset when not needed")
				anomaly(src,end_without_connection)
		elif flag == ack_flag:
			if not clients.get(src,0):
				return
			elif not clients[src].get(sport,0):
				# there isn't a connection with that port
				return
				#anomaly(src,ack_without_connection)
			elif clients[src][sport] == 1 and str(pkt.tcp.seq)=="1":
				clients[src][sport] = 2 # connection established
				#print("Conn Created on port {}: {}".format(sport,clients[src].get(sport,-1)))
				addConn(src,sport,pkt.sniff_timestamp)
		
		if args.statsTimer > 0:
			## Add the stats
			if not stats.get(src,0):
				stats[src] = {}
			if not stats[src].get("totalPackets",0):
				stats[src]["totalPackets"] = 0
			if not stats[src].get("totalBytes",0):
				stats[src]["totalBytes"] = 0
			stats[src]["totalBytes"] += int(pkt.length)
			#print("adding {} bytes".format(int(pkt.length)))
			stats[src]["totalPackets"] += 1
	elif src == "10.1.5.2" and flag == synAck_flag:
		# Server accepting connection
		dst = str(pkt.ip.dst)
		dport=str(pkt.tcp.dstport)
		clients[dst][dport] = 1 # Syn ACK sent
		#print("Syn ack found for port {}".format(dport))
	

def getAttacks(ip):
	if blacklist.get(ip,0) == 1:
		return "[Multiple Connections]"
	elif blacklist.get(ip,0) == 2:
		return "[synflood]"
	elif blacklist.get(ip,0) == 3:
		return "[Multiple Connections][Synflood]"
	else:
		return ""

def checkRates():
	threading.Timer(args.statsTimer, checkRates).start()
	print("---------------------------------------------  {}  ----------".format(datetime.fromtimestamp(time.time())))
	for key, ip in stats.items():
		print("{}{} -> {}{}{}".format(OKBLUE,key,FAIL,getAttacks(key),ENDC))
		for key2, stat in ip.items():
			print("\t{}:\t\t {} /s".format(key2,stat/args.statsTimer))
		tmp =0
		for dur in conn_duration.get(key,[]):
			tmp += dur
		if tmp > 0:
			print("\tAverageDuration:\t\t {} sec".format(round(tmp/len(conn_duration.get(key)),3)))
	#print(conn_duration)
	conn_duration.clear()
	stats.clear()
	# Allow other notifications
	anomalies.clear()

if args.statsTimer > 0:
	checkRates()

capture.apply_on_packets(print_callback)
