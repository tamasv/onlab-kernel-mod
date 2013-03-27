#!/usr/bin/python
import sys
#from pyDes import *
from scapy.all import *
import ctypes
dnscc_lib = ctypes.cdll.LoadLibrary("./libdnscc_crypt.so")
dnscc_lib.dnscc_crypt_init();
#
dns_resolver_ip = "192.168.52.30"
dns_dport = 53
#send a test packet

dns_id = 11234
dns_sport = random.randrange(10000,60000,1)
#print dns_sport
#part2 and part3 from des seed

def ip_to_uint32(ip):
	t = socket.inet_aton(ip)
	return struct.unpack("I", t)[0]

def uint32_to_ip(ipn):
	t = struct.pack("I", ipn)
	return socket.inet_ntoa(t)

#c_uint16 ports = dns_sport ^ dns_dport 
#c_uint32 seed3 = 
#print ip_to_uint32("192.168.52.1")
dns_id = dnscc_lib.dnscc_crypt(dns_id,socket.htons(dns_sport),socket.htons(dns_dport),ip_to_uint32("192.168.52.1"),ip_to_uint32(dns_resolver_ip))
p=sr1(IP(dst=dns_resolver_ip)/UDP(sport=dns_sport,dport=dns_dport)/DNS(id=dns_id,rd=1,qd=DNSQR(qname="www.google.com", qtype="A")));
if p:
	p.show()

