
import socket
from struct import *
import datetime
import time
import argparse
import pcapy
import sys
# from networking.ethernet import Ethernet
# from networking.pcap import Pcap

def main(args):
    if args.interface:
        dev = args.interface
        print('using args int')
    else: 
        #ask user to enter device name to sniff
        print ("Available devices are :")
        for d in pcapy.findalldevs() :
            print (d)
        dev = raw_input("Enter device name to sniff : ")
    capture = pcapy.open_live(dev , 65536 , 1 , 0)
    if args.time:
        timeout = args.time
        print('using args time')
    else:
        timeout = 30
    timeout_start = time.time()
    while time.time() < timeout_start + timeout:
        (header, packet) = capture.next()
        print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
        parse_packet(packet)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b
 

def parse_packet(packet) :
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print ('Destination MAC : ' + eth_addr(packet[0:6]) + ', Source MAC : ' + eth_addr(packet[6:12]) + ', Protocol : ' + str(eth_protocol))
 
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        ip_header = packet[eth_length:20+eth_length]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        print ('Version : ' + str(version) + ', IP Header Length : ' + str(ihl) + ', TTL : ' + str(ttl) + ', Protocol : ' + str(protocol) + ', Source Address : ' + str(s_addr) + ', Destination Address : ' + str(d_addr))
 
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--time", help="The length of time to capture packets for", action="store",type=int, dest="time")
    parser.add_argument("-i", "--interface", help="The network interface to capture traffic on", action="store", type=str, dest="interface")
    args = parser.parse_args()
    main(args)
