#!/usr/bin/python3.6
from struct import *
from pypacker.layer567.rtp import RTP
import socket
import datetime
import time
import argparse
import pcapy
import sys
import struct
from pprint import pprint

def main(args):
    if args.interface:
        dev = args.interface
    else: 
        #ask user to enter device name to sniff
        print ("Available devices are :")
        for d in pcapy.findalldevs() :
            print (d)
        dev = input("Enter device name to sniff : ")
    capture = pcapy.open_live(dev , 65536 , 1 , 0)
    if args.time:
        timeout = args.time
    else:
        timeout = 30
    timeout_start = time.time()
    file = open('testfile.raw','ab+') 
    while time.time() < timeout_start + timeout:
        (header, packet) = capture.next()
        print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
        parse_packet(packet, file)
    file.close()
    convert_au()
    # got a capture of UDP packets, now to convert to best type

def convert_au():
    header = [ 0x2e736e64, 24, 0xffffffff, 1, 8000, 1 ]
    au=open('out.au','wb')
    au.write ( struct.pack ( ">IIIIII", *header ) )
    raw = open('testfile.raw','rb').read()
    au.write(raw)
    au.close()


#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

def parse_packet(packet, file) :
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    # print ('Destination MAC : ' + eth_addr(packet[0:6]) + ', Source MAC : ' + eth_addr(packet[6:12]) + ', Protocol : ' + str(eth_protocol))
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
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
 
        print ('Version : ' + str(version) + ', IP Header Length : ' + str(ihl) + ', TTL : ' + str(ttl) + ', Protocol : ' + str(protocol) + ', Source Address : ' + str(s_addr) + ', Destination Address : ' + str(d_addr))
        # #UDP packets
        if protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
            udph = unpack('!HHHH' , udp_header)
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
            data = packet[h_size:]
            rtp = RTP(data)
            print('RTP Payload')
            print(rtp)
            # print("rtp commi/ng")
            # pprint(vars(rtp))
            # print("type")
            # print(rtp.type)
            # pprint(vars(rtp))
            # print("rtp")
            # print(rtp)
            # print("\n\n")
            # print("\n\n")
            if(rtp._type == 32768):
                file.write(rtp._body_bytes) 
            #  8000 hz u-law stero
            #  
            # get the RTP header length, the rest is the payload
            # print 'Data : ' + data
            
        # #TCP protocol
        # if protocol == 6 :
        #     t = iph_length + eth_length
        #     tcp_header = packet[t:t+20]
 
        #     tcph = unpack('!HHLLBBHHH' , tcp_header)
             
        #     source_port = tcph[0]
        #     dest_port = tcph[1]
        #     sequence = tcph[2]
        #     acknowledgement = tcph[3]
        #     doff_reserved = tcph[4]
        #     tcph_length = doff_reserved >> 4
             
        #     print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
             
        #     h_size = eth_length + iph_length + tcph_length * 4
        #     data_size = len(packet) - h_size
             
        #     #get data from the packet
        #     data = packet[h_size:]
             
        #     print 'Data : ' + data
 
        # #ICMP Packets
        # elif protocol == 1 :
        #     u = iph_length + eth_length
        #     icmph_length = 4
        #     icmp_header = packet[u:u+4]
 
        #     icmph = unpack('!BBH' , icmp_header)
             
        #     icmp_type = icmph[0]
        #     code = icmph[1]
        #     checksum = icmph[2]
             
        #     print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
             
        #     h_size = eth_length + iph_length + icmph_length
        #     data_size = len(packet) - h_size
             
        #     #get data from the packet
        #     data = packet[h_size:]
             
        #     print 'Data : ' + data 
        # #some other IP packet like IGMP
        # else :
        #     print 'Protocol other than TCP/UDP/ICMP'
             
        # print
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--time", help="The length of time to capture packets for", action="store",type=int, dest="time")
    parser.add_argument("-i", "--interface", help="The network interface to capture traffic on", action="store", type=str, dest="interface")
    args = parser.parse_args()
    main(args)
