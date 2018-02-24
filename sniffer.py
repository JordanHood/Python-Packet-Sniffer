#!/usr/bin/python3.6
from struct import *
from pypacker.layer567.rtp import RTP
from networking.pcap import Pcap
import os
import socket
import datetime
import time
import argparse
import pcapy
import sys
import struct

file_types = {
    32768: 'g771'
}

def main(args):
    try:
        os.remove("out.au")
    except OSError:
        pass
    try:
        if args.interface:
            dev = args.interface
        else: 
            #ask user to enter device name to sniff
            print ("Available devices are :")
            for d in pcapy.findalldevs() :
                print (d)
            dev = input("Enter device name to sniff : ")
        capture = pcapy.open_live(dev , 65536 , True , 0)
        if args.time:
            timeout = args.time
        else:
            timeout = 30
        timeout_start = time.time()
        while time.time() < timeout_start + timeout:
            (header, packet) = capture.next()
            print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
            parse_packet(packet)
        convert_au()
    except KeyboardInterrupt: sys.exit()

def convert_au():
    try:
        header = [ 0x2e736e64, 24, 0xffffffff, 1, 8000, 1 ]
        au=open('out.au','wb')
        au.write ( struct.pack ( ">IIIIII", *header ) )
        raw = open('outfile_g771.raw','rb').read()
        au.write(raw)
        au.close()
        os.remove('outfile_g771.raw')
    except OSError:
        pass

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

def parse_packet(packet) :
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
            try:
                # only convert packets with a type we understand
                fileName = 'outfile_' + file_types[rtp._type] +'.raw'
                print("apsonsdipv "+file_types[rtp._type])
                file = open(fileName,'ab+') 
                file.write(rtp._body_bytes) 
                file.close()
            except KeyError:
                # Key is not present
                print('error with ')
                print(rtp._type)
                pass
            print('\n')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--time", help="The length of time to capture packets for", action="store",type=int, dest="time")
    parser.add_argument("-i", "--interface", help="The network interface to capture traffic on", action="store", type=str, dest="interface")
    args = parser.parse_args()
    main(args)
