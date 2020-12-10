#! /usr/local/bin/python3.5

import socket
import struct
import textwrap
import ipv4_packets
import ipv6_packets
import multiple_protocol_methods
from format_packets import *

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = multiple_protocol_methods.ethernet_frame(raw_data)

        print(TAB_1 + '\n Ethernet Frame: ')
        print(TAB_2 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8: # IPv4
            
            (version, header_length, ttl, proto, src, target, data) = ipv4_packets.ipv4_Packet(data)
            print(TAB_1 + "IPV4 Packet:")
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_3 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1:
                multiple_protocol_methods.icmp_packet_template_method(data)

            # TCP
            elif proto == 6:
                multiple_protocol_methods.tcp_template_method(raw_data, data)
            # UDP
            elif proto == 17:
                multiple_protocol_methods.udp_template_method(data)

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_output_line(DATA_TAB_2, data))
        elif(eth_proto == 56710): # IPv6 - It is 56710 as htons converts it FROM 34525 
                                  # (the original value read - which is 86DD in HEX and indicates the packet being IPv6
                                  # - more info on https://tools.ietf.org/html/rfc2464#section-3)
            
            next_header, data = ipv6_packets.ipv6_header(data)

            # ORDER DEFINED ON RFC8200 - https://tools.ietf.org/html/rfc8200
            #Hop-by-Hop Options
            if(next_header == 0 ):
                next_header, data = ipv6_packets.hop_by_hop_options(data)
                # pass
            #Destination Options
            if(next_header == 60 ):
                next_header, data = ipv6_packets.destination_options(data)
            #Routing
            if(next_header == 43 ):
                next_header, data =  ipv6_packets.routing_header(data)
                
            #Fragment
            if(next_header == 44 ):
                next_header, data =  ipv6_packets.fragment_header(data)
            #Authentication
            if(next_header == 51 ):
                next_header, data =  ipv6_packets.authentication_header(data)
                
            #Encapsulating Security Payload
            if(next_header == 50 ):
                next_header, data =  ipv6_packets.encapsuling_header(data)
            if(next_header == 59) :
                print("No next header")
            #ICMPv6
            if(next_header == 58 ):
                # Defined on https://tools.ietf.org/html/rfc4443#page-3   <--- The same as ICMPv4 :)
                multiple_protocol_methods.icmp_packet_template_method(data)

            # TCP
            if(next_header == 6):
                multiple_protocol_methods.tcp_template_method(raw_data, data)

            # UDP
            if(next_header == 17):
                multiple_protocol_methods.udp_template_method(data)
            
        elif(eth_proto==1544): # ARP
            print(TAB_1 + " --- ARP Protocol ---")
        else:
            print('Ethernet Data:')
            print(format_output_line(DATA_TAB_1, data))



main()
