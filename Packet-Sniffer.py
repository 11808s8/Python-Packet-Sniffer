#! /usr/local/bin/python3.5

import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print('\n Ethernet Frame: ')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            pass
            # (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)
            # print(TAB_1 + "IPV4 Packet:")
            # print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            # print(TAB_3 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # # ICMP
            # if proto == 1:
            #     icmp_type, code, checksum, data = icmp_packet(data)
            #     print(TAB_1 + 'ICMP Packet:')
            #     print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
            #     print(TAB_2 + 'ICMP Data:')
            #     print(format_output_line(DATA_TAB_3, data))

            # # TCP
            # elif proto == 6:
            #     src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
            # '! H H L L H H H H H H', raw_data[:24])
            #     print(TAB_1 + 'TCP Segment:')
            #     print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
            #     print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
            #     print(TAB_2 + 'Flags:')
            #     print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
            #     print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))

            #     if len(data) > 0:
            #         # HTTP
            #         if src_port == 80 or dest_port == 80:
            #             print(TAB_2 + 'HTTP Data:')
            #             try:
            #                 http = HTTP(data)
            #                 http_info = str(http.data).split('\n')
            #                 for line in http_info:
            #                     print(DATA_TAB_3 + str(line))
            #             except:
            #                 print(format_output_line(DATA_TAB_3, data))
            #         else:
            #             print(TAB_2 + 'TCP Data:')
            #             print(format_output_line(DATA_TAB_3, data))
            # # UDP
            # elif proto == 17:
            #     src_port, dest_port, length, data = udp_seg(data)
            #     print(TAB_1 + 'UDP Segment:')
            #     print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            # # Other IPv4
            # else:
            #     print(TAB_1 + 'Other IPv4 Data:')
            #     print(format_output_line(DATA_TAB_2, data))
        elif(eth_proto == 56710):
            print("IPV6")
            print("eth prot {}".format(eth_proto))
            print(data[:1])
            print("\ndata\n")
            print(data)
            first_32_bits, \
                    payload_length,\
                    next_header, \
                    hop_limit = struct.unpack('! IHBB', data[:8])
            # version = struct.unpack('! B', data[:1])

            version = first_32_bits >> 28
            traffic_class = (first_32_bits >> 20) & 255
            flow_label = first_32_bits & 1048575
            
            # flow_label
            # BITS
                            #4+8+20+16+8+8

            print("First word")
            print(bin(first_32_bits))
            print("Version")
            print(version)
            print("Traffic Class")
            print(bin(traffic_class))
            print("Flow Label")
            print(bin(flow_label))
            print("Payload Length")
            print(bin(payload_length))
            print("Next Header")
            print(next_header)
            proto = next_header
            print("Hop Limit")
            print(bin(hop_limit))
            
            src_address = socket.inet_ntop(socket.AF_INET6, data[8:24])
            dst_address = socket.inet_ntop(socket.AF_INET6, data[24:40])

            print("Source Address")
            print(src_address)
            print("Dest Address")
            print(dst_address)

            data = data[40:]
            #@TODO: Put UDP and TCP here as well (from IPv4 above)

            # ORDER DEFINED ON RFC8200
            #Hop-by-Hop Options
            if(next_header == 0 ):
                next_header, data = hop_by_hop_options(data)
                # pass
            #Destination Options
            if(next_header == 60 ):
                pass
            #Routing
            if(next_header == 43 ):
                pass
            #Fragment
            if(next_header == 44 ):
                pass
            #Authentication
            if(next_header == 51 ):
                pass
            #Encapsulating Security Payload
            if(next_header == 50 ):
                pass
            #ICMPv6
            if(next_header == 58 ):
                pass
            # version = data[0]
            # print(version)
            # print("Not Converted")
            # print(bin(version))
            # version = version >> 4
            # print("Converted")
            # print(version)
            input()
            # version, traffic_class, flow_label, payload_length,next_header, hop_limit = struct.unpack('! H', data[:40])
            # ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        else:
            print('Ethernet Data:')
            print(format_output_line(DATA_TAB_1, data))


def hop_by_hop_options(data):
    next_header, header_length = struct.unpack('! B B', data[:2])
    print("Next header")
    print(next_header)
    print("Header Length")
    print(header_length)
    # print("Options")
    # print(options)

    '''
    BY DEFINITION ON https://tools.ietf.org/html/rfc8200#section-4.3
    Hdr Ext Len         8-bit unsigned integer.  Length of the
                          Hop-by-Hop Options header in 8-octet units,
                          not including the first 8 octets.


                          That is: 1 octet = 8 bits (1 byte)
                            as it uses 8 octets by default for the number in Hdr Ext len,
                            from that logic we have:
                            Hdr Ext Len * 8 
                            As it does not include the first 8 octets, we have
                            to add to it
                            Hdr Ext Len * 8 + 8
    '''

    data = data[:hdr_ext_len_converter(header_length)]
    input()
    return (next_header, data)

def hdr_ext_len_converter(octets):
    return hdr_ext_len_converter_raw(octets, 8)

def hdr_ext_len_converter_raw(octets, default_octet_number=8):
    return int(octets*default_octet_number+8)

# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # Format MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpack IPv4 Packets Recieved
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks for any ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks for any TCP Packet
def tcp_seg(data):
    (src_port, destination_port, sequence, acknowledgenment, offset_reserv_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserv_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >>4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpacks for any UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Formats the output line
def format_output_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
