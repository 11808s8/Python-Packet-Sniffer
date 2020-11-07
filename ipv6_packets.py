from format_packets import *
import struct
import socket

def ipv6_header(data):
    
    first_32_bits, \
            payload_length,\
            next_header, \
            hop_limit = struct.unpack('! IHBB', data[:8])
    
    version = first_32_bits >> 28
    traffic_class = (first_32_bits >> 20) & 255
    flow_label = first_32_bits & 1048575
    
    src_address = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst_address = socket.inet_ntop(socket.AF_INET6, data[24:40])

    print(TAB_1 + "IPV6 Packet:")
    print(TAB_2 + "Version: {}, Traffic Class: {}, Flow Label: {}".format(version, traffic_class, flow_label))
    print(TAB_2 + "Payload Length: {}, Next Header: {}, Hop Limit: {}".format(payload_length, next_header, hop_limit))
    print(TAB_3 + "Source Address: {}".format(src_address))
    print(TAB_3 + "Destination Address: {}".format(dst_address))
    
    data = data[40:]
    return (next_header, data)

def hop_by_hop_options(data):
    next_header, header_length = struct.unpack('! B B', data[:2])

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

    print(TAB_1 + "Hop-by-hop options:")
    print(TAB_2 + "Next Header: {}, Header Length: {}".format(next_header, header_length))

    data = data[:hdr_ext_len_converter(header_length)]
    return (next_header, data)

def hdr_ext_len_converter(octets):
    return hdr_ext_len_converter_raw(octets, 8)

def hdr_ext_len_converter_4_octets(octets):
    return hdr_ext_len_converter_raw(octets, 4)

def hdr_ext_len_converter_raw(octets, default_octet_number=8):
    return int(octets*default_octet_number+8)

def destination_options(data):
    next_header, header_length = struct.unpack('! B B', data[:2])
    
    print(TAB_1 + "Destination options:")
    print(TAB_2 + "Next Header: {}, Header Length: {}".format(next_header, header_length))

    # header length uses the same definition as HOP BY HOP options

    data = data[:hdr_ext_len_converter(header_length)]
    return (next_header, data)

def routing_header(data):
    next_header, header_length, routing_type, segments_left = struct.unpack('! B B B B', data[:4])

    # header length uses the same definition as HOP BY HOP options

    print(TAB_1 + "Routing Header:")
    print(TAB_2 + "Header Length: {}, Routing Type: {}, Segments Left: {}".format(next_header, routing_type,segments_left))

    data = data[:hdr_ext_len_converter(header_length)]
    return (next_header, data)

def fragment_header(data):
    next_header, reserved, offset_res_flag_word, identification = struct.unpack('! B B H I', data[:8])
    
    fragment_offset = offset_res_flag_word >> 3
    res = offset_res_flag_word & 6
    m_flag = offset_res_flag_word & 1
    
    
    print(TAB_1 + "Fragment Header:")
    print(TAB_2 + 'Next Header: {}, Reserved: {}, Fragment Offset: {}'.format(next_header, reserved, fragment_offset))
    print(TAB_3 + 'Res: {}, M Flag: {}, Identification: {}'.format(res, m_flag, identification))

    data = data[8:]
    return (next_header,data)


# Defined on https://tools.ietf.org/html/rfc4302
def authentication_header(data):
    next_header, payload_length, reserved, spi, sequence_number = struct.unpack('! B B H I I', data[:12])
    print(TAB_1 + "Authentication Header:")
    print(TAB_2 + 'Next Header: {}, Payload Length: {}, Reserved: {}'.format(next_header, payload_length, reserved))
    print(TAB_3 + 'Security Parameters Index: {}, Sequence Number Field: {}'.format(spi, sequence_number))

    data = data[:hdr_ext_len_converter_4_octets(payload_length)]

    return (next_header, data)
    
def encapsuling_header(data):
    print("No next header")
    return (59, data) # returns a no next header, as this one is hard as heck to calculate :). More info on: https://tools.ietf.org/html/rfc4303
