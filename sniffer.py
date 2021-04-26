import socket
import struct 
import textwrap



TAB_1 = '\t  - '
TAB_2 = '\t\t  - '
TAB_3 = '\t\t\t  - '
TAB_4 = '\t\t\t\t  - '

DATA_TAB_1 = '\t  - '
DATA_TAB_2 = '\t\t  - '
DATA_TAB_3 = '\t\t\t  - '
DATA_TAB_4 = '\t\t\t\t  - '



def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_addr, src_addr, eth_proto, data = ethernet_frame(raw_data)
        print('\n Ehternet Frame: ')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_addr, src_addr, eth_proto))

        # 8 for IPv4

        if eth_proto ==8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4_PAcket: ')
            print(TAB_2 + 'Version: {}, header_length: {}, TTL(Time to Live): {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            


            # 1 for ICMP

            if proto ==1:
                (icmp_type, code, checksum, data) = ICMP_packet(data)
                print(TAB_1 + 'ICMP_PAcket: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data: {}')
                print(format_multi_line(DATA_TAB_3, data))

            
            # 6 for TCP

            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_packet(data)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source port: {}, Destination port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: {}')
                print(format_multi_line(DATA_TAB_3, data))

            # 17 for UDP     

            elif proto == 17:
                (src_port, dest_port, size, data) = udp_packet(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source port: {}, Destination port: {}, Length: {}'.format(src_port, dest_port, size))
                print(TAB_2 + 'Data: {}')
                print(format_multi_line(DATA_TAB_3, data))

            # Other     

            else:
                print(TAB_1 + 'Data: {}')
                print(format_multi_line(DATA_TAB_2, data))

        else:
            print('Data: {}')
            print(format_multi_line(DATA_TAB_1, data))








# Unpack Ethernet Frame

def ethernet_frame(data):
    src_mac, dest_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Return properly formatted MAC Address

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# Unpacking Ipv4 Packets

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Properly formatted Ipv4 address
    
#127.0.0.1

def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpack ICMP PAckets

def ICMP_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP Packet    

def tcp_packet(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserve_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserve_flags >> 12) * 4
    flag_urg = (offset_reserve_flags & 32) >> 5
    flag_ack = (offset_reserve_flags & 16) >> 4
    flag_psh = (offset_reserve_flags & 8) >> 3
    flag_rst = (offset_reserve_flags & 4) >> 2
    flag_syn = (offset_reserve_flags & 2) >> 1
    flag_fin = (offset_reserve_flags & 1)

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset :]


# Unpack UDP PAcket

def udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]



# formats multi line data

def format_multi_line(prefix, string, size = 80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -=1

    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])





main()        