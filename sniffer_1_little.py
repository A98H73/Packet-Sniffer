import socket
import struct 
import textwrap
import os
import time
from datetime import datetime


TAB_1 = '\t  - '
TAB_2 = '\t\t  - '
TAB_3 = '\t\t\t  - '
TAB_4 = '\t\t\t\t  - '

DATA_TAB_1 = '\t  - '
DATA_TAB_2 = '\t\t  - '
DATA_TAB_3 = '\t\t\t  - '
DATA_TAB_4 = '\t\t\t\t  - '


#     Pcap Global Header Format :
#                       ( magic number + 
#                         major version number + 
#                         minor version number + 
#                         GMT to local correction +
#                         accuracy of timestamps + 
#                         max length of captured #packets, in octets +
#                         data link type) 
#
#


PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '


# Global Header Values
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1


class Pcap:

 def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
  self.pcap_file = open(filename, 'wb') 
  self.pcap_file.write(struct.pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER, PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, link_type))
  print ("[+] Link Type : {}".format(link_type))

 def writelist(self, data=[]):
  for i in data:
   self.write(i)
  return

 def write(self, data):
  ts_sec, ts_usec = map(int, str(time.time()).split('.'))
  length = len(data)
  self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
  self.pcap_file.write(data)

 def close(self):
  self.pcap_file.close()



def main():


    # Create socket 
    if os.name == "nt":
        conn = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
        conn.bind((raw_input("[+] YOUR_INTERFACE : "),0))
        conn.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        conn.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
    else:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

    # datetime object containing current date and time

    now = datetime.now()
    count=0

    # dd/mm/YY H:M:S
    dt_string = now.strftime("%d/%m/%Y_%H:%M:%S")

    pcap_file1 = Pcap("Sniffed_packet_1.pcap")

    while True:
        
        count+=1

        raw_data, addr = conn.recvfrom(65535)
        
        pcap_file1.write(raw_data)



        dest_addr, src_addr, eth_proto, data = ethernet_frame(raw_data)
        print('\n Ehternet Frame: ')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_addr, src_addr, eth_proto))

        # in file
        # pcap_file.write('\n Ehternet Frame: ')
        # pcap_file.write(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_addr, src_addr, eth_proto))

        # 8 for IPv4

        if eth_proto ==8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4_PAcket: ')
            print(TAB_2 + 'Version: {}, header_length: {}, TTL(Time to Live): {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # In file

            # pcap_file.write(TAB_1 + 'IPv4_PAcket: ')
            # pcap_file.write(TAB_2 + 'Version: {}, header_length: {}, TTL(Time to Live): {}'.format(version, header_length, ttl))
            # pcap_file.write(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            
            

            # 1 for ICMP

            if proto ==1:
                (icmp_type, code, checksum, data) = ICMP_packet(data)
                print(TAB_1 + 'ICMP_PAcket: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data: {}')
                print(format_multi_line(DATA_TAB_3, data))

                #In file

                # pcap_file.write (TAB_1 + 'ICMP_PAcket: ')
                # pcap_file (TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                # pcap_file.write(TAB_2 + 'Data: {}')
                # pcap_file.write(format_multi_line(DATA_TAB_3, data))

            
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

                # IN File

                # pcap_file.write(TAB_1 + 'TCP Segment: ')
                # pcap_file.write(TAB_2 + 'Source port: {}, Destination port: {}'.format(src_port, dest_port))
                # pcap_file.write(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                # pcap_file.write(TAB_2 + 'Flags')
                # pcap_file.write(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                # pcap_file.write(TAB_2 + 'Data: {}')
                # pcap_file.write(format_multi_line(DATA_TAB_3, data))


            # 17 for UDP     

            elif proto == 17:
                (src_port, dest_port, size, data) = udp_packet(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source port: {}, Destination port: {}, Length: {}'.format(src_port, dest_port, size))
                print(TAB_2 + 'Data: {}')
                print(format_multi_line(DATA_TAB_3, data))

                # In File

                # pcap_file.write(TAB_1 + 'UDP Segment: ')
                # pcap_file.write(TAB_2 + 'Source port: {}, Destination port: {}, Length: {}'.format(src_port, dest_port, size))
                # pcap_file.write(TAB_2 + 'Data: {}')
                # pcap_file.write(format_multi_line(DATA_TAB_3, data))

            # Other     

            else:
                print(TAB_1 + 'Data: {}')
                print(format_multi_line(DATA_TAB_2, data))

                # In file    

                # pcap_file.write(TAB_1 + 'Data: {}')
                # pcap_file.write(format_multi_line(DATA_TAB_2, data))


        else:
            print('Data: {}')
            print(format_multi_line(DATA_TAB_1, data))


            # In File    

            # pcap_file.write('Data: {}')
            # pcap_file.write(format_multi_line(DATA_TAB_1, data))



        # flush data

        pcap_file1.pcap_file.flush()

        if count>=100:
            break

    # Closing the file
    pcap_file1.close()










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
