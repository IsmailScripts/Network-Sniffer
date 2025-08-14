import socket
import struct
import textwrap

PROTOCOLS = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def main():
    try:
        # Create a raw socket for IPv4 packets
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        # Bind to all interfaces
        conn.bind(('192.168.0.197', 0))
        # Enable promiscuous mode to capture all packets
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        print("Packet sniffer started. Press Ctrl+C to stop...")
        while True:
            raw_data, addr = conn.recvfrom(65536)
            version, header_length, ttl, proto, src, target, data = ipv4_packet(raw_data)
            print('\nIPv4 Packet:')
            print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'Protocol: {PROTOCOLS.get(proto)}, Source: {src}, Target: {target}')

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('ICMP Packet:')
                print(f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print('TCP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print('Flags:')
                print(f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print('UDP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
    except PermissionError:
        print("Error: This script requires administrative privileges to capture raw packets. Please run Command Prompt as Administrator and try again.")
    except KeyboardInterrupt:
        print("\nStopping packet sniffer...")
    finally:
        try:
            # Disable promiscuous mode
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            conn.close()
        except:
            pass

if __name__ == '__main__':
    main()