import sys

from packet_struct import *
from header_class import *
from connection_class import *

MAGIC_NUMBER = b'\xa1\xb2\xc3\xc4'

all_packets = []

def initialize():
    """
    Read from the standard input a file and returns a list of packets.
    """


    if len(sys.argv) < 2:
        print("---ERROR: Expecting a file or filepath to be passed through")
        sys.exit(1)
    if len(sys.argv) > 2:
        print("---WARNING: Expecting a single file or filepath to be passed through: will only use the first one")
    

    cap_file = open(sys.argv[1], "rb")
    data = cap_file.read(24)
    g_header = Global_Header(data)

    packet_header = cap_file.read(16)
    packet_num = 0
    orig_time = None

    all_packets = []

    while packet_header != b'':
        p_h = Packet_Header(packet_header, g_header)
        p_d = cap_file.read(p_h.get_incl_len())

        if orig_time == None:
            orig_time = p_h.ts_sec + (p_h.ts_usec/ 1000000)

        i_h = p_d[14:]
        ip_header = IP_Header()
        ip_header.get_header_len(i_h[0:1])
        ip_header.get_total_len(i_h[2:4])
        ip_header.get_IP(i_h[12:16], i_h[16:20])

        t_h = p_d[ip_header.ip_header_len + 14:]
        tcp_header = TCP_Header()
        tcp_header.get_src_port(t_h[0:2])
        tcp_header.get_dst_port(t_h[2:4])
        tcp_header.get_seq_num(t_h[4:8])
        tcp_header.get_ack_num(t_h[8:12])
        tcp_header.get_data_offset(t_h[12:13])
        tcp_header.get_flags(t_h[13:14])
        tcp_header.get_window_size(t_h[14:15], t_h[15:16])

        p = packet()
        p.IP_header = ip_header
        p.TCP_header = tcp_header
        p.timestamp_set(p_h.ts_sec.to_bytes(4, 'little'), p_h.ts_usec.to_bytes(4, 'little'), orig_time)
        p.packet_No_set(packet_num)

        packet_num += 1
        all_packets.append(p)

        packet_header = cap_file.read(16)


    cap_file.close()
    return all_packets

def sort_connections(packets):
    """
    """
    keys = []
    connections = {}

    for p in packets:

        ips = (p.IP_header.src_ip, p.IP_header.dst_ip)
        ips_r = tuple(ips[::-1])
        ports = (p.TCP_header.src_port, p.TCP_header.dst_port)
        ports_r = tuple(ports[::-1])

        curr_key  = (ips, (p.TCP_header.src_port, p.TCP_header.dst_port))
        curr_key2 = (ips_r, ports_r)

        if curr_key in keys:
            connections[curr_key].add_packet(p)
            continue
        if curr_key2 in keys:
            connections[curr_key2].add_packet(p)
            continue
        
        c = connection(p, len(keys)+1)
        keys.append(curr_key)
        connections[curr_key] = c


    return (keys, connections)

def part_a(connections):
    """
    """
    print("A) Total number of connections: ", len(connections[1]))
    print("\n________________________________________________\n")

def part_b(connections):
    """
    """
    print("B) Connection's details\n")
    for k in connections[0]:
        connections[1][k].print_result()
        if k != connections[0][-1]:
            print("++++++++++++++++++++++++++++++++")
    print("________________________________________________\n")

def part_c(connections):
    """
    """

    complete_connections = []
    num_resetted = 0
    num_open = 0

    for key in connections[0]:
        c = connections[1][key]
        if c.resetted:
            num_resetted = num_resetted + 1
        if c.open:
            num_open = num_open + 1

        if c.num_fin > 0 and c.num_syn > 0:
            complete_connections.append(c)

    print("C) General\n")
    print("Total number of complete TCP connections:", len(complete_connections))
    print("Number of reset TCP connections:", num_resetted)
    print("Number of TCP connections that were still open when trace capture ended:", num_open)
    print("________________________________________________\n")

def part_d(connections):
    """
    """

    complete_connections = []

    for key in connections[0]:
        c = connections[1][key]
        if c.num_fin > 0 and c.num_syn > 0:
            complete_connections.append(c)
    
    minimum_duration = None
    maximum_duration = None
    sum_duration = 0

    minimum_rtt = None
    maximum_rtt = None
    sum_rtt = 0
    total_rtt_packets = 0

    minimum_p_sent = None
    maximum_p_sent = None
    sum_p_sent = 0

    minimum_rcws = None
    maximum_rcws = None
    sum_rcws = 0

    total_packets = 0

    for c in complete_connections:
        sum_duration = sum_duration + c.duration
        if minimum_duration is None or minimum_duration > c.duration:
            minimum_duration = c.duration

        if maximum_duration is None or maximum_duration < c.duration:
            maximum_duration = c.duration
        
        packets_sent = len(c.packets_from_source) + len(c.packets_from_dest)
        sum_p_sent = sum_p_sent + packets_sent
        if minimum_p_sent is None or minimum_p_sent > packets_sent:
            minimum_p_sent = packets_sent
        if maximum_p_sent is None or maximum_p_sent < packets_sent:
            maximum_p_sent = packets_sent
        
        for p in c.packets_from_source + c.packets_from_dest:
            sum_rcws = sum_rcws + p.TCP_header.window_size
            total_packets = total_packets + 1
            if minimum_rcws is None or minimum_rcws > p.TCP_header.window_size:
                minimum_rcws = p.TCP_header.window_size
            if  maximum_rcws is None or maximum_rcws < p.TCP_header.window_size:
                maximum_rcws = p.TCP_header.window_size
            

        rtt_packets = calculate_rtt(c)
        total_rtt_packets = total_rtt_packets + len(rtt_packets)
        for v in rtt_packets:
            sum_rtt = sum_rtt + v
            if minimum_rtt is None or minimum_rtt > v:
                minimum_rtt = v
            if maximum_rtt is None or maximum_rtt < v:
                maximum_rtt = v
        
    if minimum_duration is None:
        minimum_duration = 0
    if maximum_duration is None:
        maximum_duration = 0
    if maximum_rtt is None:
        maximum_rtt = 0
    if minimum_rtt is None:
        minimum_rtt = 0
    if minimum_p_sent is None:
        minimum_p_sent = 0
    if maximum_p_sent is None:
        maximum_p_sent = 0
    if minimum_rcws is None:
        minimum_rcws = 0
    if maximum_p_sent is None:
        maximum_p_sent = 0
    
    print("D) Complete TCP connections\n")
    print("Minimum time duration:", minimum_duration, "seconds")
    print("Mean time duration:", round(sum_duration/len(complete_connections), 6), "seconds")
    print("Maximum time duration:", maximum_duration, "seconds")
    print("\n")
    print("Minimum RTT value:", minimum_rtt)
    print("Mean RTT value:", round(sum_rtt/total_rtt_packets, 6))
    print("Maximum RTT value:", maximum_rtt)
    print("\n")
    print("Minimum number of packets including both send/received:", minimum_p_sent)
    print("Mean number of packets including both send/received:", round(sum_p_sent/len(complete_connections), 6))
    print("Maximum number of packets including both send/received:", maximum_p_sent)
    print("\n")
    print("Minimum receive window size including both send/received:", minimum_rcws)
    print("Mean receive window size including both send/received:", round(sum_rcws/total_packets, 6))
    print("Maximum receive window size including both send/received:", maximum_rcws)
    print("________________________________________________\n")

def calculate_rtt(c):
    rtt_packets  = []


    for p in c.packets_from_source:
        data_size = p.IP_header.total_len - p.IP_header.ip_header_len - p.TCP_header.data_offset
        if p.TCP_header.flags["SYN"] == 0 and p.TCP_header.flags["FIN"] == 0:
            continue
        if p.TCP_header.flags["RST"] == 1:
            continue
        for n in c.packets_from_dest:
            if n.TCP_header.flags["ACK"] == 1 and n.TCP_header.ack_num == p.TCP_header.seq_num+data_size+1:
                p.get_RTT_value(n)
                n.RTT_flag = True
                rtt_packets.append(p.RTT_value)
                break
    
    return rtt_packets

    
    


        

def main():
    packets = initialize()
    connections = sort_connections(packets)
    
    part_a(connections)
    part_b(connections)
    part_c(connections)
    part_d(connections)

if __name__ == '__main__':
    main()