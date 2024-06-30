from FSM import TCPState

from scapy.layers.inet import Ether, IP, TCP
from scapy.sendrecv import send
from scapy.all import *
import random
import threading
import time
import sys


def send_synack_packet(src_ip, src_port, dst_ip, dst_port, seq_num, ack_num, iface):
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags="SA", seq=seq_num, ack=ack_num)
    packet = ip_layer / tcp_layer
    send(packet, iface=iface)


def send_fin_packet(src_ip, src_port, dst_ip, dst_port, seq_num, ack_num, iface):
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags="F", seq=seq_num, ack=ack_num)
    packet = ip_layer / tcp_layer
    send(packet, iface=iface)


def send_fin_ack(src_ip, src_port, dst_ip, dst_port, seq_num, ack_num, iface):
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags="FA", seq=seq_num, ack=ack_num)
    packet = ip_layer / tcp_layer
    send(packet, iface=iface)


def send_ack(src_ip, src_port, dst_ip, dst_port, seq_num, ack_num, iface):
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags="A", seq=seq_num, ack=ack_num)
    packet = ip_layer / tcp_layer
    send(packet, iface=iface)


def handle_retransmit(ack):
    print("In thread to retransmit" + str(ack))
    time.sleep(1)
    while ack in data_sent:
        send(data_sent[ack], iface)
        time.sleep(1)
    print("Exiting thread to retransmit" + str(ack))


def synack_retransmit(source_ip, source_port, dest_ip, dest_port, init_seq, seq, iface):
    time.sleep(2)
    while status.state == "SYNACK_SENT":
        print("Didn't get client ack, retransmitting syn/ack")
        send_synack_packet(source_ip, source_port, dest_ip, dest_port, init_seq, seq+1, iface)
        time.sleep(1)
    print("Exiting thread to retransmit syn/ack")


def handle_pkt(pkt):
    ip = pkt[IP]
    tcp = pkt[TCP]
    flags = tcp.flags
    seq = tcp.seq
    ack = tcp.ack
    global dest_port

    if status.state == "LISTEN" and (flags & 0x02) and not (flags & 0x10):
        status.handle_event("RECEIVE_SYN")
        print("Initial sequence number " + str(init_seq))
        dest_port = ip.sport
        send_synack_packet(source_ip, source_port, dest_ip, dest_port, init_seq, seq+1, iface)
        status.handle_event("SEND_SYNACK")
        t = threading.Thread(target=synack_retransmit, args=(source_ip, source_port, dest_ip, dest_port, init_seq, seq+1, iface))
        t.start()

    if status.state == "SYNACK_SENT" and (flags & 0x10) and not (flags & 0x02) and not (flags & 0x01):
        if flags & 0x10 and ack == init_seq+1:
            print("Handshake complete")
            status.handle_event("RECEIVE_ACK")
            try:
                with open(path, 'rb') as file:
                    while True:
                        data = file.read(chunk_size)
                        if not data: 
                            break
                        else:
                            ip_layer = IP(src=source_ip, dst=dest_ip)
                            tcp_layer = TCP(sport=source_port, dport=dest_port, flags="PA", seq=ack, ack=seq)
                            packet = ip_layer / tcp_layer / data
                            send(packet, iface=iface)
                            ack += len(data)
                            data_sent[ack] = packet # need to add first bc client acknlowladges reciept of data
                            t = threading.Thread(target=handle_retransmit, args=(ack,))
                            t.start()
            except FileNotFoundError:
                print(f"File not found: {path}")
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            print("Recieved incorrect ack " + str(ack))

    if status.state == "ESTABLISHED":
        if flags & 0x10 and ack in data_sent:
            data_sent.pop(ack)
            if ack > last_nums[0]:
                last_nums[0] = ack
            if seq > last_nums[0]:
                last_nums[1] = seq
            print("Recieved ack for packet with seq " + str(ack))
        if not data_sent:
            print("All packets sent acked by the client")
            send_fin_packet(source_ip, source_port, dest_ip, dest_port, last_nums[0], last_nums[1], iface)
            status.handle_event("CLOSE")

    if status.state == "FIN_WAIT_1": # we send a fin once we're done transmitting and the client has everything
        if flags & 0x10:
             status.handle_event("RECEIVE_FIN_ACK")

    if status.state == "FIN_WAIT_2":
        if (flags & 0x01):
            status.handle_event("RECEIVE_FIN")
            send_ack(source_ip, source_port, dest_ip, dest_port, ack, seq+1, iface)
    
    if status.state == "TIME_WAIT":
        time.sleep(1)
        status.handle_event("TIMEOUT")
       


if __name__ == "__main__":
    source_ip = "ip"
    source_port = 5050
    dest_ip = "ip"
    dest_port = 5050
    path = "fill in path here"
    iface = "fill in iface"
    status = TCPState()
    init_seq = random.randint(0, 2**32 - 1)
    chunk_size=1024
    data_sent = {}    
    last_nums = [0, 0]

    filter_str = f"tcp and dst port {source_port} and src host {dest_ip} and dst host {source_ip}"
    status.handle_event("PASSIVE_OPEN")
    sniff(filter=filter_str, iface=iface, prn=handle_pkt)
    print("Server closed")
