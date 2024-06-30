from FSM import TCPState

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send
from scapy.all import *
import random
import struct


def send_syn_packet(src_ip, src_port, dst_ip, dst_port, seq_num, iface):
    ip_layer = IP(src=src_ip, dst=dst_ip)

    tcp_options = [
        ('SAckOK', b'')  # Specify support for SACK
    ]

    tcp_layer = TCP(sport=src_port, dport=dst_port, flags='S', seq=seq_num, options=tcp_options)
    packet = ip_layer / tcp_layer
    send(packet, iface=iface)


def syn_retransmit(source_ip, source_port, dest_ip, dest_port, seq, iface):
    time.sleep(1)
    while status.state == "SYN_SENT":
        print("Client didn't respond to syn - retransmitting")
        send_syn_packet(source_ip, source_port, dest_ip, dest_port, seq, iface)
        time.sleep(1)
    print("Exiting thread to retransmit syn")


def send_ack(src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, iface):    
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags='A', seq=seq_num, ack=ack_num)
    packet = ip_layer / tcp_layer
    send(packet, iface=iface)


def send_fin(src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, iface):
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags='F', seq=seq_num, ack=ack_num)
    packet = ip_layer / tcp_layer
    send(packet, iface=iface)


def send_sack(src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, start, end, iface):
    # IP and TCP layers
    ip_layer = IP(src=src_ip, dst=dst_ip)

    tcp_options = [
        ("MSS", 1460),
        ("SAckOK", b""),
        ("SAck", struct.pack("!II", start, end))  # Pack start and end values into network byte order
    ]

    tcp_layer = TCP(sport=src_port, dport=dst_port, flags='A', seq=seq_num, ack=ack_num, options=tcp_options)

    # Construct packet
    packet = ip_layer / tcp_layer

    # Send packet
    send(packet, iface=iface)


def write_payload(payload):
    with open(path, "ab") as f:
        if not found_headers[0]:
            payload_str = payload.decode('latin1')
            header_end = payload_str.find('\r\n\r\n')
            if header_end != -1:
                payload = payload[header_end+4:]
                found_headers[0] = True 
        f.write(payload)


def lost_ack():
    print("Server either doesn't send the last ack to close or it was lost")
    status.handle_event("RECEIVE_ACK")


def handle_pkt(pkt):
    ip = pkt[IP]
    tcp = pkt[TCP]
    flags = tcp.flags
    seq = tcp.seq
    ack = tcp.ack
    global final_seq_num

    print(flags)


    if status.state == "SYN_SENT" and (flags & 0x12):
        if (ack == init_seq+1):
            status.handle_event("RECEIVE_SYN_ACK")
            send_ack(source_ip, dest_ip, source_port, dest_port, ack, seq+1, iface)
            expected_seq[0] = seq+1
        else:
            print("Recived syn/ack with invalid ack number")

    if status.state == "ESTABLISHED" and flags & 0x10:
        payload = bytes(tcp.payload)
        if seq == expected_seq[0]:
            expected_seq[0] += len(payload)
            write_payload(payload)
            send_ack(source_ip, dest_ip, source_port, dest_port, ack, expected_seq[0], iface)
            print("Acked sequence number: " + str(seq))

            while expected_seq[0] in buffer:
                payload = buffer.pop(expected_seq[0])
                write_payload(payload)
                expected_seq[0] += len(payload)
        else:
            print("Received out-of-order packet with sequence number " + str(seq))
            if (seq > expected_seq[0]) and seq not in buffer:
                send_sack(source_ip, dest_ip, source_port, dest_port, ack, expected_seq[0], seq, seq+len(payload), iface)
                print("Sacked packet with sequence number: " + str(seq))
            if seq not in buffer:
                buffer[seq] = bytes(tcp.payload)
                print("Added packet to the buffer")

    if (status.state == "ESTABLISHED") and (flags & 0x01):
        payload = bytes(tcp.payload)
        send_ack(source_ip, dest_ip, source_port, dest_port, ack, seq+1+len(payload), iface)
        status.handle_event("RECEIVE_FIN")
        send_fin(source_ip, dest_ip, source_port, dest_port, ack, seq+1+len(payload), iface)
        final_seq_num = seq+1+len(payload)
        status.handle_event("SEND_FIN")
        timer = threading.Timer(5.0, lost_ack)
        timer.start()

    if status.state == "LAST_ACK":
        if (flags & 0x10) and seq == final_seq_num:
            print("Recieved final ack, fully closing connection")
            status.handle_event("RECEIVE_ACK")


if __name__ == "__main__":
    source_ip = "ip"
    source_port = 4204
    dest_ip = "ip"
    dest_port = 8080
    iface = "iface"
    status = TCPState()
    init_seq = random.randint(0, 2**32 - 1)
    data_recieved = {}
    buffer = {}

    expected_seq = [0]
    found_headers = [False]
    path = "image.jpeg"
    final_seq_num = 0


    filter_str = f"tcp and src port {dest_port} and dst port {source_port} and src host {dest_ip} and dst host {source_ip}"
    if status.state == "CLOSED":
        status.handle_event("ACTIVE_OPEN")
        send_syn_packet(source_ip, source_port, dest_ip, dest_port, init_seq, iface)
        t = threading.Thread(target=syn_retransmit, args=(source_ip, source_port, dest_ip, dest_port, init_seq, iface,))
        t.start()
    sniff(filter=filter_str, iface=iface, prn=handle_pkt)
    print("Client closed")
