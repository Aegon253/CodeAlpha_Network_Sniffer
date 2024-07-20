from scapy.all import *

def handle_packets(packet):
    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto

            if packet.haslayer(TCP):
                tcp_src_port = packet[TCP].sport
                tcp_dst_port = packet[TCP].dport
                print(f"TCP:  {ip_src}:{tcp_src_port} --> {ip_dst}:{tcp_dst_port} | protocol: {proto}")

                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    if b'HTTP' in payload:
                        print(f"HTTP:  {ip_src}:{tcp_src_port} --> {ip_dst}:{tcp_dst_port} | protocol: {proto}")

            elif packet.haslayer(UDP):
                udp_src_port = packet[UDP].sport
                udp_dst_port = packet[UDP].dport
                print(f"UDP Packet: {ip_src}:{udp_src_port} --> {ip_dst}:{udp_dst_port} | protocol: {proto}")

            else:
                print(f"IP Packet: {ip_src} --> {ip_dst} | protocol: {proto}")
                
    except Exception as e:
        print(f"Error in processing: {e}")

sniff(prn=handle_packets)
