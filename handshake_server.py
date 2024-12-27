from scapy.all import *
import threading

def filter_by_message(packet):
    
    if (packet.haslayer(IP) and
        packet.haslayer(TCP) and
        packet[TCP].dport == 256
        ):

        if packet[TCP].flags == "S":

            reply_packet = IP(dst=packet[IP].src) / TCP(dport=packet[TCP].sport, flags="SA") / Raw(load="OK")
            send(reply_packet)


sniff(lfilter=filter_by_message)