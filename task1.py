
import scapy.all as scapy

class PacketSniffer:
    def __init__(self, interface):
        self.interface = interface

    def start_sniffing(self):
        scapy.sniff(iface=self.interface, store=False, prn=self.process_packet)

    def process_packet(self, packet):
        if packet.haslayer(scapy.IP):
            ip_packet = IPPacket(packet)
            ip_packet.print_info()

            transport_layer = ip_packet.get_transport_layer()
            if transport_layer:
                transport_layer.print_info()

class IPPacket:
    def __init__(self, packet):
        self.packet = packet

    def print_info(self):
        source_ip = self.packet[scapy.IP].src
        destination_ip = self.packet[scapy.IP].dst
        protocol = self.packet[scapy.IP].proto
        print(f"IP Packet: {source_ip} -> {destination_ip} Protocol: {protocol}")

    def get_transport_layer(self):
        if self.packet.haslayer(scapy.TCP):
            return TCPPacket(self.packet)
        elif self.packet.haslayer(scapy.UDP):
            return UDPPacket(self.packet)
        return None

class TransportLayerPacket:
    def __init__(self, packet):
        self.packet = packet

    def print_info(self):
        pass

class TCPPacket(TransportLayerPacket):
    def print_info(self):
        source_port = self.packet[scapy.TCP].sport
        destination_port = self.packet[scapy.TCP].dport
        print(f"TCP Packet: {self.packet[scapy.IP].src}:{source_port} -> {self.packet[scapy.IP].dst}:{destination_port}")

class UDPPacket(TransportLayerPacket):
    def print_info(self):
        source_port = self.packet[scapy.UDP].sport
        destination_port = self.packet[scapy.UDP].dport
        print(f"UDP Packet: {self.packet[scapy.IP].src}:{source_port} -> {self.packet[scapy.IP].dst}:{destination_port}")

interface = "eth0"  
sniffer = PacketSniffer(interface)
sniffer.start_sniffing()
