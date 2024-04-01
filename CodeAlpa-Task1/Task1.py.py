import scapy.all as scapy

class PacketSniffer:
    def __init__(self, interface, filter_protocol=None, log_file=None):
        self.interface = interface
        self.filter_protocol = filter_protocol
        self.log_file = log_file
        self.packet_count = 0

    def start_sniffing(self):
        try:
            scapy.sniff(iface=self.interface, filter=self.filter_protocol, prn=self.process_packet)
        except Exception as e:
            print(f"An error occurred: {e}")

    def process_packet(self, packet):
        try:
            self.packet_count += 1
            print(f"\nPacket #{self.packet_count}")
            if packet.haslayer(scapy.IP):
                ip_packet = IPPacket(packet)
                ip_packet.print_info()

                transport_layer = ip_packet.get_transport_layer()
                if transport_layer:
                    transport_layer.print_info()

            self.log_packet(packet)
        except Exception as e:
            print(f"Error processing packet: {e}")

    def log_packet(self, packet):
        if self.log_file:
            with open(self.log_file, "a") as file:
                file.write(str(packet) + "\n")

class IPPacket:
    def __init__(self, packet):
        self.packet = packet

    def print_info(self):
        source_ip = self.packet[scapy.IP].src
        destination_ip = self.packet[scapy.IP].dst
        protocol = self.packet[scapy.IP].proto
        print(f"IP Packet: {source_ip} -> {destination_ip} Protocol: {protocol}")

    def get_transport_layer(self):
        try:
            if self.packet.haslayer(scapy.TCP):
                return TCPPacket(self.packet)
            elif self.packet.haslayer(scapy.UDP):
                return UDPPacket(self.packet)
            return None
        except Exception as e:
            print(f"Error getting transport layer: {e}")

class TransportLayerPacket:
    def __init__(self, packet):
        self.packet = packet

    def print_info(self):
        pass

class TCPPacket(TransportLayerPacket):
    def print_info(self):
        try:
            source_port = self.packet[scapy.TCP].sport
            destination_port = self.packet[scapy.TCP].dport
            print(f"TCP Packet: {self.packet[scapy.IP].src}:{source_port} -> {self.packet[scapy.IP].dst}:{destination_port}")
        except Exception as e:
            print(f"Error printing TCP packet info: {e}")

class UDPPacket(TransportLayerPacket):
    def print_info(self):
        try:
            source_port = self.packet[scapy.UDP].sport
            destination_port = self.packet[scapy.UDP].dport
            print(f"UDP Packet: {self.packet[scapy.IP].src}:{source_port} -> {self.packet[scapy.IP].dst}:{destination_port}")
        except Exception as e:
            print(f"Error printing UDP packet info: {e}")

def main():
    interface = "eth0"  # Change this to your network interface
    filter_protocol = "tcp or udp"  # Filter for TCP or UDP packets, you can customize this
    log_file = "packet_log.txt"  # Log file path
    sniffer = PacketSniffer(interface, filter_protocol, log_file)
    sniffer.start_sniffing()

if __name__ == "__main__":
    main()
