from scapy.all import sniff, IP, TCP, UDP

# Function to capture packets and count protocols using Scapy
def get_protocol_breakdown():
    protocol_counts = {
        'ARP': 0, 
        'ICMP (Ping)': 0, 
        'TCP (Web/Data)': 0, 
        'UDP (DNS/Other)': 0, 
        'Other': 0
    }
    
    try:
        # Sniff packets on the wlan0 interface for 3 seconds
        packets = sniff(iface="wlan0", timeout=3, store=True)
        
        for packet in packets:
            if 'ARP' in packet:
                protocol_counts['ARP'] += 1
            elif 'ICMP' in packet:
                protocol_counts['ICMP (Ping)'] += 1
            elif 'IP' in packet:
                if 'TCP' in packet:
                    protocol_counts['TCP (Web/Data)'] += 1
                elif 'UDP' in packet:
                    protocol_counts['UDP (DNS/Other)'] += 1
                else:
                    protocol_counts['Other'] += 1
            else:
                protocol_counts['Other'] += 1

        total_packets = len(packets)
        
        # Calculate percentages
        protocol_breakdown = {}
        for proto, count in protocol_counts.items():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            protocol_breakdown[proto] = f"{count} packets ({percentage:.1f}%)"
            
        return protocol_breakdown

    except Exception as e:
        # If sniffing fails, it reports the error to the dashboard
        return {"Error": f"Scapy Sniff Failed: {str(e)}"}