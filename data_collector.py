import csv
import sys
import os
import time
from network_tools import get_protocol_breakdown

def collect_data(label, filename="network_data.csv", num_samples=25):
    # The field names for your CSV file
    fieldnames = ['ARP_Count', 'ICMP_Count', 'TCP_Count', 'UDP_Count', 'Other_Count', 'Label']
    
    with open(filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        # Write header only if the file is new/empty
        if csvfile.tell() == 0:
            writer.writeheader()

        print(f"Collecting {num_samples} samples for Label {label}...")
        for i in range(num_samples):
            # Run the Scapy Analysis (3-second block)
            protocol_data = get_protocol_breakdown()
            
            # Extract only the counts and prepare the row
            row = {}
            for key, value in protocol_data.items():
                count = int(value.split(' packets')[0])
                row[key.split(' ')[0] + '_Count'] = count # 'ARP_Count', 'TCP_Count', etc.

            row['Label'] = label
            
            # Write and wait
            writer.writerow(row)
            print(f"Sample {i+1}/{num_samples} collected.")
            time.sleep(1) # Wait a short time before the next capture

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: sudo python3 data_collector.py <label> <num_samples> [filename]")
        sys.exit(1)

    try:
        label = int(sys.argv[1])
        num_samples = int(sys.argv[2])
        filename = sys.argv[3] if len(sys.argv) > 3 else "network_data.csv"
        
        if os.geteuid() != 0:
            print("Error: This script must be run with sudo.")
            sys.exit(1)
        
        collect_data(label, filename, num_samples)
        print(f"Collection complete. Data saved to {filename}")

    except ValueError:
        print("Error: Label and num_samples must be integers.")
        sys.exit(1)