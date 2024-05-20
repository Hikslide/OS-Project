from scapy.all import *
import logging
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import threading

logging.basicConfig(filename='C:/Users/ibrahim embaby/OneDrive/Desktop/os_proj_phase3/traffic_analysis.log', 
                    level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

stop_capture = False
block_list = set()

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if src_ip in block_list or dst_ip in block_list:
            logging.info(f"Blocked packet from {src_ip} to {dst_ip}")
            return False, f"Blocked packet: {src_ip} or {dst_ip}"

        if protocol == 6:  # TCP
            payload = packet[TCP].payload
            if len(payload) > 0:
                logging.info(f"TCP packet detected from {src_ip} to {dst_ip}")
                return False, f"TCP packet detected from {src_ip} to {dst_ip}"
        elif protocol == 17:  # UDP
            payload = packet[UDP].payload
            if len(payload) > 0:
                logging.info(f"UDP packet detected from {src_ip} to {dst_ip}")
                return False, f"UDP packet detected from {src_ip} to {dst_ip}"
        elif protocol == 1:  # ICMP
            logging.info(f"ICMP packet detected from {src_ip} to {dst_ip}")
            return False, f"ICMP packet detected from {src_ip} to {dst_ip}"
    return True, None  # Packet is fine

def packet_callback(packet):
    result, error = analyze_packet(packet)
    if result:
        print("Network traffic is fine.")
    else:
        print(f"Network traffic contains suspicious packets. Error: {error}")
        if "Blocked packet" in error:
            print(f"IP Blocked: {error}")

def test_with_pcap(pcap_file):
    sniff(offline=pcap_file, prn=packet_callback)

def start_live_capture():
    global stop_capture
    stop_capture = False
    threading.Thread(target=sniff, kwargs={'prn': packet_callback, 'stop_filter': lambda _: stop_capture, 'store': 0}).start()

def stop_live_capture():
    global stop_capture
    stop_capture = True
    messagebox.showinfo("Capture Terminated", "Live capture has been terminated.")

def browse_pcap_file():
    pcap_file = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
    if pcap_file:
        test_with_pcap(pcap_file)

def add_ip_to_block_list():
    ip = simpledialog.askstring("Input", "Enter IP address to block:")
    if ip:
        block_list.add(ip)
        messagebox.showinfo("IP Blocked", f"IP {ip} has been added to the block list.")
        logging.info(f"IP {ip} has been added to the block list.")
    else:
        logging.info("No IP address was entered.")

def view_block_list():
    if block_list:
        block_list_str = "\n".join(block_list)
        messagebox.showinfo("Block List", f"Blocked IP addresses:\n{block_list_str}")
    else:
        messagebox.showinfo("Block List", "No IP addresses are currently blocked.")

def remove_ip_from_block_list():
    ip = simpledialog.askstring("Input", "Enter IP address to unblock:")
    if ip in block_list:
        block_list.remove(ip)
        messagebox.showinfo("IP Unblocked", f"IP {ip} has been removed from the block list.")
        logging.info(f"IP {ip} has been removed from the block list.")
    else:
        messagebox.showinfo("IP Not Found", f"IP {ip} was not found in the block list.")


def create_gui():
    root = tk.Tk()
    root.title("Network Traffic Analyzer and Firewall")

    frame = tk.Frame(root, padx=10, pady=10)
    frame.pack(padx=10, pady=10)

    live_capture_button = tk.Button(frame, text="Start Live Capture", command=start_live_capture)
    live_capture_button.grid(row=0, column=0, padx=5, pady=5)

    stop_capture_button = tk.Button(frame, text="Stop Live Capture", command=stop_live_capture)
    stop_capture_button.grid(row=0, column=1, padx=5, pady=5)

    pcap_file_button = tk.Button(frame, text="Open PCAP File", command=browse_pcap_file)
    pcap_file_button.grid(row=0, column=2, padx=5, pady=5)

    block_ip_button = tk.Button(frame, text="Block IP", command=add_ip_to_block_list)
    block_ip_button.grid(row=1, column=0, padx=5, pady=5)

    view_block_list_button = tk.Button(frame, text="View Block List", command=view_block_list)
    view_block_list_button.grid(row=1, column=1, padx=5, pady=5)
    
    unblock_ip_button = tk.Button(frame, text="Unblock IP", command=remove_ip_from_block_list)
    unblock_ip_button.grid(row=1, column=2, padx=5, pady=5)    

    root.mainloop()

def main():
    create_gui()

if __name__ == "__main__":
    main()
