# Packet Sniffer README

## Overview
 Welcome to the Packet Sniffer project! This Python-based tool utilizes the Scapy library to capture and analyze network packets in real-time. Packet sniffing is an essential technique for network administrators and security professionals to monitor and diagnose network issues, and for educational purposes to understand network protocols and traffic.


## Features
 - Capture live network packets.
 - Display detailed information about each packet, including source and destination IPs. 
 - ports, and protocol types.
 - Support for various protocols such as TCP, UDP, and HTTP.


## Requirements
 - Python 3.6 or later
 - Scapy library

# Installation
### 1. Clone the Repository


	git clone https://github.com/Aegon253/Network_Sniffer.git
	cd Network_Sniffer
 
### 2. Install Scapy
	pip install scapy


# Running the Packet Sniffer
 1. Navigate to the project directory

	cd Network_Sniffer
 2. Run the Packet Sniffer
	sudo python packet_sniffer.py

### Note: Running the packet sniffer requires root privileges to access network interfaces.


### Usage:
 Once the packet sniffer is running, it will start capturing packets on the default network interface. It will display information about each captured packet in the terminal. To stop the packet sniffer, you can use Ctrl + C.


