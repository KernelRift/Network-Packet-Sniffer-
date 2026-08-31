# Python Network Packet Sniffer & Analyzer

A Python-based network packet sniffer developed using Scapy to capture and analyze network traffic in an authorized lab environment.

## Features

- Capture network packets using Scapy

- Identify IPv4 traffic

- Extract source and destination IP addresses

- Identify common protocols such as TCP, UDP, ICMP, and DNS

- Extract source and destination ports

- Display packet size

- Display a hexadecimal preview of packet payload

- Extract DNS query information when available

- Display protocol statistics

- Export captured packet information to CSV

- Command-line interface with configurable packet count and network interface

## Technologies

- Python 3

- Scapy

- CSV

- Linux

## Project Structure

```
network-packet-sniffer/  
├── packet\_sniffer.py  
├── requirements.txt  
├── README.md  
├── screenshots/  
└── demo/
```

## Installation

Clone the repository and enter the project directory:

```
git clone https://github.com/KernelRift/Network-Packet-Sniffer-.git  
cd network-packet-sniffer
```

Create a virtual environment:

```
python3 -m venv venv  
source venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

## Usage

Find available network interfaces:

```
ip addr
```

Run the packet sniffer:

```
sudo python3 packet\_sniffer.py -i eth0 -c 20
```

Replace `eth0` with the appropriate interface on your system.

You can also specify a custom CSV output file:

```
sudo python3 packet\_sniffer.py -i eth0 -c 50 -o packets.csv
```

## Example Output

```
No.  Source IP        Destination IP     Protocol    Src     Dst     Size  
---------------------------------------------------------------------------  
1    192.168.1.10     8.8.8.8            ICMP        -       -       98  
2    8.8.8.8          192.168.1.10       ICMP        -       -       98  
3    192.168.1.10     93.184.216.34      TCP         48231   443     66
```

## Learning Objectives

This project demonstrates practical understanding of:

- Network packet structure

- IP addressing

- TCP and UDP communication

- ICMP traffic

- DNS communication

- Network protocol analysis

- Packet capture

- Python network programming

- Basic security monitoring

## Security and Ethical Use

This tool should only be used to capture traffic on networks and systems where you have explicit authorization.

Do not use this application to intercept or analyze other people's private network traffic.

## Other CODSOFT Project

➡️ [Secure File Sharing Application](https://github.com/KernelRift/secure-file-sharing-web)

## Internship Task

This project was developed as part of a Python internship task demonstrating packet capture, network communication analysis, protocol identification, and organized presentation of captured data.
