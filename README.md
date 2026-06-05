# Task 5 - Wireshark Packet Analyzer

## Objective
Capture live network packets and identify
basic protocols and traffic types.

## Tools Used
- Wireshark (packet capture)
- Python 3 with Scapy (packet analysis)

## Protocols Identified
| Protocol | Count | Description |
|----------|-------|-------------|
| TCP | 743 | Reliable connection-based traffic |
| DNS | 312 | Domain name resolution queries |
| UDP | 187 | Fast connectionless traffic |
| ICMP | 65 | Ping/diagnostic packets |
| HTTP | 45 | Unencrypted web traffic |

## Wireshark Filters Used
| Filter | Purpose |
|--------|---------|
| dns | Show only DNS packets |
| tcp | Show only TCP packets |
| http | Show only HTTP packets |
| icmp | Show only ping packets |
| tls | Show only HTTPS packets |

## How to Run Python Analyzer
1. pip install scapy
2. cd C:\CyberTask5
3. python packet_analyzer.py
4. Enter path to your .pcap file

## Key Concepts Learned
- What packets are and how they travel
- How Wireshark captures network traffic
- Difference between TCP and UDP
- What DNS queries look like
- How to filter and analyze protocols
- Security risks in unencrypted traffic
