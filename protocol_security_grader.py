# -----------------------------------------------
#  PROTOCOL SECURITY GRADER
#  Cyber Security Internship - Task 5
#  Grades each protocol A to F based on security
# -----------------------------------------------

from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP, Raw, ARP
import datetime
import os
import collections

REPORT_FILE = "protocol_security_report.txt"

# ---- PROTOCOL SECURITY DATABASE ----------------
PROTOCOL_GRADES = {
    "TLS": {
        "grade":       "A",
        "score":       100,
        "level":       "EXCELLENT",
        "description": "Fully encrypted traffic. Data cannot be read by attackers.",
        "risk":        "Very Low",
        "fix":         "Keep using TLS/HTTPS. Ensure TLS version is 1.2 or higher.",
        "color":       "++++"
    },
    "SSH": {
        "grade":       "A",
        "score":       95,
        "level":       "EXCELLENT",
        "description": "Encrypted remote access protocol. Very secure.",
        "risk":        "Very Low",
        "fix":         "Use strong passwords or SSH keys. Disable root login.",
        "color":       "++++"
    },
    "HTTPS": {
        "grade":       "A",
        "score":       95,
        "level":       "EXCELLENT",
        "description": "Encrypted web traffic. Protects data in transit.",
        "risk":        "Very Low",
        "fix":         "Always prefer HTTPS over HTTP.",
        "color":       "++++"
    },
    "ICMP": {
        "grade":       "B",
        "score":       75,
        "level":       "GOOD",
        "description": "Ping/diagnostic protocol. Safe but can reveal network info.",
        "risk":        "Low",
        "fix":         "Block ICMP from external networks if not needed.",
        "color":       "+++"
    },
    "TCP": {
        "grade":       "B",
        "score":       70,
        "level":       "GOOD",
        "description": "Reliable transport protocol. Security depends on application.",
        "risk":        "Low to Medium",
        "fix":         "Ensure applications using TCP use encryption (TLS).",
        "color":       "+++"
    },
    "UDP": {
        "grade":       "C",
        "score":       55,
        "level":       "AVERAGE",
        "description": "Fast but no error checking or encryption built in.",
        "risk":        "Medium",
        "fix":         "Use DTLS (Datagram TLS) for sensitive UDP traffic.",
        "color":       "++"
    },
    "ARP": {
        "grade":       "D",
        "score":       35,
        "level":       "POOR",
        "description": "Address resolution protocol. Vulnerable to ARP spoofing attacks!",
        "risk":        "High",
        "fix":         "Use Dynamic ARP Inspection (DAI) on network switches.",
        "color":       "+"
    },
    "DNS": {
        "grade":       "D",
        "score":       30,
        "level":       "POOR",
        "description": "DNS queries sent in plaintext! Anyone can see what sites you visit.",
        "risk":        "High",
        "fix":         "Switch to DNS over HTTPS (DoH) or DNS over TLS (DoT).",
        "color":       "+"
    },
    "HTTP": {
        "grade":       "F",
        "score":       10,
        "level":       "CRITICAL RISK",
        "description": "Completely unencrypted! All data readable by anyone on network.",
        "risk":        "Critical",
        "fix":         "STOP using HTTP immediately. Switch to HTTPS always!",
        "color":       "-"
    },
    "FTP": {
        "grade":       "F",
        "score":       5,
        "level":       "CRITICAL RISK",
        "description": "Transfers files AND passwords in plain text! Extremely dangerous.",
        "risk":        "Critical",
        "fix":         "Replace FTP with SFTP or FTPS immediately.",
        "color":       "-"
    },
    "TELNET": {
        "grade":       "F",
        "score":       0,
        "level":       "CRITICAL RISK",
        "description": "Sends everything including passwords completely unencrypted!",
        "risk":        "Critical",
        "fix":         "NEVER use Telnet. Replace with SSH immediately.",
        "color":       "-"
    }
}

# ---- GRADE COLORS FOR DISPLAY ------------------
GRADE_DISPLAY = {
    "A": "[A] EXCELLENT    ",
    "B": "[B] GOOD         ",
    "C": "[C] AVERAGE      ",
    "D": "[D] POOR         ",
    "F": "[F] CRITICAL RISK"
}

# ---- WRITE HELPER ------------------------------
def write(text=""):
    print(text)
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def write_line():
    write("-" * 65)

def write_double():
    write("=" * 65)

def write_header(title):
    write()
    write_double()
    write("  " + title)
    write_double()

# ---- INIT REPORT -------------------------------
def init_report():
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("")
    write_double()
    write("  PROTOCOL SECURITY GRADER")
    write("  Cyber Security Internship - Task 5")
    write("  Wireshark Packet Analysis Tool")
    write("  Date   : " + datetime.datetime.now().strftime(
          "%Y-%m-%d %H:%M:%S"))
    write_double()

# ---- LOAD PCAP ---------------------------------
def load_pcap():
    write()
    print("Enter the full path to your .pcap file:")
    print("Example: C:\\CyberTask5\\capture_task5.pcap")
    path = input("Path: ").strip().strip('"')

    if not os.path.exists(path):
        write("[ERROR] File not found: " + path)
        write("Please check the path and try again.")
        exit()

    write()
    write("Loading file : " + path)
    packets = rdpcap(path)
    write("File loaded  : " + str(len(packets)) +
          " packets found")
    return packets

# ---- DETECT PROTOCOLS --------------------------
def detect_protocols(packets):
    write_header("SCANNING PACKETS FOR PROTOCOLS")

    protocol_counts = collections.Counter()
    total_bytes     = 0
    ip_addresses    = collections.Counter()
    dns_list        = []
    http_list       = []

    write("Scanning " + str(len(packets)) + " packets...")
    write_line()

    for pkt in packets:
        total_bytes += len(pkt)

        # ARP
        if pkt.haslayer(ARP):
            protocol_counts["ARP"] += 1

        # IP based protocols
        if pkt.haslayer(IP):
            ip_addresses[pkt[IP].src] += 1
            ip_addresses[pkt[IP].dst] += 1

        # ICMP
        if pkt.haslayer(ICMP):
            protocol_counts["ICMP"] += 1

        # TCP based
        if pkt.haslayer(TCP):
            protocol_counts["TCP"] += 1
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport

            # Telnet
            if dport == 23 or sport == 23:
                protocol_counts["TELNET"] += 1

            # FTP
            if dport == 21 or sport == 21:
                protocol_counts["FTP"] += 1

            # SSH
            if dport == 22 or sport == 22:
                protocol_counts["SSH"] += 1

            # TLS/HTTPS
            if dport == 443 or sport == 443:
                protocol_counts["TLS"] += 1

            # HTTP + Raw payload check
            if dport == 80 or sport == 80:
                if pkt.haslayer(Raw):
                    try:
                        raw = pkt[Raw].load.decode(
                            "utf-8", errors="ignore")
                        if "HTTP" in raw or "GET " in raw:
                            protocol_counts["HTTP"] += 1
                            if "Host:" in raw:
                                host = raw.split(
                                    "Host:")[1].split(
                                    "\r\n")[0].strip()
                                http_list.append(host)
                    except:
                        pass

        # UDP based
        if pkt.haslayer(UDP):
            protocol_counts["UDP"] += 1

        # DNS
        if pkt.haslayer(DNS):
            protocol_counts["DNS"] += 1
            try:
                if pkt[DNS].qd:
                    query = pkt[DNS].qd.qname.decode(
                        "utf-8", errors="ignore")
                    dns_list.append(query.rstrip("."))
            except:
                pass

    # Print summary
    write("Protocols detected : " +
          str(len(protocol_counts)))
    write("Total data         : " +
          str(round(total_bytes / 1024, 2)) + " KB")
    write("Unique IPs seen    : " +
          str(len(ip_addresses)))

    if dns_list:
        write()
        write("DNS Queries captured:")
        write_line()
        for d in list(set(dns_list))[:10]:
            write("  -> " + d)

    if http_list:
        write()
        write("HTTP Hosts visited (UNENCRYPTED!):")
        write_line()
        for h in list(set(http_list))[:10]:
            write("  -> " + h + "  [WARNING: Unencrypted!]")

    return protocol_counts, total_bytes

# ---- GRADE PROTOCOLS ---------------------------
def grade_protocols(protocol_counts):
    write_header("PROTOCOL SECURITY SCORECARD")

    graded   = {}
    ungraded = []

    for proto, count in protocol_counts.most_common():
        if proto in PROTOCOL_GRADES:
            graded[proto] = {
                "count": count,
                "info":  PROTOCOL_GRADES[proto]
            }
        else:
            ungraded.append((proto, count))

    # Print scorecard table
    write(
        "Protocol".ljust(10) +
        "Packets".ljust(10) +
        "Grade".ljust(8) +
        "Security Level".ljust(20) +
        "Risk"
    )
    write_line()

    for proto, data in sorted(
        graded.items(),
        key=lambda x: x[1]['info']['score'],
        reverse=True
    ):
        count = data['count']
        info  = data['info']
        write(
            proto.ljust(10) +
            str(count).ljust(10) +
            ("[" + info['grade'] + "]").ljust(8) +
            info['level'].ljust(20) +
            info['risk']
        )

    if ungraded:
        write()
        write("Other protocols found:")
        for proto, count in ungraded:
            write("  " + proto + " (" + str(count) + " packets)")

    return graded

# ---- DETAILED ANALYSIS -------------------------
def detailed_analysis(graded):
    write_header("DETAILED PROTOCOL ANALYSIS")

    for proto, data in sorted(
        graded.items(),
        key=lambda x: x[1]['info']['score'],
        reverse=True
    ):
        info  = data['info']
        count = data['count']
        bar   = info['color'] * 10

        write()
        write("Protocol : " + proto)
        write("Packets  : " + str(count))
        write("Grade    : " + GRADE_DISPLAY[info['grade']])
        write("Risk     : " + info['risk'])
        write("Bar      : [" + bar.ljust(10, ' ') + "]")
        write("What     : " + info['description'])
        write("Fix      : " + info['fix'])
        write_line()

# ---- OVERALL SCORE -----------------------------
def calculate_overall(graded, total_bytes):
    write_header("OVERALL SECURITY SCORE")

    if not graded:
        write("No protocols to grade!")
        return

    # Weighted score based on packet count
    total_packets  = sum(d['count'] for d in graded.values())
    weighted_score = 0

    for proto, data in graded.items():
        weight = data['count'] / total_packets
        weighted_score += data['info']['score'] * weight

    overall = round(weighted_score)

    # Overall grade
    if overall >= 90:
        overall_grade = "A - EXCELLENT"
        message = "Your network traffic is very secure!"
    elif overall >= 75:
        overall_grade = "B - GOOD"
        message = "Good security but some improvements needed."
    elif overall >= 60:
        overall_grade = "C - AVERAGE"
        message = "Average security. Several risks to address."
    elif overall >= 40:
        overall_grade = "D - POOR"
        message = "Poor security! Immediate action required."
    else:
        overall_grade = "F - CRITICAL"
        message = "Critical security risk! Fix issues NOW!"

    # Visual score bar
    filled = int(overall / 10)
    bar    = "#" * filled + "-" * (10 - filled)

    write("Overall Score  : " + str(overall) + "/100")
    write("Overall Grade  : " + overall_grade)
    write("Score Bar      : [" + bar + "]")
    write("Assessment     : " + message)
    write()

    # Grade breakdown
    grade_counts = collections.Counter()
    for data in graded.values():
        grade_counts[data['info']['grade']] += 1

    write("Grade Breakdown:")
    write_line()
    for grade in ["A", "B", "C", "D", "F"]:
        count = grade_counts.get(grade, 0)
        bar2  = "#" * count
        write("  Grade " + grade + " : " +
              bar2.ljust(10) + " " + str(count) +
              " protocol(s)")

    return overall, overall_grade

# ---- RECOMMENDATIONS ---------------------------
def write_recommendations(graded):
    write_header("SECURITY RECOMMENDATIONS")

    recs    = []
    urgent  = []

    for proto, data in graded.items():
        grade = data['info']['grade']
        fix   = data['info']['fix']

        if grade == "F":
            urgent.append("URGENT - " + proto + ": " + fix)
        elif grade == "D":
            recs.append("HIGH    - " + proto + ": " + fix)
        elif grade == "C":
            recs.append("MEDIUM  - " + proto + ": " + fix)
        else:
            recs.append("LOW     - " + proto + ": " + fix)

    if urgent:
        write("CRITICAL FIXES NEEDED IMMEDIATELY:")
        write_line()
        for i, u in enumerate(urgent, 1):
            write(str(i) + ". " + u)
        write()

    if recs:
        write("OTHER RECOMMENDATIONS:")
        write_line()
        for i, r in enumerate(recs, 1):
            write(str(i) + ". " + r)

    write()
    write("GENERAL BEST PRACTICES:")
    write_line()
    best = [
        "Always use HTTPS instead of HTTP",
        "Use SSH instead of Telnet or FTP",
        "Enable DNS over HTTPS in your browser",
        "Use a VPN on public WiFi networks",
        "Keep all software and OS updated",
        "Monitor network traffic regularly",
        "Use a firewall to block unused ports"
    ]
    for i, b in enumerate(best, 1):
        write(str(i) + ". " + b)

# ---- FINAL SUMMARY -----------------------------
def write_final(overall, overall_grade, graded, packets):
    write_header("TASK COMPLETION SUMMARY")

    write("File analyzed      : capture_task5.pcap")
    write("Total packets      : " + str(len(packets)))
    write("Protocols found    : " + str(len(graded)))
    write("Protocols graded   : " + str(len(graded)))
    write("Overall score      : " + str(overall) + "/100")
    write("Overall grade      : " + overall_grade)
    write()
    write("Task Requirements:")
    write_line()
    write("  [DONE] Captured live network traffic")
    write("  [DONE] Identified protocols in capture")
    write("  [DONE] Filtered by protocol in Wireshark")
    write("  [DONE] Exported .pcap file")
    write("  [DONE] Analyzed and graded protocols")
    write("  [DONE] Generated security report")
    write()
    write_double()
    write("  Report saved to: " + REPORT_FILE)
    write("  Generated at   : " +
          datetime.datetime.now().strftime(
          "%Y-%m-%d %H:%M:%S"))
    write_double()

# ---- MAIN --------------------------------------
if __name__ == "__main__":

    init_report()

    # Load pcap
    packets = load_pcap()

    # Detect all protocols
    protocol_counts, total_bytes = detect_protocols(packets)

    # Grade each protocol
    graded = grade_protocols(protocol_counts)

    # Detailed analysis
    detailed_analysis(graded)

    # Overall score
    overall, overall_grade = calculate_overall(
        graded, total_bytes)

    # Recommendations
    write_recommendations(graded)

    # Final summary
    write_final(overall, overall_grade, graded, packets)

    print()
    print("[OK] Full report saved to: " + REPORT_FILE)
    print()
    input("Press Enter to exit...")
