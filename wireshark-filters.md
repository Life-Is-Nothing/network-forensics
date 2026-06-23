# 🔬 Wireshark Filters — Network Forensics

> Filtres Wireshark essentiels pour l'investigation réseau — by [@ibramoha2](https://github.com/ibramoha2)

## 🌐 Filtres de base

```wireshark
# Par IP
ip.addr == 192.168.1.1
ip.src == 192.168.1.1
ip.dst == 10.0.0.1

# Par port
tcp.port == 80
tcp.port == 443
udp.port == 53

# Protocoles
http
dns
ftp
ssh
telnet
smtp
pop
imap

# TCP flags
tcp.flags.syn == 1
tcp.flags.rst == 1
tcp.flags.fin == 1
```

## 🚨 Détection d'attaques

```wireshark
# Scan de ports (SYN scan)
tcp.flags.syn==1 && tcp.flags.ack==0

# Brute force SSH (beaucoup de connexions)
tcp.port==22 && tcp.flags.syn==1

# DNS exfiltration (requêtes longues)
dns && frame.len > 100

# HTTP credentials en clair
http.request.method == "POST"
http contains "password"
http contains "login"

# ARP spoofing
arp.duplicate-address-detected

# ICMP flood
icmp && ip.src == TARGET_IP

# Connexions vers port inhabituel
tcp.dstport > 1024 && tcp.flags.syn==1

# Trafic FTP (credentials en clair)
ftp.request.command == "USER"
ftp.request.command == "PASS"
```

## 📊 Statistiques

```
Statistics > Conversations       → Top communicants
Statistics > Protocol Hierarchy  → Répartition protocoles
Statistics > IO Graphs           → Trafic dans le temps
Statistics > Endpoints           → IPs actives
Analyze > Follow TCP Stream      → Reconstituer session
```

## 🔧 tshark (CLI)

```bash
# Lire PCAP
tshark -r capture.pcap

# Filtrer
tshark -r capture.pcap -Y "http.request"

# Extraire champs
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport

# Top IPs
tshark -r capture.pcap -T fields -e ip.src | sort | uniq -c | sort -rn | head

# Extraire fichiers HTTP
tshark -r capture.pcap --export-objects http,output_dir/

# DNS queries
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name
```
