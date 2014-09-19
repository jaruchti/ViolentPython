# Book example of analyzing a packet capture to determine if a fast-flux attack has occured.  In a fast-flux attack, the IP address associated with a domain name is rapidly changed.

from scapy.all import *

def handlePkt(pkt, dnsRecords):
  if pkt.haslayer(DNSRR):
    rrname = pkt.getlayer(DNSRR).rrname
    rdata  = pkt.getlayer(DNSRR).rdata
    if dnsRecords.has_key(rrname):
      if rdata not in dnsRecords[rrname]:
        dnsRecords[rrname].append(rdata)
    else:
      dnsRecords[rrname] = []
      dnsRecords[rrname].append(rdata)

def main():
  pkts = rdpcap('fastFlux.pcap')
  dnsRecords = {}

  for pkt in pks:
    handlePkt(pkt, dnsRecords)

  for item in dnsRecords:
    print '[+] ' + item + ' has ' + str(len(dnsRecords[item])) + ' unique IPs'

if __name__ == '__main__':
  main()
