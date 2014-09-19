# Book example of sniffing wireless network probes from saved networks.

from scapy.all import *

def sniffProbe(p):
  if p.haslayer(Dot11ProbeReq):
    netName = p.getlayer(Dot11ProbeReq).info
    if netName not in probeReqs:
      print '[+] Detected New Probe Request: ' + netName

sniff(iface='en0', prn=sniffProbe)
