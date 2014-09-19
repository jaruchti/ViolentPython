# Book example of identifying a spoofed attacker using the TTL (time-to-life) field

import time
import optparse
from scapy.all import *


def checkTTL(ipsrc, ttl, ttlValues, thresh):
  if IPTEST(ipsrc).iptype() == 'PRIVATE':
    return
  if not ttlValues.has_key(ipsrc):
    pck = srl(IP(dst=ipsrc) / ICMP(), retry = 0, timeout = 1, verbose = 0)
    ttlValues[ipsrc] = pkt.ttl
  if abs(int(ttl) - int(ttlValues[ipsrc])) > thresh:
    print '\n[!] Detected Possible Spoofed Packet From: ' + ipsrc
    print '[!] TTL: ' + ttl + ', Actual TTL: ' + str(ttlValues[ipsrc])

def testTTL(ttlValues, thresh):
  # Nested function to grab the packet parameter passed implicitly from scapy.
  def testPacket(pkt):
    try:
      if pkt.haslayer(IP):
        ipsrc = pkt.getlayer(IP).src
        ttl = str(pkt.ttl)
        checkTTL(ipsrc, ttl, ttlValues, thresh)
    except:
      pass

def main():
  parser = optparse.OptionParser('usage%prog -i <interface> -t <thresh>')
  parser.add_option('-i', dest='iface', type='string', help='specify network interface')
  parser.add_option('-t', dest='thresh', type='int', help='specify threshold count')
  
  (options, args) = parser.parse_args()
  if options.iface == None:
    conf.iface = 'eth0'
  else:
    conf.iface = options.iface

  if options.thresh != None:
    thresh = options.thresh
  else:
    thresh = 5

  ttlValues = {}
  sniff(prn=testTTL(ttlValues, thresh), store=0)

if __name__ == '__main__':
  main()
