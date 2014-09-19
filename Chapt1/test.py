# Book example Python program which scans IP addresses and compares the banner against known vulnerable service versions.

import socket
import os
import sys

def retBanner(ip, port):
  try:
    socket.setdefaulttimeout(2)
    s = socket.socket()
    s.connect((ip, port))
    banner = s.recv(1024)
    return banner
  except:
    return

def checkVulns(banner, vulnFile):
  f = open(vulnFile, 'r')
  for line in f.readlines():
    if line.strip('\n') in banner:
      print '[+] Server is vulnerable: ' +\
        banner.strip('\n')
        
def main():
  if len(sys.argv) == 2:
    vulnFile = sys.argv[1]
    if not os.path.isfile(vulnFile):
      print '[-] ' + vulnFile + 'does not exist.'
      exit(0)
      if not os.occess(vulnFile, os.R_OK):
        print '[-] ' + vulnFile + ' access denied.'
        exit(0)
  else:
    print '[-] Usage: ' + str(sys.argv[0]) + ' <vuln filename>'
    exit(0)
 
  portList = [21,22,35,80,110,443]
  for x in range(147, 150):
    ip = '192.168.95.' + str(x)
    for port in portList:
      banner = retBanner(ip, port)
      if banner:
        print '[+] ' + ip + ': ' + banner
        checkVulns(banner, vulnFile)

if __name__ == '__main__':
  main()
