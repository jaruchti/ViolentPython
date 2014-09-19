# Python script to find bluetooth devices
import time
from bluetooth import *

def findDevs( alreadyFound ):
  foundDevs = discover_devices(lookup_names=True)
  for (addr, name) in foundDevs:
    if addr not in alreadyFound:
      print '[*] Found Bluetooth Device: ' + str(name)
      print '[+] MAC address: ' + str(addr)
      alreadyFound.append(addr)

def main():
  alreadyFound = {}

  while True:
    findDevs( alreadyFound )
    time.sleep(5)

if __name__ == '__main__':
  main()
