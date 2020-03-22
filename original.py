#!/usr/bin/python

import sys, os, signal
from multiprocessing import Process

from scapy.all import *

interface = ' '  # the interface to be put in monitod mode
aps = [] # this will store the Access points found.
duplicates = []
wname = []
list_accesspoints= []
class accesspoint_object:
  def __init__(self, ssid, mac, channel, enc):
    self.ssid = ssid
    self.mac = mac
    self.channel = channel
    self.enc = enc



def FindAps(pkt) :
	
	if pkt.haslayer(Dot11Beacon):
			if pkt.addr2 not in aps:
				aps.append(pkt.addr2)	
				encryption = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
				if re.search("privacy", encryption): enc = 'Y'
				else: enc = 'N'
				print " [+] %s with MAC %s channel: %s encryption: %s" %(pkt.info, pkt.addr2,int( ord(pkt[Dot11Elt:3].info)), enc)
				if pkt.info not in list_accesspoints.ssid:
					list_accesspoints.append(accesspoint_object(pkt.info,pkt.addr2,int( ord(pkt[Dot11Elt:3].info)),enc))
				else: duplicates.append(accesspoint_object(pkt.info,pkt.addr2,int( ord(pkt[Dot11Elt:3].info)),enc))
				wname.append(pkt.info)


def prino():
	accespoint_map = {}
	print(len(list_accesspoints))
	
	print(len(duplicates))
	for i in range (len (list_accesspoints) -1):
		for y in range (len (list_accesspoints) -1):
 			if list_accesspoints[i].ssid == list_accesspoints[y].ssid:
 			duplicates.append(list_accesspoints[i].ssid)
		y+=1
	i+=1		print(duplicates[0])
	
	#if it.ssid == duplicates[1] :
		#	print('duplicate name')
		#	print(duplicates[1])
		#	print('accesspoint mac add in big list')
		#	print(it.mac)
		#print(list_accesspoints[3].ssid, list_accesspoints[3].enc)
	

	

	#print(duplicates)

					
			
		#temp = pkt
			
		#while temp :
		#	temp = temp.getlayer(Dot11Elt)
		#	if temp and temp.ID == 0 and (temp.info not in aps):	
		#		aps.add(temp.info)
		#		print len(aps), pkt.addr3, temp.info
		#		break
		#	temp = temp.payload
def channel():
	while True:
		try:
			channel = random.randrange(1,12)
			os.system("iw dev %s set channel %d" % (interface, channel))
			time.sleep(1)
		except KeyboardInterrupt:
			break
def signal_handler(signal, frame):
	pkt.terminate()
	pkt.join()

	print "\n-=-=-=-=-=  Here is what we found =-=-=-=-=-=-"
	print "Total APs found: %d" % len(aps)
	
	sys.exit(0)

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Usage %s with monitor_interface" % sys.argv[0]
		sys.exit(1)
	
	print "[+] Scanning all the channels this can take some time....                                                          "


	interface = sys.argv[1]

	pkt = Process(target = channel)
	pkt.start()

	signal.signal(signal.SIGINT, signal_handler)
	

	sniff(iface=interface, count = 400, prn = FindAps)	
	#Test(wname)
	prino()	
	
