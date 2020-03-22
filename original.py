#!/usr/bin/python

import sys, os, signal
from multiprocessing import Process
import toolz
from scapy.all import *

interface = ' '  # the interface to be put in monitod mode
aps = [] # this will store the Access points found.
duplicates = []
wname = []
list_accesspoints= []
class accesspoint_object:
  def __init__(self, ssid, mac, channel, enc, signal, phiser):
    self.ssid = ssid
    self.mac = mac
    self.channel = channel
    self.enc = enc
    self.signal = signal
    self.phiser = phiser


def FindAps(pkt) :
	
	if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
			if pkt.addr2 not in aps:
				aps.append(pkt.addr2)	
				encryption = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
				wifiphiser = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
				radiotap = pkt.getlayer(RadioTap)
				signal = radiotap.dBm_AntSignal

				if re.search('12345', wifiphiser): phiser = 'wifiphiser is around'
				else: phiser = 'No wifiphiser around'

				if re.search("privacy", encryption): enc = 'Y'
				else: enc = 'N'
				print " [+] %s with MAC %s channel: %s encryption: %s signal: %s phiser: %s" %(pkt.info, pkt.addr2,int( ord(pkt[Dot11Elt:3].info)), enc, signal, phiser)
				list_accesspoints.append(accesspoint_object(pkt.info,pkt.addr2,int( ord(pkt[Dot11Elt:3].info)),enc, signal, phiser))
				duplicates.append(accesspoint_object(pkt.info,pkt.addr2,int( ord(pkt[Dot11Elt:3].info)),enc, signal, phiser))
				wname.append(pkt.info)


def prino():
	accespoint_map = {}
	print(len(list_accesspoints))
	unique_words = toolz.unique(list_accesspoints, key=lambda w: w.ssid)
	for w in unique_words:
		print(w.ssid)

	

	

	#print(duplicates)

					
def channel():  #This will hope from channel 1 to 12
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
	

	sniff(iface=interface, count = 500, prn = FindAps)
	#Test(wname)
	prino()	
	
