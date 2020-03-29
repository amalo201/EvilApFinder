#!/usr/bin/python

import sys, os, signal, re
from multiprocessing import Process
from binascii import hexlify
import toolz
from scapy.all import *
from operator import attrgetter
interface = ' '  # the interface to be put in monitod mode
#aps = []  # this will store the Access points found.
duplicates = []
deauth = []
probetest= []
aps_list = []
list_accesspoints = []
pineap = []

class accesspoint_object:
    def __init__(self, ssid, mac, channel, enc, signal,phiser):
        self.ssid = ssid
        self.mac = mac
        self.channel = channel
        self.enc = enc
        self.signal = signal
        self.phiser = phiser

class deauthacet:
    def __init__(self, mac , count):
        self.mac = mac
        self.count =count

def FindAps(pkt):


    if  pkt.haslayer(Dot11Beacon):

        ssid, mac = pkt.info, pkt.addr2
        aps = "{}=*={}".format(mac, ssid)
        if aps not in aps_list:
            aps_list.append(aps)

            encryption = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                        {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

            radiotap = pkt.getlayer(RadioTap)
            signal = radiotap.dBm_AntSignal
            phiser = "Beacon"

            if re.search("privacy", encryption):
                enc = 'Y'
            else:
                enc = 'N'

            print " [+] %s with MAC %s channel: %s encryption: %s signal: %s phiser: %s" % (pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal, phiser)
            list_accesspoints.append(accesspoint_object(pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal, phiser))




    if pkt.haslayer(Dot11ProbeResp):


        specific = pkt.getlayer(Dot11Elt)
        while specific and specific.ID != 221:
            specific = specific.payload.getlayer(Dot11Elt)
        if specific.ID == 221:
            this = str(specific)
            if re.search("Company" , this):
                phiser = 'WifiPhiser Vendor Specifics spotted, proceed with caution'
            else : phiser = 'not phissher'

        if pkt.addr2 not in probetest:
            probetest.append(pkt.addr2)
            encryption = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
            radiotap = pkt.getlayer(RadioTap)
            signal = radiotap.dBm_AntSignal

            if re.search("privacy", encryption):
                enc = 'Y'
            else:
                enc = 'N'
            #print "Sniffing Probe Responses for WiFiPhiser"
            print " [+] %s with MAC %s channel: %s encryption: %s signal: %s phiser: %s" % (pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal, phiser)
            #print ('End of Probe')

    if pkt.haslayer(Dot11Deauth):
        if len(deauth)>0:
            if deauth[0].mac == pkt.addr2:
                deauth[0].count +=1
            else:
                deauth.append(deauthacet(pkt.addr2,  1))
        else :
            deauth.append(deauthacet(pkt.addr2, 1))


def newtest():
    print('len dup', len(duplicates))
    for i in range(0,len(duplicates)):

        for y in range(i+1,len(duplicates)):

            if duplicates[i].mac == duplicates[y].mac:
                print('dup i ', duplicates[i].mac)
                pineap.append(duplicates[i])
                pineap.append(duplicates[y])
                #pineap.append(duplicates[y].mac)
    for i in pineap:
        print i.mac
        print i.ssid
        print i.channel

def test():
    print("lenght deauth", len(deauth))
    if len(deauth) >0:
        for i in duplicates:
            if deauth[0].mac == i.mac:
                print ("this mac is probably the victim", i.mac)

        print("mac deauth", deauth[0].mac)
        print("count of deauth packets", deauth[0].count)

def prino():

	print('len access', len(list_accesspoints))
	for i in range(0,len(list_accesspoints)):

		for y in range(i+1,len(list_accesspoints)):

			if list_accesspoints[i].ssid == list_accesspoints[y].ssid and list_accesspoints[i] not in duplicates:
			        duplicates.append(list_accesspoints[i])
			        duplicates.append(list_accesspoints[y])

	print("length duplicates")
	print(len(duplicates))
	print('length list_access')
	print(len(list_accesspoints))
	unique_words = toolz.unique(list_accesspoints, key=lambda w: w.ssid)
	for w in unique_words:
			print(w.ssid)

	print("duplicates:")
	for u in duplicates:
		print(u.ssid)
		print(u.mac)
		print(u.channel)



def channel():  # This will hope from channel 1 to 12
    while True:
        try:
            channel = random.randrange(1, 13)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break


def signal_handler(signal, frame):
    pkt.terminate()
    pkt.join()

    print
    "\n-=-=-=-=-=  Here is what we found =-=-=-=-=-=-"
    print
    "Total APs found: %d" % len(aps_list)

    sys.exit(0)



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage %s with monitor interface" %sys.argv[0]
        sys.exit(1)

    print "[+] Scanning all the channels this can take some time....                                                          "

    interface = sys.argv[1]

    signal.signal(signal.SIGINT, signal_handler)

    pkt = Process(target=channel)
    pkt.start()

    sniff(iface=interface, count=500, prn=FindAps, store = 0)
    prino()
    #test()
    newtest()


z
