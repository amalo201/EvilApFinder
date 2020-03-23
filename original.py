#!/usr/bin/python

import sys, os, signal
from multiprocessing import Process
import toolz
from scapy.all import *

interface = ' '  # the interface to be put in monitod mode
aps = []  # this will store the Access points found.
duplicates = []
wname = []
list_accesspoints = []
deauth = []
OUIs = []


class accesspoint_object:
    def __init__(self, ssid, mac, channel, enc, signal,OUI):
        self.ssid = ssid
        self.mac = mac
        self.channel = channel
        self.enc = enc
        self.signal = signal
        self.OUI = OUI

class deauthacet:
    def __init__(self, mac , count):
        self.mac = mac
        self.count =count


def FindAps(pkt):

    if  pkt.haslayer(Dot11Beacon):
        if pkt.addr2 not in aps:
            aps.append(pkt.addr2)
            encryption = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

            radiotap = pkt.getlayer(RadioTap)
            signal = radiotap.dBm_AntSignal


            if re.search("privacy", encryption):
                enc = 'Y'
            else:
                enc = 'N'

            OUI = "This is a beacon"

            #if OUI != "":
            print " [+] %s with MAC %s channel: %s encryption: %s signal: %s OUI: %s" % (pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal,OUI)
            list_accesspoints.append(accesspoint_object(pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal,OUI))

            wname.append(pkt.info)

    if pkt.haslayer(Dot11ProbeResp):
        print "sniffing probe resp"

        specific = pkt.getlayer(Dot11Elt).payload
        #a = specific.info.encode('hex')
        OUI = specific [:6]

        if re.search("x07Company\ ", OUI):
            print "phiser"
        else:
            print " no phiser"




        #print("oui before specific",a)
        print(OUI)

        #if OUI not in OUIs:
            #OUIs.append(specific)
            #print('oui appendend', OUIs)
            #OUIs.append("yausfdyusafduysafduyasfdusayfduyasfduysafdyusagdugsadiugsadugasidhisahdisaugdisaugduiasg")
            #for i in OUIs:
            #    if i == "Company":
            #       print "Wifi phiser is here"
        #print OUIs


        #print " [+] %s with MAC %s channel: %s encryption: %s signal: %s OUI: %s" % (pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal, OUI)
        #list_accesspoints.append(accesspoint_object(pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal, OUI))



    if pkt.haslayer(Dot11Deauth):
        if len(deauth)>0:
            if deauth[0].mac == pkt.addr2:
                deauth[0].count +=1
            else:
                deauth.append(deauthacet(pkt.addr2, 1))
        else :
            deauth.append(deauthacet(pkt.addr2, 1))


def test():
    print("lenght deauth", len(deauth))
    if len(deauth) >0:
        print("mac deauth", deauth[0].mac)
        print("mac deauth", deauth[0].count)


def prino():
	#accespoint_map = {}
	print(len(list_accesspoints))
	for i in range(0,len(list_accesspoints)-1):
		#print("i:", i)
		for y in range(i+1,len(list_accesspoints)):
		#	print("y,", y)
			if list_accesspoints[i].ssid == list_accesspoints[y].ssid:
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
# print(duplicates)


def channel():  # This will hope from channel 1 to 12
    while True:
        try:
            channel = random.randrange(1, 12)
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
    "Total APs found: %d" % len(aps)

    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage %s with monitor_interface" % sys.argv[0]
        sys.exit(1)

    print "[+] Scanning all the channels this can take some time....                                                          "

    interface = sys.argv[1]

    pkt = Process(target=channel)
    pkt.start()

    signal.signal(signal.SIGINT, signal_handler)
    sniff(iface=interface, count=1000, prn=FindAps)
    # Test(wname)
    prino()
    test()
