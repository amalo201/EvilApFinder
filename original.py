#!/usr/bin/python

import sys, os, signal, re
from multiprocessing import Process
import toolz
from scapy.all import *

interface = ' '  # the interface to be put in monitod mode
#aps = []  # this will store the Access points found.
duplicates = []
deauth = []
probetest= []
aps_list = []
list_accesspoints = []
pineap = []
f = open("myfile.txt", "w")


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



def getroot():
    if os.geteuid() == 0:
        print " [+] Running as root..."
        print"" \
             ""
    else:
        print "[+] You are not root.. Please run as root!"

def FindAps(pkt):

    if  pkt.haslayer(Dot11Beacon):

        ssid, mac = pkt.info, pkt.addr2
        aps = "{}=*={}".format(ssid, mac)
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


def pineapple():
    for i in range(0,len(list_accesspoints)):

        for y in range(i+1,len(list_accesspoints)):

            if list_accesspoints[i].mac == list_accesspoints[y].mac:
                pineap.append(list_accesspoints[i])
                pineap.append(list_accesspoints[y])

    unique_words = toolz.unique(pineap, key=lambda i: i.ssid)
    print "[+] Possible Wifi Pineapple in the area....", len(pineap)
    print "[+] List of SSIDs with same Mac:"
    for i in unique_words:
        print ("SSID:  " , i.ssid)
        print ("MAC:  " , i.mac)
        print ("Channel:  ", i.channel)
        print ("Encryption:  ", i.enc)
        print "" \
              ""

def test():
    print "[+] Number of Deauthentication Packets Received", len(deauth)
    if len(deauth) >0:
        for i in duplicates:
            if deauth[0].mac == i.mac:
                print ("This MAC is probably the victim AP", i.mac)

        print " [+] MAC Deauthenticating", deauth[0].mac
        print " [+] Number of Deauthentication Packets", deauth[0].count

def prino():

	print('[+] Number of Access Points Found', len(list_accesspoints))
	for i in range(0,len(list_accesspoints)):

		for y in range(i+1,len(list_accesspoints)):

			if list_accesspoints[i].ssid == list_accesspoints[y].ssid and list_accesspoints[i] not in duplicates:
			        duplicates.append(list_accesspoints[i])
			        duplicates.append(list_accesspoints[y])

	print("[+] Duplicates number")
	print(len(duplicates))
	print("[+] Total Access Points Found")
	print(len(list_accesspoints))
	unique_words = toolz.unique(list_accesspoints, key=lambda w: w.ssid)
	for w in unique_words:
			print(w.ssid)

	print("[+] Duplicate Access Points")

	for u in duplicates:
		print(u.ssid)
		print(u.mac)
		print(u.channel)

def writeduplicates():

    myfile = open("duplicates.txt", "w")
    for i in duplicates:
        print >> myfile, i.mac, "=", i.ssid
    myfile.close()

def pineapplemac():
    if len(pineap) > 0:
        newfile = open("pineapplemac.txt", "w")

        for i in pineap:
            print >> newfile, i.mac
        newfile.close()





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

    getroot()
    print " [+] Scanning all the channels this can take some time.... "
    print "" \
          ""
    interface = sys.argv[1]

    signal.signal(signal.SIGINT, signal_handler)

    pkt = Process(target=channel)
    pkt.start()


    sniff(iface=interface, count=500, prn=FindAps, store = 0)
    prino()
    test()
    writeduplicates()
    pineapple()
    pineapplemac()


