#!/usr/bin/python

import sys, os, signal, re, stat
from multiprocessing import Process
import toolz
from scapy.all import *
import netifaces


duplicates = []
deauth = []
probetest= []
aps_list = []
list_accesspoints = []
pineap = []
wifiphisher = []


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



def getroot(): #Ensures the user is root.
    
    if os.geteuid() == 0:
        print (" [+] Running as root...")
        print("" \
             "")
    else:
        print ("[+] You are not root.. Please run as root!")

def getinterface(): #Finds the wireless interface and activates monitor mode

    global iface
    netifaces.interfaces()
    for iface in netifaces.interfaces():
        if iface.startswith('wlan'):
            print "Interface found..Starting monitor mode..."
            os.system('airmon-ng start %s'%iface)
    netifaces.interfaces()
    for iface in netifaces.interfaces():
        if iface.startswith('wlan'):
            print "Monitor mode sucessful"


def FindAps(pkt): #Sniffs the air for Beacon, Probe Responses and Deauthentication packets. Retrieves SSID, BSSID, CHANNEL, ENCRYPTION and RSS from APs nearby.

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

            print (" [+] %s with MAC %s channel: %s encryption: %s signal: %s phiser: %s" %(pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal, phiser))
            list_accesspoints.append(accesspoint_object(pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal, phiser))




    if pkt.haslayer(Dot11ProbeResp):


        specific = pkt.getlayer(Dot11Elt)
        while specific and specific.ID != 221:
            specific = specific.payload.getlayer(Dot11Elt)
        if specific.ID == 221:
            this = str(specific)
            if re.search("Company" , this):
                wifiphisher.append(pkt.addr2)
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


def pineapple(): #Lists all the SSIDs with same MAC, identifies pineapple
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

def deauthtest(): #Checks the Deauthentication packets and prints the MAC of AP being deauthenticated
    
    print "[+] Number of Deauthentication Packets Received", len(deauth)
    if len(deauth) >0:
        for i in duplicates:
            if deauth[0].mac == i.mac:
                print ("This MAC is probably the victim AP", i.mac)

        print " [+] MAC Deauthenticating", deauth[0].mac
        print " [+] Number of Deauthentication Packets", deauth[0].count

def findall(): #List all the Access Points Found and Duplicate SSIDs

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



def writeduplicates(): #Creates a file with all the duplicates, that is later used in duplicates.py

    myfile = open("duplicates.txt", "w")
    for i in duplicates:
        print >> myfile, i.mac.upper(), "=", i.ssid
    myfile.close()



def pineapplemac():  #Blacklists the MAC of multiple SSIDs with same MAC..KARMA attack from Wifipineapple preventing connection from user
    if len(pineap) > 0:


        for i in pineap:
            newfile = open("pineapplemac", "w")
            print >> newfile, "#!/bin/bash" '\n' '\n' "mac=$(wpa_cli status -i wlan0 | grep bssid | cut -d '=' -f 2 )" '\n' '\n' "if [[ $mac ==", i.mac, " ]]; then" '\n' "   " "nmcli device disconnect wlan0" '\n' "fi"

        os.chmod("pineapplemac", stat.S_IXUSR)
        os.rename('pineapplemac', '/etc/network/if-up.d/pineapplemac')




def wifiphiser():  #Identifies access points run by wifiphisher and blacklists its MAC preventing connection from user
    if len(wifiphisher) > 0:


        for i in wifiphisher:
            newfile = open("wifiphisher", "w")
            print >> newfile, "#!/bin/bash" '\n' '\n' "mac=$(wpa_cli status -i wlan0 | grep bssid | cut -d '=' -f 2 )" '\n' '\n' "if [[ $mac ==", i, "]]; then" '\n' "   " "nmcli device disconnect wlan0" '\n' "fi"

        os.chmod("wifiphisher", stat.S_IXUSR)
        os.rename('wifiphisher', '/etc/network/if-up.d/wifiphisher')




#This function should only be used if the user has 2 wireless interfaces.
# It achieves the same results as duplicate.py script but does not require the user to exit this script.

#def examineduplicates():
#   if len(duplicates) > 0:
#        options = duplicates
#        print "Choose access point to investigate further" "\n"
#        for i in range(0, len(options)):
#            print str(i) + ':', options[i].ssid, ':', options[i].mac

#        inp = int(input("Enter a number: "))
#        inp2 = int(input("Enter SSID number: "))

#        inp3 = int(input("Enter the duplicate to check against: "))


 #       while inp and inp2 not in range (0,len(options)):
 #           inp = int(input("Enter a valid number:"))
 #           inp2 = int(input("Enter a valid SSID:"))
 #           inp3 = int(input("Enter a valid number of duplicate:"))

  #      if inp and inp2 in range(0,len(options)):
#         inp = options[inp].mac.upper()
  #          inp2 = options[inp2].ssid

#            inp3 = options[inp3].mac.upper()

 #           print "here is", inp2, "with MAC", inp
 #           print "here is", inp2, "with MAC", inp3

 #           os.system("wpa_cli -i wlan0 disconnect")
 #           time.sleep(5)
 #           os.system("nmcli device wifi connect %s bssid %s" % (inp2, inp3))
 #           time.sleep(5)
  #          os.system("nmcli device wifi rescan")
   #         time.sleep(6)
    #        os.system("nmcli device wifi connect %s bssid %s" % (inp2,inp))
    #        time.sleep(5)
    #        os.system("dhclient wlan0")
    #        time.sleep(5)
  #          os.system("ifconfig")
   #         time.sleep(2)
    #        os.system("curl ipinfo.io")
     
     #       time.sleep(2)
     #       os.system("traceroute www.google.com")

#            print "Repeat for next duplicate " "\n"

#            os.system("wpa_cli -i wlan0 disconnect")
#            time.sleep(5)
 #           os.system("nmcli connection delete %s" % (inp2))
  #          time.sleep(3)
   #         os.system("nmcli device wifi connect %s bssid %s" % (inp2 ,inp3))
    #        time.sleep(5)

    #        os.system("dhclient wlan0")
    #        time.sleep(5)
    #        os.system("ifconfig")
    #        time.sleep(2)
    #        os.system("curl ipinfo.io")
    #        time.sleep(2)
    #        os.system("traceroute www.google.com")


def channel():  # This will hope from channel 1 to 12
    while True:
        try:
            channel = random.randrange(1, 13)
            os.system("iw dev %s set channel %d" % (iface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break


def signal_handler(signal, frame):
    pkt.terminate()
    pkt.join()


    sys.exit(0)




if __name__ == "__main__":
  

    getroot()
    getinterface()
    time.sleep(1)
    print " [+] Scanning all the channels on interface %s this can take some time...." %iface
    print "" \
          ""

    signal.signal(signal.SIGINT, signal_handler)

    pkt = Process(target=channel)
    pkt.start()


    sniff(iface=iface, count=200, prn=FindAps, store = 0)
    findall()
    deauthtest()
    writeduplicates()
    pineapple()
    pineapplemac()
    wifiphiser()
    #examineduplicates()

    if len(duplicates) > 0:   #Comment this if you are using 2 wireless cards and the examineduplicates function ;)

        answer = None
        while answer not in ("Yes", "No"):
            answer = str(input ("Duplicates found, would you like to examine them? Yes or No: "))
            if answer == "Yes":
                print "Okay exit this script and run duplicates.py"
                time.sleep(3)
            elif answer == "No":
                print "Okay, Ciao Ciao"
                sys.exit()
            else:
                print "Please enter Yes or No."
