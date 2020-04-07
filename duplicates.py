#!/usr/bin/python

import sys, os, signal, re, stat
from multiprocessing import Process
import toolz
from scapy.all import *
import netifaces


def getinterface():

    global iface

    for iface in netifaces.interfaces():
        if iface.endswith('mon'):
            os.system("airmon-ng stop %s" %iface)
    netifaces.interfaces()
    for iface in netifaces.interfaces():
        if iface.startswith('wlan'):
            print "Using interface %s" %iface


def dups():

    content = []

    with open ('duplicates.txt', 'r') as f:
        content = f.readlines()

        count = -1
        for i in content:
            count = count + 1
            print count ,i

        inp = raw_input("Enter the BSSID in Block Capitals: ")
        inp2 = raw_input("Enter SSID name as seen above: ")

        inp3 = raw_input("Enter the duplicate BSSID to check against: ")

        print "here is", inp2, "with MAC", inp
        print "here is", inp2, "with MAC", inp3

        os.system("nmcli device wifi connect %s bssid %s" % (inp2, inp))
        time.sleep(3)

        os.system("ifconfig")
        time.sleep(2)
        os.system("curl ipinfo.io")
        time.sleep(2)
        os.system("traceroute www.google.com")

        print
        "Repeat for next duplicate " "\n"


        os.system("nmcli connection delete %s" % (inp2))
        time.sleep(3)
        os.system("nmcli device wifi connect %s bssid %s" % (inp2, inp3))
        time.sleep(5)
        os.system("ifconfig")
        time.sleep(2)
        os.system("curl ipinfo.io")
        time.sleep(2)
        os.system("traceroute www.google.com")




if __name__ == "__main__":

    getinterface()
    dups()