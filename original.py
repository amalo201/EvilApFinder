 specific = pkt.getlayer(Dot11Elt)
        while specific and specific.ID != 221:
            specific = specific.payload.getlayer(Dot11Elt)
        if specific.ID == 221:
            this = str(specific)
            if re.search("Company" and "WAP" and "12345" and "Wireless A", this):
                phiser = 'WifiPhiser Vendor Specifics spotted, proceed with caution'



                print " [+] %s with MAC %s channel: %s encryption: %s signal: %s OUI: %s phiser: %s" % (pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal, phiser)
                list_accesspoints.append(accesspoint_object(pkt.info, pkt.addr2, int(ord(pkt[Dot11Elt:3].info)), enc, signal, phiser))
