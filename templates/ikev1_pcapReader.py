from scapy.all import *

def openPCAPFile(path: str) -> scapy.plist.PacketList:
    return rdpcap(path)

def getISAKMPPackets(packets: scapy.plist.PacketList) -> []:
    ISAKMPList = []
    for packet in packets:
        if packet.haslayer(ISAKMP):
            ISAKMPList.append(packet[ISAKMP])
    return ISAKMPList
