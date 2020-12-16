from scapy.all import *
import binascii

ISAKMP_KEX_NAME = ISAKMP_payload_KE
ISAKMP_NONCE_NAME = ISAKMP_payload_Nonce

def getIniatorSAPacket(packets: []) -> scapy.layers.isakmp.ISAKMP:
    for packet in packets:
        # Cookie-Wert des Responders muss mit 0 initialisiert sein
        if binascii.hexlify(bytes(packet[ISAKMP].resp_cookie)) == b'0000000000000000':
            return packet

def getResponderSAPacket(packets: []) -> scapy.layers.isakmp.ISAKMP:
    for packet in packets:
        # Responder antwortet mit gesetztem Cookie-Wert (ungleich 0)
        if binascii.hexlify(bytes(packet[ISAKMP].resp_cookie)) != b'0000000000000000':
            return packet

def getPayloadFromISAKMP(packet: scapy.layers.isakmp.ISAKMP, name: str) -> bytes:
    return packet[name].load

def getCookieFromISAKMP(respPacket: scapy.layers.isakmp.ISAKMP, responderCookie: bool) -> bytes:
    return respPacket[ISAKMP].resp_cookie if responderCookie else respPacket[ISAKMP].init_cookie

def getSAPayloadFromInitPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    # Skippe die ersten 4 Bytes (Beginne ab DOI)
    return bytes(packet[ISAKMP_payload_SA])[4:packet[ISAKMP_payload_SA].length]

def getResponderIDFromRespPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    return bytes([packet[ISAKMP_payload_ID].IDtype]) + bytes([packet[ISAKMP_payload_ID].ProtoID]) + bytes(b"\x00") + bytes([packet[ISAKMP_payload_ID].Port]) + packet[ISAKMP_payload_ID].load

def getRespHashfromPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    return packet[ISAKMP_payload_Hash].load
