from multiprocessing import Process
from scapy.all import *

import os
import sys
import time



def get_mac(ip):
    """
    this function gets and records the MAC address of the network
    :param ip:
    :return: mac address of device allocated ip
    """
    arp_pkt = ARP(pdst=ip)
    broadcast_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")

    responses = srp(broadcast_pkt/arp_pkt,
                    timeout=1,
                    verbose=False)
    pass


class Arper:
    def __init__(self, victim, destination, interface="eth0"):
        self.victim_ip = victim
        self.gateway_ip=destination
        self.interface=interface

        self.victim_mac = get_mac(self.victim_ip)
        self.gateway_mac = get_mac(self.gateway_ip)
        #This function initiate the class


    def run(self):
        #this function runs the overall structure of the attack
        pass


    def poison(self):
        #this function performs the poisoning process
        pass

    def sniff(self, count=200):
        #this function performs the sniffing attack
        pass

    def restore(self):
        #this function restores the network to its usual once the attack is finished
        pass


if __name__ == '__main__':
    #(victim, destination, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    (victim, destination, interface) = ("192.168.2.171", "192.168.2.1", "eth0")
    myarp = Arper(victim, destination, interface)
    myarp.run()