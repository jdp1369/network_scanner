#!/bin/usr/env python3

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target",dest="ip",help="Provide IP Address of target system")
    options = parser.parse_args()

    if not options.ip:
        print("[-] Please specify the IP Address, use --help for info.")
    return options

def scan(ip):
    #scapy.arping(ip)
    arp_request =scapy.ARP(pdst=ip)
    #print(arp_request.summary())
    #scapy.ls(scapy.ARP()) for listing all the feilds
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    arp_request_broadcast = broadcast/arp_request
    # answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []

    for element in answered_list:
        client_dic = {"ip":element[1].psrc,"mac":element[1].hwsrc}
        clients_list.append(client_dic)
    return clients_list

def print_result(result_list):
    print("IP\t\tMAC Address\n--------------------------------------")
    for client in result_list:
        print(client["ip"]+"\t"+client["mac"])

options = get_arguments()
scan_result = scan(options.ip)
print_result(scan_result)
