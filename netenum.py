#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import socket
import ipaddress
import json
from datetime import datetime
from scapy.all import ARP, IP, ICMP, Ether, sr1, srp
from mac_vendor_lookup import MacLookup
from prettytable import PrettyTable


## doPingSweep
# interface = Host's interface (string, eg. 'eth0')
# ips = list of IPs to scan (list of IPv4Address objects)
# resolve = if True, resolve DNS names (boolean)
# timeout = timeout for each ping (integer)
# varbose = if True, print verbose output (boolean)
def doPingSweep(interface:str, ips:list, resolve=False, timeout=1, varbose=False)->list:
    ret = []
    try:
        for ip in ips:
            host = {}

            if varbose: print("ICMP: Echo Request %s" % ip, end =" ")

            host['ip'] = str(ip)
            start_time = datetime.now()
            ans = sr1(IP(dst=str(ip))/ICMP(), timeout=timeout, verbose=False)
            if ans:
                host['rtt'] = '%.2f' % ((datetime.now() - start_time).microseconds /1000) # microseconds to milliseconds
                host['time'] = datetime.now()

                # resolve DNS names
                host['name'] = ""
                if resolve:
                    if varbose: print("Resolving Name...", end =" ")
                    host['name'] = resolveHostName(ipaddress.ip_address(host['ip']))
                    if varbose: print("%s" % host['name'] ,end =" ")

                if varbose: print("Round Trip Time: %sms" % host['rtt'])

            else:
                if varbose: print("Timed out")
                continue

            ret.append(host)

    except KeyboardInterrupt:
        print("\n[*] Keyboard Interrupt")
        exit(1)

    return ret


## doArpScan
# interface = Host's interface (string, eg. 'eth0')
# ips = list of IPs to scan (list of IPv4Address objects)
# resolve = if True, resolve DNS names (boolean)
# timeout = timeout for each ping (integer)
# varbose = if True, print verbose output (boolean)
def doArpScan(interface:str, ips:list, resolve=False, timeout=1, varbose=False)->list:

    ret = []
    try:
        for ip in ips:

            found = False
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(ip)),
                        timeout = timeout,
                        iface = interface,
                        verbose=False,
                        inter = 0.1)
            if varbose: print("ARP: Who has %s?" % ip, end =" ")

            for _, rcv in ans:
                host = {}
                host['ip'] = rcv.sprintf("%ARP.psrc%")
                host['mac'] = rcv.sprintf("%Ether.src%")

                # resolve DNS names
                host['name'] = ""
                if resolve: host['name'] = resolveHostName(ipaddress.ip_address(host['ip']))

                # resolve MAC vendor
                try:
                    host['vendor'] = MacLookup().lookup(host['mac'])
                except Exception as e:
                    host['vendor'] = "Unknown"

                host['time'] = datetime.now()

                if varbose: print("...Respond: %s (%s)" % (host['mac'], host['vendor']))

                ret.append(host)
                found=True

            if varbose and not found: print("...No response")

    except KeyboardInterrupt:
        print("\n[*] Keyboard Interrupt")
        exit(1)

    return ret

## getHostAddresses
# network = network to get hosts (IPv4Network object)
# return = list of IPAddress objects without broadcast and loopback addresses (list)
def getHostAddresses(network)->list:
    netaddr = network.network_address
    broadcast = network.broadcast_address
    host_addresses = []
    for host in network.hosts():
        if host == netaddr or host == broadcast:
            continue
        host_addresses.append(host)
    return host_addresses

## resolveHostName
# ip = IP address to resolve (IPv4Address object)
# return = hostname if resolved, otherwize empty (string)
def resolveHostName(ip:ipaddress.ip_address)->str:
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception as e:
        return ""


if __name__ == "__main__":

    # --- Argument Parser
    parser = argparse.ArgumentParser(description='Scan your network with ARP and Ping',
                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                    epilog="!!! Please use for your own risk !!!\n\n" +
                                            "Created by: Neustrashimy\n" +
                                            "Report bug to: https://github.com/Neustrashimy/netenum.py/issues\n\n")

    parser.add_argument('-i', '--interface', type=str, nargs='?', help='Interface to use')
    parser.add_argument('-t', '--target',    type=str, nargs='?', help='Target IPv4 address (eg. 192.168.0.1)')
    parser.add_argument('-n', '--network',   type=str, nargs='?', help='Target IPv4 network, CIDR Expression (eg. 192.168.0.0/24)')
    parser.add_argument('-p', '--ping',      action='store_true', help='Perform Ping sweep')
    parser.add_argument('-a', '--arp',       action='store_true', help='Perform ARP scan')
    parser.add_argument('-r', '--resolve',   action='store_true', help='Resolve Hostname from IP')
    parser.add_argument('-w', '--timeout',   type=int, nargs='?', default=1, help='Timeout for ping/arp scan (default: 1)')
    parser.add_argument('-o', '--output',    choices=['table', 'json'], default='table', help='Output Style (default: table)')
    parser.add_argument('-v', '--verbose',   action='store_true', help='Verbose output')

    args = parser.parse_args()


    # --- Argument Validation

    if args.interface is None:
        print('[!] You must specify an interface')
        exit(1)

    if args.target is None and args.network is None:
        print('[!] You must specify a target IP address or IP Network')
        exit(1)
    
    ips = None
    if args.target: # single target
        try:
            ips = [ipaddress.ip_address(args.target)]
        except ValueError:
            print('[!] Invalid target IP address: %s' % args.target)
            exit(1)

    if args.network: # network target
        try:
            network = ipaddress.ip_network(args.network)
            ips = getHostAddresses(network)
        except ValueError:
            print('[!] Invalid target IP network: %s' % args.network)
            exit(1)
    
    if args.ping is False and args.arp is False:
        print('[!] You must specify a scan type --arp or --ping')
        exit(1)

    if args.timeout < 1:
        print('[!] You must specify a timeout greater than 0')
        exit(1)


    # --- Main

    # ping sweep
    if args.ping:
        if args.verbose: print("[*] Performing Ping Sweep...")
        ret = doPingSweep(args.interface, ips, args.resolve, args.timeout, args.verbose)
        if args.verbose: print("[*] Finished Ping Sweep")
        
        if args.output == 'table':
            if(len(ret) == 0):
                print("[!] No hosts responded to ping")
                exit(0)

            table = PrettyTable(['IP', 'HostName' ,'RTT', 'Time'])
            table.align = "l"
            for host in ret:
                table.add_row([host['ip'], host['name'], host['rtt'] + "ms", host['time'].strftime("%Y-%m-%d %H:%M:%S")])
            print(table)

        elif args.output == 'json':
            print(json.dumps(ret))



    # arp scan
    if args.arp:
        if args.verbose: print("[*] Performing ARP scan...")
        ret = doArpScan(args.interface, ips, args.resolve, args.timeout, args.verbose) # return list of dicts
        if args.verbose: print("[*] Finished ARP scan")

        if args.output == 'table':
            if(len(ret) == 0):
                print("[!] No hosts responded to ARP")
                exit(0)
            
            table = PrettyTable(['IP', 'HostName', 'MAC', 'Vendor', 'Time'])
            table.align = "l"
            for host in ret:
                table.add_row([host['ip'], host['name'], host['mac'], host['vendor'], host['time'].strftime("%Y-%m-%d %H:%M:%S")])
            print(table)

        elif args.output == 'json':
            print(json.dumps(ret))
    