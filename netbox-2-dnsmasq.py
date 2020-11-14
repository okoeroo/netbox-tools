#!/usr/bin/env python3

import sys
import os
import subprocess
import argparse
import uuid
import pprint
import psutil
import re
import ipaddress
import json
import requests
import json
import localzone
import dns
import dns.zone
import dns.name
import dns.rdtypes

#from netboxers import netboxers
from netboxers import netboxers_helpers
from netboxers import netboxers_cli
from netboxers import netboxers_queries




# This function will create a DNSMasq formatted DHCP config file from Netbox
## Create DNSMasq DHCP config file by:
## 1. Fetching defaults
## 2. Fetching VRFs, and VRF info.
## 3. Fetch associated default gateway and DNS config
## 4. Fetch (virtual) hosts and its data (IP and MAC)

def netbox_to_dnsmasq_dhcp_config(ctx):
    # Truncate and open file cleanly
    netboxers_helpers.write_to_ddo_fh(ctx, None)

    # Generic settings
    netboxers_helpers.write_to_ddo_fh(ctx, "dhcp-leasefile=" + ctx['dhcp_lease_file'])

    if ctx['dhcp_authoritive']:
        netboxers_helpers.write_to_ddo_fh(ctx, "dhcp-authoritative")

    netboxers_helpers.write_to_ddo_fh(ctx, "domain=" + ctx['dhcp_default_domain'])

    # Get prefixes
    prefixes = netboxers_helpers.query_netbox(ctx, "ipam/prefixes/")

    if prefixes['count'] == 0:
        print("No prefixes found to complete")

    for prefix_obj in prefixes['results']:
        dnsmasq_dhcp = ""

        # Skip non-IPv4
        if prefix_obj['is_pool'] != True:
            continue

        # Generate VRF header, example

        ### Site:    Home
        ### Role:    Untagged
        ### Vlan:    66 (Home VLAN) with ID: 66
        ### VRF:     vrf_66_homelan
        ### Prefix:  192.168.1.0/24


        if prefix_obj['site'] is not None:
            dnsmasq_dhcp = " ".join([dnsmasq_dhcp, "\n###", 
                                     "Site:   ", 
                                     prefix_obj['site']['name']])
        if prefix_obj['role'] is not None:
            dnsmasq_dhcp = " ".join([dnsmasq_dhcp, "\n###",
                                     "Role:   ",
                                     prefix_obj['role']['name']])
        if prefix_obj['vlan'] is not None:
            dnsmasq_dhcp = " ".join([dnsmasq_dhcp, "\n###",
                                     "Vlan:   ",
                                     prefix_obj['vlan']['display_name'],
                                     "with ID:",
                                     str(prefix_obj['vlan']['vid'])])
        if prefix_obj['vrf'] is not None:
            dnsmasq_dhcp = " ".join([dnsmasq_dhcp, "\n###",
                                     "VRF:    ",
                                     prefix_obj['vrf']['name']])
        if prefix_obj['prefix'] is not None:
            dnsmasq_dhcp = " ".join([dnsmasq_dhcp, "\n###",
                                     "Prefix: ",
                                     prefix_obj['prefix']])
        # Print comment/header
        netboxers_helpers.write_to_ddo_fh(ctx, dnsmasq_dhcp)
        netboxers_helpers.write_to_ddo_fh(ctx, "")

        # Get default gateway from the VRF based on a tag
        default_gateway_ip_addr_obj = netboxers_queries.get_net_default_gateway_from_vrf(ctx, prefix_obj['vrf']['id'])
        if default_gateway_ip_addr_obj is not None:
            default_gateway_ip_addr = \
                ipaddress.ip_address(default_gateway_ip_addr_obj['address'].split("/")[0])

            # Write default gateway
            if default_gateway_ip_addr is not None:
                netboxers_helpers.write_to_ddo_fh(ctx, "dhcp-option=" + \
                                     ",".join([netboxers_queries.get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                                               "3", # Default gateway
                                               str(default_gateway_ip_addr)
                                              ]) +
                                     "  # Default Gateway")

                # Get DNS from the default gateway record
                default_dnsname_ip_addr = netboxers_queries.get_dns_host_from_ip_address(ctx, \
                    default_gateway_ip_addr_obj)

                # Write DNS server
                if default_dnsname_ip_addr is not None:
                    netboxers_helpers.write_to_ddo_fh(ctx, "dhcp-option=" + \
                                         ",".join([netboxers_queries.get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                                                   "6", # Default DNS
                                                   str(default_dnsname_ip_addr)
                                                  ]) +
                                         "  # Default DNS")

        # Print dhcp-range
        ip_network = ipaddress.ip_network(prefix_obj['prefix'])
        netboxers_helpers.write_to_ddo_fh(ctx, "dhcp-range=" + \
                             ",".join([netboxers_queries.get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                                     str(ip_network.network_address + \
                                         ctx['dhcp_host_range_offset_min']),
                                     str(ip_network.network_address + \
                                         ctx['dhcp_host_range_offset_max']),
                                     str(ip_network.netmask),
                                     ctx['dhcp_default_lease_time_range']
                                    ]))

        netboxers_helpers.write_to_ddo_fh(ctx, "")


        # Query all IP addresses in the VRF. From each, fetch the associated interface and its MAC
        # Extract all IP addresses in the VRF
        dhcp_host_tuples = netboxers_queries.get_dhcp_host_dict_from_vrf(ctx, prefix_obj['vrf']['id'])

        for tup in dhcp_host_tuples:
            # dhcp-host=eth0,a0:3e:6b:aa:6e:fc,Acer_Wit_Lieke,192.168.1.67,600m
            netboxers_helpers.write_to_ddo_fh(ctx, "dhcp-host=" +
                                 ",".join([netboxers_queries.get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                                           tup['mac_address'],
                                           tup['host_iface'],
                                           tup['ip_addr'],
                                           ctx['dhcp_default_lease_time_host']
                                          ]))



def powerdns_recursor_zonefile(ctx):
    zone = dns.zone.Zone(ctx['dhcp_default_domain'], relativize=False)

    rr_obj = {}
    rr_obj['type']    = 'SOA'
    rr_obj['name']    = netboxers_helpers.dns_canonicalize(ctx['dhcp_default_domain'])
    rr_obj['mname']   = netboxers_helpers.dns_canonicalize('ns.' + ctx['dhcp_default_domain'])
    rr_obj['rname']   = 'hostmaster.' + ctx['dhcp_default_domain']
    rr_obj['serial']  = 7
    rr_obj['refresh'] = 86400
    rr_obj['retry']   = 7200
    rr_obj['expire']  = 3600000
    rr_obj['minimum'] = 1800

    netboxers_helpers.add_rr_to_zone(ctx, zone, rr_obj)

    rr_obj = {}
    rr_obj['type'] = 'NS'
    rr_obj['name'] = '@'
    rr_obj['data'] = netboxers_helpers.dns_canonicalize('ns.' + ctx['dhcp_default_domain'])

    netboxers_helpers.add_rr_to_zone(ctx, zone, rr_obj)


    # Query for prefixes and ranges
    q = netboxers_helpers.query_netbox(ctx, "ipam/prefixes/")

    for prefix_obj in q['results']:

        # Skip non-IPv4
        if prefix_obj['family']['value'] != 4:
            continue

        # Only focus on Home
        if prefix_obj['site']['slug'] != 'home':
            continue

        # Query all IP addresses in the VRF. From each, fetch the associated interface and its MAC
        # Extract all IP addresses in the VRF
        ip_addrs_in_vrf = netboxers_queries.get_dhcp_host_dict_from_vrf(ctx, prefix_obj['vrf']['id'])

        # Run through the tupples
        for tupple in ip_addrs_in_vrf:

            # Add the A record for each interface
            rr_obj = {}
            rr_obj['type'] = 'A'
            rr_obj['name'] = netboxers_helpers.normalize_name(tupple['hostname'] + "_" + \
                                            tupple['interface_name'])
            rr_obj['data'] = str(tupple['ip_addr'])

            netboxers_helpers.add_rr_to_zone(ctx, zone, rr_obj)


            if 'mac_address' not in tupple or \
                    tupple['mac_address'] is None or \
                    len(tupple['mac_address']) == 0:
                print("No mac address available for",
                        tupple['hostname'],
                        "interface",
                        tupple['interface_name'],
                        "with",
                        tupple['ip_addr'],
                        file=sys.stderr)
                continue

            devices = netboxers_queries.fetch_devices_from_mac_address(ctx, tupple['mac_address'])
            if devices is None:
                print("No device found based on MAC address:", tupple['mac_address'], 
                        file=sys.stderr)
                continue

            # Assume only first record to be relevant, as the MAC address is unique.
            device = devices['results'][0]

            # Extract primary IP of device or virtual machine
            if 'primary_ip' in device and 'address' in device['primary_ip']:
                plain_ip_address = device['primary_ip']['address'].split('/')[0]

                # Check: is it equal to the current record?
                if tupple['ip_addr'] == plain_ip_address:

                    rr_obj['name'] = netboxers_helpers.normalize_name(tupple['hostname'] + "_" + \
                                                    tupple['interface_name'])
                    rr_obj = {}
                    rr_obj['type'] = 'CNAME'
                    rr_obj['name'] = netboxers_helpers.normalize_name(tupple['hostname'])
                    rr_obj['data'] = netboxers_helpers.dns_canonicalize(netboxers_helpers.normalize_name(tupple['hostname'] + "_" + \
                                                                     tupple['interface_name'] + \
                                                                     "." + \
                                                                     ctx['dhcp_default_domain'])
                                                     )

                    netboxers_helpers.add_rr_to_zone(ctx, zone, rr_obj)


    # Inject footer file
    if 'zonefooter' in ctx and len(ctx['zonefooter']) > 0:
        f = open(ctx['zonefooter'], 'r')
        foot = f.read()
        f.close()

    # Write zonefile
    f = open(ctx['zonefile'], 'w')
    zone.to_file(f, relativize=True)

    # Add footer to zonefile
    if foot is not None:
        f.write(foot)

    f.close()
    return


### WORK IN PROGRESS 192.168.x.x only
def powerdns_recursor_zoneing_reverse_lookups(ctx):
    print(ctx['zonefile_in_addr'])
    ### ctx['zonefile_in_addr']

    #ipam/ip-addresses/
    zone_name = "168.192.in-addr.arpa"
    zone = dns.zone.Zone(netboxers_helpers.dns_canonicalize(zone_name), relativize=False)

    rr_obj = {}
    rr_obj['type']    = 'SOA'
    rr_obj['name']    = netboxers_helpers.dns_canonicalize(zone_name)
    rr_obj['mname']   = netboxers_helpers.dns_canonicalize("ns." + ctx['dhcp_default_domain'])
    rr_obj['rname']   = netboxers_helpers.dns_canonicalize('hostmaster.' + ctx['dhcp_default_domain'])
    rr_obj['serial']  = 7
    rr_obj['refresh'] = 86400
    rr_obj['retry']   = 7200
    rr_obj['expire']  = 3600000
    rr_obj['minimum'] = 1800

    netboxers_helpers.add_rr_to_zone(ctx, zone, rr_obj)

    rr_obj = {}
    rr_obj['type'] = 'NS'
    rr_obj['name'] = '@'
    rr_obj['data'] = netboxers_helpers.dns_canonicalize('ns.' + ctx['dhcp_default_domain'])

    netboxers_helpers.add_rr_to_zone(ctx, zone, rr_obj)


    # Query for prefixes and ranges
    q = netboxers_helpers.query_netbox(ctx, "ipam/ip-addresses/")

    for ip_addr_obj in q['results']:
        tupple = {}

        # Skip non-IPv4
        if ip_addr_obj['family']['value'] != 4:
            continue

        ## HACK
        if not ip_addr_obj['address'].startswith('192.168'):
            print(ip_addr_obj['address'], "not in 192.168")
            continue

        # No interface? Skip
        if 'assigned_object' not in ip_addr_obj:
            print("No interface assigned to", ip_addr_obj['address'])
            continue


        # Assemble the tupple
        tupple['ip_addr'] = ip_addr_obj['address']

        if 'device' in ip_addr_obj['assigned_object']:
            tupple['host_name'] = ip_addr_obj['assigned_object']['device']['name']
        elif 'virtual_machine' in ip_addr_obj['assigned_object']:
            tupple['host_name'] = ip_addr_obj['assigned_object']['virtual_machine']['name']

        tupple['interface_name'] = ip_addr_obj['assigned_object']['name']

        ip_addr_interface = ipaddress.IPv4Interface(tupple['ip_addr'])
        tupple['rev_ip_addr'] = ipaddress.ip_address(ip_addr_interface.ip).reverse_pointer

        # Debug
        #netboxers_helpers.pp(tupple)

        # Add the PTR record for each interface
        # 131.28.12.202.in-addr.arpa. IN PTR svc00.apnic.net.
        rr_obj = {}
        rr_obj['type'] = 'PTR'

        # Strip the zone from the name
        lesser = 0 - len(zone_name) - 1
        rr_obj['name'] = tupple['rev_ip_addr'][:lesser]
        rr_obj['data'] = netboxers_helpers.dns_canonicalize(netboxers_helpers.normalize_name(tupple['host_name'] + "_" + \
                                                         tupple['interface_name'] + "." + \
                                                         ctx['dhcp_default_domain']))

        netboxers_helpers.add_rr_to_zone(ctx, zone, rr_obj)


    # Write zonefile
    f = open(ctx['zonefile_in_addr'], 'w')
    zone.to_file(f, relativize=False)

    f.close()
    return



### Main
def main(ctx):
    if 'dnsmasq_dhcp_output_file' in ctx and ctx['dnsmasq_dhcp_output_file'] is not None:
        print("Netbox to DNSMasq DHCP config")
        netbox_to_dnsmasq_dhcp_config(ctx)

    if 'zonefile' in ctx and ctx['zonefile'] is not None:
        print("Netbox to DNS Zonefile")
        powerdns_recursor_zonefile(ctx)

    if 'zonefile_in_addr' in ctx and ctx['zonefile_in_addr'] is not None:
        print("Netbox to DNS Zonefile for reverse lookups")
        powerdns_recursor_zoneing_reverse_lookups(ctx)


### Start up
if __name__ == "__main__":
    # initialize
    ctx = netboxers_helpers.get_ctx()
    ctx = netboxers_cli.argparsing(ctx)

    # Checks
    if not netboxers_cli.sanity_checks(ctx):
        sys.exit(1)

    # Go time
    main(ctx)
