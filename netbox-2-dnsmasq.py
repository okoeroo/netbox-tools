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


def argparsing():
    # Parser
    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument("-v", "--verbose",
                        dest='verbose',
                        help="Verbose mode. Default is off",
                        action="store_true",
                        default=False)
    parser.add_argument("-k", "--authkey",
                        dest='authkey',
                        help="Netbox authentication key.",
                        default=None,
                        type=str)
    parser.add_argument("-do", "--dnsmasq-dhcp-output-file",
                        dest='dnsmasq_dhcp_output_file',
                        help="DNSMasq format DHCP output file based on Netbox info.",
                        default=None,
                        type=str)
    parser.add_argument("-bu", "--base-url",
                        dest='netbox_base_url',
                        help="Netbox base URL.",
                        default=None,
                        type=str)
    parser.add_argument("-ltr", "--dhcp-default-lease-time-range",
                        dest='dhcp_default_lease_time_range',
                        help="DHCP Default Lease Time for a DHCP range.",
                        default="12h",
                        type=str)
    parser.add_argument("-lth", "--dhcp-default-lease-time-host",
                        dest='dhcp_default_lease_time_host',
                        help="DHCP Default Lease Time for a fixed DCHP host.",
                        default="600m",
                        type=str)
    parser.add_argument("-min", "--dhcp-host-range-offset-min",
                        dest='dhcp_host_range_offset_min',
                        help="DHCP Host range offset minimum.",
                        default=100,
                        type=int)
    parser.add_argument("-max", "--dhcp-host-range-offset-max",
                        dest='dhcp_host_range_offset_max',
                        help="DHCP Host range offset maximum.",
                        default=199,
                        type=int)
    parser.add_argument("-lf", "--dhcp-lease-file",
                        dest='dhcp_lease_file',
                        help="DHCP Lease file.",
                        default="/var/cache/dnsmasq/dnsmasq-dhcp.leasefile",
                        type=str)
    parser.add_argument("-da", "--dhcp-authoritive",
                        dest='dhcp_authoritive',
                        help="Set DHCP Authoritive flag",
                        action="store_true",
                        default=True)
    parser.add_argument("-ddd", "--dhcp-default-domain",
                        dest='dhcp_default_domain',
                        help="DHCP Default Domain.",
                        default="koeroo.local",
                        type=str)

    parser.add_argument("-z", "--zonefile",             dest='zonefile',
                                                        help="Zonefile format to be consumed by Bind or PowerDNS.",
                                                        default=None,
                                                        type=str)
    parser.add_argument("-e", "--zoneheader",           dest='zoneheader',
                                                        help="Zonefile header template.",
                                                        default=None,
                                                        type=str)
    parser.add_argument("-f", "--zonefooter",           dest='zonefooter',
                                                        help="Zonefile footer template.",
                                                        default=None,
                                                        type=str)
    args = parser.parse_args()

    ctx = {}
    ctx['verbose']                        = args.verbose
    ctx['authkey']                        = args.authkey
    ctx['dnsmasq_dhcp_output_file']       = args.dnsmasq_dhcp_output_file
    ctx['netbox_base_url']                = args.netbox_base_url
    ctx['dhcp_default_lease_time_range']  = args.dhcp_default_lease_time_range
    ctx['dhcp_default_lease_time_host']   = args.dhcp_default_lease_time_host
    ctx['dhcp_host_range_offset_min']     = args.dhcp_host_range_offset_min
    ctx['dhcp_host_range_offset_max']     = args.dhcp_host_range_offset_max
    ctx['dhcp_lease_file']                = args.dhcp_lease_file
    ctx['dhcp_authoritive']               = args.dhcp_authoritive
    ctx['dhcp_default_domain']            = args.dhcp_default_domain

    ctx['zonefile']           = args.zonefile
    ctx['zoneheader']         = args.zoneheader
    ctx['zonefooter']         = args.zonefooter
    return ctx

def get_uuid_value(value):
    m = re.search("UUID:(.*)$", value)
    if m:
        return m.group(1)
    else:
        return None

def is_lease_time(value):
    m = re.search("^[0-9]+[hms]", value)
    if m:
        return True
    else:
        return False

def get_lease_time(value):
    m = re.search("^[0-9]+[hms]", value)
    if m:
        return m.group(0)
    else:
        return None

def is_valid_macaddr802(value):
    allowed = re.compile(r"""
                         (
                             ^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$
                            |^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$
                         )
                         """,
                         re.VERBOSE|re.IGNORECASE)

    if allowed.match(value) is None:
        return False
    else:
        return True

def load_file_into_array(filename, emptylines=True):
    if emptylines:
        return open(filename, "r", encoding='utf-8').read().splitlines()
    else:
        return filter(None, open(filename, "r", encoding='utf-8').read().splitlines())

def is_ipaddress(to_check):
    try:
        ipaddress.ip_address(to_check)
        return True
    except Exception as err:
        return False


def put_zonefile(ctx):
#    pp = pprint.PrettyPrinter(indent=4)
#    pp.pprint(ctx['dhcp-hosts'])

    header = open(ctx['zoneheader']).read()
    footer = open(ctx['zonefooter']).read()

    # Write header to buffer
    output = header

    longest_hostname = 0
    for dhcp_host_tuple in ctx['dhcp-hosts']:
        if len(dhcp_host_tuple['hostname']) > longest_hostname:
            longest_hostname = len(dhcp_host_tuple['hostname'])

    for dhcp_host_tuple in ctx['dhcp-hosts']:
        w_len = longest_hostname - len(dhcp_host_tuple['hostname']) + 4
        output = output + dhcp_host_tuple['hostname'].lower() + " " * w_len + "A" + "  " + dhcp_host_tuple['ipaddress']
        output = output + "\n"

    # Write footer to output buffer
    output = output + footer

    if ctx['verbose'] == True:
        print(output)

    f = open(ctx['zonefile'], 'w')
    f.write(output)
    f.close()


def normalize_name(name):
    return name.lower().replace(" ", "_").replace("-", "_").replace("\"", "").replace("\'", "")

def strip_query(ctx, query):
    # Pattern is base_url/api/query, all double bits should be stripped 

    if query.startswith(ctx['netbox_base_url'] + '/api/'):
        return query[len(ctx['netbox_base_url'] + '/api/'):]

    return query

### 
def query_netbox(ctx, query, req_parameters=None):
    req_headers = {}
    req_headers['Authorization'] = " ".join(["Token", ctx['authkey']])
    req_headers['Content-Type'] = "application/json"
    req_headers['Accept'] = "application/json; indent=4"

    query_stripped = strip_query(ctx, query)

    get_req = requests.get('{}/api/{}'.format(ctx['netbox_base_url'], query_stripped),
                           timeout=3,
                           headers=req_headers,
                           params=req_parameters)
    get_req.raise_for_status()

    return get_req.json()

### Sanity checks: on failure, makes no sense to continue
def sanity_checks(ctx):
    if ctx['authkey'] is None:
        print("No Netbox authentication key provided")
        return False

    if ctx['netbox_base_url'] is None:
        print("No Netbox base URL provided")
        return False

    #auto-correct base URL
    if ctx['netbox_base_url'].endswith('/'):
        ctx['netbox_base_url'] = ctx['netbox_base_url'][:-1]

    if not ctx['netbox_base_url'].startswith('http://') and \
        not ctx['netbox_base_url'].startswith('https://'):
        print("The provided base URL does not start with http:// or https://. Value:",
            ctx['netbox_base_url'])
        sys.exit(1)

    # Debug output
    if ctx['verbose']:
        print('Authkey', ctx['authkey'])
        print('Netbox base URL', ctx['netbox_base_url'])
        print()
    return True


def write_to_ddo_fh(ctx, s):
    # Truncate file
    if s is None and ctx['dnsmasq_dhcp_output_file'] is not None:
        open(ctx['dnsmasq_dhcp_output_file'], 'w').close()
        return

    # Print or write
    if ctx['dnsmasq_dhcp_output_file'] is None:
        print(s)
    else:
        with open(ctx['dnsmasq_dhcp_output_file'], 'a') as the_file:
            the_file.write(s + os.linesep)


# Default gateway from the VRF
def get_net_default_gateway_from_vrf(ctx, vrf_id):

    # Extract net_default_gateway from the VRF
    parameters = {}
    parameters['vrf_id'] = vrf_id
    parameters['tag']    = 'net_default_gateway'
    q_ip_addrs = query_netbox(ctx, "ipam/ip-addresses/", parameters)

    if q_ip_addrs['count'] == 0:
        write_to_ddo_fh(ctx, "# No default gateway available")
        return None
    else:

        return q_ip_addrs['results'][0]


# Grab DNS host based on the DNS configured on the default gateway
# host of a VRF
# Assuming this variable is filled
def get_dns_host_from_ip_address(ctx, ip_addr_obj):

    if ip_addr_obj['dns_name'] is not None and \
        len(ip_addr_obj['dns_name']) > 0:

        default_dnsname_ip_addr = \
            ipaddress.ip_address(ip_addr_obj['dns_name'])
        return default_dnsname_ip_addr
    else:
        return None

# Query all IP addresses in the VRF. From each, fetch the associated interface and its MAC
# Extract all IP addresses in the VRF
def get_ip_addrs_in_vrf(ctx, vrf_id):
    results = []

    parameters = {}
    parameters['vrf_id'] = vrf_id
    q_ip_addrs = query_netbox(ctx, "ipam/ip-addresses/", parameters)

    if q_ip_addrs['count'] == 0:
        write_to_ddo_fh(ctx, "# No IP addresses in the VRF available.")
    else:
        for ip_addr_obj in q_ip_addrs['results']:
            ip_addr = \
                ipaddress.ip_address(ip_addr_obj['address'].split("/")[0])

            ip_net = \
                ipaddress.ip_network(ip_addr_obj['address'], strict=False)

            # Get hostname
            if ip_addr_obj['interface']['device'] is not None:
                host_name = \
                    ip_addr_obj['interface']['device']['name']
            elif ip_addr_obj['interface']['virtual_machine'] is not None:
                host_name = \
                    ip_addr_obj['interface']['virtual_machine']['name']
            else:
                host_name = "undefined"

            # Get MAC from interface object
            interface_obj = query_netbox(ctx, ip_addr_obj['interface']['url'])
            mac_address = interface_obj['mac_address']


            # Get interface name
            interface_name =  ip_addr_obj['interface']['name']

            try:
                if mac_address is None:
                    write_to_ddo_fh(ctx, "## No MAC address available. " + str(ip_addr))
                    continue

                if host_name is None:
                    write_to_ddo_fh(ctx, "## No hostname available.")
                    continue

                if ip_addr is None:
                    write_to_ddo_fh(ctx, "## No IPv4 Address available.")
                    continue

                if interface_name is None:
                    write_to_ddo_fh(ctx, "## No interface name available.")
                    continue

                results.append({'mac_address': mac_address,
                                'host_name': host_name,
                                'interface_name': interface_name,
                                'ip_addr': ip_addr})
            except Exception as e:
                print(str(e))

                pp = pprint.PrettyPrinter(indent=4)
                pp.pprint(ip_addr_obj)
                sys.exit(1)

    return results

#                # dhcp-host=eth0,a0:3e:6b:aa:6e:fc,Acer_Wit_Lieke,192.168.1.67,600m
#                write_to_ddo_fh(ctx, "dhcp-host=" + ",".join([ prefix_obj['vrf']['name'],
#                                                mac_address,
#                                                normalize_name(host_name + "_" + interface_name),
#                                                str(ip_addr),
#                                                ctx['dhcp_default_lease_time_host'],
#                                              ]))
    

# This function will create a DNSMasq formatted DHCP config file from Netbox
def netbox_to_dnsmasq_dhcp_config(ctx):
    # Generic settings
    write_to_ddo_fh(ctx, "dhcp-leasefile=" + ctx['dhcp_lease_file'])

    if ctx['dhcp_authoritive']:
        write_to_ddo_fh(ctx, "dhcp-authoritative")

    write_to_ddo_fh(ctx, "domain=" + ctx['dhcp_default_domain'])


    # Query for prefixes and ranges
    q = query_netbox(ctx, "ipam/prefixes/")

    for prefix_obj in q['results']:
        dnsmasq_dhcp = ""

        # Skip non-IPv4
        if prefix_obj['family']['value'] != 4:
            continue

        # Only focus on Home
        if prefix_obj['site']['slug'] != 'home':
            continue

        # Generate VRF header
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
        write_to_ddo_fh(ctx, dnsmasq_dhcp)
        write_to_ddo_fh(ctx, "")

        # Print dhcp-range
        ip_network = ipaddress.ip_network(prefix_obj['prefix'])
        write_to_ddo_fh(ctx, "dhcp-range=" + ",".join([prefix_obj['vrf']['name'],
                                        str(ip_network.network_address + \
                                            ctx['dhcp_host_range_offset_min']),
                                        str(ip_network.network_address + \
                                            ctx['dhcp_host_range_offset_max']),
                                        str(ip_network.netmask),
                                        ctx['dhcp_default_lease_time_range']
                                       ]))

###########
        default_gateway_ip_addr_obj = get_net_default_gateway_from_vrf(ctx, prefix_obj['vrf']['id'])
        if default_gateway_ip_addr_obj is not None:
            default_gateway_ip_addr = \
                ipaddress.ip_address(default_gateway_ip_addr_obj['address'].split("/")[0])

            if default_gateway_ip_addr is not None:
                write_to_ddo_fh(ctx, "".join(["dhcp-option=",
                               prefix_obj['vrf']['name'],
                               ",",
                               "3", # Default gateway
                               ",",
                               str(default_gateway_ip_addr),
                               "  # Default Gateway"
                              ]))

                default_dnsname_ip_addr = get_dns_host_from_ip_address(ctx, \
                    default_gateway_ip_addr_obj)

                if default_dnsname_ip_addr is not None:
                    write_to_ddo_fh(ctx, "".join(["dhcp-option=",
                                   prefix_obj['vrf']['name'],
                                   ",",
                                   "6", # Default DNS
                                   ",",
                                   str(default_dnsname_ip_addr),
                                   "  # Default DNS"
                                  ]))

        write_to_ddo_fh(ctx, "")


        # Query all IP addresses in the VRF. From each, fetch the associated interface and its MAC
        # Extract all IP addresses in the VRF
        ip_addrs_in_vrf = get_ip_addrs_in_vrf(ctx, prefix_obj['vrf']['id'])

        for tupple in ip_addrs_in_vrf:

            # dhcp-host=eth0,a0:3e:6b:aa:6e:fc,Acer_Wit_Lieke,192.168.1.67,600m
            write_to_ddo_fh(ctx, "dhcp-host=" + ",".join([ prefix_obj['vrf']['name'],
                                            tupple['mac_address'],
                                            normalize_name(tupple['host_name'] + "_" + \
                                                tupple['interface_name']),
                                            str(tupple['ip_addr']),
                                            ctx['dhcp_default_lease_time_host'],
                                          ]))

        write_to_ddo_fh(ctx, "")


### Main
def main(ctx):
    # Truncate and open file
    write_to_ddo_fh(ctx, None)

    netbox_to_dnsmasq_dhcp_config(ctx)

### Start up
if __name__ == "__main__":
    ctx = argparsing()
    if not sanity_checks(ctx):
        sys.exit(1)

    main(ctx)
