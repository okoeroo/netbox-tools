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
    parser.add_argument("-lt", "--dhcp-default-lease-time",
                        dest='dhcp_default_lease_time',
                        help="DHCP Default Lease Time.",
                        default="12h",
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

    parser.add_argument("-d", "--dhcp",                 dest='dhcp',
                                                        help="DNSMasq input file with DHCP Host records.",
                                                        default=None,
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
    parser.add_argument("-j", "--json",                 dest='json',
                                                        help="Output JSON file.",
                                                        action="store_true",
                                                        default=False)
    parser.add_argument("-ah", "--all-dhcp-hosts",      dest='all_dhcp_hosts',
                                                        help="All DHCP Hosts.",
                                                        action="store_true",
                                                        default=False)
    parser.add_argument("-lu", "--lookup-by-uuid",      dest='lookup_by_uuid',
                                                        help="Lookup and output one host object, based on UUID value.",
                                                        default=None,
                                                        type=str)
    parser.add_argument("-li", "--lookup-by-ipv4",      dest='lookup_by_ipv4',
                                                        help="Lookup and output one host object, based on IPv4 address value.",
                                                        default=None,
                                                        type=str)
    parser.add_argument("-lm", "--lookup-by-mac",       dest='lookup_by_mac',
                                                        help="Lookup and output one host object, based on MAC address value.",
                                                        default=None,
                                                        type=str)
    parser.add_argument("-lh", "--lookup-by-hostname",  dest='lookup_by_hostname',
                                                        help="Lookup and output one host object, based on hostname value.",
                                                        default=None,
                                                        type=str)
    args = parser.parse_args()

    ctx = {}
    ctx['verbose']                    = args.verbose
    ctx['authkey']                    = args.authkey
    ctx['dnsmasq_dhcp_output_file']   = args.dnsmasq_dhcp_output_file
    ctx['netbox_base_url']            = args.netbox_base_url
    ctx['dhcp_default_lease_time']    = args.dhcp_default_lease_time
    ctx['dhcp_host_range_offset_min'] = args.dhcp_host_range_offset_min
    ctx['dhcp_host_range_offset_max'] = args.dhcp_host_range_offset_max
    ctx['dhcp_lease_file']            = args.dhcp_lease_file
    ctx['dhcp_authoritive']           = args.dhcp_authoritive
    ctx['dhcp_default_domain']        = args.dhcp_default_domain

    ctx['dhcp']               = args.dhcp
    ctx['zonefile']           = args.zonefile
    ctx['zoneheader']         = args.zoneheader
    ctx['zonefooter']         = args.zonefooter
    ctx['json']               = args.json
    ctx['all_dhcp_hosts']     = args.all_dhcp_hosts
    ctx['lookup_by_uuid']     = args.lookup_by_uuid
    ctx['lookup_by_ipv4']     = args.lookup_by_ipv4
    ctx['lookup_by_mac']      = args.lookup_by_mac
    ctx['lookup_by_hostname'] = args.lookup_by_hostname
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


def fetch_dhcphosts(ctx):
    ctx['dhcpraw'] = list(load_file_into_array(ctx['dhcp'], True))
    ctx['dhcp-hosts'] = []

    # Loop through all entries
    for line in ctx['dhcpraw']:
        s = line.strip()

        # Skip all lines, except those with dhcp-host, post trimming/stripping
        # whitespaces
        if s.startswith('dhcp-host'):
            line_params = s.split("=")[1]
            elements = line_params.split(",")

            dhcp_host_tuple = {}

            #Detect element
            # From the manual: -G, --dhcp-host=[<hwaddr>][,id:<client_id>|*][,set:<tag>][,<ipaddr>][,<hostname>][,<lease_time>][,ignore]
            l_uuid = get_uuid_value(line_params)
            if l_uuid is not None:
                dhcp_host_tuple['uuid'] = l_uuid

            for el in elements:
                if el in psutil.net_if_addrs().keys():
                    #print(el, "iface")
                    dhcp_host_tuple['iface_scope'] = el
                elif is_valid_macaddr802(el):
                    #print(el, "mac")
                    dhcp_host_tuple['mac'] = el
                elif el.startswith('id:'):
                    #print(el, "id")
                    dhcp_host_tuple['id'] = el.split(':')[1]
                elif el.startswith('set:'):
                    #print(el, "set")
                    dhcp_host_tuple['set'] = el.split(':')[1]
                elif is_ipaddress(el):
                    #print(el, "ipaddress")
                    dhcp_host_tuple['ipaddress'] = el
                elif is_lease_time(el):
                    #print(el, "lease time")
                    dhcp_host_tuple['lease_time'] = get_lease_time(el)
                elif el == 'ignore':
                    #print(el, "ignore")
                    dhcp_host_tuple['ignore'] = True
                else:
                    #print(el, "hostname")
                    # If all else fails
                    dhcp_host_tuple['hostname'] = el

            #print(s)
            #print(line_params)
            #print(elements)
            #print(dhcp_host_tuple)

            # print(dhcp_host_tuple)

            ctx['dhcp-hosts'].append(dhcp_host_tuple)

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

### Main
def main(ctx):

    # Generic settings
    print("dhcp-leasefile=" + \
        ctx['dhcp_lease_file'])

    if ctx['dhcp_authoritive']:
        print("dhcp-authoritative")

    print("domain=" + \
        ctx['dhcp_default_domain'])


    # Query for prefixes and ranges
    q = query_netbox(ctx, "ipam/prefixes/")

    for prefix_obj in q['results']:
        dnsmasq_dhcp = ""

#        pp = pprint.PrettyPrinter(indent=4)
#        pp.pprint(prefix_obj)

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
        print(dnsmasq_dhcp)
        print("")

        # Print dhcp-range
        ip_network = ipaddress.ip_network(prefix_obj['prefix'])
        print("dhcp-range=" + ",".join([prefix_obj['vrf']['name'],
                                        str(ip_network.network_address + \
                                            ctx['dhcp_host_range_offset_min']),
                                        str(ip_network.network_address + \
                                            ctx['dhcp_host_range_offset_max']),
                                        str(ip_network.netmask),
                                        ctx['dhcp_default_lease_time']
                                       ]))

        # Extract net_default_gateway from the VRF
        parameters = {}
        parameters['vrf_id'] = prefix_obj['vrf']['id']
        parameters['tag']    = 'net_default_gateway'
        q_ip_addrs = query_netbox(ctx, "ipam/ip-addresses/", parameters)

        if q_ip_addrs['count'] == 0:
            print("# No default gateway available")
        else:
#            pp = pprint.PrettyPrinter(indent=4)
#            pp.pprint(q_ip_addrs)

            default_gateway_ip_addr = \
                ipaddress.ip_address(q_ip_addrs['results'][0]['address'].split("/")[0])
            default_gateway_ip_network = \
                ipaddress.ip_network(q_ip_addrs['results'][0]['address'], strict=False)

            print("".join(["dhcp-option=",
                           prefix_obj['vrf']['name'],
                           ",",
                           "3", # Default gateway
                           ",",
                           str(default_gateway_ip_addr),
                           "  # Default Gateway"
                          ]))

            # Grab DNS host based on the DNS configured on the default gateway
            # host of a VRF
            # Assuming this variable is filled
            if q_ip_addrs['results'][0]['dns_name'] is not None and \
                len(q_ip_addrs['results'][0]['dns_name']) > 0:

                default_dnsname_ip_addr = \
                    ipaddress.ip_address(q_ip_addrs['results'][0]['dns_name'])

                print("".join(["dhcp-option=",
                               prefix_obj['vrf']['name'],
                               ",",
                               "6", # Default DNS
                               ",",
                               str(default_dnsname_ip_addr),
                               "  # Default DNS"
                              ]))
        print("")


    sys.exit(0)

    if ctx['dhcp'] is None:
        print("No DHCP input file set")
        return

    # Fetch DHCP Hosts and throws them into ctx['dhcp-hosts']
    fetch_dhcphosts(ctx)

#    pp = pprint.PrettyPrinter(indent=4)
#    pp.pprint(ctx)

    if  'dhcp' in ctx and ctx['dhcp'] is not None and \
        'zonefile' in ctx and ctx['zonefile'] is not None and \
        'zoneheader' in ctx and ctx['zoneheader'] is not None and \
        'zonefooter' in ctx and ctx['zonefooter'] is not None:
        # Put a new zonefile out
        put_zonefile(ctx)

    if 'json' in ctx and ctx['json']:
        y = json.dumps(ctx, indent=4)
        print(y)

    if 'all_dhcp_hosts' in ctx and ctx['all_dhcp_hosts']:
        y = json.dumps(ctx['dhcp-hosts'], indent=4)
        print(y)

    if 'lookup_by_uuid' in ctx and ctx['lookup_by_uuid'] is not None:
        fail = True
        for host_obj in ctx['dhcp-hosts']:
            if 'uuid' in host_obj and \
                    host_obj['uuid'] == ctx['lookup_by_uuid']:
                y = json.dumps(host_obj, indent=4)
                print(y)
                fail = False
                break
        if fail:
            sys.exit(1)

    if 'lookup_by_ipv4' in ctx and ctx['lookup_by_ipv4'] is not None:
        fail = True
        for host_obj in ctx['dhcp-hosts']:
            if 'ipaddress' in host_obj and \
                    host_obj['ipaddress'] == ctx['lookup_by_ipv4']:
                y = json.dumps(host_obj, indent=4)
                print(y)
                fail = False
                break
        if fail:
            sys.exit(1)

    if 'lookup_by_mac' in ctx and ctx['lookup_by_mac'] is not None:
        fail = True
        for host_obj in ctx['dhcp-hosts']:
            if 'mac' in host_obj and \
                    host_obj['mac'] == ctx['lookup_by_mac']:
                y = json.dumps(host_obj, indent=4)
                print(y)
                fail = False
                break
        if fail:
            sys.exit(1)

    if 'lookup_by_hostname' in ctx and ctx['lookup_by_hostname'] is not None:
        fail = True
        for host_obj in ctx['dhcp-hosts']:
            if 'hostname' in host_obj and \
                    host_obj['hostname'].lower() == ctx['lookup_by_hostname'].lower():
                y = json.dumps(host_obj, indent=4)
                print(y)
                fail = False
                break
        if fail:
            sys.exit(1)

### Start up
if __name__ == "__main__":
    ctx = argparsing()
    if not sanity_checks(ctx):
        sys.exit(1)

    main(ctx)
