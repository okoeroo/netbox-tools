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

    parser.add_argument("-z", "--zonefile",
                        dest='zonefile',
                        help="Zonefile format to be consumed by Bind or PowerDNS.",
                        default=None,
                        type=str)
    parser.add_argument("-rl", "--relativize",
                        dest='zonefile_relativize',
                        help="Create relativized names in the zonefile",
                        action="store_true",
                        default=True)

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
    ctx['zonefile']                       = args.zonefile
    ctx['zonefile_relativize']            = args.zonefile_relativize

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

def pp(obj):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(obj)


def dns_canonicalize(s):
    if not s.endswith('.'):
        return s + '.'
    else:
        return


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
def query_netbox_call(ctx, query, req_parameters=None):
    req_headers = {}
    req_headers['Authorization'] = " ".join(["Token", ctx['authkey']])
    req_headers['Content-Type'] = "application/json"
    req_headers['Accept'] = "application/json; indent=4"

    query_stripped = strip_query(ctx, query)

    if ctx['verbose']:
        print(query_stripped)

    get_req = requests.get('{}/api/{}'.format(ctx['netbox_base_url'], query_stripped),
                           timeout=3,
                           headers=req_headers,
                           params=req_parameters)
    get_req.raise_for_status()

    if ctx['verbose']:
        print(get_req.text)


    # Results retrieved
    return get_req.json()

def query_netbox(ctx, query, req_parameters=None):

    # Results retrieved
    response = query_netbox_call(ctx, query, req_parameters)

    # Merge response in memory
    req_next = response # setups for loop
    while 'next' in req_next and req_next['next'] and len(req_next['next']) > 0:
        res_next = query_netbox_call(ctx, req_next['next'], req_parameters)

        if ctx['verbose']:
            print(res_next)

        for i in res_next['results']:
            response['results'].append(i)

        req_next = res_next

    return response

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


def get_ipaddress_from_ipaddresses_obj(ip_addr_obj):
    return str(ipaddress.ip_address(ip_addr_obj['address'].split("/")[0]))


def get_network_address_from_ipaddresses_obj(ip_addr_obj):
    return str(ipaddress.ip_network(ip_addr_obj['address'], strict=False))


def get_macaddress_from_ipaddresses_obj(ctx, ip_addr_obj):

    # Get MAC from interface object
    interface_obj = query_netbox(ctx, ip_addr_obj['assigned_object']['url'])
    return interface_obj['mac_address']


def get_hostname_from_ipaddresses_obj(ip_addr_obj):
    if 'assigned_object' not in ip_addr_obj:
        return "no_assigned_object"

    try:
        if 'device' in ip_addr_obj['assigned_object']:
            return ip_addr_obj['assigned_object']['device']['name']
        elif 'virtual_machine' in ip_addr_obj['assigned_object']:
            return ip_addr_obj['assigned_object']['virtual_machine']['name']
        else:
            return "undefined"

    except Exception as e:
        print(str(e))
        pp(ip_addr_obj)
        sys.exit(1)


def get_interface_name_from_ipaddresses_obj(ip_addr_obj):
    if 'assigned_object' not in ip_addr_obj:
        return "no_assigned_object"

    # Get interface name
    return ip_addr_obj['assigned_object']['name']


def assemble_dhcp_host_dict_from_ip_addr_obj(ctx, ip_addr_obj):
    res_tup = {}

    res_tup['ip_addr'] = get_ipaddress_from_ipaddresses_obj(ip_addr_obj)
    res_tup['ip_net'] = get_network_address_from_ipaddresses_obj(ip_addr_obj)
    res_tup['mac_address'] = get_macaddress_from_ipaddresses_obj(ctx, ip_addr_obj)

    res_tup['hostname'] = get_hostname_from_ipaddresses_obj(ip_addr_obj)
    res_tup['normalized_hostname'] = normalize_name(res_tup['hostname'])

    res_tup['interface_name'] = get_interface_name_from_ipaddresses_obj(ip_addr_obj)
    res_tup['host_iface'] = res_tup['normalized_hostname'] + "_" + res_tup['interface_name']

    return res_tup


def get_vrf_vlan_name_from_prefix_obj(prefix_obj):
    return prefix_obj['vrf']['name'] + "_vlan_" + str(prefix_obj['vlan']['vid'])


def get_dhcp_host_dict_from_vrf(ctx, vrf_id):
    parameters = {}
    parameters['vrf_id'] = vrf_id
    q_ip_addrs = query_netbox(ctx, "ipam/ip-addresses/", parameters)

    if q_ip_addrs['count'] == 0:
        return None

    dhcp_hosts = []

    # VRF scoped dhcp hosts
    for ip_addr_obj in q_ip_addrs['results']:
        dhcp_hosts.append(assemble_dhcp_host_dict_from_ip_addr_obj(ctx,
                                                                   ip_addr_obj))

    return dhcp_hosts


# This function will create a DNSMasq formatted DHCP config file from Netbox
## Create DNSMasq DHCP config file by:
## 1. Fetching defaults
## 2. Fetching VRFs, and VRF info.
## 3. Fetch associated default gateway and DNS config
## 4. Fetch (virtual) hosts and its data (IP and MAC)

def netbox_to_dnsmasq_dhcp_config(ctx):
    # Truncate and open file cleanly
    write_to_ddo_fh(ctx, None)

    # Generic settings
    write_to_ddo_fh(ctx, "dhcp-leasefile=" + ctx['dhcp_lease_file'])

    if ctx['dhcp_authoritive']:
        write_to_ddo_fh(ctx, "dhcp-authoritative")

    write_to_ddo_fh(ctx, "domain=" + ctx['dhcp_default_domain'])

    # Get prefixes
    prefixes = query_netbox(ctx, "ipam/prefixes/")

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
        write_to_ddo_fh(ctx, dnsmasq_dhcp)
        write_to_ddo_fh(ctx, "")

        # Get default gateway from the VRF based on a tag
        default_gateway_ip_addr_obj = get_net_default_gateway_from_vrf(ctx, prefix_obj['vrf']['id'])
        if default_gateway_ip_addr_obj is not None:
            default_gateway_ip_addr = \
                ipaddress.ip_address(default_gateway_ip_addr_obj['address'].split("/")[0])

            # Write default gateway
            if default_gateway_ip_addr is not None:
                write_to_ddo_fh(ctx, "dhcp-option=" + \
                                     ",".join([get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                                               "3", # Default gateway
                                               str(default_gateway_ip_addr)
                                              ]) +
                                     "  # Default Gateway")

                # Get DNS from the default gateway record
                default_dnsname_ip_addr = get_dns_host_from_ip_address(ctx, \
                    default_gateway_ip_addr_obj)

                # Write DNS server
                if default_dnsname_ip_addr is not None:
                    write_to_ddo_fh(ctx, "dhcp-option=" + \
                                         ",".join([get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                                                   "6", # Default DNS
                                                   str(default_dnsname_ip_addr)
                                                  ]) +
                                         "  # Default DNS")

        # Print dhcp-range
        ip_network = ipaddress.ip_network(prefix_obj['prefix'])
        write_to_ddo_fh(ctx, "dhcp-range=" + \
                             ",".join([get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                                     str(ip_network.network_address + \
                                         ctx['dhcp_host_range_offset_min']),
                                     str(ip_network.network_address + \
                                         ctx['dhcp_host_range_offset_max']),
                                     str(ip_network.netmask),
                                     ctx['dhcp_default_lease_time_range']
                                    ]))

        write_to_ddo_fh(ctx, "")


        # Query all IP addresses in the VRF. From each, fetch the associated interface and its MAC
        # Extract all IP addresses in the VRF
        dhcp_host_tuples = get_dhcp_host_dict_from_vrf(ctx, prefix_obj['vrf']['id'])

        for tup in dhcp_host_tuples:
            # dhcp-host=eth0,a0:3e:6b:aa:6e:fc,Acer_Wit_Lieke,192.168.1.67,600m
            write_to_ddo_fh(ctx, "dhcp-host=" +
                                 ",".join([get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                                           tup['mac_address'],
                                           tup['host_iface'],
                                           tup['ip_addr'],
                                           ctx['dhcp_default_lease_time_host']
                                          ]))


def add_rr_to_zone(ctx, zone, rr_obj):
    if 'name' not in rr_obj:
        raise "rr_obj missing name"

    if 'type' not in rr_obj:
        raise "rr_obj missing type"

    if 'ttl' not in rr_obj:
        rr_obj['ttl'] = 86400

    rdclass = dns.rdataclass._by_text.get('IN')

    # A
    if rr_obj['type'] == 'A': 
        if 'name' not in rr_obj or 'type' not in rr_obj or 'data' not in rr_obj:
            raise "rr_obj missing elements for A record"

        rdtype = dns.rdatatype._by_text.get(rr_obj['type'])
        rdataset = zone.find_rdataset(rr_obj['name'], rdtype=rdtype, create=True)
        rdata = dns.rdata.from_text(rdclass, rdtype, rr_obj['data'])
        rdataset.add(rdata, ttl=rr_obj['ttl'])
        return

    # PTR
    if rr_obj['type'] == 'PTR': 
        if 'name' not in rr_obj or 'type' not in rr_obj or 'data' not in rr_obj:
            raise "rr_obj missing elements for A record"

        print(rr_obj['name'])
        rdtype = dns.rdatatype._by_text.get(rr_obj['type'])
        rdataset = zone.find_rdataset(rr_obj['name'], rdtype=rdtype, create=True)
        rdata = dns.rdata.from_text(rdclass, rdtype, rr_obj['data'])
        rdataset.add(rdata, ttl=rr_obj['ttl'])
        return

#            # Add PTR Resource Record
#            rdtype = dns.rdatatype._by_text.get('PTR')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.ANY.PTR.PTR(rdclass, rdtype,
#                target = Name((rr.content.rstrip('.') + '.').split('.'))
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))

    # CNAME
    if rr_obj['type'] == 'CNAME': 
        if 'name' not in rr_obj or 'type' not in rr_obj or 'data' not in rr_obj:
            raise "rr_obj missing elements for CNAME record"

        rdtype = dns.rdatatype._by_text.get(rr_obj['type'])
        rdataset = zone.find_rdataset(rr_obj['name'], rdtype=rdtype, create=True)
        rdata = dns.rdata.from_text(rdclass, rdtype, rr_obj['data'])
        rdataset.add(rdata, ttl=rr_obj['ttl'])
        return

    # SOA
    if rr_obj['type'] == 'SOA':
        if 'name' not in rr_obj or 'type' not in rr_obj or \
            'mname' not in rr_obj or 'rname' not in rr_obj:
            raise "rr_obj missing elements for SOA record"

        rdtype = dns.rdatatype._by_text.get(rr_obj['type'])
        rdataset = zone.find_rdataset(rr_obj['name'], rdtype=rdtype, create=True)
        rdata = dns.rdtypes.ANY.SOA.SOA(rdclass, rdtype,
                    mname = dns.name.Name(rr_obj['mname'].split('.')),
                    rname = dns.name.Name(rr_obj['rname'].split('.')),
                    serial = rr_obj['serial'],
                    refresh = rr_obj['refresh'],
                    retry = rr_obj['retry'],
                    expire = rr_obj['expire'],
                    minimum = rr_obj['minimum']
        )
        rdataset.add(rdata, ttl=rr_obj['ttl'])
        return

    # NS
    if rr_obj['type'] == 'NS':
        rdtype = dns.rdatatype._by_text.get(rr_obj['type'])
        rdataset = zone.find_rdataset(rr_obj['name'], rdtype=rdtype, create=True)

        if rr_obj['data'][-1:] != '.':
             rr_obj['data'] = rr_obj['data'] + '.'

        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS,
                                 rr_obj['data'])

        rdataset.add(rdata, ttl=rr_obj['ttl'])
#
#def generate_zone_file(origin):
#    """Generates a zone file.
#     
#    Accepts the zone origin as string (no trailing dot).
#      
#    Returns the contents of a zone file that contains all the resource records
#    associated with the domain with the provided origin.
#     
#    """
#    Domain = get_model('powerdns_manager', 'Domain')
#    Record = get_model('powerdns_manager', 'Record')
#     
#    the_domain = Domain.objects.get(name__exact=origin)
#    the_rrs = Record.objects.filter(domain=the_domain).order_by('-type')
#     
#    # Generate the zone file
#     
#    origin = Name((origin.rstrip('.') + '.').split('.'))
#     
#    # Create an empty dns.zone object.
#    # We set check_origin=False because the zone contains no records.
#    zone = dns.zone.from_text('', origin=origin, relativize=False, check_origin=False)
#     
#    rdclass = dns.rdataclass._by_text.get('IN')
#     
#    for rr in the_rrs:
#         
#        # Add trailing dot to rr.name
#        record_name = rr.name.rstrip('.') + '.'
#         
#        if rr.type == 'SOA':
#            # Add SOA Resource Record
#             
#            # SOA content:  primary hostmaster serial refresh retry expire default_ttl
#            bits = rr.content.split()
#            # Primary nameserver of SOA record
#            primary = bits[0].rstrip('.') + '.'
#            mname = Name(primary.split('.'))
#            # Responsible hostmaster from SOA record
#            hostmaster = bits[1].rstrip('.') + '.'
#            rname = Name(hostmaster.split('.'))
#             
#            rdtype = dns.rdatatype._by_text.get('SOA')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.ANY.SOA.SOA(rdclass, rdtype,
#                mname = mname,
#                rname = rname,
#                serial = int(bits[2]),
#                refresh = int(bits[3]),
#                retry = int(bits[4]),
#                expire = int(bits[5]),
#                minimum = int(bits[6])
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))
#         
#        elif rr.type == 'NS':
#            # Add NS Resource Record
#            rdtype = dns.rdatatype._by_text.get('NS')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.ANY.NS.NS(rdclass, rdtype,
#                target = Name((rr.content.rstrip('.') + '.').split('.'))
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))
#         
#        elif rr.type == 'MX':
#            # Add MX Resource Record
#            rdtype = dns.rdatatype._by_text.get('MX')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.ANY.MX.MX(rdclass, rdtype,
#                preference = int(rr.prio),
#                exchange = Name((rr.content.rstrip('.') + '.').split('.'))
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))
#         
#        elif rr.type == 'TXT':
#            # Add TXT Resource Record
#            rdtype = dns.rdatatype._by_text.get('TXT')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.ANY.TXT.TXT(rdclass, rdtype,
#                strings = [rr.content.strip('"')]
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))
#         
#        elif rr.type == 'CNAME':
#            # Add CNAME Resource Record
#            rdtype = dns.rdatatype._by_text.get('CNAME')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.ANY.CNAME.CNAME(rdclass, rdtype,
#                target = Name((rr.content.rstrip('.') + '.').split('.'))
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))
#         
#        elif rr.type == 'A':
#            # Add A Resource Record
#            rdtype = dns.rdatatype._by_text.get('A')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.IN.A.A(rdclass, rdtype,
#                address = rr.content
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))
#         
#        elif rr.type == 'AAAA':
#            # Add AAAA Resource Record
#            rdtype = dns.rdatatype._by_text.get('AAAA')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.IN.AAAA.AAAA(rdclass, rdtype,
#                address = rr.content
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))
#         
#        elif rr.type == 'SPF':
#            # Add SPF Resource Record
#            rdtype = dns.rdatatype._by_text.get('SPF')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.ANY.SPF.SPF(rdclass, rdtype,
#                strings = [rr.content.strip('"')]
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))
#         
#        elif rr.type == 'PTR':
#            # Add PTR Resource Record
#            rdtype = dns.rdatatype._by_text.get('PTR')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.ANY.PTR.PTR(rdclass, rdtype,
#                target = Name((rr.content.rstrip('.') + '.').split('.'))
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))
#         
#        elif rr.type == 'SRV':
#            # Add SRV Resource Record
#             
#            # weight port target
#            weight, port, target = rr.content.split()
#             
#            rdtype = dns.rdatatype._by_text.get('SRV')
#            rdataset = zone.find_rdataset(record_name, rdtype=rdtype, create=True)
#            rdata = dns.rdtypes.IN.SRV.SRV(rdclass, rdtype,
#                priority = int(rr.prio),
#                weight = int(weight),
#                port = int(port),
#                target = Name((target.rstrip('.') + '.').split('.'))
#            )
#            rdataset.add(rdata, ttl=int(rr.ttl))
#             
#     
#    # Export text (from the source code of http://www.dnspython.org/docs/1.10.0/html/dns.zone.Zone-class.html#to_file)
#    EOL = '\n'
#    f = StringIO.StringIO()
#    f.write('$ORIGIN %s%s' % (origin, EOL))
#    zone.to_file(f, sorted=True, relativize=False, nl=EOL)
#    data = f.getvalue()
#    f.close()
#    return data


## Based on the mac address fetch a device.
## The device can be a virtual machine or device
def fetch_devices_from_mac_address(mac_address):
    parameters = {}
    parameters['mac_address'] = mac_address

    # Device or VM?
    devices = query_netbox(ctx, "dcim/devices/", parameters)
    if devices['count'] == 0:
        devices = query_netbox(ctx, "virtualization/virtual-machines/", parameters)
        if devices['count'] == 0:
            # Not in Database...
            return None

    return devices

def extract_primary_ip_from_device_obj(device):

    # Extract primary IP from device or virtual machine
    if 'primary_ip' in device['results'][0] and 'address' in device['results'][0]['primary_ip']:
        plain_ip_address = device['results'][0]['primary_ip']['address'].split('/')[0]


def powerdns_recursor_zoneing(ctx):
    zone = dns.zone.Zone(ctx['dhcp_default_domain'], relativize=False)

    rr_obj = {}
    rr_obj['type']    = 'SOA'
    rr_obj['name']    = dns_canonicalize(ctx['dhcp_default_domain'])
    rr_obj['mname']   = dns_canonicalize('ns.' + ctx['dhcp_default_domain'])
    rr_obj['rname']   = 'hostmaster.' + ctx['dhcp_default_domain']
    rr_obj['serial']  = 7
    rr_obj['refresh'] = 86400
    rr_obj['retry']   = 7200
    rr_obj['expire']  = 3600000
    rr_obj['minimum'] = 1800

    add_rr_to_zone(ctx, zone, rr_obj)

    rr_obj = {}
    rr_obj['type'] = 'NS'
    rr_obj['name'] = '@'
    rr_obj['data'] = dns_canonicalize('ns.' + ctx['dhcp_default_domain'])

    add_rr_to_zone(ctx, zone, rr_obj)


    # Query for prefixes and ranges
    q = query_netbox(ctx, "ipam/prefixes/")

    for prefix_obj in q['results']:

        # Skip non-IPv4
        if prefix_obj['family']['value'] != 4:
            continue

        # Only focus on Home
        if prefix_obj['site']['slug'] != 'home':
            continue

        # Query all IP addresses in the VRF. From each, fetch the associated interface and its MAC
        # Extract all IP addresses in the VRF
#####        ip_addrs_in_vrf = get_ip_addrs_in_vrf(ctx, prefix_obj['vrf']['id'])
#####        dhcp_host_tuples = get_dhcp_host_dict_from_vrf(ctx, prefix_obj['vrf']['id'])
        ip_addrs_in_vrf = get_dhcp_host_dict_from_vrf(ctx, prefix_obj['vrf']['id'])

        # Run through the tupples
        for tupple in ip_addrs_in_vrf:

            # Add the A record for each interface
            rr_obj = {}
            rr_obj['type'] = 'A'
            rr_obj['name'] = normalize_name(tupple['hostname'] + "_" + \
                                            tupple['interface_name'])
            rr_obj['data'] = str(tupple['ip_addr'])

            add_rr_to_zone(ctx, zone, rr_obj)


#            # Add the PTR record for each interface
#            # 131.28.12.202.in-addr.arpa. IN PTR svc00.apnic.net.
#            rr_obj = {}
#            rr_obj['type'] = 'PTR'
#            rr_obj['name'] = ipaddress.ip_address(str(tupple['ip_addr'])).reverse_pointer
#            rr_obj['data'] = dns_canonicalize(normalize_name(tupple['host_name'] + "_" + \
#                                                             tupple['interface_name'] + "." + \
#                                                             ctx['dhcp_default_domain']))
#
#            add_rr_to_zone(ctx, zone, rr_obj)

#            print('tupple')
#            print(tupple)

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

            devices = fetch_devices_from_mac_address(tupple['mac_address'])
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

                    rr_obj['name'] = normalize_name(tupple['hostname'] + "_" + \
                                                    tupple['interface_name'])
                    rr_obj = {}
                    rr_obj['type'] = 'CNAME'
                    rr_obj['name'] = normalize_name(tupple['hostname'])
                    rr_obj['data'] = dns_canonicalize(normalize_name(tupple['hostname'] + "_" + \
                                                                     tupple['interface_name'] + \
                                                                     "." + \
                                                                     ctx['dhcp_default_domain'])
                                                     )

                    add_rr_to_zone(ctx, zone, rr_obj)


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


### Main
def main(ctx):
    print("Netbox to DNSMasq DHCP config")
    netbox_to_dnsmasq_dhcp_config(ctx)

    print("Netbox to DNS Zonefile")
    powerdns_recursor_zoneing(ctx)

### Start up
if __name__ == "__main__":
    ctx = argparsing()
    if not sanity_checks(ctx):
        sys.exit(1)

    main(ctx)
