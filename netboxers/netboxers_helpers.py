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


def pp(obj):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(obj)


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


def normalize_name(name):
    return name.lower().replace(" ", "_").replace("-", "_").replace("\"", "").replace("\'", "")


def dns_canonicalize(s):
    if not s.endswith('.'):
        return s + '.'
    else:
        return

def get_ctx():
    ctx = {}
    return ctx

def strip_query(ctx, query):
    # Pattern is base_url/api/query, all double bits should be stripped 

    if query.startswith(ctx['netbox_base_url'] + '/api/'):
        return query[len(ctx['netbox_base_url'] + '/api/'):]

    return query

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

        rdtype = dns.rdatatype._by_text.get(rr_obj['type'])
        rdataset = zone.find_rdataset(rr_obj['name'], rdtype=rdtype, create=True)
        rdata = dns.rdata.from_text(rdclass, rdtype, rr_obj['data'])
        rdataset.add(rdata, ttl=rr_obj['ttl'])
        return

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



######### begin of dead code

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



def is_ipaddress(to_check):
    try:
        ipaddress.ip_address(to_check)
        return True
    except Exception as err:
        return False



def load_file_into_array(filename, emptylines=True):
    if emptylines:
        return open(filename, "r", encoding='utf-8').read().splitlines()
    else:
        return filter(None, open(filename, "r", encoding='utf-8').read().splitlines())


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


