#!/usr/bin/env python3

import sys
import ipaddress

from netboxers import netboxers_cli
from netboxers import netboxers_helpers
from netboxers import netboxers_queries
from netboxers.models.dnsmasq_dhcp import *
from netboxers.models.dns_zonefile import *



# This function will create a DNSMasq formatted DHCP config file from Netbox
## Create DNSMasq DHCP config file by:
## 1. Fetching defaults
## 2. Fetching VRFs, and VRF info.
## 3. Fetch associated default gateway and DNS config
## 4. Fetch (virtual) hosts and its data (IP and MAC)

def netbox_to_dnsmasq_dhcp_config(ctx):
    # Create DNSMasq DHCP config
    dnsmasq_dhcp_config = DNSMasq_DHCP_Config()

    # Fetch header info
    dnsmasq_dhcp_config.append_to_dhcp_config_generic_switches(
            DNSMasq_DHCP_Generic_Switchable("dhcp-leasefile", ctx['dhcp_lease_file']))

    if ctx['dhcp_authoritive']:
        dnsmasq_dhcp_config.append_to_dhcp_config_generic_switches(
                DNSMasq_DHCP_Generic_Switchable("dhcp-authoritative", None))

    dnsmasq_dhcp_config.append_to_dhcp_config_generic_switches(
            DNSMasq_DHCP_Generic_Switchable("domain", ctx['dhcp_default_domain']))


    # Get prefixes
    prefixes = netboxers_helpers.query_netbox(ctx, "ipam/prefixes/")

    if prefixes['count'] == 0:
        print("No prefixes found to complete")

    for prefix_obj in prefixes['results']:
        dnsmasq_dhcp_section = DNSMasq_DHCP_Section()

        # Skip non-IPv4
        if prefix_obj['is_pool'] != True:
            continue

        # Only Active Prefixes
        if prefix_obj['status']['value'] != 'active':
            print("Prefix {} not active, skipping.".format(prefix_obj['prefix']))
            continue


        # Record the DNSMasq_DHCP_Section info
        if prefix_obj['site'] is not None:
            dnsmasq_dhcp_section.set_site(prefix_obj['site']['name'])
        if prefix_obj['role'] is not None:
            dnsmasq_dhcp_section.set_role(prefix_obj['role']['name'])
        if prefix_obj['vlan'] is not None:
            dnsmasq_dhcp_section.set_vlan_id(prefix_obj['vlan']['vid'])
            dnsmasq_dhcp_section.set_vlan_name(prefix_obj['vlan']['display_name'])
        if prefix_obj['vrf'] is not None:
            dnsmasq_dhcp_section.set_vrf_name(prefix_obj['vrf']['name'])
        if prefix_obj['prefix'] is not None:
            dnsmasq_dhcp_section.set_prefix(prefix_obj['prefix'])


        # Get default gateway from the VRF based on a tag
        default_gateway_ip_addr_obj = netboxers_queries.get_net_default_gateway_from_vrf(ctx, prefix_obj['vrf']['id'])
        if default_gateway_ip_addr_obj is not None:
            default_gateway_ip_addr = \
                ipaddress.ip_address(default_gateway_ip_addr_obj['address'].split("/")[0])

            # Write default gateway
            if default_gateway_ip_addr is not None:
                # Record the default gateway
                dnsmasq_dhcp_section.append_dhcp_option(
                        DNSMasq_DHCP_Option(
                            netboxers_queries.get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                            "3", default_gateway_ip_addr))


                # Get DNS from the default gateway record
                default_dnsname_ip_addr = netboxers_queries.get_dns_host_from_ip_address(ctx, \
                    default_gateway_ip_addr_obj)

                # Write DNS server
                if default_dnsname_ip_addr is not None:
                    # Record the default gateway
                    ## Recording scope, option and value
                    dnsmasq_dhcp_section.append_dhcp_option(
                            DNSMasq_DHCP_Option(
                                netboxers_queries.get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                                "6", default_dnsname_ip_addr))

            # Write default NTP server
            if 'dhcp_default_ntp_server' in ctx and ctx['dhcp_default_ntp_server'] is not None:
                dnsmasq_dhcp_section.append_dhcp_option(
                        DNSMasq_DHCP_Option(
                            netboxers_queries.get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                            "42", ctx['dhcp_default_ntp_server']))

        # Print dhcp-range
        ip_network = ipaddress.ip_network(prefix_obj['prefix'])

        # Record the DHCP range
        dnsmasq_dhcp_section.append_dhcp_range(
                DNSMasq_DHCP_Range(
                    netboxers_queries.get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                    ip_network.network_address + ctx['dhcp_host_range_offset_min'],
                    ip_network.network_address + ctx['dhcp_host_range_offset_max'],
                    ip_network.netmask,
                    ctx['dhcp_default_lease_time_range']))


        # Query all IP addresses in the VRF. From each, fetch the associated interface and its MAC
        # Extract all IP addresses in the VRF
        dhcp_host_tuples = netboxers_queries.get_dhcp_host_dict_from_vrf(ctx, prefix_obj['vrf']['id'])

        for tup in dhcp_host_tuples:
            # TODO
            # When Device is set to Offline, skip it
            if tup['ip_addr_obj']['status']['value'] == 'offline':
                print("Device {} with MAC {} and IP address {} is Offline, skipping".format(
                                    tup['host_iface'],
                                    tup['mac_address'],
                                    tup['ip_addr']))
                continue

            # Record the DHCP host
            dnsmasq_dhcp_section.append_dhcp_host(
                    DNSMasq_DHCP_Host(
                        netboxers_queries.get_vrf_vlan_name_from_prefix_obj(prefix_obj),
                        tup['mac_address'], tup['host_iface'],
                        tup['ip_addr'], ctx['dhcp_default_lease_time_host']))

        # Record section to config
        dnsmasq_dhcp_config.append_to_dhcp_config_sections(dnsmasq_dhcp_section)


    # Truncate and open file cleanly
    netboxers_helpers.write_to_ddo_fh(ctx, None)

    ## Output DNSMasq Config to file
    netboxers_helpers.write_to_ddo_fh(ctx, str(dnsmasq_dhcp_config))


def powerdns_recursor_zonefile(ctx):
    zo = DNS_Zonefile()

    rr = DNS_Resource_Record(
            rr_type = 'SOA',
            rr_name = ctx['dhcp_default_domain'],
            soa_mname = 'ns.' + ctx['dhcp_default_domain'],
            soa_rname = 'hostmaster.' + ctx['dhcp_default_domain'],
            soa_serial = 7,
            soa_refresh = 86400,
            soa_retry = 7200,
            soa_expire = 3600000,
            soa_minimum_ttl = 1800)
    zo.add_rr(rr)


    rr = DNS_Resource_Record(
            rr_type = 'NS',
            rr_name = '@',
            rr_data = 'ns.' + ctx['dhcp_default_domain'])
    zo.add_rr(rr)


    # Query for prefixes and ranges
    q = netboxers_helpers.query_netbox(ctx, "ipam/prefixes/")

    for prefix_obj in q['results']:

        # Skip non-IPv4
        if prefix_obj['family']['value'] != 4:
            continue

        # TODO
        # Only focus on Home
        if prefix_obj['site']['slug'] != 'home':
            continue

        # Query all IP addresses in the VRF. From each, fetch the associated interface and its MAC
        # Extract all IP addresses in the VRF
        ip_addrs_in_vrf = netboxers_queries.get_dhcp_host_dict_from_vrf(ctx, prefix_obj['vrf']['id'])

        # Run through the tupples
        for tupple in ip_addrs_in_vrf:

            # TODO
            # When Device is set to Offline, skip it
            if tupple['ip_addr_obj']['status']['value'] == 'offline':
                print("Device {} with MAC {} and IP address {} is Offline, skipping".format(
                                    tupple['host_iface'],
                                    tupple['mac_address'],
                                    tupple['ip_addr']))
                continue

            # Add the A record for each interface
            rr = DNS_Resource_Record(
                    rr_type = 'A',
                    rr_name = tupple['interface_name'] + "." + tupple['hostname'],
                    rr_data = tupple['ip_addr'])
            zo.add_rr(rr)


            # Check if a mac_address is available
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

                    # Add CNAME towards primary ip_address holding interface
                    rr = DNS_Resource_Record(
                            rr_type = 'CNAME',
                            rr_name = tupple['hostname'],
                            rr_data = tupple['interface_name'] + "." + tupple['hostname'] + \
                                          "." + \
                                          ctx['dhcp_default_domain'])
                    zo.add_rr(rr)


    # Inject footer file
    if 'zonefooter' in ctx and len(ctx['zonefooter']) > 0:
        f = open(ctx['zonefooter'], 'r')
        foot = f.read()
        f.close()

    # Write zonefile
    f = open(ctx['zonefile'], 'w')

    # Write the zonefile data to file
    f.write(str(zo))
    f.write("\n")

    # Add footer to zonefile
    if foot is not None:
        f.write(foot)

    f.close()


### WORK IN PROGRESS 192.168.x.x only
def powerdns_recursor_zoneing_reverse_lookups(ctx):
    zo = DNS_Zonefile()

    print(ctx['zonefile_in_addr'])
    ### ctx['zonefile_in_addr']

    #ipam/ip-addresses/
    zone_name = "168.192.in-addr.arpa"

    rr = DNS_Resource_Record(
            rr_type = 'SOA',
            rr_name = zone_name,
            soa_mname = 'ns.' + ctx['dhcp_default_domain'],
            soa_rname = 'hostmaster.' + ctx['dhcp_default_domain'],
            soa_serial = 7,
            soa_refresh = 86400,
            soa_retry = 7200,
            soa_expire = 3600000,
            soa_minimum_ttl = 1800)
    zo.add_rr(rr)


    rr = DNS_Resource_Record(
            rr_type = 'NS',
            rr_name = '@',
            rr_data = 'ns.' + ctx['dhcp_default_domain'])
    zo.add_rr(rr)


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


        # RFC compliant domain name
#        rfc_host_name = tupple['host_name'] + "_" + \
#                            tupple['interface_name'] + "." + \
#                            ctx['dhcp_default_domain'])
        rfc_host_name = tupple['interface_name'] + "." + \
                            tupple['host_name'] + "." + \
                            ctx['dhcp_default_domain']

        rr = DNS_Resource_Record(
                rr_type = 'PTR',
                rr_name = tupple['rev_ip_addr'],
                rr_data = rfc_host_name)
        zo.add_rr(rr)


    # Not assigned must get a special PTR record
    net_vlan66 = ipaddress.ip_network('192.168.1.0/24')
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
        if 'assigned_object' in ip_addr_obj:
            print("Interface assigned to", ip_addr_obj['address'])
            if ip_addr_obj['address'] in net_vlan66.hosts():
                print("Interface assigned to", ip_addr_obj['address'], "is part of 192.168.1.0/24")

            continue

#    net4 = ipaddress.ip_network('192.168.1.0/24')
#    for ip_addr_in_net in net4.hosts():
#
#        tupple = {}
#
#        # No interface? Skip
#        if 'assigned_object' not in ip_addr_obj:
#            print("No interface assigned to", ip_addr_obj['address'])
#            continue
#
#        res = next((i for i, item in enumerate(q['results']) if item["address"] == ip_addr_in_net), None)
#
#        if res is None:
#            ip_addr_interface = ipaddress.IPv4Interface(ip_addr_in_net)
#            rev_ip_addr = ipaddress.ip_address(ip_addr_interface.ip).reverse_pointer
#            print(rev_ip_addr)


#        # Assemble the tupple
#        rfc_host_name = tupple['interface_name'] + "." + \
#                            tupple['host_name'] + "." + \
#                            ctx['dhcp_default_domain']
#
#        ip_addr_interface = ipaddress.IPv4Interface(tupple['ip_addr'])
#        tupple['rev_ip_addr'] = ipaddress.ip_address(ip_addr_interface.ip).reverse_pointer
#
#        rr = DNS_Resource_Record(
#                rr_type = 'PTR',
#                rr_name = tupple['rev_ip_addr'],
#                rr_data = rfc_host_name)
#        zo.add_rr(rr)


    # Write zonefile
    f = open(ctx['zonefile_in_addr'], 'w')

    # Write the zonefile data to file
    f.write(str(zo))
    f.write("\n")

    f.close()


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
