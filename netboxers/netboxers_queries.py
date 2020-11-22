#!/usr/bin/env python3

import sys
import ipaddress

from netboxers import netboxers_helpers


# Default gateway from the VRF
def get_net_default_gateway_from_vrf(ctx, vrf_id):

    # Extract net_default_gateway from the VRF
    parameters = {}
    parameters['vrf_id'] = vrf_id
    parameters['tag']    = 'net_default_gateway'
    q_ip_addrs = netboxers_helpers.query_netbox(ctx, "ipam/ip-addresses/", parameters)

    if q_ip_addrs['count'] == 0:
        netboxers_helpers.write_to_ddo_fh(ctx, "# No default gateway available")
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
    interface_obj = netboxers_helpers.query_netbox(ctx, ip_addr_obj['assigned_object']['url'])
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
        netboxers_helpers.pp(ip_addr_obj)
        sys.exit(1)


def get_interface_name_from_ipaddresses_obj(ip_addr_obj):
    if 'assigned_object' not in ip_addr_obj:
        return "no_assigned_object"

    # Get interface name
    return ip_addr_obj['assigned_object']['name']


def get_dhcp_host_dict_from_vrf(ctx, vrf_id):
    parameters = {}
    parameters['vrf_id'] = vrf_id
    q_ip_addrs = netboxers_helpers.query_netbox(ctx, "ipam/ip-addresses/", parameters)

    if q_ip_addrs['count'] == 0:
        return None

    dhcp_hosts = []

    # VRF scoped dhcp hosts
    for ip_addr_obj in q_ip_addrs['results']:
        dhcp_hosts.append(assemble_dhcp_host_dict_from_ip_addr_obj(ctx,
                                                                   ip_addr_obj))

    return dhcp_hosts


## Based on the mac address fetch a device.
## The device can be a virtual machine or device
def fetch_devices_from_mac_address(ctx, mac_address):
    parameters = {}
    parameters['mac_address'] = mac_address

    # Device or VM?
    devices = netboxers_helpers.query_netbox(ctx, "dcim/devices/", parameters)
    if devices['count'] == 0:
        devices = netboxers_helpers.query_netbox(ctx, "virtualization/virtual-machines/", parameters)
        if devices['count'] == 0:
            # Not in Database...
            return None

    return devices


def get_vrf_vlan_name_from_prefix_obj(prefix_obj):
    return prefix_obj['vrf']['name'] + "_vlan_" + str(prefix_obj['vlan']['vid'])


def assemble_dhcp_host_dict_from_ip_addr_obj(ctx, ip_addr_obj):
    res_tup = {}

    res_tup['ip_addr'] = get_ipaddress_from_ipaddresses_obj(ip_addr_obj)
    res_tup['ip_net'] = get_network_address_from_ipaddresses_obj(ip_addr_obj)
    res_tup['mac_address'] = get_macaddress_from_ipaddresses_obj(ctx, ip_addr_obj)

    res_tup['hostname'] = get_hostname_from_ipaddresses_obj(ip_addr_obj)
    res_tup['normalized_hostname'] = netboxers_helpers.normalize_name(res_tup['hostname'])

    res_tup['interface_name'] = get_interface_name_from_ipaddresses_obj(ip_addr_obj)
    res_tup['host_iface'] = res_tup['normalized_hostname'] + "_" + res_tup['interface_name']
    res_tup['host_iface'] = res_tup['normalized_hostname'] + "_" + res_tup['interface_name']

    res_tup['ip_addr_obj'] = ip_addr_obj

    return res_tup



###### DEAD CODE BELOW

def extract_primary_ip_from_device_obj(device):

    # Extract primary IP from device or virtual machine
    if 'primary_ip' in device['results'][0] and 'address' in device['results'][0]['primary_ip']:
        plain_ip_address = device['results'][0]['primary_ip']['address'].split('/')[0]

