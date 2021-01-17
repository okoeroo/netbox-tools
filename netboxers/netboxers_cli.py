#!/usr/bin/env python3

import os
import argparse


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


def argparsing(ctx):
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
    parser.add_argument("-dn", "--dhcp-default-ntp-server",
                        dest='dhcp_default_ntp_server',
                        help="Default NTP server distribute via DHCP.",
                        default=None,
                        type=str)
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
    parser.add_argument("-zia", "--zonefile-in-addr",
                        dest='zonefile_in_addr',
                        help="Zonefile format to be consumed by Bind or PowerDNS, but specifically for the reverse lookups.",
                        default=None,
                        type=str)

    parser.add_argument("-rl", "--relativize",
                        dest='zonefile_relativize',
                        help="Create relativized names in the zonefile",
                        action="store_true",
                        default=True)

#    parser.add_argument("-e", "--zoneheader",           dest='zoneheader',
#                                                        help="Zonefile header template.",
#                                                        default=None,
#                                                        type=str)
    parser.add_argument("-f", "--zonefooter",           dest='zonefooter',
                                                        help="Zonefile footer template.",
                                                        default=None,
                                                        type=str)
    args = parser.parse_args()

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
    ctx['dhcp_default_ntp_server']        = args.dhcp_default_ntp_server
    ctx['zonefile']                       = args.zonefile
    ctx['zonefile_in_addr']               = args.zonefile_in_addr
    ctx['zonefile_relativize']            = args.zonefile_relativize

#    ctx['zoneheader']         = args.zoneheader
    ctx['zonefooter']         = args.zonefooter
    return ctx
