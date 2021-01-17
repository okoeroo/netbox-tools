#!/usr/bin/env python3


class DNSMasq_DHCP_Generic_Switchable:
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __str__(self):
        if self.value is None:
            return self.name
        elif self.value is not None:
            return self.name + "=" + self.value


class DNSMasq_DHCP_Option:
    def __init__(self, option, value):
        scope = None
        self.option = option
        self.value = value

    def __init__(self, scope, option, value):
        self.scope = scope
        self.option = option
        self.value = value

    def get_scope(self):
        return self.scope

    def get_option(self):
        return self.option

    def get_value(self):
        return self.value

    def get_comment(self):
        if self.get_option() == "3":
            return "# Default Gateway"
        elif self.get_option() == "6":
            return "# Default DNS"
        elif self.get_option() == "42":
            return "# Default NTP"
        else:
            return ""

    def __add__(self, o):
        return self.get_str() + o

    def __str__(self):
        return self.get_str()

    def get_str(self):
        res = []

        if self.get_scope() is not None:
            res.append(str(self.get_scope()))

        res.append(str(self.get_option()))
        res.append(str(self.get_value()))

        return "dhcp-option=" + \
                ",".join(res) + \
                "  " + \
                str(self.get_comment())


class DNSMasq_DHCP_Range:
    def __init__(self, range_min, range_max, netmask, lease_time):
        scope = None
        self.range_min = range_min
        self.range_max = range_max
        self.netmask = netmask
        self.lease_time = lease_time

    def __init__(self, scope, range_min, range_max, netmask, lease_time):
        self.scope = scope
        self.range_min = range_min
        self.range_max = range_max
        self.netmask = netmask
        self.lease_time = lease_time

    def get_scope(self):
        return self.scope

    def get_range_min(self):
        return self.range_min

    def get_range_max(self):
        return self.range_max

    def get_netmask(self):
        return self.netmask

    def get_lease_time(self):
        return self.lease_time

    def __add__(self, o):
        return self.get_str() + o

    def __str__(self):
        return self.get_str()

    def get_str(self):
        res = []

        if self.get_scope() is not None:
            res.append(str(self.get_scope()))

        res.append(str(self.get_range_min()))
        res.append(str(self.get_range_max()))
        res.append(str(self.get_netmask()))
        res.append(str(self.get_lease_time()))

        return "dhcp-range=" + \
                ",".join(res)


class DNSMasq_DHCP_Host:
    def __init__(self, mac_address, hostname, ip_address, lease_time):
        scope = None
        self.mac_address = mac_address
        self.hostname = hostname
        self.ip_address = ip_address
        self.lease_time = lease_time

    def __init__(self, scope, mac_address, hostname, ip_address, lease_time):
        self.scope = scope
        self.mac_address = mac_address
        self.hostname = hostname
        self.ip_address = ip_address
        self.lease_time = lease_time

    def get_scope(self):
        return self.scope

    def get_mac_address(self):
        return self.mac_address

    def get_hostname(self):
        return self.hostname

    def get_ip_address(self):
        return self.ip_address

    def get_lease_time(self):
        return self.lease_time

    def __add__(self, o):
        return self.get_str() + o

    def __str__(self):
        return self.get_str()

    def get_str(self):
        res = []

        if self.get_scope() is not None:
            res.append(str(self.get_scope()))

        res.append(str(self.get_mac_address()))
        res.append(str(self.get_hostname()))
        res.append(str(self.get_ip_address()))
        res.append(str(self.get_lease_time()))

        return "dhcp-host=" + \
                ",".join(res)


class DNSMasq_DHCP_Section:
    def __init__(self):
        self.site = None
        self.role = None
        self.vlan_id = None
        self.vlan_name = None
        self.vrf_name = None
        self.prefix = None

        self.dhcp_options = []
        self.dhcp_ranges = []
        self.dhcp_hosts = []

    def set_site(self, site):
        self.site = site

    def set_role(self, role):
        self.role = role

    def set_vlan_id(self, vlan_id):
        self.vlan_id = vlan_id

    def set_vlan_name(self, vlan_name):
        self.vlan_name = vlan_name

    def set_vrf_name(self, vrf_name):
        self.vrf_name = vrf_name

    def set_prefix(self, prefix):
        self.prefix = prefix

    def append_dhcp_option(self, dhcp_option):
        self.dhcp_options.append(dhcp_option)

    def append_dhcp_range(self, dhcp_range):
        self.dhcp_ranges.append(dhcp_range)

    def append_dhcp_host(self, dhcp_host):
        self.dhcp_hosts.append(dhcp_host)


    def get_header(self):
        # Example
        ### Site:    Home
        ### Role:    Untagged
        ### Vlan:    66 (Home VLAN) with ID: 66
        ### VRF:     vrf_66_homelan
        ### Prefix:  192.168.1.0/24

        res = []

        if self.site is not None:
            res.append("### Site:    " + self.site)

        if self.role is not None:
            res.append("### Role:    " + self.role)

        if self.vlan_id is not None and self.vlan_name is not None:
            res.append("### Vlan:    " + self.vlan_name + " with ID: " + str(self.vlan_id))
        elif self.vlan_id is not None:
            res.append("### Vlan ID: " + str(self.vlan_id))
        elif self.vlan_name is not None:
            res.append("### Vlan:    " + self.vlan_name)

        if self.vrf_name is not None:
            res.append("### VRF:     " + self.vrf_name)

        if self.prefix is not None:
            res.append("### Prefix:  " + self.prefix)

        return "\n".join(res)

    def get_options(self):
        return self.dhcp_options

    def get_ranges(self):
        return self.dhcp_ranges

    def get_hosts(self):
        return self.dhcp_hosts


class DNSMasq_DHCP_Config:
    def __init__(self):
        self.dhcp_config_generic_switches = []
        self.dhcp_config_sections = []

    def append_to_dhcp_config_generic_switches(self, obj):
        self.dhcp_config_generic_switches.append(obj)

    def append_to_dhcp_config_sections(self, obj):
        self.dhcp_config_sections.append(obj)

    def print(self):
        print(self)

    def __str__(self):
        res = []

        for sw in self.dhcp_config_generic_switches:
            res.append(str(sw))

        for sec in self.dhcp_config_sections:
            res.append(str(""))
            res.append(str(""))
            res.append(str(sec.get_header()))

            res.append(str(""))
            for opts in sec.get_options():
                res.append(str(opts))

            res.append(str(""))
            for ran in sec.get_ranges():
                res.append(str(ran))

            res.append(str(""))
            for host in sec.get_hosts():
                res.append(str(host))

        return "\n".join(res)


