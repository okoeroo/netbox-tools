# netbox-2-dnsmasq.py

Using Netbox as source and creating DNSMasq DHCP configuration file.
Also, a PowerDNS Recursor compatible zonefile can be generated.


## DNSMasq DHCP configuration
The script will fetch all configured prefixes from Netbox.


### General DHCP settings
The dhcp lease file will be set on top of the output file. Optionally the dhcp-authoritative directive is set. The dhcp default domain can be set.


### Per prefix settings
From the prefixes, the associated VRF is retrieved and at with Site it is operating. Also the VLAN on which it is used is retrieved.

The name of the VRF and the name of the vlan will be concattenated and result into the name of the DHCP scope. The default gateway and DNS server is configured. The prefix will be configured with a DHCP range based on the `--dhcp-host-range-offset-min` and `--dhcp-host-range-offset-max` parameters, with a default lease time from the `--dhcp-default-lease-time-range` parameters.

#### Default gateway selection
Based on the VRF assessed, the first IP address with the tag `net_default_gateway` will be selected as the default gateway.

#### DNS server selection
The IP address of the default gateway will retrieved. The DNS server field associated to the IP address is retrieved and used as the DNS server.


### DHCP example output

```
dhcp-leasefile=/var/cache/dnsmasq/dnsmasq-dhcp.leasefile
dhcp-authoritative
domain=koeroo.local

### Site:    Home
### Role:    Untagged
### Vlan:    Home VLAN (66) with ID: 66
### VRF:     vrf_66_homelan
### Prefix:  192.168.1.0/24

dhcp-option=vrf_66_homelan_vlan_66,3,192.168.1.254  # Default Gateway
dhcp-option=vrf_66_homelan_vlan_66,6,192.168.1.1  # Default DNS
dhcp-range=vrf_66_homelan_vlan_66,192.168.1.100,192.168.1.199,255.255.255.0,600m

dhcp-host=vrf_66_homelan_vlan_66,B8:27:EB:F8:82:6C,kpnpibox_eth0,192.168.1.1,90m
dhcp-host=vrf_66_homelan_vlan_66,52:54:00:3B:9C:5B,unifi_eth0,192.168.1.3,90m
dhcp-host=vrf_66_homelan_vlan_66,80:EE:73:B9:B0:74,mainport_mainbridge,192.168.1.4,90m
```

## PowerDNS Zonefile configuration
A PowerDNS (recursor) compatible zonefile is generated from Netbox. A zonefile headers can be used to add the SOA record and a footer file to add addition custom records. These a prepanded or appended.

### Netbox mapping scheme
All IP address prefixes are fetched. Currently only IPv4 address are fetched. All IP addresses are fetched and associated VRFs. Each IP address will be linked through an A record with a name set to the `hostname + interface_name` combination, for example `captain_marvel_wlan0`.

In addition, the associated device record is retrieved. The IP address which is currently in processing is matched against the `primary_ip` value. If this is a match, an additional CNAME will be created to link the `hostname` of the device with the `hostname + interface_name` as canonical name value.


#### HACKS
1. All IP address prefixes are fetched. Currently only IPv4 address are fetched.
2. Only the Site name with the slug 'home' is retrieved.



### Zonfile snippet
```
@ 86400 IN NS ns
acer_tablet_lieke 86400 IN CNAME acer_tablet_lieke_wlan0
acer_tablet_lieke_wlan0 86400 IN A 192.168.1.67
apps 86400 IN CNAME apps_eth0
apps_eth0 86400 IN A 192.168.1.28
bitcoin 86400 IN CNAME bitcoin_eth0
bitcoin_eth0 86400 IN A 192.168.1.16
c200 86400 IN CNAME c200_eth0
c200_eth0 86400 IN A 192.168.1.46
captain_marvel 86400 IN CNAME captain_marvel_wlan0
```

### Zonefile header example
```
$ORIGIN koeroo.local.           ; start of namespace
$TTL 86400	                ; 1 day

@                   IN  SOA     ns.koeroo.local.    hostmaster.koeroo.local.    (
                        7       ; serial
                        43200   ; refresh
                        180     ; retry
                        1209600 ; expire
                        10800   ; minimum
                    )

; NS Records
@                   IN    NS          ns.koeroo.local.
```

### Zonefile footer example
```
; Footer

router                          CNAME   kpnpibox.koeroo.local.
ns                              CNAME   router.koeroo.local.
deadpool                        CNAME   deadpool_lan1.koeroo.local.
;                                CNAME   deadpool_lan2.koeroo.local.
samba                           CNAME   deadpool.koeroo.local.

qr                              CNAME   apps.koeroo.local.
tlsa                            CNAME   apps.koeroo.local.

experiabox_v10                  A       192.168.2.254
mail_bastion_ovh                A       10.8.0.200

phpipam                         A       192.168.203.10
netbox                          A       192.168.203.11
cloud                           CNAME   owncloud.koeroo.local.
```

## Usage
```
usage: netbox-2-dnsmasq.py [-h] [-v] [-k AUTHKEY]
                           [-do DNSMASQ_DHCP_OUTPUT_FILE]
                           [-bu NETBOX_BASE_URL]
                           [-ltr DHCP_DEFAULT_LEASE_TIME_RANGE]
                           [-lth DHCP_DEFAULT_LEASE_TIME_HOST]
                           [-min DHCP_HOST_RANGE_OFFSET_MIN]
                           [-max DHCP_HOST_RANGE_OFFSET_MAX]
                           [-lf DHCP_LEASE_FILE] [-da]
                           [-ddd DHCP_DEFAULT_DOMAIN] [-z ZONEFILE] [-rl]
                           [-e ZONEHEADER] [-f ZONEFOOTER]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode. Default is off
  -k AUTHKEY, --authkey AUTHKEY
                        Netbox authentication key.
  -do DNSMASQ_DHCP_OUTPUT_FILE, --dnsmasq-dhcp-output-file DNSMASQ_DHCP_OUTPUT_FILE
                        DNSMasq format DHCP output file based on Netbox info.
  -bu NETBOX_BASE_URL, --base-url NETBOX_BASE_URL
                        Netbox base URL.
  -ltr DHCP_DEFAULT_LEASE_TIME_RANGE, --dhcp-default-lease-time-range DHCP_DEFAULT_LEASE_TIME_RANGE
                        DHCP Default Lease Time for a DHCP range.
  -lth DHCP_DEFAULT_LEASE_TIME_HOST, --dhcp-default-lease-time-host DHCP_DEFAULT_LEASE_TIME_HOST
                        DHCP Default Lease Time for a fixed DCHP host.
  -min DHCP_HOST_RANGE_OFFSET_MIN, --dhcp-host-range-offset-min DHCP_HOST_RANGE_OFFSET_MIN
                        DHCP Host range offset minimum.
  -max DHCP_HOST_RANGE_OFFSET_MAX, --dhcp-host-range-offset-max DHCP_HOST_RANGE_OFFSET_MAX
                        DHCP Host range offset maximum.
  -lf DHCP_LEASE_FILE, --dhcp-lease-file DHCP_LEASE_FILE
                        DHCP Lease file.
  -da, --dhcp-authoritive
                        Set DHCP Authoritive flag
  -ddd DHCP_DEFAULT_DOMAIN, --dhcp-default-domain DHCP_DEFAULT_DOMAIN
                        DHCP Default Domain.
  -z ZONEFILE, --zonefile ZONEFILE
                        Zonefile format to be consumed by Bind or PowerDNS.
  -rl, --relativize     Create relativized names in the zonefile
  -e ZONEHEADER, --zoneheader ZONEHEADER
                        Zonefile header template.
  -f ZONEFOOTER, --zonefooter ZONEFOOTER
                        Zonefile footer template.
```
