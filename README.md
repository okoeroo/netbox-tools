# netbox-2-dhcp-dns.py

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

dhcp-host=vrf_66_homelan_vlan_66,B8:27:EB:FF:FF:FF,kpnpibox_eth0,192.168.1.1,90m
dhcp-host=vrf_66_homelan_vlan_66,52:54:00:FF:FF:FF,unifi_eth0,192.168.1.3,90m
dhcp-host=vrf_66_homelan_vlan_66,80:EE:73:FF:FF:FF,mainport_mainbridge,192.168.1.4,90m
```

## PowerDNS Zonefile configuration
A PowerDNS (recursor) compatible zonefile is generated from Netbox. A zonefile headers can be used to add the SOA record and a footer file to add addition custom records. These a prepanded or appended.

### Netbox mapping scheme
All IP address prefixes are fetched. Currently only IPv4 address are fetched. All IP addresses are fetched and associated VRFs. Each IP address will be linked through an A record with a name set to the `hostname + interface_name` combination, for example `captain_marvel_wlan0`.

In addition, the associated device record is retrieved. The IP address which is currently in processing is matched against the `primary_ip` value. If this is a match, an additional CNAME will be created to link the `hostname` of the device with the `hostname + interface_name` as canonical name value.


#### HACKS
1. All IP address prefixes are fetched. Currently only IPv4 address are fetched.
2. Only the Site name with the slug 'home' is retrieved.



### Zonefile snippet
```
@ 86400 IN NS ns
acer_tablet 86400 IN CNAME acer_tablet_wlan0
acer_tablet_wlan0 86400 IN A 192.168.1.67
apps 86400 IN CNAME apps_eth0
apps_eth0 86400 IN A 192.168.1.28
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

## Power


### Zonefile for reverse lookup
```
168.192.in-addr.arpa. 86400 IN NS ns.koeroo.local.
1.1.168.192.in-addr.arpa. 86400 IN PTR kpnpibox_eth0.koeroo.local.
10.1.168.192.in-addr.arpa. 86400 IN PTR storagevault_eth0.koeroo.local.
30.1.168.192.in-addr.arpa. 86400 IN PTR seccubus_eth0.koeroo.local.
32.1.168.192.in-addr.arpa. 86400 IN PTR syslog_eth0.koeroo.local.
33.1.168.192.in-addr.arpa. 86400 IN PTR grafana_eth0.koeroo.local.
34.1.168.192.in-addr.arpa. 86400 IN PTR sftp_eth0.koeroo.local.
36.1.168.192.in-addr.arpa. 86400 IN PTR mail_eth0.koeroo.local.
39.1.168.192.in-addr.arpa. 86400 IN PTR magicwand_eth0.koeroo.local.
4.1.168.192.in-addr.arpa. 86400 IN PTR mainport_mainbridge.koeroo.local.
5.1.168.192.in-addr.arpa. 86400 IN PTR deadpool_lan1.koeroo.local.
56.1.168.192.in-addr.arpa. 86400 IN PTR thor_wlan0.koeroo.local.
2.204.168.192.in-addr.arpa. 86400 IN PTR helper_enp10s0.koeroo.local.
99.204.168.192.in-addr.arpa. 86400 IN PTR iothost_eth0.koeroo.local.
168.192.in-addr.arpa. 86400 IN SOA ns.koeroo.local. hostmaster.koeroo.local. 7 86400 7200 3600000 1800
```



## Usage
```
usage: netbox-2-dhcp-dns.py [-h] [-v] [-k AUTHKEY]
                           [-do DNSMASQ_DHCP_OUTPUT_FILE]
                           [-bu NETBOX_BASE_URL]
                           [-ltr DHCP_DEFAULT_LEASE_TIME_RANGE]
                           [-lth DHCP_DEFAULT_LEASE_TIME_HOST]
                           [-min DHCP_HOST_RANGE_OFFSET_MIN]
                           [-max DHCP_HOST_RANGE_OFFSET_MAX]
                           [-lf DHCP_LEASE_FILE] [-da]
                           [-ddd DHCP_DEFAULT_DOMAIN] [-z ZONEFILE]
                           [-zia ZONEFILE_IN_ADDR] [-rl] [-e ZONEHEADER]
                           [-f ZONEFOOTER]

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
  -zia ZONEFILE_IN_ADDR, --zonefile-in-addr ZONEFILE_IN_ADDR
                        Zonefile format to be consumed by Bind or PowerDNS,
                        but specifically for the reverse lookups.
  -rl, --relativize     Create relativized names in the zonefile
  -e ZONEHEADER, --zoneheader ZONEHEADER
                        Zonefile header template.
  -f ZONEFOOTER, --zonefooter ZONEFOOTER
                        Zonefile footer template.
```

## Example script to mash it all up
```
echo "Running netbox-2-dhcp-dns.py"

~/netbox-tools/netbox-2-dhcp-dns.py \
    --authkey <heregoesyourkey> \
    --base-url http://netbox.koeroo.local \
    --dnsmasq-dhcp-output-file /tmp/generated-dhcp.conf \
    --dhcp-default-lease-time-range 600m \
    --dhcp-default-lease-time-host 90m \
    --dhcp-host-range-offset-min 100 \
    --dhcp-host-range-offset-max 199 \
    --dhcp-lease-file /var/cache/dnsmasq/dnsmasq-dhcp.leasefile \
    -da \
    --dhcp-default-domain koeroo.local \
    --zonefile /tmp/generated-zonefile \
    --zoneheader /home/pi/config/dns/zonefiles/templates/koeroo.local.header \
    --zonefooter /home/pi/config/dns/zonefiles/templates/koeroo.local.footer \
    --zonefile-in-addr /tmp/generated-168.192.in-addr.arpa.local

if [ $? -ne 0 ]; then
    echo "Error!"
    exit 1
fi

sudo cp \
    /tmp/generated-dhcp.conf \
    /etc/dnsmasq.d/dhcp.conf

echo "Reloading DNSMasq"
sudo systemctl restart dnsmasq

sudo cp \
    /tmp/generated-zonefile \
    /etc/powerdns/zonefiles/koeroo.local

echo "Backup running zonefile"
sudo cp -v /etc/powerdns/zonefiles/koeroo.local        /etc/powerdns/zonefiles/koeroo.local.backup
sudo cp -v /tmp/generated-zonefile                     /etc/powerdns/zonefiles/koeroo.local
     cp -v /tmp/generated-zonefile                     /home/pi/config/dns/powerdns/zonefiles/koeroo.local
sudo cp -v /tmp/generated-168.192.in-addr.arpa.local   /etc/powerdns/zonefiles/168.192.in-addr.arpa.local

### Assuming both koeroo.local and 168.192.in-addr.arpa.local are configured in
### recursor.conf to be loaded for the zone koeroo.local. and 168.192.in-addr.arpa.
echo sudo rec_control reload-zones
sudo rec_control reload-zones
```
