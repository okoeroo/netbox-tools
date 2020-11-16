#!/usr/bin/env python3


class DNS_Resource_Record:
    def __init__(self, **kwargs):
        self.rr_name = None
        self.rr_type = None
        self.rr_class = 'IN'
        self.rr_ttl = 86400
        self.rr_data = None

        for key, value in kwargs.items():
            # Generic
            if key == 'rr_name':
                self.rr_name = value.lower()
            elif key == 'rr_type':
                self.rr_type = value.upper()
            elif key == 'rr_class':
                self.rr_class = value.upper()
            elif key == 'rr_ttl':
                self.rr_ttl = value
            elif key == 'rr_data':
                self.rr_data = value.lower()

            # SOA
            elif key == 'soa_mname':
                self.soa_mname = self.dns_canonicalize(value).lower()
            elif key == 'soa_rname':
                # Funky e-mail: foo\.bar.example.org
                self.soa_rname = self.dns_canonicalize(value).lower()
            elif key == 'soa_serial':
                self.soa_serial = value
            elif key == 'soa_refresh':
                self.soa_refresh = value
            elif key == 'soa_retry':
                self.soa_retry = value
            elif key == 'soa_expire':
                self.soa_expire = value
            elif key == 'soa_minimum_ttl':
                self.soa_minimum_ttl = value

            # MX
            elif key == 'mx_priority':
                self.mx_priority = value
            elif key == 'mx_value':
                self.mx_data = self.dns_canonicalize(value).lower()


        # Post processing
        if self.rr_type == 'SOA':
            self.rr_name = self.dns_canonicalize(self.rr_name)
            self.rr_data = " ".join([   self.soa_mname,
                                        self.soa_rname,
                                        str(self.soa_serial),
                                        str(self.soa_refresh),
                                        str(self.soa_retry),
                                        str(self.soa_expire),
                                        str(self.soa_minimum_ttl)])
        elif self.rr_type == 'MX':
            self.rr_data = " ".join([   self.mx_priority,
                                        self.mx_data])
        elif self.rr_type == 'NS':
            self.rr_data = self.dns_canonicalize(self.rr_data)
        elif self.rr_type == 'CNAME':
            self.rr_name = self.normalize_name(self.rr_name)
            self.rr_data = self.normalize_name(self.rr_data)
            self.rr_data = self.dns_canonicalize(self.rr_data)
        elif self.rr_type == 'A':
            self.rr_name = self.normalize_name(self.rr_name)
            self.rr_data = str(self.rr_data)
        elif self.rr_type == 'PTR':
            self.rr_name = self.dns_canonicalize(self.rr_name)
            self.rr_data = self.normalize_name(self.rr_data)
            self.rr_data = self.dns_canonicalize(self.rr_data)


        # Sanity checks
        if self.rr_name is None:
            raise InputError("DNS_Resource_Record(__init__)", "No rr_name provided")
        elif self.rr_type is None:
            raise InputError("DNS_Resource_Record(__init__)", "No rr_type provided")
        elif self.rr_class is None:
            raise InputError("DNS_Resource_Record(__init__)", "No rr_class provided")
        elif self.rr_ttl is None:
            raise InputError("DNS_Resource_Record(__init__)", "No rr_ttl provided")
        elif self.rr_data is None:
            raise InputError("DNS_Resource_Record(__init__)", "No rr_data provided")

    def dns_canonicalize(self, s):
        if s == '@':
            return s

        if not s.endswith('.'):
            return s + '.'
        else:
            return s

    def normalize_name(self, name):
        return name.lower().replace(" ",
                                    "_").replace("-",
                                                 "_").replace("\"",
                                                              "").replace("\'",
                                                                          "")

    def __str__(self):
        res = []

        res.append(self.rr_name)
        res.append(str(self.rr_ttl))
        res.append(self.rr_class)
        res.append(self.rr_type)
        res.append(self.rr_data)

        return " ".join(res)

class DNS_Zonefile:
    def __init__(self):
        self.resource_records = []

    def add_rr(self, rr):
        self.resource_records.append(rr)

    def get_str(self):
        res = []
        for rr in self.resource_records:
            res.append(str(rr))

        return "\n".join(res)

    def __str__(self):
        return self.get_str()


"""
@ 86400 IN SOA ns hostmaster.koeroo.local 7 86400 7200 3600000 1800

$TTL 86400
@   IN  SOA     ns.icann.org. noc.dns.icann.org. (
        2020080302  ;Serial
        7200        ;Refresh
        3600        ;Retry
        1209600     ;Expire
        3600        ;Minimum TTL
)
"""
