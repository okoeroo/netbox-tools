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


def get_uuid_value(value):
    m = re.search("UUID:(.*)$", value)
    if m:
        return m.group(1)
    else:
        return None

def get_ctx():
    ctx = {}
    return ctx
