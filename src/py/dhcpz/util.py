#!/usr/bin/python
"""
dhcpz.util
"""

import string
import netifaces

def _ip_config_init():
    """
    Helper for network_config()
    """
    _ip_config = {}
    for iface_name in netifaces.interfaces():
        iface = netifaces.ifaddresses(iface_name)
        if netifaces.AF_INET not in iface:
            continue
        for ip_config in iface[netifaces.AF_INET]:
            ip_config_addr = ip_config['addr']
            _ip_config[ip_config_addr] = iface_name, ip_config
    return _ip_config

def network_config(include_local=False):
    """
    Return network configuration information for the local machine.

    @todo: Cache?
    """
    config = _ip_config_init()
    
    if not include_local:
        return dict((key,value) for key, value in config.iteritems() if not key.startswith("127."))
    else:
        return config

def to_list(_input):
    return map(string.strip, _input.split(","))



