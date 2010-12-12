#!/usr/bin/python

from setuptools import setup

setup(
    name             = "dhcpz",
    version          = "0.2.0",
    author           = [
        "Nicholas VonHollen", 
        "Brian Lamar"
    ],
    author_email     = [
        "nicholas.vonhollen@rackspace.com",
        "brian.lamar@rackspace.com",
    ],
    license          = "Apache License 2.0",
    packages         = ['dhcpz', 'dhcpz.handlers'],
    package_dir      = {"":"src/py"},
    install_requires = ['gevent', 'netifaces'],
    data_files       = [
        ('/etc/init.d', ['src/init.d/dhcpz']),
        ('/usr/bin', ['src/bin/dhcpz'])
    ],
)
