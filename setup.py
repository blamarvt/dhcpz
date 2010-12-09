from setuptools import setup

setup(
		name="dhcpz",
		version="0.1.1",
		author="Nicholas VonHollen",
		author_email="nicholas.vonhollen@rackspace.com",
		license="Apache License 2.0",
		packages=['dhcpz'],
		package_dir={"":"src/py"},
		data_files=[('/etc/init.d', ['src/init.d/dhcpz'])],
		entry_points="""
		[console_scripts]
                dhcpz=dhcpz:main
		"""
		)
