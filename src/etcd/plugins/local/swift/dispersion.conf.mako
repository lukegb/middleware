<%
    cfg = dispatcher.call_sync('service.swift.get_config')
%>\
[dispersion]
# Please create a new account solely for using dispersion tools, which is
# helpful for keep your own data clean.
auth_url = http://localhost:8080/auth/v1.0
auth_user = test:tester
auth_key = testing
# auth_version = 1.0
#
# NOTE: If you want to use keystone (auth version 2.0), then its configuration
# would look something like:
# auth_url = http://localhost:5000/v2.0/
# auth_user = tenant:user
# auth_key = password
# auth_version = 2.0
#
# endpoint_type = publicURL
# keystone_api_insecure = no
#
# swift_dir = /usr/local/etc/swift
# dispersion_coverage = 1.0
# retries = 5
# concurrency = 25
# container_populate = yes
# object_populate = yes
# container_report = yes
# object_report = yes
# dump_json = no
