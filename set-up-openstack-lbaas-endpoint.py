#!/usr/bin/env python

# This script does end-to-end set up of an LBaaS-based endpoint (or if there is gap in what is automatable it tell the
# user what to do).  The possibility of being able to automate endpoint creation is one of the possible advantages of
# using LBaaS and is script is a proof of concept of that.  It isn't intended as production code, but production code could be based on it.

# The input to the script is a simple JSON file (first command line argument) containing details of the endpoint setup.
# Example JSON:
# {
#     "fqdn": "my-fqdn.example.com",
#     "endpoint_port": 443,
#     "endpoint_proto": "HTTPS",
#
#     "real_service_ips": [
#         "192.168.3.15",
#         "192.168.3.10",
#         "192.168.3.11"
#     ],
#     "real_service_port": 9200,
#     "real_service_proto": "HTTP",
#
#     "pool_has_standby": false,
#     "pool_lb_method": "ROUND_ROBIN",
#
#     "pool_subnet_cidr": "192.168.3.0/24"
# }
# You must source your openrc file before running this.  This file can be downloaded from Horizon.
# This script uses the OpenStack CLI so that must be insalled already.
# Some output goes to stdout (including actions being taken and sharing the URLs for the endpoint that was set up).
# Some additional output gets appended to "./lbaas-endpoint-create-debug.log".
# If any errors are encountered, the script will exit without cleaning up any of its changes.


import csv
import json

import os
import subprocess
import sys
import re
from datetime import datetime


os.environ['PYTHONWARNINGS']="ignore:Unverified HTTPS request" # suppress warning from designate

# in a production script should handle different error cases and roll back changes (mb create a rollback sequence of commands as go along)
# in a production script should make put some of the above into modules/classes

debug_log_filename = 'lbaas-endpoint-create-debug.log'
debug_log = open(debug_log_filename,'a')

####################################################################
# user inputs
#

with open(sys.argv[1], "r") as user_input_fh:
    user_input = json.load(user_input_fh)

## hooks to stop skip re-creating different entities (minimizes our impact on openstack during development)
# set these to something other than None to skip the corresponding allocation
pool_id = None
vip_port_id= None
vip_fip_id= None
vip_fip_addr= None
# set this to True to skip the adding of members to a pool
skip_member_addition = False

####################################################################

def run_command(cmd):
    msg="[{}] running '{}'".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"),cmd)
    print "  "+msg
    debug_log.write(msg+"\n")
    cmd_stdout = subprocess.check_output(cmd, universal_newlines=True, shell=True) # will throw CalledProcessError if get non-zero exit code
    return cmd_stdout

def run_neutron_command(subcommand, args_str):
    cmd = 'neutron ' + subcommand + ' ' + args_str
    cmd_stdout = run_command(cmd)
    debug_log.write("output from " + subcommand + ":\n" + cmd_stdout + "\n")
    return cmd_stdout

def run_designate_command(subcommand, args_str):
    cmd = 'designate ' + subcommand + ' ' + args_str
    cmd_stdout = run_command(cmd)
    debug_log.write("output from " + subcommand + ":\n" + cmd_stdout + "\n")
    return cmd_stdout

def shell_output_format_to_dict(text):
    dict = {}
    line_parser = re.compile(r'(?P<field>\w+)="?(?P<value>.*?)"?\n')
    for match in line_parser.finditer(text):
        dict[match.group('field')] = match.group('value')
    # note that we ignore lines that don't match the pattern
    return dict

def csv_output_format_to_dict_list(text):
    return list(csv.DictReader(text.split("\n")))

def run_designate_command_into_dict_list(subcommand, args_str):
    cmd_stdout = run_designate_command(subcommand, ' -f csv ' + args_str)

    list = csv_output_format_to_dict_list(cmd_stdout)
    return list

def lookup_subnet_id_for_cidr(sought_cidr):
    cmd_stdout = run_neutron_command('subnet-list', '-f csv -c id -c cidr --quote none --cidr \'{}\''.format(sought_cidr))
    subnets = csv.DictReader(cmd_stdout.split("\n")) # read the command stdout as CSV into sequence of dicts
    # due to some bug, we can get results out that don't match the requested CIDR

    for subnet in subnets:
        if subnet['cidr'] == sought_cidr: # filter down to just the requested CIDR
            return subnet['id']
    return None

def do_neutron_create(subcommand, args_str):
    cmd_stdout = run_neutron_command(subcommand, ' -f shell ' + args_str)

    created_obj = shell_output_format_to_dict(cmd_stdout)
    return created_obj


def create_lbaas_pool(pool_name, pool_desc, subnet_id, proto, lb_method):
    args_str = '--subnet-id {} ' \
               '--lb-method \'{}\' ' \
               '--protocol {} ' \
               '--name {} ' \
               '--description \'{}\'' \
        .format(subnet_id, lb_method, proto, pool_name, pool_desc)

    pool = do_neutron_create('lb-pool-create', args_str)
    return pool

def add_member_to_lbaas_pool(pool_id, member_ip, member_port, member_weight):
    args_str = '--address {} ' \
               '--protocol-port {} ' \
               '--weight {} ' \
               '{}'\
        .format(member_ip, member_port, member_weight, pool_id)

    member = do_neutron_create('lb-member-create', args_str)
    return member

def create_fip(network_name):
    args_str = '\'' + network_name + '\''
    fip = do_neutron_create('floatingip-create', args_str)
    return fip

def create_fip_for_corp_access():
    return create_fip("fips-prod")

def associate_fip(fip_id, port_id):
    return run_neutron_command('floatingip-associate', '{} {}'.format(fip_id, port_id))

def create_lbaas_vip(vip_name, vip_desc, vip_port, pool_id, proto, subnet_id):
    args_str = '--subnet-id {} ' \
               '--protocol {} ' \
               '--protocol-port {} ' \
               '--name {} ' \
               '--description \'{}\' ' \
               '{}' \
        .format(subnet_id, proto, vip_port, vip_name, vip_desc, pool_id)

    vip = do_neutron_create('lb-vip-create', args_str)
    return vip

def get_list_of_domains():
    domains = run_designate_command_into_dict_list('domain-list', '')
    return domains

def get_domain_record_list(domain_id):
    records = run_designate_command_into_dict_list('record-list', domain_id)
    return records

def lookup_A_dns_record_for_ip(sought_ip):
    """search all DNS records in all domains for an A entry for the IP address"""
    # IP must match by exact string
    domains = get_list_of_domains()
    for domain in domains:
        records = get_domain_record_list(domain["id"])
        for record in records:
            if record["type"] == 'A' and record["data"] == sought_ip:
                return record
    return None # could not find

####################################################################
# validate input

expected_openrc_env_vars = ['OS_USERNAME', 'OS_PROJECT_DOMAIN_NAME', 'OS_PROJECT_NAME', 'OS_AUTH_URL', 'OS_PASSWORD', 'OS_REGION_NAME']
for expected_var in expected_openrc_env_vars:
    if expected_var not in os.environ:
        sys.exit("expected {} to be set in environment; source your openrc file before running this script".format(expected_var))

if user_input["endpoint_proto"] not in ['HTTPS', 'TCP']:
    sys.exit("VIP service protocol {} is not currently supported by this script".format(user_input["endpoint_proto"]))


####################################################################
# pre-compute

# protocol for LBaaS (HTTPS if real service is HTTP, otherwise TCP)
lbaas_proto = 'HTTPS' if user_input["real_service_proto"] == 'HTTP' else 'TCP'

member_weights = {}
if user_input["pool_has_standby"]:
    raise NotImplementedError("this script doesn't handle active-standby currently")
else:
    for ip in user_input["real_service_ips"]:
        member_weights[ip] = 1

endpoint_fqdn = user_input["fqdn"]
# naming and descriptions of pool and VIP (not visible to end user)
pool_name = user_input["fqdn"] + "-pool"
vip_name = user_input["fqdn"] + "-vip"
pool_desc = "The real services for " + user_input["fqdn"]
vip_desc = "The LBaaS VIP for " + user_input["fqdn"]

print "* looking up subnet ID for {}".format(user_input["pool_subnet_cidr"])
subnet_id = lookup_subnet_id_for_cidr(user_input["pool_subnet_cidr"])
if subnet_id is None:
    sys.exit("could not locate subnet for CIDR '{}' in '{}' '{}'".format(user_input["pool_subnet_cidr"], os.environ.get('OS_PROJECT_DOMAIN_NAME'), os.environ.get('OS_PROJECT_NAME')))

if user_input["endpoint_proto"] == 'HTTPS':
    endpoint_url_port_part = '' if user_input["endpoint_port"] == 443 else ':' + str(user_input["endpoint_port"])


####################################################################
print "\n* starting to create {} endpoint based on {} ({})".format(endpoint_fqdn, user_input["pool_subnet_cidr"], subnet_id)

################################
# Create pool

if pool_id is None:
    print "\n* creating {}".format(pool_name)
    pool = create_lbaas_pool(pool_name, pool_desc, subnet_id, lbaas_proto, user_input["pool_lb_method"])
    pool_id = pool["id"]


################################
# Add members
if not skip_member_addition:
    members = {}
    for member_ip in member_weights:
        print "\n* adding member {}:{} to {} with weight {}".format(member_ip, user_input["real_service_port"], pool_name, member_weights[member_ip])
        member = add_member_to_lbaas_pool(pool_id, member_ip, user_input["real_service_port"], member_weights[member_ip])
        members[member_ip] = member

################################
# Add VIP

if vip_port_id is None:
    print "\n* creating {} for {}".format(vip_name, pool_name)
    vip = create_lbaas_vip(vip_name, vip_desc, user_input["endpoint_port"], pool_id, lbaas_proto, subnet_id)
    vip_port_id = vip["port_id"]
    vip_address = vip["address"]

if user_input["endpoint_proto"] == 'HTTPS':
    endpoint_ip_url = 'https://' + vip_address + endpoint_url_port_part
    print '\n=> {} was created and should be available soon (though the SSL cert will not match for that URL)'.format(endpoint_ip_url)
elif user_input["endpoint_proto"] == 'TCP':
    print '\n=> succeeded so far, TCP port {} on {} should be available soon'.format(user_input["endpoint_port"], vip_address)

################################
# Allocate a FIP for us to associate with the VIP

if vip_fip_id is None or vip_fip_addr is None:
    print "\n* allocating a FIP to use for the VIP"
    vip_fip = create_fip_for_corp_access()
    vip_fip_id = vip_fip["id"]
    vip_fip_addr = vip_fip["floating_ip_address"]

################################
# Associate a FIP with VIP

print "\n* associating FIP {} with {}".format(vip_fip_addr, vip_name)
associate_fip(vip_fip_id, vip_port_id)

if user_input["endpoint_proto"] == 'HTTPS':
    endpoint_ip_url = 'https://' + vip_fip_addr + endpoint_url_port_part
    print '\n=> {} should be available soon (though the SSL cert will not match for that URL)'.format(endpoint_ip_url)
elif user_input["endpoint_proto"] == 'TCP':
    print '\n=> succeeded so far, TCP port {} on {} should be available soon'.format(user_input["endpoint_port"], vip_fip_addr)

################################
# get IP-based DNS entry for the VIP

print "\n* looking for IP-based DNS entry for {}".format(vip_fip_addr)
vip_fip_dns_record = lookup_A_dns_record_for_ip(vip_fip_addr)
if vip_fip_dns_record is None:
    sys.exit("could not locate DNS record for '{}'".format(vip_fip_addr))
vip_fip_ip_fqdn = vip_fip_dns_record["name"]

################################
# create a FQDN for the VIP

print "\n=> now arrange for a CName to map the fqdn to the VIP's FQDN"
print """details:
       CName Record: {}.
       Data: {}.
""".format(endpoint_fqdn, vip_fip_ip_fqdn)

# once we are able to add the DNS entry ourselves, the command might be something like:
# - designate record-create --name <endpoint-fqdn>.
#   --type CNAME --data <vip-fip-ip-fqdn>. --description
#   "<description>"
#   <domain-id>

################################
# final notices to user

if user_input["endpoint_proto"] == 'HTTPS' and user_input["real_service_proto"] == 'HTTPS':
    # real service is terminating the HTTPS connection
    print "=> you will need a CA-signed SSL key and cert with common name '{}' to install on each of your real servers; this is needed to avoid SSL cert warnings\n".format(endpoint_fqdn)

if user_input["endpoint_proto"] == 'HTTPS':
    endpoint_fqdn_url = 'https://' + endpoint_fqdn + endpoint_url_port_part
    print "=> your endpoint URL is {}, you should be able to use that after the DNS entry is added\n".format(endpoint_fqdn_url)
elif user_input["endpoint_proto"] == 'TCP':
    print "=> your endpoint is {} on {}; you should be able to access that after the DNS entry is added\n".format(user_input["endpoint_port"], endpoint_fqdn)

####################################################################

debug_log.write('==================================\n\n')
debug_log.close()