# set-up-openstack-lbaas-endpoint

This is a working proof of concept script to automatically set up an 
endpoint using OpenStack LBaaS (Load Balancing as a Service).  By 
endpoint I mean a load-balanced virtual server with a DNS entry.

The script creates the endpoint from scratch, provisioning a LBaaS pool,
a VIP port, a VIP FIP, and endpoint FIP.  It doesn't add the DNS entry 
currently but outputs what needs to be included in it.

You need to provide a JSON with endpoint details as the first command 
line argument.  That needs to look like:

```json
{
    "fqdn": "my-fqdn.example.com",
    "endpoint_port": 443,
    "endpoint_proto": "HTTPS",
    
    "real_service_ips": [
        "192.168.3.15",
        "192.168.3.10",
        "192.168.3.11"
    ],
    "real_service_port": 9200,
    "real_service_proto": "HTTP",
    
    "pool_has_standby": false,
    "pool_lb_method": "ROUND_ROBIN",
    
    "pool_subnet_cidr": "192.168.3.0/24"
}
```

Source your openstack openrc file before running this script.  You also 
need to have the OpenStack CLIs installed.

See the top of the script for info about the debug log and more about 
the script. 