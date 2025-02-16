#!/usr/bin/env python

from __future__ import print_function
import sys
import yaml
import pprint
import boto3
import socket

class IpFinder:

    def __init__(self, config):
        self.config = config

    # EC2
    def get_ec2_info(self, ec2):
        instances = ec2.describe_instances(
            Filters=[{
                'Name': 'instance-state-name',
                'Values': ['running', 'stopped', 'stopping'],
            }]
        )
        for reservation in instances["Reservations"]:
            for instance in reservation["Instances"]:
                if 'PublicIpAddress' in instance:
                    finder_info.append({
                        'service': "ec2",
                        'public_ip': instance["PublicIpAddress"],
                        'resource_id': instance["InstanceId"]
                    })

    # NAT Gateway
    def get_natgateway_info(self, ec2):
        instances = ec2.describe_nat_gateways(
            Filters=[{
                'Name': 'state',
                'Values': ['available', 'pending'],
            }]
        )
        for reservation in instances["NatGateways"]:
            for address in reservation["NatGatewayAddresses"]:
                finder_info.append({
                    'service': "natgateway",
                    'public_ip': address["PublicIp"],
                    'resource_id': reservation["NatGatewayId"]
                })

    # RDS
    def get_rds_info(self, rds):
        instances = rds.describe_db_instances()
        for instance in instances["DBInstances"]:
            dns = instance['Endpoint']["Address"]
            try:
                ip_address = socket.gethostbyname(dns)
            except Exception as e:
                ip_address = "DNS resolution failed"
            resource_id = instance["DbiResourceId"] + " (" + instance["DBInstanceIdentifier"] + ")"
            if instance["PubliclyAccessible"]:
                finder_info.append({
                    'service': "rds",
                    'public_ip': ip_address,
                    'resource_id': resource_id
                })

    # Elastic IP
    def get_elastic_ip_info(self, ec2):
        addresses = ec2.describe_addresses()
        for address in addresses["Addresses"]:
            if "PublicIp" in address:
                finder_info.append({
                    'service': "elasticip",
                    'public_ip': address["PublicIp"],
                    'resource_id': address.get("AllocationId", "N/A")
                })

    # API Gateway
    def get_apigateway_info(self, apigw, region):
        apis = apigw.get_rest_apis()
        for api in apis.get("items", []):
            api_id = api["id"]
            # Construct endpoint domain assuming a regional endpoint
            domain = f"{api_id}.execute-api.{region}.amazonaws.com"
            try:
                ip = socket.gethostbyname(domain)
            except Exception as e:
                ip = "DNS resolution failed"
            finder_info.append({
                'service': "apigateway",
                'public_ip': ip,
                'resource_id': api_id
            })

    # Classic ELB
    def get_classic_elb_info(self, elb_client):
        elbs = elb_client.describe_load_balancers()
        for lb in elbs.get("LoadBalancerDescriptions", []):
            if lb.get("Scheme") == "internet-facing":
                dns = lb["DNSName"]
                try:
                    ip = socket.gethostbyname(dns)
                except Exception as e:
                    ip = "DNS resolution failed"
                finder_info.append({
                    'service': "classic-elb",
                    'public_ip': ip,
                    'resource_id': lb["LoadBalancerName"]
                })

    # ALB / ELB v2
    def get_alb_info(self, elbv2_client):
        lbs = elbv2_client.describe_load_balancers()
        for lb in lbs.get("LoadBalancers", []):
            if lb.get("Scheme") == "internet-facing":
                dns = lb["DNSName"]
                try:
                    ip = socket.gethostbyname(dns)
                except Exception as e:
                    ip = "DNS resolution failed"
                finder_info.append({
                    'service': "alb",
                    'public_ip': ip,
                    'resource_id': lb["LoadBalancerArn"]
                })

    # Redshift
    def get_redshift_info(self, redshift):
        clusters = redshift.describe_clusters()
        for cluster in clusters.get("Clusters", []):
            if cluster.get("PubliclyAccessible", False):
                dns = cluster["Endpoint"]["Address"]
                try:
                    ip = socket.gethostbyname(dns)
                except Exception as e:
                    ip = "DNS resolution failed"
                finder_info.append({
                    'service': "redshift",
                    'public_ip': ip,
                    'resource_id': cluster["ClusterIdentifier"]
                })

    # ElasticSearch
    def get_elasticsearch_info(self, es):
        domains = es.list_domain_names()
        for domain in domains.get("DomainNames", []):
            domain_name = domain["DomainName"]
            details = es.describe_elasticsearch_domain(DomainName=domain_name)
            endpoint = details["DomainStatus"].get("Endpoint")
            if endpoint:
                try:
                    ip = socket.gethostbyname(endpoint)
                except Exception as e:
                    ip = "DNS resolution failed"
                finder_info.append({
                    'service': "elasticsearch",
                    'public_ip': ip,
                    'resource_id': domain_name
                })

def _get_config_from_file(filename):
    with open(filename, "r") as stream:
        config = yaml.load(stream, Loader=yaml.SafeLoader)
    return config

def get_boto_session(profile_name, aws_region):
    return boto3.Session(profile_name=profile_name, region_name=aws_region)

def is_service_enabled(service_name):
    return service_name in aws_services_list

def _print_output(dic):
    if config_output_format == 'csv':
        s = "service_name,public_ip,resource_id\n"
        for x in dic:
            s += "{},{},{}\n".format(x["service"], x["public_ip"], x["resource_id"])
        print(s)
    else:
        for x in dic:
            print(x)

if __name__ == "__main__":
    finder_info = []
    default_aws_region = "us-east-1"
    config = _get_config_from_file(sys.argv[1])
    ipfinder = IpFinder(config)
    aws_regions_list = config.get("assertions").get("regions", [])
    aws_services_list = config.get("assertions").get("services", [])
    config_output_format = config.get("assertions").get("output_format")
    boto_session = get_boto_session(config["profile_name"], default_aws_region)

    # execute for each AWS region
    for aws_region in aws_regions_list:
        boto_session = get_boto_session(config["profile_name"], aws_region)

        # EC2
        if is_service_enabled("ec2"):
            ec2 = boto_session.client("ec2", region_name=aws_region)
            ipfinder.get_ec2_info(ec2)

        # NAT Gateway
        if is_service_enabled("natgateway"):
            ec2 = boto_session.client("ec2", region_name=aws_region)
            ipfinder.get_natgateway_info(ec2)

        # RDS
        if is_service_enabled("rds"):
            rds = boto_session.client("rds", region_name=aws_region)
            ipfinder.get_rds_info(rds)

        # Elastic IP
        if is_service_enabled("elasticip"):
            ec2 = boto_session.client("ec2", region_name=aws_region)
            ipfinder.get_elastic_ip_info(ec2)

        # API Gateway
        if is_service_enabled("apigateway"):
            apigw = boto_session.client("apigateway", region_name=aws_region)
            ipfinder.get_apigateway_info(apigw, aws_region)

        # Elastic Load Balancer (Classic and ALB)
        if is_service_enabled("elasticloadbalancer"):
            elb = boto_session.client("elb", region_name=aws_region)
            ipfinder.get_classic_elb_info(elb)
            elbv2 = boto_session.client("elbv2", region_name=aws_region)
            ipfinder.get_alb_info(elbv2)

        # Redshift
        if is_service_enabled("redshift"):
            redshift = boto_session.client("redshift", region_name=aws_region)
            ipfinder.get_redshift_info(redshift)

        # ElasticSearch
        if is_service_enabled("elasticsearch"):
            es = boto_session.client("es", region_name=aws_region)
            ipfinder.get_elasticsearch_info(es)

    _print_output(finder_info)
