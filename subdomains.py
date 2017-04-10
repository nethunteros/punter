from dnsdumpster import DNSDumpsterAPI
import socket
import binascii


'''
############################################
#               SUBDOMAINS                 #
############################################
'''
def subdomains_search(host):

    dnsdumpster_data = DNSDumpsterAPI.DNSDumpsterAPI().search(host)

    return dnsdumpster_data


'''
############################################
#      CHECK IF IP IN SUBDOMAIN            #
############################################
'''
#
# Code from:
# https://diego.assencio.com/?index=85e407d6c771ba2bc5f02b17714241e2
#
def ip_in_subnetwork(ip_address, subnetwork):
    """
    Returns True if the given IP address belongs to the
    subnetwork expressed in CIDR notation, otherwise False.
    Both parameters are strings.

    Both IPv4 addresses/subnetworks (e.g. "192.168.1.1"
    and "192.168.1.0/24") and IPv6 addresses/subnetworks (e.g.
    "2a02:a448:ddb0::" and "2a02:a448:ddb0::/44") are accepted.
    """

    (ip_integer, version1) = ip_to_integer(ip_address)
    (ip_lower, ip_upper, version2) = subnetwork_to_ip_range(subnetwork)

    if version1 != version2:
        raise ValueError("incompatible IP versions")

    return (ip_lower <= ip_integer <= ip_upper)


def ip_to_integer(ip_address):
    """
    Converts an IP address expressed as a string to its
    representation as an integer value and returns a tuple
    (ip_integer, version), with version being the IP version
    (either 4 or 6).

    Both IPv4 addresses (e.g. "192.168.1.1") and IPv6 addresses
    (e.g. "2a02:a448:ddb0::") are accepted.
    """

    # try parsing the IP address first as IPv4, then as IPv6
    for version in (socket.AF_INET, socket.AF_INET6):

        try:
            ip_hex = socket.inet_pton(version, ip_address)
            ip_integer = int(binascii.hexlify(ip_hex), 16)

            return (ip_integer, 4 if version == socket.AF_INET else 6)
        except:
            pass

    raise ValueError("invalid IP address")


def subnetwork_to_ip_range(subnetwork):
    """
    Returns a tuple (ip_lower, ip_upper, version) containing the
    integer values of the lower and upper IP addresses respectively
    in a subnetwork expressed in CIDR notation (as a string), with
    version being the subnetwork IP version (either 4 or 6).

    Both IPv4 subnetworks (e.g. "192.168.1.0/24") and IPv6
    subnetworks (e.g. "2a02:a448:ddb0::/44") are accepted.
    """

    try:
        fragments = subnetwork.split('/')
        network_prefix = fragments[0]
        netmask_len = int(fragments[1])

        # try parsing the subnetwork first as IPv4, then as IPv6
        for version in (socket.AF_INET, socket.AF_INET6):

            ip_len = 32 if version == socket.AF_INET else 128

            try:
                suffix_mask = (1 << (ip_len - netmask_len)) - 1
                netmask = ((1 << ip_len) - 1) - suffix_mask
                ip_hex = socket.inet_pton(version, network_prefix)
                ip_lower = int(binascii.hexlify(ip_hex), 16) & netmask
                ip_upper = ip_lower + suffix_mask

                return (ip_lower,
                        ip_upper,
                        4 if version == socket.AF_INET else 6)
            except:
                pass
    except:
        pass

    raise ValueError("invalid subnetwork")

'''
############################################
#            CHECK CLOUDFLARE              #
############################################
#
# https://github.com/m0rtem/CloudFail/blob/master/cloudfail.py
#
'''
def check_provider_for_cloudflare(provider):
    if "CloudFlare" not in str(provider):
        return "Not Cloudflare"
    else:
        return "Cloudflare"


def build_cloudlfare_iplist(provider, ip):
    if "CloudFlare" in str(provider):
        return ip
    else:
        return

def in_cloudlflare_ip(ip):

    # From https://www.cloudflare.com/ips-v4
    cloudflare_ranges = [
                         '103.21.244.0/22',
                         '103.22.200.0/22',
                         '103.31.4.0/22',
                         '104.16.0.0/12',
                         '108.162.192.0/18',
                         '131.0.72.0/22',
                         '141.101.64.0/18',
                         '162.158.0.0/15',
                         '172.64.0.0/13',
                         '173.245.48.0/20',
                         '188.114.96.0/20',
                         '190.93.240.0/20',
                         '197.234.240.0/22',
                         '198.41.128.0/17',
                         '199.27.128.0/21'
                         ]


    for subnet in cloudflare_ranges:
        isInNetwork = ip_in_subnetwork(ip, subnet)
        if isInNetwork:
            return True
        else:
            return False

    return
