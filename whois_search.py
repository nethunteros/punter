from ipwhois import IPWhois
import whois

'''
############################################
#               WHOIS                      #
############################################
'''
def whois_target(host):

    # Technically this is still passive recon
    # because you still aren't hitting target
    w = whois.whois(host)

    return w.text, w.emails, w


def whois_ip(ip):

    # Default to not found
    cidr, ranges = "CIDR not found", "Range not found"

    # Get whois for IP. Returns a list with dictionary
    ip_dict = IPWhois(ip).lookup_rws()

    if ip_dict['nets'][0].get('cidr')
        cidr = ip_dict['nets'][0].get('cidr')

    if ip_dict['nets'][0].get('range'):
        ranges = ip_dict['nets'][0].get('range')

    return cidr, ranges