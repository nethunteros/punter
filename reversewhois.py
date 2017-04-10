import requests
import socket
from bs4 import BeautifulSoup
from time import sleep


'''
Taken an modified from:
https://github.com/joekir/rwhois/blob/master/netutils.py
Removed nmap function
'''


def query_rwhois(search_terms, remove_entries=True):

    """
    Scrapes a reverse whois page for search_terms provided
    :return: dictionary of organisations and their live domains
    :rtype: dict
    """
    # Its one of the few free options for reverse whois
    base_url = "http://viewdns.info/reversewhois/?q=" + search_terms
    org_dict = dict()

    """
        Scrape the domains from the reverse whois lookup html table
    """

    print("[+] Retreiving base url: %s" % base_url)
    r = requests.get(url=base_url, headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'})

    if r.ok:
        soup = BeautifulSoup(r.content, 'html.parser')

        domain_table = soup('table')[3]
        domain_list = [row('td')[0].string for row in domain_table.findAll('tr')]
        if domain_list and domain_list[0] is not None:
            domain_list.remove("Domain Name")  # filter the header
            org_dict[search_terms] = domain_list

        """
            Next get rid of domains that are no longer dns resolvable.
            Using items() so we can delete while iterating
        """
        for org in org_dict.items():
            for domain in org[1]:
                try:
                    socket.gethostbyname_ex(domain)[2]
                except:
                    # case where there is no dns record
                    org_dict[org[0]].remove(domain)

        sleep(3)

        return org_dict