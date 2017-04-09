import dns.resolver
import random
from time import sleep


def dns_query(search_term):

    try:

        my_resolver = dns.resolver.Resolver()

        # List of public DNS Servers:
        # https://www.lifewire.com/free-and-public-dns-servers-2626062
        #
        my_resolver.nameservers = ['8.8.8.8', '8.8.4.4',  # Google
                                   '209.244.0.3', '209.244.0.4',  # Verisign
                                   '64.6.64.6', '64.6.65.6',  # Level3
                                   '84.200.69.80', '84.200.70.40',  # DNS.WATCH
                                   '8.26.56.26', '8.20.247.20',  # Comodo Secure DNS
                                   '208.67.222.222', '208.67.220.220']  # Open DNS

        ip = random.choice(my_resolver.query(search_term))

        print("[+] Resolved %s to %s " % (search_term, ip))

        sleep(2)

        return ip

    except:

        print("[-] Could not resolve %s" % search_term)

        return "Not resolved"