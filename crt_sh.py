import urllib
import requests
from bs4 import BeautifulSoup


def req_crtsh(search_string):

    subdomain_list = []
    base_url = "https://crt.sh/?q=%25." + search_string

    print("[+] Requesting URL %s" % base_url)

    r = requests.get(url=base_url, headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'})

    if r.ok:
        soup = BeautifulSoup(r.content, 'lxml')

        try:

            table = soup.findAll('table')[2]

            rows = table.find_all(['tr'])

            for row in rows:
                cells = row.find_all('td', limit=5)

                if cells:
                    name = cells[3].text
                    subdomain_list.append(name)

            # Remove duplicate domains from list
            subdomain_list = list(set(subdomain_list))

            remove_wildcard_list = []
            for x in subdomain_list:
                if "*." not in x:
                    remove_wildcard_list.append(x)
                else:
                    print("[!] Detected wildcard domain %s" % x)
                    print("[!] Removing from subdomain list!")

            # Debug: print all subdomains in list
            for domain in remove_wildcard_list:
                print("[+] Found SSL cert for subdomain: %s" % domain)

            return remove_wildcard_list

        except:
            print("error retriving information")

req_crtsh("digg.com")