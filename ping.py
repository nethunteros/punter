from time import sleep
import requests
import random


def ping(domain):

    ping_servers =[ "https://helloacm.com/api/ping/?host=",
                    "https://uploadbeta.com/api/ping/?host=",
                    "https://happyukgo.com/api/ping/?host=" ]

    server = random.choice(ping_servers)

    # https://helloacm.com/api/ping/?host=HelloACM.com
    base_url = server + str(domain)

    print("[+] Requesting ping from: %s" % base_url)
    r = requests.get(base_url, headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'})

    json_result = r.json()

    print('[+] Sleeping for five seconds')
    sleep(5)

    return str(json_result)