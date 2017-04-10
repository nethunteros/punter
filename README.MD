# Punter

Punter (passive hunter) helps with the first step in footprinting a domain.  The idea is not to touch the target domain but passively find a good initial amount of information and put it into an easy to view report.  It uses:

* DNS Dumpster
* Whois
* Reverse whois on email
* Haveibeenpwned lookup on emails found
* CRT.sh to find subdomains
* Crimeflare to uncover true IP's behind Cloudflare
* TODO: Shodan scans, net range from Whois

Whois and DNS lookups are still down on host, not through an API so if you are worried about that take precautions.  Otherwise, all other lookups are down using other services.

A HTML report is generated with results, just double click and open it.


## Setup

```pip install -r requirements.txt```

## Run

Change the target to domain you are interested in:

```python main.py -t google.com```

## Credits

* Everyone who built apis/websites this script scrapes form
* @jmingov for html fixes/putting up with my terrible scripts

TODO: 

* Use ping and curl API  to test if host is up 
* Enable Shodan scanning for each IP
* Grab html of site/headers using another service
