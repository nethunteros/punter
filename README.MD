# Punter

A quick little python script I wrote to take DNS Dumpster and WHOIS data and run a reverse whois on results.
A HTML report is generated with results, just double click and open it.

Plans are to add shodan scanning for each resolved IP using the Shodan API (see todo at bottom)

Be nice and don't spam these services.  This is just something I threw together to get snapshot of domain in one place.

## Setup

```pip install -r requirements.txt```

## Run

Change the target to domain you are interested in:

```python main.py -t google.com```

## Credits

* Everyone who built apis/websites this script scrapes form
* @jmingov for html fixes/putting up with my terrible scripts

TODO: 

* Enable Cloudflare check (see https://github.com/m0rtem/CloudFail/blob/master/cloudfail.py)
* Use Crimeflare to find real IP
* Use ping and curl API  to test if host is up 
* Enable Shodan scanning for each IP
* Grab html of site/headers using another service