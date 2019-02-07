# -*- coding: UTF-8 -*-
import ConfigParser as configparser
import argparse
import logging
import os
import os.path
import time
import re
import json

# These are for the lookups
import subdomains
import reversewhois
import whois_search
import crt_sh
import dns_resolve
import shodan_search
import crimeflaredb
import haveibeenpwned
import ping
import virustotal

now = time.strftime("-%m-%w-%y-%H-%M-%S-")

'''
############################################
#         ARGS & CONFIG OPTIONS            #
#https://gist.github.com/drmalex07/9995807 #
############################################
'''
argp = argparse.ArgumentParser()

# Required argument for target
argp.add_argument ("-t", "--target", dest='target', type=str, help="Domain to target");

# Add an optional string argument 'config'
argp.add_argument ("-c", "--config", dest='config_file', default='config.cfg', type=str, help="Set config file");

# Add a optional switch
argp.add_argument ("-d", "--down", dest='dl', action='store_true', required=False, help="Download crimeflare db");

# Parse command line
args = argp.parse_args()

if args.dl:
    crimeflaredb.dl_crimeflare()
    exit()

here = os.path.realpath('.')

if args.config_file:
    config_file = args.config_file
else:
    config_file = 'config.cfg'

logging.info('Reading configuration from %s' %(config_file))
config = configparser.ConfigParser(defaults = {'here': here})
config.read(config_file)

try:
    ping_enabled = config.getboolean('PING', 'enable_ping')
    shodan_enabled = config.getboolean('SERVICE', 'enable_shodan')
    shodan_api_key = config.get('API_KEYS', 'shodan_api_key')
    virustotal_enabled = config.getboolean('SERVICE', 'enable_virustotal')
    virustotal_api_key = config.get('API_KEYS', 'virustotal_api_key')

except:
    print('Error reading file: %s\nCheck filename or formatting of config file' % config_file)
    exit

target = args.target


#-- CRIMEFLARE DOWNLOAD/UNZIP --#
def crimedb():
    crimeflaredb.dl_crimeflare()

#-- FIX DNSDUMPSTER HTTP/HTTPS --#
# https://stackoverflow.com/a/3663505
def rchop(thestring, ending):
  if thestring.endswith(ending):
    return thestring[:-len(ending)]
  return thestring

#-- START --#
def main(target):

    # Check to see if we have a target
    if not target:
        print("[!] No target specified.  See help or other options")
        exit()
    else:
        # If we do then check to make sure its formatted correctly
        match = re.search('http:\/\/www\.', target)
        match2 = re.search('www\.', target)

        if match:
            print('[-] Remove http://www. from target for best results')
            exit()
        elif match2:
            print('[-] Remove www from subdomain')
            exit()

    if not os.path.exists('data/ipout'):
        print("[!] Missing crimeflare database!  Downloading and unzipping...")
        crimedb()
    try:

        print('''
                         ..,co88oc.oo8888cc,..
  o8o.               ..,o8889689ooo888o"88888888oooc..
.88888             .o888896888".88888888o'?888888888889ooo....
a888P          ..c6888969""..,"o888888888o.?8888888888"".ooo8888oo.
088P        ..atc88889"".,oo8o.86888888888o 88988889",o888888888888.
888t  ...coo688889"'.ooo88o88b.'86988988889 8688888'o8888896989^888o
 888888888888"..ooo888968888888  "9o688888' "888988 8888868888'o88888
  ""G8889""'ooo888888888888889 .d8o9889""'   "8688o."88888988"o888888o .
           o8888'""""""""""'   o8688"          88868. 888888.68988888"o8o.
           88888o.              "8888ooo.        '8888. 88888.8898888o"888o.
           "888888'               "888888'          '""8o"8888.8869888oo8888o .
      . :.:::::::::::.: .     . :.::::::::.: .atc. : ::.:."8888 "888888888888o
                                                        :..8888,. "88888888888.
                                                        .:o888.o8o.  "866o9888o
         ｱu刀ｲ乇尺 = ｱﾑ丂丂ﾉ√乇 んu刀ｲ乇尺                   :888.o8888.  "88."89".
                                                        . 89  888888    "88":.
            ENUMERATE THE TARGET                        :.     '8888o
                                                         .       "8888..
                                                                   888888o.
                                                                    "888889,
                                                             . : :.:::::::.: :.
        ''')


        # Lists to hold our ips
        cloudflare_ips = []
        not_cloudflare_ips = []

        print("[+] Enumerate subdomains passively")
        subdomains_dict = subdomains.subdomains_search(target)

        print("[+] Querying whois info")
        whois_text, whois_emails, whois_dict = whois_search.whois_target(target)

        print("[+] Reverse lookup domains by email then check if IP resolves")
        email_list = []

        if whois_emails:

            print("[+] Emails found in whois")

            if isinstance(whois_emails, basestring):
                whois_emails = [whois_emails]

            for email in whois_emails:

                # Add list of most popular hosting companies
                ignore_emails = ['abuse@godaddy.com', 'abusecomplaints@markmonitor.com', 'abuse@web.com', 'DNS_Admin_Mail@amilink.com',
                                 'abuse@enom.com', 'domainabuse@tucows.com', 'help@hover.com', 'customerservice@networksolutions.com']

                if email in ignore_emails:
                    print("[!] Skipping email: %s" % email)
                else:
                    print("[+] Found email: %s" % email)
                    email_list.append(reversewhois.query_rwhois(email))
        else:
            print("[!] No emails found in whois! Skipping")

        print(email_list)

    except:
        print("Error connecting=> obtaining info")
        exit()

    # Output data into something redable
    print("[+] Target: %s" % target)
    print("[+] Domain: %s" % subdomains_dict.get('domain'))
    print("[+] Name servers found in WHOIS data:")
    if whois_dict.name_servers:
        for ns in whois_dict.name_servers:
            print("[+] Name server: %s " % ns)
    else:
        print("[!] Name server not found!")
    print("[+] Get data out of dnsdumpster:")
    for x in subdomains_dict.get('dns_records').get('host'):
        print('[+] HOST (A): %s' % x)
    if subdomains_dict.get('dns_records').get('dns'):
        for x in subdomains_dict.get('dns_records').get('dns'):
            print('[+] DNS: %s' % x)
    if subdomains_dict.get('dns_records').get('txt'):
        for x in subdomains_dict.get('dns_records').get('txt'):
            print('[+] TXT: %s' % x)
    if subdomains_dict.get('dns_records').get('mx'):
        for x in subdomains_dict.get('dns_records').get('mx'):
            print('[+] MX: %s' % x)
    print("[+] Checking for ssl certs for any subdomains using crt.sh")
    crtsh_results = crt_sh.req_crtsh(target)

    # Begin HTML generator
    with open(target + now + 'report.html', 'w') as html:
        html.write('''
        <!DOCTYPE html>
        <html>
        ''')
        html.write('<head><title>Site: '+ target + now + '</title>')
        html.write('''
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="shortcut icon" type="image/png" href="assets/img/favicon.ico">
            <link rel="stylesheet" href="assets/bootstrap/css/bootstrap.css">
            <link rel="stylesheet" href="assets/css/styles.css">
        </head>

        <body>
            <div class="container">
                <header>
                    <div class="page-header">
        ''')
        # Add target to banner
        html.write('\t\t\t<h1>Site: ' + target + '</h1> Scan conducted on: ' + now + '</div>\r')
        html.write('''
                </header>
                <nav class="navbar navbar-default">
                    <div class="container-fluid">
                        <div class="navbar-header"><a class="navbar-brand navbar-link" href="#">Home </a>
                            <button class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navcol-1">
                            <span class="sr-only">Toggle navigation</span><span class="icon-bar"></span>
                            <span class="icon-bar"></span><span class="icon-bar"></span></button>
                        </div>
                        <div class="collapse navbar-collapse" id="navcol-1">
                            <ul class="nav navbar-nav">
                                <li class="active" role="presentation"><a href="#dnsdumpster">DNS DUMPSTER</a></li>
                                <li role="presentation"><a href="#whois">WHOIS </a></li>
                                <li role="presentation"><a href="#reversewhois">REVERSE WHOIS</a></li>
                                <li role="presentation"><a href="#SSL_certs">CRT.SH SSL</a></li>
                                <li role="presentation"><a href="#virus_total">Virus Total</a></li>
                                <li role="presentation"><a href="#shodan">SHODAN </a></li>
                            </ul>
                        </div>
                    </div>
                </nav>
                <hr>
                <span id="dnsdumpster">Host A Records</span>
                <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th data-sortable="true">Domain </th>
                            <th data-sortable="true">Header </th>
                            <th data-sortable="true">Country </th>
                            <th data-sortable="true">Provider </th>
                            <th data-sortable="true">Reverse DNS</th>
                            <th data-sortable="true">AS </th>
                            <th data-sortable="true">IP</th>
                            <th data-sortable="true">Cloudflare</th>
                        </tr>
                    </thead>
                    <tbody>''')

        # Fill in DNS Dumpster into table
        # A Records
        if subdomains_dict.get('dns_records').get('host'):
            for x in subdomains_dict.get('dns_records').get('host'):

                # Build list of cloudlfare IPs
                cloudflare_host_records = subdomains.build_cloudlfare_iplist(x.get('provider'), x.get('ip'))
                if cloudflare_host_records:
                    cloudflare_ips.append(cloudflare_host_records)
                else:
                    not_cloudflare_ips.append(x.get('ip'))

                domain_dumpster = rchop(x.get('domain'), 'HTTPS:')
                domain_dumpster = rchop(domain_dumpster, 'HTTP:')
                header_dumpster = rchop(x.get('header'), 'HTTPS:')
                header_dumpster = rchop(header_dumpster, 'HTTP:')

                html.write('\t\t\t<tr>')
                html.write('\t\t\t<td>' + domain_dumpster + '</td>\r')
                html.write('\t\t\t<td>' + header_dumpster + '</td>\r')
                html.write('\t\t\t<td>' + x.get('country') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('provider') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('reverse_dns') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('as') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('ip') + '</td>\r')
                html.write('\t\t\t<td>' + subdomains.check_provider_for_cloudflare(x.get('provider')) + '</td>\r')
                html.write('\t\t\t</tr>\r')
        else:
                html.write('\t\t\t<tr>No data found</tr>')
        html.write(''' </tbody>
                </table>
            </div>''')

        html.write('''<hr>
                <span>DNS Records</span>
                <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th data-sortable="true">Domain </th>
                            <th data-sortable="true">Header </th>
                            <th data-sortable="true">Country </th>
                            <th data-sortable="true">Provider </th>
                            <th data-sortable="true">Reverse DNS</th>
                            <th data-sortable="true">AS </th>
                            <th data-sortable="true">IP</th>
                            <th data-sortable="true">Cloudflare</th>
                        </tr>
                    </thead>
                    <tbody>''')

        if subdomains_dict.get('dns_records').get('dns'):
            for x in subdomains_dict.get('dns_records').get('dns'):

                # Build list of cloudlfare IPs
                cloudflare_dns_records = subdomains.build_cloudlfare_iplist(x.get('provider'), x.get('ip'))
                if cloudflare_dns_records:
                    cloudflare_ips.append(cloudflare_dns_records)
                else:
                    not_cloudflare_ips.append(x.get('ip'))

                html.write('\t\t\t<tr>')
                html.write('\t\t\t<td>' + x.get('domain') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('header') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('country') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('provider') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('reverse_dns') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('as') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('ip') + '</td>\r')
                html.write('\t\t\t<td>' + subdomains.check_provider_for_cloudflare(x.get('provider')) + '</td>\r')
                html.write('\t\t\t</tr>')
        else:
            html.write('\t\t\t<tr>No data found</tr>')

        html.write(''' </tbody>
                </table>
            </div>''')

        html.write('''<hr>
                <span>MX Records</span>
                <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th data-sortable="true">Domain </th>
                            <th data-sortable="true">Header </th>
                            <th data-sortable="true">Country </th>
                            <th data-sortable="true">Provider </th>
                            <th data-sortable="true">Reverse DNS</th>
                            <th data-sortable="true">AS </th>
                            <th data-sortable="true">IP</th>
                            <th data-sortable="true">Cloudflare</th>
                        </tr>
                    </thead>
                    <tbody>''')

        if subdomains_dict.get('dns_records').get('mx'):
            for x in subdomains_dict.get('dns_records').get('mx'):

                # Build list of cloudlfare IPs
                cloudflare_mx_records = subdomains.build_cloudlfare_iplist(x.get('provider'), x.get('ip'))
                if cloudflare_mx_records:
                    cloudflare_ips.append(cloudflare_mx_records)
                else:
                    not_cloudflare_ips.append(x.get('ip'))

                html.write('\t\t\t<tr>')
                html.write('\t\t\t<td>' + x.get('domain') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('header') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('country') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('provider') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('reverse_dns') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('as') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('ip') + '</td>\r')
                html.write('\t\t\t<td>' + subdomains.check_provider_for_cloudflare(x.get('provider')) + '</td>\r')
                html.write('\t\t\t</tr>')
        else:
            html.write('\t\t\t<tr>No data found</tr>')

        html.write(''' </tbody>
                </table>
            </div>
            <div class="row">
            <div class="col-md-6">
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th id="whois">Emails Found in WHOIS</th>
                                <th id="whois">Have I Been Pwned?</th>
                            </tr>
                        </thead>
                        <tbody>
        ''')
        if whois_emails:
            for email in whois_emails:
                pwned_email = haveibeenpwned.pwned_email_check(email)
                try:
                    html.write('\t\t\t<tr><td>' + email + '</td><td>' + pwned_email + '</td></tr>\r')
                    print("[+] Whois email %s | Pwned: %s" % (email, pwned_email))
                except:
                    html.write('\t\t\t<tr><td>Error writing whois</td></tr>\r')
                    print('Error writing whois email')
                    pass
        else:
            html.write('\t\t\t<tr><td>No emails found</td></tr>\r')

        html.write('''
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col-md-6">
            ''')
        html.write('<p><p><span>WHOIS Info:</span><p><pre>' + whois_text.encode('utf-8') + '</pre>')
        html.write('''
            </div>
        </div>
        </div>
        <div class="container">
        <hr>
        <b>
        <span id="reversewhois">Reverse WHOIS</span>
        </b>
        <p>
        <p>
        ''')

        # We have a list of dictionary.  Values in dictionary are a list. So K, V= is a list

        i = 1  # For loop (label each email)

        # Loop over list and get each dictionary item
        for emails in email_list:
            # Loop over key, value (list)
            for key in emails:
                print("[+] Emails: %s" % key)
                html.write(' <div class="panel-group" role="tablist" aria-multiselectable="true" id="mailAccordion' + str(i) + '">')
                html.write('''<div class="panel panel-default">''')
                html.write('<div class="panel-heading" role="tab" id="heading' + str(i) + '> <h4 class="panel-title">')
                html.write('<a class="collapsed" role="button" data-toggle="collapse" data-parent="#mailAccordion-' + str(i) + '" aria-expanded="true" href="#mails_mail' + str(i) +'">')
                html.write(key)
                html.write('</a></h4></div><div class="panel-collapse" id="mails_mail' + str(i) + '" role="tabpanel">')
                html.write('''
                    <div class="panel-body"><span> </span>
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Domain</th>
                                        <th>Resolved IP</th
                                    </tr>
                                </thead>
                                <tbody>
                ''')

                # Add 1 to i for each loop
                i += 1

                # For each value add a cell
                for domains in emails.itervalues():
                    for v in domains:
                        email_domain_resolve = dns_resolve.dns_query(v)
                        print("[+] Domain associated with email %s: %s | IP: %s"
                              % (key, v, str(email_domain_resolve)))
                        html.write('<tr><td>' + v + '</td>')
                        html.write('<td>' + str(email_domain_resolve) + '<td></tr>')

                html.write('''
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            ''')
        html.write('''
        <p>
        <hr>
        <p>
        <p>
        <div class="container"><span id="SSL_certs"><strong>SSL Certs from CRT.SH</strong></span>
        <p>
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Subdomain </th>
                            <th>IP</th>
                            <th>Cloudflare</th>
                        </tr>
                    </thead>
                    <tbody>''')
        if crtsh_results:
            print("[+] CRT SH Results:")
            for subdomain in crtsh_results:
                resolved_ip = str(dns_resolve.dns_query(subdomain))

                # Holy double negative! (aka If this IP resolved then check from cloudlflare)
                if not "Not resolved" in resolved_ip:
                    check_resolved_ip = subdomains.in_cloudlflare_ip(resolved_ip)
                    if check_resolved_ip:
                        resolved_ip_cloudflare = "Cloudflare enabled"
                        cloudflare_ips.append(resolved_ip)
                    else:
                        resolved_ip_cloudflare = "Not cloudflare"
                        not_cloudflare_ips.append(resolved_ip)
                else:
                    resolved_ip_cloudflare = "Not resolved"

                html.write('<tr><td>' + str(subdomain) + '</td><td>' + resolved_ip + '</td><td>'+ resolved_ip_cloudflare + '</td></tr>' )
                print("[+] Subdomain: %s | Resolved IP: %s | Cloudflare: %s" % (str(subdomain), resolved_ip, resolved_ip_cloudflare))
        else:
            html.write('<tr><td>No results found</td><td>No results found</td></tr>')
        html.write('''
                    </tbody>
                </table>
            </div>
        </div>
        ''')

        # If Virustotal is enabled, then query Virustotal API
        if virustotal_enabled:
            vt_results = virustotal.virustotal_api(target, virustotal_api_key)
            if vt_results:
                html.write('''
                <p>
                <hr>
                <p>
                <p>
                <div class="container"><span id="virus_total"><strong>Virustotal Subdomain</strong></span>
                <p>
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Subdomain</th>
                                </tr>
                            </thead>
                <tbody>''')
                print(json.dumps(vt_results, indent=4, separators=(',', ': ')))
                for item in vt_results:
                    vt_subdomain = item.replace('.'+target, '')
                    html.write('<tr><td>' + str(vt_subdomain) + '</td><td></tr>')
            else:
                html.write('''<tr><td>No results found</td><td>''')
        html.write('''
                    </tbody>
                </table>
            </div>
        </div>
        ''')

        # Remove duplicate IPs from both lists
        not_cloudflare_ips = list(set(not_cloudflare_ips))
        cloudflare_ips = list(set(cloudflare_ips))

        if cloudflare_ips:
            html.write('''
            <p>
            <hr>
            <p>
            <p>
            <div class="container"><span id="crimeflare"><strong>Crimeflare</strong></span>
            <p>
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Cloudflare IP </th>
                                <th>Resolved IP (Crimeflare)</th>
                            </tr>
                        </thead>
                        <tbody>''')
            crime_ip = subdomains.crimeflare(target)
            if crime_ip:
                not_cloudflare_ips.append(crime_ip)
                print("[+] Target IP: %s | Discovered IP: %s" % (target, crime_ip))
                html.write('<tr><td>' + target + '</td><td>'+ crime_ip + '</td></tr>')
            else:
                html.write('<tr><td>' + target + '</td><td>Unresolved IP</td></tr>')
        html.write('''
                    </tbody>
                </table>
            </div>
        </div>
        ''')
        if not_cloudflare_ips:
            html.write('''
            <p>
            <hr>
            <p>
            <p>
            <div class="container"><span id="shodan"><strong>IP Breakdown</strong></span>
            <p>
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th style="width:5%">IP </th>
                                <th style="width:30%">Ping</th>
                                <th style="width:60%">Shodan</th>
                            </tr>
                        </thead>
                        <tbody>''')
            for ip in not_cloudflare_ips:

                if ping_enabled:
                    # Get ping result
                    ping_result = ping.ping(ip)
                    try:
                        if "ttl" in ping_result:
                            host_status = "Host appears up"
                        else:
                            host_status = "Host appears down"
                    except:
                        host_status = "error with ttl"
                else:
                    ping_result = "Ping is not enabled"

                html.write('<tr><td>' + ip + '</td><td><pre>'+ ping_result +
                               '</pre></td><td>')

                # If shodan is enabled, then query shodan
                if shodan_enabled:
                    shodan_result = shodan_search.shodan_query(shodan_api_key, ip)
                    if shodan_result is not "No information":
                        try:
                            html.write("<pre>Operating System: %s\n</pre>" % shodan_result.get('os', 'n/a'))
                            for result in shodan_result['data']:
                                html.write('<pre>Port: %s\nBanner: %s\n\n</pre>' % (result['port'], result['data']) )
                        except:
                            html.write('No information')
                else:
                    print("[!] Shodan not enabled in config")
                    html.write('Shodan not enabled')
                    html.write('</td></tr>')
                    html.write('''
                                </tbody>
                            </table>
                        </div>
                    </div>
                    ''')

                    html.write('''
                    </div>
                    <section></section>
                    </div>
                    <script src="assets/js/jquery.min.js"></script>
                    <script src="assets/bootstrap/js/bootstrap.min.js"></script>
                    </body>
                    </html>''')

main(target)
