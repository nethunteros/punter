# -*- coding: UTF-8 -*-
import ConfigParser as configparser
import argparse
import logging
import os
import time
import re

# These are for the lookups
import subdomains
import reversewhois
import whois_search
import crt_sh
import dns_resolve
import shodan_search

now = time.strftime("-%m-%w-%y-%H-%M-%S-")

'''
############################################
#         ARGS & CONFIG OPTIONS            #
#https://gist.github.com/drmalex07/9995807 #
############################################
'''
argp = argparse.ArgumentParser()

# Required argument for target
argp.add_argument ("-t", "--target", dest='target', type=str, required=True);

# Add an optional string argument 'config' 
argp.add_argument ("-c", "--config", dest='config_file', default='config.cfg', type=str);

# Add a optional switch (boolean optional argument)
argp.add_argument ("-v", "--verbose", dest='verbose', default=False, action='store_true',
    help='Be verbose');

# Parse command line    
args = argp.parse_args()

if args.verbose:
    logging.info('Will produce verbose output')

here = os.path.realpath('.')

if args.config_file:
    config_file = args.config_file
else:
    config_file = 'config.cfg'

logging.info('Reading configuration from %s' %(config_file))
config = configparser.ConfigParser(defaults = {'here': here})
config.read(config_file)

try:
    shodan_api_key = config.get('API_KEYS', 'shodan_api_key')

    logging.info(shodan_api_key)
except:
    print('Error reading file: %s\nCheck filename or formatting of config file' % config_file)
    exit

target = args.target

match = re.search('http:\/\/www\.', target)
match2 = re.search('www\.', target)

if match:
    print('[-] Remove http://www. from target for best results')
    exit()
elif match2:
    print('[-] Remove www from subdomain')
    exit()


#-- START --#
def main(target):

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

        print("[+] Enumerate subdomains passively")
        subdomains_dict = subdomains.subdomains_search(target)

        print("[+] Querying whois info")
        whois_text, whois_emails, whois_dict = whois_search.whois_target(target)

        print("[+] Reverse lookup domains by email then check if IP resolves")
        email_list = []
        for email in whois_emails:
            email_list.append(reversewhois.query_rwhois(email))

        print(email_list)

    except:
        print("Error connecting=> obtaining info")
        exit()

    # Output data into something redable
    print("[+] Target: %s" % target)
    print("[+] Domain: %s" % subdomains_dict.get('domain'))
    print("[+] Emails found in WHOIS data:")
    for email in whois_emails:
        print("[+] Email found: %s" % email)
    print("[+] Name servers found in WHOIS data:")
    for ns in whois_dict.name_servers:
        print("[+] Name server: %s " % ns)
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
        html.write('<title>Site: '+ target + now + '</title>')
        html.write('''
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>research</title>
            <link rel="stylesheet" href="assets/bootstrap/css/bootstrap.css">
            <link rel="stylesheet" href="assets/css/styles.css">
        </head>

        <body>
            <div class="container">
                <header>
                    <div class="page-header">
        ''')
        # Add target to banner
        html.write('\t\t\t<h1>Site: ' + target + '</h1></div>\r')
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
                        </tr>
                    </thead>
                    <tbody>''')

        # Fill in DNS Dumpster into table
        # A Records
        if subdomains_dict.get('dns_records').get('host'):
            for x in subdomains_dict.get('dns_records').get('host'):
                html.write('\t\t\t<tr>')
                html.write('\t\t\t<td>' + x.get('domain') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('header') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('country') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('provider') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('reverse_dns') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('as') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('ip') + '</td>\r')
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
                        </tr>
                    </thead>
                    <tbody>''')

        if subdomains_dict.get('dns_records').get('dns'):
            for x in subdomains_dict.get('dns_records').get('dns'):
                html.write('\t\t\t<tr>')
                html.write('\t\t\t<td>' + x.get('domain') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('header') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('country') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('provider') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('reverse_dns') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('as') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('ip') + '</td>\r')
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
                        </tr>
                    </thead>
                    <tbody>''')

        if subdomains_dict.get('dns_records').get('mx'):
            for x in subdomains_dict.get('dns_records').get('mx'):
                html.write('\t\t\t<tr>')
                html.write('\t\t\t<td>' + x.get('domain') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('header') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('country') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('provider') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('reverse_dns') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('as') + '</td>\r')
                html.write('\t\t\t<td>' + x.get('ip') + '</td>\r')
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
                            </tr>
                        </thead>
                        <tbody>
        ''')
        if whois_emails:
            for email in whois_emails:
                html.write('\t\t\t<tr><td>' + email + '</td></tr>\r')
        else:
            html.write('\t\t\t<tr><td>No emails found</td></tr>\r')
        html.write('''
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col-md-6">
            ''')
        html.write('<p><p><span>WHOIS Info:</span><p><textarea rows="25" cols="50" readonly>' + whois_text + '</textarea>')
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
                print(key)
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
                                        <th>Domain </th>
                                    </tr>
                                </thead>
                                <tbody>
                ''')

                # Add 1 to i for each loop
                i += 1

                # For each value add a cell
                for domains in emails.itervalues():
                    print(domains)
                    for v in domains:
                        print(v)
                        html.write('<tr><td>' + v + '</td></tr>')
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
                        </tr>
                    </thead>
                    <tbody>''')
        if crtsh_results:
            for subdomain in crtsh_results:
                html.write('<tr><td>' + str(subdomain) + '</td><td>' + str(dns_resolve.dns_query(subdomain)) + '</td></tr>' )
        else:
            html.write('<tr><td>No results found</td><td>No results found</td></tr>')
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