# -*- coding: UTF-8 -*-
import ConfigParser as configparser
import argparse
import logging
import os
import time

# These are for the lookups
from dnsdumpster import DNSDumpsterAPI
import whois
import reversewhois
import shodan

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
    print('Shodan API key: %s' % shodan_api_key)
except:
    print('Error reading file: %s\nCheck filename or formatting of config file' % config_file)
    exit

target = args.target

'''
############################################
#               SUBDOMAINS                 #
############################################
'''
def subdomains(host):

    dnsdumpster_data = DNSDumpsterAPI.DNSDumpsterAPI().search(host)

    return dnsdumpster_data


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


#-- START --#
def main(target):

    try:
        print("[+] Enumerate subdomains passively")
        subdomains_dict = subdomains(target)

        print("[+] Query whois")
        whois_text, whois_emails, whois_dict = whois_target(target)

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
        print(email)
    print("[+] Name servers found in WHOIS data:")
    for ns in whois_dict.name_servers:
        print(ns)
    print("[+] Get data out of dnsdumpster:")
    for x in subdomains_dict.get('dns_records').get('host'):
        print('HOST(A): %s' % x)
    if subdomains_dict.get('dns_records').get('dns'):
        for x in subdomains_dict.get('dns_records').get('dns'):
            print('DNS: %s' % x)
    if subdomains_dict.get('dns_records').get('txt'):
        for x in subdomains_dict.get('dns_records').get('txt'):
            print('TXT: %s' % x)
    if subdomains_dict.get('dns_records').get('mx'):
        for x in subdomains_dict.get('dns_records').get('mx'):
            print('MX: %s' % x)

    # Begin HTML generator
    with open(target + now + 'report.html', 'w') as html:
        html.write('''
        <!DOCTYPE html>
        <html>
        ''')
        html.write('<title>'+ target + now + '</title>')
        html.write('''
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>research</title>
            <link rel="stylesheet" href="assets/bootstrap/css/bootstrap.min.css">
            <link rel="stylesheet" href="assets/css/styles.css">
        </head>

        <body>
            <div class="container">
                <header>
                    <div class="page-header">
        ''')
        # Add target to banner
        html.write('\t\t\t<h1>' + target + '</h1></div>\r')
        html.write('''
                </header>
                <nav class="navbar navbar-default">
                    <div class="container-fluid">
                        <div class="navbar-header"><a class="navbar-brand navbar-link" href="#">Home </a>
                            <button class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navcol-1"><span class="sr-only">Toggle navigation</span><span class="icon-bar"></span><span class="icon-bar"></span><span class="icon-bar"></span></button>
                        </div>
                        <div class="collapse navbar-collapse" id="navcol-1">
                            <ul class="nav navbar-nav">
                                <li class="active" role="presentation"><a href="#dnsdumpster">DNS DUMPSTER</a></li>
                                <li role="presentation"><a href="#whois">WHOIS </a></li>
                                <li role="presentation"><a href="#reversewhois">REVERSE WHOIS</a></li>
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
        html.write('<p><textarea rows="25" cols="60" readonly>' + whois_text + '</textarea>')
        html.write('''
            </div>
        </div>
        </div>

        <div class="container">
        <hr>
        ''')

        # We have a list of dictionary.  Values in dictionary are a list. So K, V= is a list

        # Loop over list and get each dictionary item
        for emails in email_list:
            print(emails)
            # Loop over key, value (list)
            for key in emails:
                print(key)
                html.write('''
                <div class="panel-group" role="tablist" aria-multiselectable="true" id="accordion-1">
                <div class="panel panel-default">
                <div class="panel-heading" role="tab">
                    <h4 class="panel-title">
                    <a role="button" data-toggle="collapse" data-parent="#accordion-1" aria-expanded="true" href="#accordion-1 .item-1">
                ''')
                html.write(key)
                html.write('''</a></h4></div>
                <div class="panel-collapse collapse in item-1" role="tabpanel">
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
        </div>
        <section></section>
        </div>
        <script src="assets/js/jquery.min.js"></script>
        <script src="assets/bootstrap/js/bootstrap.min.js"></script>
        </body>
        </html>''')


main(target)