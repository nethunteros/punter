from dnsdumpster import DNSDumpsterAPI

'''
############################################
#               SUBDOMAINS                 #
############################################
'''
def subdomains_search(host):

    dnsdumpster_data = DNSDumpsterAPI.DNSDumpsterAPI().search(host)

    return dnsdumpster_data