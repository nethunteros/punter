import requests
from time import sleep


def pwned_email_check(email):

    r = requests.get("https://haveibeenpwned.com/api/v2/breachedaccount/" + email + "?includeUnverified=true", verify=True)

    sleep(3)  # Rate limits at 1.5 seconds.  But were nice....

    # https://haveibeenpwned.com/API/v2

    if str(r.status_code) == "404":
        return "Not pwned"
    elif str(r.status_code) == "200":
        return "Email is Pwned"
    elif str(r.status_code) == "429":
        print("[!] Rate limited exceeded")
    else:
        print("[!] Error getting haveibeenpwned info!")
        return "Unknown"