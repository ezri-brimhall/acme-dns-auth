#!/usr/bin/env python3
import json
import os
import requests
import sys
import dns.resolver
import time
import configparser

config = configparser.ConfigParser()

# Time to wait for DNS propagation before checking the TXT record
DNS_PROPAGATION_PRE_WAIT = 30

# Time to wait for DNS propagation between checks
DNS_PROPAGATION_WAIT = 10

# Maximum time to wait for DNS propagation
DNS_PROPAGATION_TIMEOUT = 300

# Extra wait time for DNS propagation, for safety
DNS_PROPAGATION_POST_WAIT = 10

# URL to acme-dns instance
ACMEDNS_URL = "https://acmedns.usu.edu"
# Path for acme-dns credential storage
STORAGE_PATH = "/etc/letsencrypt/acmedns.json"
# Whitelist for address ranges to allow the updates from
# Example: ALLOW_FROM = ["192.168.10.0/24", "::1/128"]
ALLOW_FROM = ["129.123.0.0/16", "144.39.0.0/16"]
# Force re-registration. Overwrites the already existing acme-dns accounts.
FORCE_REGISTER = False

if os.path.exists("/etc/letsencrypt/acmedns.ini"):
    config.read("/etc/letsencrypt/acmedns.ini")
    if "openipam" in config:
        OPENIPAM_TOKEN = config["openipam"].get("token")
    if "acme" in config:
        ACMEDNS_URL = config["acmedns"].get("url", "https://acmedns.usu.edu")
        STORAGE_PATH = config["acmedns"].get("storage", "/etc/letsencrypt/acmedns.json")
        FORCE_REGISTER = config["acmedns"].getboolean("force_register", fallback=False)
    if "dns" in config:
        NAMESERVERS = (
            config["dns"].get("nameservers", "129.123.0.1 129.123.0.2").split()
        )
        DNS_PROPAGATION_PRE_WAIT = config["dns"].getint("propagation_pre_wait", 30)
        DNS_PROPAGATION_WAIT = config["dns"].getint("propagation_wait", 10)
        DNS_PROPAGATION_TIMEOUT = config["dns"].getint("propagation_timeout", 300)
        DNS_PROPAGATION_POST_WAIT = config["dns"].getint("propagation_post_wait", 10)
else:
    pass


#   DO NOT EDIT BELOW THIS POINT   #
#         HERE BE DRAGONS          #

DOMAIN = os.environ["CERTBOT_DOMAIN"]
if DOMAIN.startswith("*."):
    DOMAIN = DOMAIN[2:]
VALIDATION_DOMAIN = "_acme-challenge." + DOMAIN
VALIDATION_TOKEN = os.environ["CERTBOT_VALIDATION"]

try:
    dns.resolver.get_default_resolver().nameservers = NAMESERVERS
except NameError:
    pass


class AcmeDnsClient(object):
    """Handles the communication with ACME-DNS API."""

    def __init__(self, acmedns_url):
        self.acmedns_url = acmedns_url

    def register_account(self, allowfrom):
        """Register a new ACME-DNS account."""
        if allowfrom:
            # Include whitelisted networks to the registration call
            reg_data = {"allowfrom": allowfrom}
            res = requests.post(
                self.acmedns_url + "/register", data=json.dumps(reg_data)
            )
        else:
            res = requests.post(self.acmedns_url + "/register")
        if res.status_code == 201:
            # The request was successful
            return res.json()
        else:
            # Encountered an error
            msg = (
                "Encountered an error while trying to register a new acme-dns "
                "account. HTTP status {}, Response body: {}"
            )
            print(msg.format(res.status_code, res.text))
            sys.exit(1)

    def update_txt_record(self, account, txt):
        """Update the TXT challenge record to ACME-DNS subdomain."""
        update = {"subdomain": account["subdomain"], "txt": txt}
        headers = {
            "X-Api-User": account["username"],
            "X-Api-Key": account["password"],
            "Content-Type": "application/json",
        }
        res = requests.post(
            self.acmedns_url + "/update", headers=headers, data=json.dumps(update)
        )
        if res.status_code == 200:
            # Successful update
            return
        else:
            msg = (
                "Encountered an error while trying to update TXT record in "
                "acme-dns. \n"
                "------- Request headers:\n{}\n"
                "------- Request body:\n{}\n"
                "------- Response HTTP status: {}\n"
                "------- Response body: {}"
            )
            s_headers = json.dumps(headers, indent=2, sort_keys=True)
            s_update = json.dumps(update, indent=2, sort_keys=True)
            s_body = json.dumps(res.json(), indent=2, sort_keys=True)
            print(msg.format(s_headers, s_update, res.status_code, s_body))
            sys.exit(1)


class Storage(object):
    def __init__(self, storagepath):
        self.storagepath = storagepath
        self._data = self.load()

    def load(self):
        """Read the storage content from the disk to a dict structure."""
        data = dict()
        filedata = ""
        try:
            with open(self.storagepath, "r") as fh:
                filedata = fh.read()
        except IOError as e:
            if os.path.isfile(self.storagepath):
                # Only error out if file exists, but cannot be read
                print("ERROR: Storage file exists but cannot be read")
                sys.exit(1)
        try:
            data = json.loads(filedata)
        except ValueError:
            if len(filedata) > 0:
                # Storage file is corrupted
                print("ERROR: Storage JSON is corrupted")
                sys.exit(1)
        return data

    def save(self):
        """Save the storage content to disk."""
        serialized = json.dumps(self._data)
        try:
            with os.fdopen(
                os.open(self.storagepath, os.O_WRONLY | os.O_CREAT, 0o600), "w"
            ) as fh:
                fh.truncate()
                fh.write(serialized)
        except IOError as e:
            print("ERROR: Could not write storage file.")
            sys.exit(1)

    def put(self, key, value):
        """Put the configuration value to storage and sanitize it."""
        # If wildcard domain, remove the wildcard part as this will use the
        # same validation record name as the base domain
        if key.startswith("*."):
            key = key[2:]
        self._data[key] = value

    def fetch(self, key):
        """Get configuration value from storage."""
        try:
            return self._data[key]
        except KeyError:
            return None


def create_cname(openipam_url: str, auth_token: str, domain: str, content: str) -> bool:
    """Create a CNAME record with OpenIPAM."""

    try:
        res = requests.post(
            f"{openipam_url}/api/dns/add/",
            data={
                "name": domain,
                "dns_type": "CNAME",
                "content": content,
                # TTL should be less than the propagation timeout
                "ttl": 60,
            },
            headers={"Authorization": f"Token {auth_token}"},
        )
        res.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to create CNAME record: {e}")
        if res.status_code == 400:
            print(f"Response: {res.json()}")
        return False


def delete_cname(openipam_url: str, auth_token: str, domain: str) -> bool:
    """Delete a CNAME record with OpenIPAM."""

    try:
        res = requests.get(
            f"{openipam_url}/api/dns/?name={domain}&type=CNAME&limit=0",
            headers={"Authorization": f"Token {auth_token}"},
        )
        res.raise_for_status()
        # When limit is 0, the API does not construct a paginated response, and just returns an array
        # of records. We can safely assume that the response is an array.
        records = [record["id"] for record in res.json()]
        if len(records) == 0:
            print(f"No CNAME record found for {domain}")
            return True
        # There really only should be one record, but we'll loop through all of them just in case
        for record in records:
            res = requests.delete(
                f"{openipam_url}/api/dns/{record}/delete",
                headers={"Authorization": f"Token {auth_token}"},
            )
            res.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to delete DNS record: {e}")
        return False


def validate_record(domain: str, expected: str) -> bool:
    answers = dns.resolver.resolve(VALIDATION_DOMAIN, "TXT")
    for answer in answers:
        if answer.to_text() == f'"{VALIDATION_TOKEN}"':
            return True
    return False


def do_add(client, storage, account, openipam_url):

    try:
        auth_token = OPENIPAM_TOKEN
    except NameError:
        auth_token = os.environ.get("OPENIPAM_TOKEN")
        print(auth_token)
    if auth_token:
        auto_added = create_cname(
            openipam_url, auth_token, VALIDATION_DOMAIN, account["fulldomain"]
        )
        if auto_added:
            storage.put(DOMAIN, account)
            storage.save()
            # Update the TXT record in acme-dns instance
            client.update_txt_record(account, VALIDATION_TOKEN)
            try:
                wait_for_propagation(VALIDATION_DOMAIN, VALIDATION_TOKEN)
            except:
                print("DNS propagation failed.")
                return False
            return True
        else:
            print(f"Failed to create CNAME record for {VALIDATION_DOMAIN}")
            print("It may already exist. If so, please delete it and try again.")
            print(
                "To add the record manually, remove the OPENIPAM_TOKEN configuration / environment variable and run this script again"
            )
            return False
    else:
        # Display the notification for the user to update the main zone
        msg = "Please add the following CNAME record to your main DNS zone:\n{}"
        cname = "{} CNAME {}.".format(VALIDATION_DOMAIN, account["fulldomain"])
        print(msg.format(cname))
        # Update the TXT record in acme-dns instance
        client.update_txt_record(account, VALIDATION_TOKEN)
        return False


def wait_for_propagation(domain, secret):
    """Wait for the DNS record to propagate."""
    print("Waiting for DNS records to propagate...")
    time.sleep(DNS_PROPAGATION_PRE_WAIT)
    start = time.time()
    propagated = False
    while not propagated:
        try:
            if validate_record(domain, secret):
                propagated = True
        except dns.resolver.NXDOMAIN:
            pass
        time.sleep(DNS_PROPAGATION_WAIT)
        if time.time() - start > DNS_PROPAGATION_TIMEOUT:
            raise Exception("Timeout waiting for DNS records to propagate.")

    time.sleep(DNS_PROPAGATION_POST_WAIT)


if __name__ == "__main__":
    # Init
    client = AcmeDnsClient(ACMEDNS_URL)
    storage = Storage(STORAGE_PATH)

    # Check if an account already exists in storage
    account = storage.fetch(DOMAIN)

    openipam_url = os.environ.get("OPENIPAM_URL", "https://openipam.usu.edu")

    auto_added = False
    if FORCE_REGISTER or not account:
        account = client.register_account(ALLOW_FROM)

        if not do_add(client, storage, account, openipam_url):
            sys.exit(1)
    else:
        # Verify that the record is correct by querying DNS
        try:
            valid = validate_record(VALIDATION_DOMAIN, VALIDATION_TOKEN)
        except dns.resolver.NXDOMAIN:
            if not do_add(client, storage, account, openipam_url):
                sys.exit(1)

        if not valid:
            print("Existing record is incorrect. Updating...")
            if delete_cname(openipam_url, OPENIPAM_TOKEN, VALIDATION_DOMAIN):
                if not do_add(client, storage, account, openipam_url):
                    sys.exit(1)
            else:
                print("Failed to update CNAME record.")
                print(
                    "Please update the record to the following and run this script again:"
                )
                print(f"{VALIDATION_DOMAIN} CNAME {account['fulldomain']}.")
                sys.exit(1)
