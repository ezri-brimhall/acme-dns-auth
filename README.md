# acme-dns-auth

A version of https://github.com/wackyblackie/acme-dns-certbot modified for USU.

# INSTRUCTIONS

Install certbot

If you don’t already have the Python Requests library installed, you will need to do that. How to install it can vary by system and your preferences. It can be found in all major linux distribution package repos, or here is an example of installing it with pip:

```
pip install requests
```

Get the acme-dns-auth.py script: https://raw.githubusercontent.com/utahstate/acme-dns-auth/main/acme-dns-auth.py

(I usually put it in the /etc/letsencrypt folder)

```
wget "https://raw.githubusercontent.com/utahstate/acme-dns-auth/main/acme-dns-auth.py"
```

Make the script executable:

```
chmod +x acme-dns-auth.py
```

Check the header variables in the acme-dns-auth.py script:

```
ACMEDNS_URL = "https://acmedns.usu.edu"
ALLOW_FROM = [ "129.123.0.0/16", "144.39.0.0/16" ]
```

Run the certbot command. Use a -d <fqdn> for each subject alt name.

```
certbot certonly --manual --manual-auth-hook /etc/letsencrypt/acme-dns-auth.py --preferred-challenges dns --debug-challenges -d domain1.usu.edu -d domain2.usu.edu
```

While the script is running it will pause with information on the CNAMES you need to create. Make sure to get the CNAME information from the output and fill out the CNAME request form (or talk to an openIPAM admin that can add it for you) You will have to make a CNAME for each subject alt name. If you can, wait until the CNAMES are active before continuing to run the script, otherwise letsencrypt will not be able to verify the host and will not be able to give you your certs. Make sure to ask for TXT records from the CNAME. (see troubleshooting below)

This is how the CNAME request should look like:

```
CNAME being requested: _acme-challenge.<hostname>
Hostname of computer: <data>.acmedns.usu.edu
```

When testing the CNAME, make sure you request a TXT record since most DNS lookup tools will ask for A records by default and that will fail. Here are some example commands you could use. The first goes against your systems DNS server, the 2nd goes against Cloudflare’s DNS servers (1.1.1.1).  Let’s Encrypt seems to use 44.231.13.183 (our DNS server in AWS) to do their DNS checks.

```
host -t txt _acme-challenge.<hostname>
host -t txt _acme-challenge.<hostname> 1.1.1.1
host -t txt _acme-challenge.<hostname> 44.231.13.183
```

When the script has run successfully it will show you where your certs are located and you can configure your webserver to use it.

Finally, you need to make sure the service will automatically start using the new cert after it is renewed. Here are some examples of how to accomplish this:

1. Put a script in the /etc/letsencrypt/renewal-hooks/post/ directory that will take care of whatever needs to be done for you. For example, here is a script to restart apache:

```
#!/bin/bash
/usr/sbin/service apache2 restart
```

Put that in a file in the renewal-hook/post directory and make sure it is executable.

2. Add a line like this into /etc/letsencrypt/cli.ini or the renewal configuration file in /etc/letsencrypt/renewal/<hostname>.conf (this will reload an nginx server)

```
deploy-hook = service nginx reload
```


## Troubleshooting:

### The script errored out but you still received your certs:

I’ve found the acme-dns-auth.py script sometimes will error out but you will still receive your cert from letsencrypt. You should have a file /etc/letsencrypt/acmedns.json (unless you changed the STORAGE_PATH header in the script) if it ran properly. If that isn’t there, set the FORCE_REGISTER header in the script to ‘True’ and then run the ‘certbot renew --dry-run’ command. If it runs successfully and you have the acmedns.json file then things should be fine. Make sure to change the FORCE_REGISTER header variable in the script back to ‘False’ when finished.

### Letsencrypt couldn’t verify my CNAMES and didn’t give me the cert

Sometimes something will trigger a lookup prematurely and the NXDOMAIN will be cached around the internet for the CNAME. This causes letsencrypt’s verification to fail. Give it an hour or two and run certbot run again.

