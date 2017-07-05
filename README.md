# Installation
The following python packages need to be installed.

`pip install requests termcolor pyopenssl ndg-httpsclient pyasn1`

You should have a cron entry running every minute

` */1 * * * * python /path/to/dyndns.py`

# Configuration
You will need a vaild SiteHost / MyHost API key with access to the `DNS` and `MONITOR` endpoints.

Edit `dyndns.py` and add your API key and client id and change the variables at the top to suit your needs.
