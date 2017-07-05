#!/usr/bin/python3

# Required pip packages
#  - pip install requests termcolor pyopenssl ndg-httpsclient pyasn1

import collections
import requests
import smtplib
import socket
import time
from termcolor import colored

# Your SiteHost API Key
api_key = "ENTER API KEY HERE"

# Your SiteHost / MyHost client ID
client_id = ENTER CLIENT ID HERE

# A list of domains that your client ID controls
domains = ["mydomain.nz"]

# A whitelist list of records that will be updated
update_records = ["mydomain.nz", "*.mydomain.nz"]

# The SMTP server to use for sending alert emails
smtp_server = "127.0.0.1"

# A list of email addresses to receive notification alert emails
alert_emails = ['myemail@ubuntu']

def msg(message):
    """
    Print a message with timestamp
    """
    print('[' + time.strftime("%Y-%m-%d %H:%M") + '] ' + message)

def info(message):
    """
    Print an info message
    """
    msg(colored('[INFO]: ', 'green') + message)

def warn(message):
    """
    Print an warning message
    """
    msg(colored('[WARN]: ', 'yellow') + message)

def error(message):
    """
    Print an error message
    """
    msg(colored('[ERROR]: ', 'red') + message)

def get_ip():
    """
    Return the current IP address
    """
    try:
        r = requests.get("http://httpbin.org/ip")
        return r.json()['origin'] if r.status_code == 200 else None
    except requests.ConnectionError:
        return None

def get_dns_ip(domain):
    """
    Return machine's current IP address in DNS.
    """
    try:
        return socket.gethostbyname(domain)
    except socket.error:
        return None

def update_domain(domain, ip_address):
    """
    Updates the domains A records with the new IP address
    """
    records = get_records(domain)

    if records is not None:
        for record in records:
            # We only want to update A records
            if record['type'] == 'A':
                if record['name'] in update_records:
                    update_record(domain, record['id'], record['type'], record['name'], ip_address)
                else:
                    warn(' - Skipping ' + colored(record['type'], 'green') + ' record: ' + colored(record['name'], 'yellow'))

def update_record(domain, record_id, type, name, ip_address, priority=0):
    """
    Update an individual record
    """
    try:
        info(' - Updating ' + colored(type, 'green') + ' record: ' + colored(name, 'green'))
        r = requests.get(
            'https://mysth.safeserver.net.nz/1.0/dns/update_record.json?apikey=%s&client_id=%d&domain=%s&record_id=%s&type=%s&name=%s&content=%s&prio=%d' % (
                api_key, client_id, domain, record_id, type, name, ip_address, priority
            ))

        if r.status_code == 200 and r.json()['status'] is False:
            error(r.text)
    except requests.ConnectionError:
        error('Cannot communicate with the API: update_record()')

def get_records(domain):
    """
    Retrieve all records for this domain
    """
    try:
        r = requests.get(
            "https://mysth.safeserver.net.nz/1.0/dns/list_records.json?apikey=%s&client_id=%d&domain=%s" %(
                api_key, client_id, domain
            ))

        if r.status_code == 200 and r.json()['status'] is False:
            error(r.text)
            return None

        return r.json()['return']
    except requests.ConnectionError:
        error('Cannot communicate with the API: get_records()')

def get_mon_hosts():
    """
    Retrieve all hosts being monitored
    """
    try:
        r = requests.get(
            "https://mysth.safeserver.net.nz/1.0/mon/list_hosts.json?apikey=%s&client_id=%d" % (
                api_key, client_id
            ))

        if r.status_code == 200 and r.json()['status'] is False:
            error(r.text)
            return None

        return r.json()['return']
    except requests.ConnectionError:
        error('Cannot communicate with the API: get_mon_hosts()')

def update_monitoring(domain, ip):
    """
    Update the monitored hosts with the new IP address
    """

    hosts = get_mon_hosts()

    if hosts is not None:
        for host in hosts:
            if host['hostname'] == domain and host['ip_addr'] != ip:
                info(' - Updating ' + colored(domain, 'green') + ' monitoring: ' + colored(ip, 'green'))
                update_mon_host(host['id'], ip)

def update_mon_host(host_id, ip):
    """
    update a single host with new ip
    """
    try:
        request_params = collections.OrderedDict()
        request_params['client_id'] = client_id
        request_params['host_id'] = host_id
        request_params['params[ip_addr]'] = ip

        r = requests.post(
            "https://mysth.safeserver.net.nz/1.0/mon/update_host.json?apikey=%s" % (
                api_key,
            ), data=request_params)

        if r.status_code == 200 and r.json()['status'] is False:
            error(r.text)
            return None

        r = requests.post(
            "https://mysth.safeserver.net.nz/1.0/mon/update_config.json?apikey=%s" % (api_key))

        if r.status_code == 200 and r.json()['status'] is False:
            error(r.text)
            return None

    except requests.ConnectionError:
        error('Cannot communicate with the API: update_mon_host()')

def send_email(to, domain, ip, sender = 'dyndns@ubuntu'):
    """
    Send an email alert
    """

    if not isinstance(to, list):
        error('Email recipients must be provided as a python list.')
    else:
        try:
            m = """From: %s
To: %s
Subject: [%s] IP address has changed

Domain: %s
IP Address: %s
Updated Records: %s
""" % (sender, ','.join(to), domain, domain, ip, ','.join(update_records))

            s = smtplib.SMTP(smtp_server, 25)
            s.sendmail(sender, ','.join(to), m)
            info('Notification Email Sent: ' + colored(', '.join(to), 'green'))
        except socket.error:
            error('Failed to send notification email, could not connect to SMTP server: ' + colored(smtp_server + ':25', 'green'))
        except SMTPException:
            error('Failed to send notification email to: ' + colored(', '.join(to), 'green'))

if __name__ == "__main__":
    current_ip = get_ip()

    if current_ip is None:
        error('Could not retrieve current IP address from internet.')
        exit(-1)

    for domain in domains:
        dns_ip = get_dns_ip(domain)

        info('Checking domain: ' + colored(domain, 'green') + ' (' + colored(dns_ip, 'green') + ')')

        if dns_ip is None:
            warn(colored('Updating, could not determine IP from DNS', 'yellow'))
            info('Updating domain ' + colored(domain, 'green') + ' with current ip ' + colored(current_ip, 'green'))
            update_domain(domain, current_ip)
            update_monitoring(domain, current_ip)
            send_email(alert_emails, domain, current_ip)
        elif dns_ip != current_ip:
            info('Updating domain ' + colored(domain, 'green') + ' with current ip ' + colored(current_ip, 'green'))
            update_domain(domain, current_ip)
            update_monitoring(domain, current_ip)
            send_email(alert_emails, domain, current_ip)
        else:
            info('DNS is up to date!')
