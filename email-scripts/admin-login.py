#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2020, Wazuh Inc.
# October 20, 2020.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
import json
import sys
import time
import os
import smtplib
from email.utils import formataddr
from email.message import EmailMessage
from json2html import *

email_server = "relay.deheus.es"
email_from = "ESLCWAZUH@deheus.com"

# ossec.conf configuration:
#  <integration>
#      <name>custom-email-alerts</name>
#      <hook_url>emailrecipient@example.com</hook_url>
#      <level>10</level>
#      <group>multiple_drops|authentication_failures</group>
#      <alert_format>json</alert_format>
#  </integration>

# Global vars

debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '{0}/logs/integrations-email.log'.format(pwd)


def main(args):
    """
    Main function. This will call the functions to prepare the message and send the email
    """
    debug("# Starting")

    # Read args
    alert_file_location = args[1]
    recipients = args[3]

    debug("# Webhook")
    debug(recipients)

    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)

    debug("# Generating message")
    subject, msg = generate_msg(json_alert)
    debug(msg)

    debug("# Sending message")
    send_email(recipients, subject, msg)


def send_email(recipients,subject,body):
    """
    Function to send email using an unautheticated email server.
    """
    TO = recipients.split(',')
    em = EmailMessage()
    em['To'] = TO
    # em['From'] = email_from
    em['From'] = formataddr(('Wazuh', email_from))
    em['Subject'] = subject
    em.add_header('Content-Type','text/html')
    em.set_content(body, subtype='html')
    try:
        # SMTP_SSL Example
        mailserver = smtplib.SMTP(email_server, 25)
        mailserver.ehlo() # optional, called by login()
        mailserver.send_message(em)
        mailserver.close()
        debug('Successfully sent the mail to {}'.format(TO))
    except Exception as e:
        debug("Failed to send mail to {}".format(TO))
        debug("With error: {}".format(e))


def debug(msg):
    """
    Function to generate debug logs
    """
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        f = open(log_file, "a")
        f.write(msg)
        f.close()


def generate_msg(alert):
    """
    Function that will provide the custom subject and body for the email.
    It takes as input a dictionary object generated from the json alert
    """
    title = alert['rule']['description'] if 'description' in alert['rule'] else ''
    description = alert['rule']['description']
    level = alert['rule']['level']
    agentname = alert['agent']['name']
    t = time.strptime(alert['timestamp'].split('.')[0],'%Y-%m-%dT%H:%M:%S')
    timestamp = time.strftime('%c',t)
    location = alert['location']
    devname = ['data'['devname']
    user = ['data']['user']
    reason = ['data']['reason']
    log = alert['full_log']
    subject = '[Wazuh Alert]: Fortigate:[ {0} ]'.format(attack)

    msg = """
    <html><head></head>
    <style>
        table.tabla-detail {{ max-width:800px; margin:0 auto; border-collapse:collapse; padding:0; font-family:verdana; }}
        table.tabla-detail p {{ margin:0; text-align:left }}
        table.tabla-detail td {{ padding-left:.5em; border:2px solid #38414f }}
        table.tabla-detail .cabecera-tabla {{ background-color:#38414f; color:#c9cbc3; font-family:verdana; font-weight:700 }}
        table.tabla-detail .celda-detail {{ background-color:#c6d0d7 }}
        table.tabla-detail .tabla-codigo td {{ border:none }}
        strong {{ color: #004a75; }}
    </style>
    <body style="font-family: Verdana">
    <p>
    <table class="tabla-detail">
    <colgroup><col><col>
    </colgroup>
    <tr class="tabla-detail">
    <td class="tabla-manual cabecera-tabla" colspan="2">Este es un mensaje automatico enviado desde su Wazuh Server.</td>
    </tr>
    <tr class="tabla-detail">
    <td><p class="Normal"><strong>DevName</strong></p></td>
    <td class="tabla-manual celda-detail"><p><strong>{}</strong></p></td>
    </tr>
    <tr class="tabla-detail">
    <td><p class="Normal"><strong>user</strong></p></td>
    <td class="tabla-manual celda-detail"><p><strong>{}</strong></p></td>
    </tr>
    <tr class="tabla-detail">
    <td><p class="Normal"><strong>reason</strong></p></td>
    <td class="tabla-manual celda-detail"><p><strong>{}</strong></p></td>
    </tr>
    <tr class="tabla-detail">
    <td><p class="Normal"><strong>Timestamp</strong></p></td>
    <td class="tabla-manual celda-detail"><p><strong>{}</strong></p></td>
    </tr>
    <tr class="tabla-detail">
    <td><p class="Normal"><strong>Location</strong></p></td>
    <td class="tabla-manual celda-detail"><p><strong>{}</strong></p></td>
    </tr>
    <tr class="tabla-detail">
    <td><p class="Normal"><strong>Full log</strong></p></td>
    <td class="tabla-manual celda-detail"><p><strong>{}</strong></p></td>
    </tr>
    </table>
    </body>
    </html>
    """.format(devname,user,reason, timestamp, location, log)

    return subject, msg



if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                now,
                sys.argv[1],
                sys.argv[2],
                sys.argv[3],
                sys.argv[4] if len(sys.argv) > 4 else '',
            )
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True

        # Logging the call
        f = open(log_file, 'a')
        f.write(msg + '\n')
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise