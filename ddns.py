#!/usr/bin/env python3
"""
Dynamic DNS for Firewall for Vultr
By MBRCTV, molexx

credit for https://github.com/andyjsmith/Vultr-Dynamic-DNS
"""
import sys
import time
import requests
import smtplib
import json
import socket
from email.message import EmailMessage
from email.headerregistry import Address
import logging
import yaml
from os.path import exists
from logging.config import dictConfig




loop_forever = True
#loop_forever = False
sleep_duration_secs = 60

if "once" in sys.argv:
    loop_forever = False


#TESTING
do_delete = True
do_create = True
do_email = True
#do_email = False



log_cfg = ''
if exists('logging.yaml'):
    with open('logging.yaml', 'r') as f:
        log_cfg = yaml.safe_load(f.read())

if log_cfg:
    dictConfig(log_cfg)
else:
    #logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"))
    #logging.basicConfig(level="DEBUG")
    #logging.basicConfig(level="INFO")
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S')


logger = logging.getLogger(__name__)
# Import the values from the configuration file
with open("ddns_config.json") as config_file:
    config = json.load(config_file)  # read ddns_config.json and convert JSON to Python


logger.setLevel(logging.DEBUG)



firewalls = config.get("firewalls")
global_api_key = config.get("api_key")
global_email = config.get("email")


#always run at least once - will be changed later if loop_forever is False
loop_again = True


previous_ip = ''

#if __name__ == '__main__':
while loop_again:
    vultr_error = False
    found_count = 0
    uptodate_count = 0
    rule_replaced_count = 0
    new_rule_created_count = 0
    fail_count = 0
    fail_add_rule_count = 0
    rule_ok_count = 0
    external_ip = None   # cache ip from ipify.org across multiple configured firewalls

    for fw in firewalls:
        firewallgroup = fw.get("firewallgroup")
        notes = fw.get("notes")
        ddns_domain = fw.get("ddns_domain")
        api_key = fw.get("api_key")
        email = fw.get("email")


        if not api_key:
            api_key = global_api_key

        if not api_key:
          raise('api_key not defined')



        # Get the public IP of the server
        if ddns_domain:
            logger.debug("getting public ip using local dns query to ddns_domain '%s'...", ddns_domain)
            # your os sends out a dns query
            ip = socket.gethostbyname(ddns_domain)
        else:
            #need to use service to get external ip address
            if external_ip:
                ip = external_ip
            else:
                logger.debug("getting public ip by querying ipify.org...")
                try:
                    external_ip = requests.get("https://api.ipify.org/").text
                except Exception as e:
                    logger.exception("Could not lookup external IP address")
                    external_ip = None
                    continue
                    # try again next time!

                if not external_ip:
                    logger.error("failed to get IP from ipify.org")
                    continue

                # 1.3.5.7 123.567.901.345
                if 7 <= len(external_ip) <= 15 and external_ip.count(".") != 3:
                    logger.error("IP from ipify.org does not look like an ipv4 address: %s", external_ip)
                    external_ip = None
                    continue

                # ip from ipify.org looks good!
                ip = external_ip

        logger.debug("got public ip: %s", ip)

        if not ip:
             logger.error("failed to get public IP, will sleep and try again")
             continue

        if ip == previous_ip:
            #ip not changed since last loop, skip to the delay
            logger.debug("ip not changed since last run, skipping.")
            continue



        logger.debug("calling vultr api to get rules for group '%s'...", firewallgroup)
        # Get the list of DNS records from Vultr to translate the record name to recordid
        res = requests.get("https://api.vultr.com/v2/firewalls/" +
                                            firewallgroup + "/rules", headers={"Authorization": "Bearer " + api_key})


        logger.debug("vultr api returns res: %s", res)
        restxt = res.text
        logger.debug("vultr api returns body: %s", restxt)
        res_dict = json.loads(restxt)
        raw_rules = res_dict['firewall_rules']
        logger.debug("parsed existing rules: %s", raw_rules)
        logger.debug("checking %s existing rules for rule with note '%s' with ip '%s'...", len(raw_rules), notes, ip)


        #there is no update rule, so if rule is found with old IP address then it will be deleted and recreated
        create_rule = False
        deleted_rule = False
        # Make a new varible with the vultr ip
        v_ip = None
        for rule in raw_rules:
            if rule["notes"] == notes:
                found_count = found_count + 1
                v_ip = rule["subnet"]

                # Cancel if no records from Vultr match the config file
                if not v_ip:
                    logger.warning("Configuration error, no ip found in firewall rule with note %s.", notes)
                    continue

                # Check if the IP address actually differs from any of the records
                needsUpdated = False
                if v_ip != ip:
                    needsUpdated = True

                # Cancel if the IP has not changed
                if not needsUpdated:
                    #logger.info("your ip is: %s", ip)
                    logger.info("Rule %s has note '%s' and is up-to-date with ip %s", rule['id'] , notes, ip)
                    uptodate_count = uptodate_count + 1
                    rule_ok_count = rule_ok_count + 1
                    continue

                logger.info("your public IP is different to that in the vultr firewall rule with notes '%s'", notes)
                logger.info("Old IP on Vultr: %s, current Device IP: %s", v_ip, ip )

#    "id": 1,
#    "ip_type": "v4",
#    "action": "accept",
#    "protocol": "tcp",
#    "port": "80",
#    "subnet": "192.0.2.0",
#    "subnet_size": 24,
#    "source": "",
#    "notes": "Example Firewall Rule"


                delete_url = "https://api.vultr.com/v2/firewalls/" + firewallgroup + "/rules/" + str(rule['id'])
                logger.debug("Deleting vultr rule by sending a DELETE to '%s'...", delete_url)
                if do_delete:
                    delete_response = requests.delete(delete_url,
                                                headers={"Authorization": "Bearer " + api_key}
                    )
                    if delete_response.status_code == 204:
                        logger.info("Current rule with note '%s' for port %s has been deleted ", notes, rule['port'])
                        deleted_rule = True
                    else:
                        fail_count = fail_count + 1
                        vultr_error = "Could not delete rule '%s': res: '%s', res.text: '%s'" % (rule, delete_response, delete_response.text)
                        logger.warning(vultr_error)
                        continue

                create_rule = True

        #end loop around rules

        if found_count == 0:
            logger.warning("No rules found with notes '%s'.", notes)
            create_rule = True


        if create_rule:
            #rule will be set to the last rule from the for loop above so lets not use it
            new_rule = {}
            new_rule['subnet_size'] = 0
            new_rule['source'] = ''
            new_rule['subnet'] = ip
            new_rule['notes'] = notes
            new_rule['action'] = 'accept'
            new_rule['ip_type'] = 'v4'
            new_rule['protocol'] = 'tcp'
            new_rule['port'] = '22'

#  "subnet_size": 0,

            #bug in vultr api?
            #if not "ip_type" in rule:
            #    rule["ip_type"] = rule["type"]

            logger.debug("Creating new vultr rule: %s", new_rule)

            rule_json = json.dumps(new_rule, indent = 2)

            if do_create:
                create_response = requests.post("https://api.vultr.com/v2/firewalls/" + firewallgroup + "/rules",
                                                data=rule_json,
                                                 headers={"Authorization": "Bearer " + api_key}
                )
                if create_response.status_code == 201:
                    logger.info("user %s has been updated to %s", notes, ip)
                    if deleted_rule:
                        rule_replaced_count = rule_replaced_count + 1
                    else:
                        new_rule_created_count = new_rule_created_count + 1
                    rule_ok_count = rule_ok_count + 1
                else:
                    #this can happen when another rule already exists for the same parameters
                    vultr_error = "Could not add rule '%s': res: '%s', res.text: '%s'" % (rule_json, create_response, create_response.text)
                    logger.warning(vultr_error)
                    fail_add_rule_count = fail_add_rule_count + 1


        if fail_count == 0:
            previous_ip = ip
            #only set previous ip if successful, forcing another check after waiting

        rules_processed_count = rule_replaced_count + fail_count + uptodate_count
        rules_changed_count = rule_replaced_count + new_rule_created_count


        logger.debug("STATS: vultr_error: '%s', found_count: %s, uptodate_count: %s, rule_replaced_count: %s, new_rule_created_count: %s, fail_count: %s, fail_add_rule_count: %s, rule_ok_count: %s", vultr_error, found_count, uptodate_count, rule_replaced_count, new_rule_created_count, fail_count, fail_add_rule_count, rule_ok_count)



        if found_count != rules_processed_count:
            logger.warning("%s rules were found with notes '%s' but %s rules were processed", found_count, notes, rules_processed_count)

        if uptodate_count > 0 and fail_count == 0:
            logger.info("fail_count is 0, %s rule(s) found with note '%s' were already up-to-date with current ip %s.", uptodate_count, notes, ip)



        if rules_changed_count == 0:
            continue


        if email:
            from_email = email.get("from_email")
            to_email = email.get("to_email")
            login = email.get("login")
            password = email.get("password")
            from_name = email.get("from_name")
            smtp_server = email.get("smtp_server")
        else:
            from_email = global_email.get("from_email")
            to_email = global_email.get("to_email")
            login = global_email.get("login")
            password = global_email.get("password")
            from_name = global_email.get("from_name")
            smtp_server = global_email.get("smtp_server")

        # send email report
        if not from_email:
            logger.info("No from_email configured for this firewall or globally.")
            continue
        else:
            to_address_l = []

        if not smtp_server:
            smtp_server = 'smtp.gmail.com'

        if not login:
            login = from_email


        if not vultr_error:
            email_text = "%s firewall entries with note '%s' have been set with IP %s" % (rules_changed_count, notes, ip)
            email_subject_suffix = "OK"
        else:
            email_text = "Error updating at least one firewall entry with note '%s' to new IP %s: %s" % (notes, ip, vultr_error)
            email_subject_suffix = "ERROR"


        msg = EmailMessage()
        msg.set_content(email_text)
        msg['Subject'] = "[VultrIP] IP UPDATE %s" % (email_subject_suffix)
        msg['From'] = from_email
        msg['To'] = ', '.join(to_email)

        logger.info("Sending email using smtp server %s: %s", smtp_server, msg)


        if not do_email:
            continue

        try:
            server = smtplib.SMTP(smtp_server, 587)
            server.ehlo()
            server.starttls()
            server.login(login, password)
            server.send_message(msg)
            server.close()
            logger.info("Successfully sent confirmation email to '%s'", to_email)
        except Exception as e:
            logger.exception("Failed to send email using %s", smtp_server)


    # end loop around configured firewalls

    if loop_forever:
        logger.debug("looping forever, sleeping for %s s...", sleep_duration_secs)
        time.sleep(sleep_duration_secs)
    else:
        logger.debug("looping is disabled, set loop_forever = True to loop forever with a delay")
        loop_again = False
        #TODO exit with failure depending on counts
#found_count

        if fail_count > 0:
            logger.warning("At least one update failure.", fail_count)
        if found_count == 0:
            logger.warning("No rules found with notes '%s'.", notes)
        if uptodate_count >0:
            logger.info("%s records already up-to-date", uptodate_count)
        if rules_changed_count >0:
            logger.info("updated %s records ok", rules_changed_count)


# end loop on 'loop'
