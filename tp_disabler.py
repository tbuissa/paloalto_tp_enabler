import pan.xapi
import xml.etree.ElementTree as ET
from getpass import getpass
from datetime import datetime

# Variables to authenticate
cred = {}
cred['api_username'] = input("User: ")
cred['api_password'] = getpass("Password: ")
cred['hostname'] = input("Palo Alto Hostname or IP Address: ")

# Threat Prevention Policy that will be applied on rules
tp_policy = '<member>%s</member>' % "ips_base" # input("Threat Prevention Policy Name: ")

#Counting Rules Variables
rules_tp_removed = 0 # Rules with profile-setting removed


# Creates file to log execution
log_file = open('logging.txt','a')
# Creates file to log rules unchanged or failed tasks
fail = open('fail.txt','a')
# Creates file to log rules updated or successed tasks
success = open('success.txt', 'a')

# Defines xpath to rules
def rules_xpath(vsys_name):
    return "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/rulebase/security/rules" % (vsys_name)

# Defines xpath to profile-setting
def ps_xpath(rules_xpath,rule_name):
    return "%s/entry[@name='%s']/profile-setting" % (rules_xpath,rule_name)

# Writes log on correct files
def logging(message,status = None):
    log_file.write(datetime.now().strftime("%Y-%m-%d--%H-%M-%S")+" -- \
    "+message+"\n")
    if status == 'success':
        success.write(message+" -- \
        "+datetime.now().strftime("%Y-%m-%d--%H-%M-%S")+"\n")
    elif status == 'fail':
        fail.write(message+" -- \
        "+datetime.now().strftime("%Y-%m-%d--%H-%M-%S")+"\n")
    return message

print(logging('Initiating Threat Prevention Enabler'))

# Authenticates on Palo Alto API
try:
    xapi = pan.xapi.PanXapi(**cred)
    print(logging('authentication on Palo Alto %s succeded with user %s\
        ' % (cred['hostname'],cred['api_username']),'success'))
except Exception as err:
    print(logging('authentication on Palo Alto %s failed with user %s\
        ' % (cred['hostname'],cred['api_username']),'fail'))
    print(logging('error: '+str(err),'fail'))

# Executes show command to retreive configurations of all vsys
try:
    xapi.get("/config/devices/entry[@name='localhost.localdomain']/vsys")
except pan.xapi.PanXapiError as err:
    print("error: " + str(err))
vsys_list = ET.fromstring(str(xapi.xml_result()))
print(vsys_list)


# For loop to iterate through vsys in Palo Alto
for vsys in vsys_list:
    print()
    print(vsys.tag, vsys.attrib)
    # Get Rules configured in Vsys
    try:
        rule_path = rules_xpath(vsys.attrib['name'])
        xapi.get(rule_path)
        vsys_rules = ET.fromstring(str(xapi.xml_result()))
        print(xapi.xml_result())
    except Exception as err:
        print()
        print(logging('Vsys %s does not have rules to be configured...\
        ' % (vsys.attrib['name'])))
        print()
        vsys_rules = None

    try:
        # For loop to iterate Rules with or without profile-setting
        for rule in vsys_rules:
            print('Rule: %s' % (rule.attrib['name']))
            try:
                profile_setting = ps_xpath(rule_path,rule.attrib['name'])
                xapi.get(profile_setting)
            except pan.xapi.PanXapiError as err:
                print(str(err))  

            # Removes tp profile
            # current_rule = ET.fromstring(str(xapi.xml_result()))
            # for params in current_rule:
            #     if params.tag == "profiles":
            #         for profile in params:
            #             if profile.tag == "vulnerability":


            # if xapi.xml_result().replace("\n","") == "  "+tp_policy and rule.attrib['name'] == "teste-buissa-ips":
            try:
                xapi.delete(xpath=profile_setting)
                rules_tp_removed += 1
                
                print(logging('Rule %s had a profile-setting configured. Removing it.\
                ' % (rule.attrib['name']),'success'))

            except pan.xapi.PanXapiError as err:
                print(str(err))
                
    except Exception as err:
        print()

print(logging('A total %s rules had the threat prevention applied and were updated.  \
    ' % rules_tp_removed ))

fail.close()
success.close()
log_file.close()