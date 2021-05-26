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
tp_policy = '<member>%s</member>' % input("Threat Prevention Policy Name: ")

#Counting Rules Variables
rules_no_ps = 0 # Rules with no profile-setting configure yet
rules_group_ps = 0 # Rules with profile-setting configured with group
rules_profile_ps = 0 # Rules with profile-setting configured with threat policy
rules_profile_no_ps = 0 # Rules with profile-setting without threat policy

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
    #xapi.show("/config/devices/entry/vsys")
    xapi.get("/config/devices/entry[@name='localhost.localdomain']/vsys")
except pan.xapi.PanXapiError as err:
    print(str(err))
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

            # Identifies Rules without profile-setting configured
            if xapi.xml_result() == None:
                rules_no_ps += 1
                try:
                    xapi.set(xpath="%s/profiles/vulnerability\
                    " % (profile_setting),
                                element=tp_policy)
                except pan.xapi.PanXapiError as err:
                    print(str(err))

                
                print(logging('Rule %s had no profile-setting configured yet. Updating it.\
                ' % (rule.attrib['name']),'success'))

            # Continues on Rules with profile-setting configured
            else:
                current_rule = ET.fromstring(str(xapi.xml_result()))
                for params in current_rule:
                    # Identifies Rules configured with profile groups
                    if params.tag == 'group':
                        print(logging('Rule %s has a profile group\
                        ' % (rule.attrib['name']),'fail'))
                        rules_group_ps += 1
                    
                    # Identifies Rules configured with profiles individually
                    elif params.tag == 'profiles':
                        count = 0
                        for profile in params:

                            # Identifies Rules that already has a Threat-
                            # Prevention policy configured
                            if profile.tag == 'vulnerability':
                                count = 1
                                rules_profile_ps += 1
                                print(logging('Rule %s has a tp policy configured\
                                ' % (rule.attrib['name']),'fail'))
                        
                        # Identifies Rules that does not have a Threat-Prevention policy configured
                        if count == 0:
                            try:
                                xapi.set(xpath="%s/profiles/vulnerability\
                                " % (profile_setting),
                                    element= tp_policy)
                            except pan.xapi.PanXapiError as err:
                                print(str(err))

                            rules_profile_no_ps += 1
                            print(logging('Rule %s updated with tp policy\
                            ' % (rule.attrib['name']),'success'))
                    else:
                        print(logging('Rule %s has an unknown parameter\
                            ' % (rule.attrib['name']),'fail'))
    except Exception as err:
        print()

print(logging('A total of %s rules were found. \
    ' % (rules_no_ps+rules_group_ps+rules_profile_ps+rules_profile_no_ps)+'\n \
    %s rules did not have any profile-setting configured and were updated.  \
    ' % rules_no_ps +'\n %s rules already had a profile-setting configured \
    with groups and were not updated.  ' % rules_group_ps +'\n \
    %s rules had profile-setting configured but no threat prevention policy \
    and were updated.  ' % rules_profile_no_ps +'\n \
    %s rules had profile-setting configured with threat prevention policy and \
    were not updated.' % rules_profile_ps))

fail.close()
success.close()
log_file.close()