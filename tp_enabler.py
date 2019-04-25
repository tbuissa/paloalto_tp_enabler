import pan.xapi
import xml.etree.ElementTree as ET
from getpass import getpass
from datetime import datetime

# Variables to authenticate
cred = {}
cred['api_username'] = input("User: ")
cred['api_password'] = getpass("Password: ")
cred['hostname'] = input("Palo Alto Hostname or IP Address: ")




import creds
cred = creds.get_cred()


# Creates file to log execution
log_file = open('logging.txt','a')
# Creates file to log rules unchanged or failed tasks
fail = open('fail.txt','a')
# Creates file to log rules updated or successed tasks
success = open('success.txt', 'a')

# Writes log on correct files
def logging(message,status = None):
    log_file.write(message+" -- \
        "+datetime.now().strftime("%Y-%m-%d--%H-%M-%S")+"\n")
    if status == 'success':
        success.write(message+" -- \
            "+datetime.now().strftime("%Y-%m-%d--%H-%M-%S")+"\n")
    elif status == 'fail':
        fail.write(message+" -- \
            "+datetime.now().strftime("%Y-%m-%d--%H-%M-%S")+"\n")
    return message

# Authenticates on Palo Alto API
xapi = pan.xapi.PanXapi(**cred)

# Executes show command to retreive configurations of all vsys
xapi.show("/config/devices/entry/vsys")
vsys_list = ET.fromstring(str(xapi.xml_result()))


# For loop to iterate through vsys in Palo Alto
for vsys in vsys_list:
    print()
    print(vsys.tag, vsys.attrib)
    # Get Rules configured in Vsys
    try:
        xapi.get("/config/devices/entry/vsys/entry[@name='%s']/rulebase/\
            security/rules" % (vsys.attrib['name']))
        
        vsys_rules = ET.fromstring(str(xapi.xml_result()))
        print(xapi.xml_result())
    except:
        print()
        print('Vsys %s does not have rules to be configured...\
            ' % (vsys.attrib['name']))
        print()

    # For loop to iterate Rules with or without profile-setting
    for rule in vsys_rules:
        print('Rule: %s' % (rule.attrib['name']))
        xapi.get("/config/devices/entry/vsys/entry[@name='%s']/rulebase/\
            security/rules/entry[@name='%s']/profile-setting\
                " % (vsys.attrib['name'],rule.attrib['name']))

        # Identifies Rules without profile-setting configured
        if xapi.xml_result() == None:
            print('2')



            
            print(logging('','success'))

        # Continues on Rules with profile-setting configured
        else:
            current_rule = ET.fromstring(str(xapi.xml_result()))
            for params in current_rule:
                # Identifies Rules configured with profile groups
                if params.tag == 'group':
                    print(logging('Rule %s has a profile group\
                        ' % (rule.attrib['name']),'fail'))
                
                # Identifies Rules configured with profiles individually
                elif params.tag == 'profiles':
                    count = 0
                    for profile in params:

                        # Identifies Rules that already has a Threat-
                        # Prevention policy configured
                        if profile.tag == 'vulnerability':
                            count = 1
                            print('3')




                            print(logging('Rule %s has a tp policy configured\
                                ' % (rule.attrib['name']),'fail'))
                    
                    # Identifies Rules that does not have a Threat-
                    # Prevention policy configured
                    if count == 0:
                        print('4')




                        print(logging('Rule %s updated with tp policy\
                            ' % (rule.attrib['name']),'success'))
                else:
                    print(logging('Rule %s has an unknown parameter\
                        ' % (rule.attrib['name']),'fail'))

fail.close()
success.close()
log_file.close()
