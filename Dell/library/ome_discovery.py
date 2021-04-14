#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Dell EMC OpenManage Ansible Modules
# Version 2.2
# Copyright (C) 2020 Dell Inc.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# All rights reserved. Dell, EMC, and other trademarks are trademarks of Dell Inc. or its subsidiaries.
# Other trademarks may be trademarks of their respective owners.
#


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ome_discovery
short_description: Create, modify or delete a discovery job
version_added: "2.9"
description: This module creates, modifies or deletes a discovery job
options:
  hostname:
    description: Target IP Address or hostname.
    type: str
    required: true
  username:
    description: Target username.
    type: str
    required: true
  password:
    description: Target user password.
    type: str
    required: true
  port:
    description: Target HTTPS port.
    type: int
    default: 443
  name:
    description: Name of the discovery job.
    type: str
    required: true
  discover_range:
    description: 
        - "10.35.0.0"
        - "10.36.0.0-10.36.0.255"
        - "10.37.0.0/24"
        - "2607:f2b1:f083:135::5500/118"
        - "2607:f2b1:f083:135::a500-2607:f2b1:f083:135::a600"
        - "hostname.domain.tld"
        - "hostname"
        - "2607:f2b1:f083:139::22a"
    type: list
    required: true
  discover_username:
    description: 
        - "Discovery user name."
        - "Example: The iDRAC user for server discovery."
    type: str
    required: true
  discover_password:
    description: 
        - "Discovery password."
        - "Example: The iDRAC password for server discovery."
    type: str
    required: true
  trap_destination:
    description: Enable trap reception from discovered iDRAC servers and MX7000 chassis
    type: bool
    required: false
  device_type:
    description: Type of device to discover.
    choices: [server, chassis]
    default: server
    type: str
    required: false
  schedule:
    description: When to run the discovery job
    choices: [run_now, run_later]
    default: run_now
    required: false
  schedule_cron:
    description: 
        - "Schedule to run the discovery job on. Use cron style syntax. Date is in UTC."
        - "Daily at 12:00AM UTC: '0 0 0 * * ? *'"
    type: str  
    required: false
  state:
    description:
      - C(present) creates discovery job
      - C(absent) deletes discovery job
    choices: [present, absent]
    default: present
requirements:
    - "python >= 2.7.5"
author: "Trevor Squillario <Trevor.Squillario@Dell.com>"
'''

EXAMPLES = r'''
---
- name: Create discovery job by IP range now
  ome_discovery:
    hostname: "192.168.0.1"
    username: "username"
    password: "password"
    schedule: "run_now"
    name: "TestDiscovery"
    device_type: "server"
    discover_range: 
      - "192.168.1.100/26"
    discover_username: "root"
    discover_password: "calvin"
    trap_destination: True

- name: Create discovery job by IP now and on daily schedule
  ome_discovery:
    hostname: "192.168.0.1"
    username: "username"
    password: "password"
    schedule: "run_now"
    schedule_cron: "0 17 19 * * ? *"
    name: "TestDiscovery"
    device_type: "server"
    discover_range: 
      - 192.168.1.100
      - 192.168.1.101
      - 192.168.1.102
    discover_username: "root"
    discover_password: "calvin"
    trap_destination: True

- name: Create discovery job by hostname later
  ome_discovery:
    hostname: "192.168.0.1"
    username: "username"
    password: "password"
    schedule: "run_later"
    schedule_cron: 0 19 19 16 5 ? 2019"
    name: "TestDiscovery"
    device_type: "server"
    discover_range: 
      - host01.example.com
      - host02.example.com
    discover_username: "root"
    discover_password: "calvin"
    trap_destination: True

- name: Create discovery job for chassis by hostname now and on daily schedule
  ome_discovery:
    hostname: "192.168.0.1"
    username: "username"
    password: "password"
    schedule: "run_now"
    schedule_cron: "0 17 19 * * ? *"
    name: "TestDiscovery"
    device_type: "chassis"
    discover_range: 
      - mx7000-01.example.com
    discover_username: "admin"
    discover_password: "calvin"
    trap_destination: True

'''

RETURN = r'''
---
msg:
  description: Overall status of the operation.
  returned: always
  type: str
  sample: "Successfully created a Discovery Job"
status:
  description: Details of the user operation, when I(state) is C(present).
  returned: When I(state) is C(present).
  type: dict
  sample:
'''

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.remote_management.dellemc.ome import RestOME
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.urls import ConnectionError, SSLValidationError

def get_discover_device_payload(module_params):
    """ Payload for discovering devices """
    discovery_config_details = {
            "DiscoveryConfigGroupName":"Server Discovery",
            "DiscoveryConfigModels":[
                {
                    "DiscoveryConfigTargets":[
                        {
                            "NetworkAddressDetail":""
                        }],
                    "ConnectionProfile":"{\"profileName\":\"\",\"profileDescription\": \
			              \"\",\"type\":\"DISCOVERY\",\"credentials\" :[{\"type\":\
			               \"WSMAN\",\"authType\":\"Basic\",\"modified\":false,\"credentials\":\
			               {\"username\":\"\",\"password\":\"\",\"port\":443,\"retries\":3,\"timeout\":\
			               60}}]}",
                    "DeviceType":[1000]}],
            "Schedule":{
                "Cron": "startnow", 
                "RunLater": False, 
                "RunNow": True
            },
            "TrapDestination": False,
            "CommunityString": False
    }
    return discovery_config_details

def get_discovery_job(name, rest_obj):
    path = 'DiscoveryConfigService/DiscoveryConfigGroups?$top=1000'
    http_method = 'GET'
    resp = rest_obj.invoke_request(http_method, path)
    job = None
    if resp.success:
        resp_json = resp.json_data
        if resp_json['@odata.count'] > 0:
            for resp_job in resp_json['value']:
                if resp_job['DiscoveryConfigGroupName'] == name:
                    job = resp_job
    return job

def delete_discovery_job(discovery_id, rest_obj):
    path = 'DiscoveryConfigService/Actions/DiscoveryConfigService.RemoveDiscoveryGroup'
    http_method = 'POST'
    payload = {
        "DiscoveryGroupIds":[discovery_id]
    }
    resp = rest_obj.invoke_request(http_method, path, data=payload)
    return resp

def update_discover_device_payload(module_params, discovery_job):
    changed = False
    device_type_map = {
        "server": 1000,
        "network_switch": 7000,
        "storage": 5000,
        "chassis": 2000
    }
    discovery_payload = get_discover_device_payload(module_params)

    if discovery_job: # Modify existing job
        http_method = "PUT"
        path = 'DiscoveryConfigService/DiscoveryConfigGroups(%s)' % (discovery_job['DiscoveryConfigGroupId'])

        # Update payload with values from discovery job
        discovery_payload['DiscoveryConfigGroupId'] = discovery_job['DiscoveryConfigGroupId']
        discovery_payload["DiscoveryConfigGroupName"] = discovery_job["DiscoveryConfigGroupName"]
        discovery_payload["DiscoveryConfigModels"][0]["DeviceType"][0] = discovery_job["DiscoveryConfigModels"][0]["DeviceType"][0]
        discovery_payload["DiscoveryConfigModels"][0]["DiscoveryConfigTargets"] = discovery_job["DiscoveryConfigModels"][0]["DiscoveryConfigTargets"]
        discovery_payload["Schedule"] = discovery_job["Schedule"]
        discovery_connection_profile = json.loads(discovery_job["DiscoveryConfigModels"][0]["ConnectionProfile"])
        payload_connection_profile = json.loads(discovery_payload["DiscoveryConfigModels"][0]["ConnectionProfile"])
        payload_connection_profile['credentials'][0]['credentials']['username'] = discovery_connection_profile['credentials'][0]['credentials']['username']
        # Password is not being sent in the request
        discovery_payload["DiscoveryConfigModels"][0]["ConnectionProfile"] = json.dumps(discovery_connection_profile)
        discovery_payload["TrapDestination"] = discovery_job["TrapDestination"]
           
    else: # Create new discovery job
        http_method = "POST"
        path = 'DiscoveryConfigService/DiscoveryConfigGroups'
        discovery_payload["DiscoveryConfigModels"][0]["DiscoveryConfigTargets"][:] = []
        discovery_payload["DiscoveryConfigModels"][0]["DeviceType"][0] = device_type_map[module_params["device_type"]]

    # Update payload based on module params
    if module_params["schedule"] == "run_later":
        discovery_payload["Schedule"]["RunNow"] = False
        discovery_payload["Schedule"]["RunLater"] = True
    else:
        discovery_payload["Schedule"]["RunNow"] = True
        discovery_payload["Schedule"]["RunLater"] = False
    discovery_payload["DiscoveryConfigGroupName"] = module_params['name']
    if len(module_params['discover_range']) > 0:
        payload_hosts = [] # Build list of hosts from existing range
        for item in discovery_payload["DiscoveryConfigModels"][0]["DiscoveryConfigTargets"]:
            payload_hosts.append(item["NetworkAddressDetail"])
        for host in module_params['discover_range']:
            if host != ' ' and host not in payload_hosts: # Only add if not currently in range
                discovery_payload["DiscoveryConfigModels"][0]["DiscoveryConfigTargets"].append({"NetworkAddressDetail": host})
                changed = True
    if discovery_payload["TrapDestination"] != module_params['trap_destination']:
        discovery_payload["TrapDestination"] = module_params['trap_destination']
        changed = True
    if discovery_payload["Schedule"]["Cron"] != module_params['schedule_cron']:
        discovery_payload["Schedule"]["Cron"] = module_params['schedule_cron']
        changed = True
    connection_profile = json.loads(discovery_payload["DiscoveryConfigModels"][0]["ConnectionProfile"])
    if module_params['discover_username']:
        if connection_profile['credentials'][0]['credentials']['username'] != module_params['discover_username']:
            connection_profile['credentials'][0]['credentials']['username'] = module_params['discover_username']
            changed = True
    if module_params['discover_password']:
        if connection_profile['credentials'][0]['credentials']['password'] != module_params['discover_password']: # Since the password is sent as null from the API this will always be True
            connection_profile['credentials'][0]['credentials']['password'] = module_params['discover_password']
            changed = True
    discovery_payload["DiscoveryConfigModels"][0]["ConnectionProfile"] = json.dumps(connection_profile)

    return discovery_payload, http_method, path, changed

def fail_module(module, **failmsg):
    module.fail_json(**failmsg)

def main():
    module = AnsibleModule(
        argument_spec={
            "hostname": {"required": True, "type": 'str'},
            "username": {"required": True, "type": 'str'},
            "password": {"required": True, "type": 'str', "no_log": True},
            "port": {"required": False, "default": 443, "type": 'int'},
            "schedule": {"required": False, "default": "run_now", "type": 'str',
                    "choices": ['run_now', 'run_later']}, 
            "schedule_cron": {"required": False, "default": "startnow", "type": 'str'},
            "name": {"required": True, "type": 'str'},
            "discover_range": {"required": False, "type": 'list'},
            "discover_username": {"required": False, "type": 'str'},
            "discover_password": {"required": False, "type": 'str', "no_log": True},
            "trap_destination": {"required": False, "default": False, "type": 'bool'},
            "device_type": {"required": False, "default": "server", "type": 'str', 
                    "choices": ['server', 'chassis']}, 
            "state": {"required": False, "default": "present",
                    "choices": ['present', 'absent']}
        },
        required_if=[['schedule', 'run_later', ['schedule_cron']],
                     ['state', 'present', ['discover_range', 'discover_username', 'discover_password']]],
        supports_check_mode=False)

    try:
        with RestOME(module.params, req_session=True) as rest_obj:
            discovery_job = get_discovery_job(module.params['name'], rest_obj)
            if module.params['state'] == "present":
                discovery_payload, http_method, path, changed = update_discover_device_payload(module.params, discovery_job)
                if changed:
                    resp = rest_obj.invoke_request(http_method, path, data=discovery_payload)
                    if resp.success:
                        if http_method == "POST":
                            module.exit_json(msg="Successfully created a Discovery Job", changed=True, status=resp.json_data, data=discovery_payload)
                        elif http_method == "PUT":
                            module.exit_json(msg="Successfully modified a Discovery Job", changed=True, status=resp.json_data, data=discovery_payload)
                else: 
                    module.exit_json(msg="No changes made to Discovery Job", changed=False, status=resp.json_data, data=discovery_payload)
            elif module.params['state'] == "absent":
                if discovery_job:
                    discovery_id = discovery_job['DiscoveryConfigGroupId']
                    delete_resp = delete_discovery_job(discovery_id, rest_obj)
                    if delete_resp.success:
                        module.exit_json(msg="Successfully deleted a Discovery Job", changed=True)
                else:
                    fail_module(module, msg="Unable to find Discovery Job %s" % (module.params['name']))

    except HTTPError as err:
        fail_module(module, msg=str(err), status=json.load(err))
    except (URLError, SSLValidationError, ConnectionError, TypeError, ValueError) as err:
        fail_module(module, msg=str(err))

if __name__ == '__main__':
    main()