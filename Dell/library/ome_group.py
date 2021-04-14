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
module: ome_group_device
short_description: Add or remove devices from a group
version_added: "2.9"
description: This module adds or removed a device from a group
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
    description: Name of the group.
    type: str
    required: true
  devices:
    description: List of device names as they appear in OME
    type: list
    required: true
  state:
    description:
      - C(present) adds device to group
      - C(absent) removed device from group
    choices: [present, absent]
    default: present
requirements:
    - "python >= 2.7.5"
author: "Trevor Squillario <Trevor.Squillario@Dell.com>"
'''

EXAMPLES = r'''
---
- name: Add devices to group
  ome_group_device:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "Group001"
    devices: 
        - "MX740c-C39PZZZ.example.com"
        - "MX840c-C39NZZZ.example.com"

'''

RETURN = r'''
---
msg:
  description: Overall status of the operation.
  returned: always
  type: str
  sample: "Successfully added devices to group"
'''

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.remote_management.dellemc.ome import RestOME
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.urls import ConnectionError, SSLValidationError

def get_device(name, rest_obj):
    path = "DeviceService/Devices?$filter=DeviceName eq '%s'" % (name)
    http_method = 'GET'
    resp = rest_obj.invoke_request(http_method, path.replace(" ", "%20"))
    device = None
    if resp.success:
        resp_json = resp.json_data
        if resp_json['@odata.count'] > 0:
            device = resp_json['value'][0]
    return device

def get_group(name, rest_obj):
    path = "GroupService/Groups?$filter=Name eq '%s'" % (name)
    http_method = 'GET'
    resp = rest_obj.invoke_request(http_method, path.replace(" ", "%20"))
    group = None
    if resp.success:
        resp_json = resp.json_data
        if resp_json['@odata.count'] > 0:
            group = resp_json['value'][0]
    return group

def get_group_devices(group_id, rest_obj):
    path = "GroupService/Groups(%s)/Devices" % (group_id)
    http_method = 'GET'
    resp = rest_obj.invoke_request(http_method, path)
    group_device_ids = []
    if resp.success:
        resp_json = resp.json_data
        for group_device in resp_json["value"]:
            group_device_ids.append(group_device["Id"])
    return group_device_ids

def add_device_to_group(group_id, device_ids, rest_obj):
    path = "GroupService/Actions/GroupService.AddMemberDevices"
    http_method = 'POST'
    payload = {
        "GroupId": 0,
        "MemberDeviceIds" : []
    }
    payload["GroupId"] = group_id
    payload["MemberDeviceIds"] = device_ids
    resp = rest_obj.invoke_request(http_method, path, data=payload)
    return resp

def fail_module(module, **failmsg):
    module.fail_json(**failmsg)

def main():
    module = AnsibleModule(
        argument_spec={
            "hostname": {"required": True, "type": 'str'},
            "username": {"required": True, "type": 'str'},
            "password": {"required": True, "type": 'str', "no_log": True},
            "port": {"required": False, "default": 443, "type": 'int'},
            "name": {"required": True, "type": 'str'},
            "devices": {"required": True, "type": 'list'},
            "state": {"required": False, "default": "present",
                    "choices": ['present', 'absent']}
        },
        supports_check_mode=False)

    try:
        with RestOME(module.params, req_session=True) as rest_obj:
            group = get_group(module.params['name'], rest_obj)

            if group:
                if module.params['state'] == 'present':
                    if len(module.params['devices']) > 0:
                        device_ids = []
                        group_device_ids = get_group_devices(group['Id'], rest_obj)
                        for device_name in module.params['devices']:
                            device = get_device(device_name, rest_obj)
                            if device and device['Id'] not in group_device_ids:
                                device_ids.append(device['Id'])
                        
                        if len(device_ids) > 0:
                            device_resp = add_device_to_group(group['Id'], device_ids, rest_obj)
                            if device_resp.success:
                                module.exit_json(msg="Successfully added devices to group", changed=True)
                        else:
                            module.exit_json(msg="No devices added to group", changed=False)

                if module.params['state'] == 'absent':
                    fail_module(module, msg="This feature is not supported at this time")

            else:
                fail_module(module, msg="Unable to find group %s" %s (module.params['name']))

    except HTTPError as err:
        fail_module(module, msg=str(err), status=json.load(err))
    except (URLError, SSLValidationError, ConnectionError, TypeError, ValueError) as err:
        fail_module(module, msg=str(err))

if __name__ == '__main__':
    main()