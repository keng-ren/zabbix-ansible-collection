#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Zabbix Ltd
# GNU General Public License v2.0+ (see COPYING or https://www.gnu.org/licenses/gpl-2.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: zabbix_host
short_description: Module for creating hosts, deleting and updating existing hosts.
description:
    - The module is designed to create, update or delete a host in Zabbix.
    - In case of updating an existing host, only the specified parameters will be updated.
author:
    - Zabbix Ltd (@zabbix)
requirements:
    - "python >= 2.6"
options:
    state:
        description: Create or delete host.
        required: false
        type: str
        default: present
        choices: [ present, absent ]
    hostid:
        description:
            - An existing host to update or delete.
            - Ignored for new hosts.
            - Required for host name changes.
        type: str
        aliases: [ id ]
    host:
        description:
            - Host name to create.
            - The name of an existing host in case of an update or deletion.
        type: str
        aliases: [ host_name ]
    name:
        description: Visible host name
        type: str
        aliases: [ visible_name ]
    update_strategy:
        description: 
            - Controls how host properties O(hostgroups), O(templates), O(macros), and O(interfaces) are updated.
        type: dict
        suboptions:
            hostgroups:
                description:                
                    - How the host's host group membership should be modified.
                    - If V(replace), all host groups that are not listed in the task will be unlinked.
                    - If V(merge), host groups listed in the task will be linked to the host if not already linked. 
                    - If V(delete), all host groups listed in the task will be unlinked from the host.
                    - For V(merge) and V(delete) strategies, any existing host groups not linked in the task will be unaffected.
                type: str
                default: replace
                choices: [ replace, merge, delete ]
            templates:
                description:
                    - How the host's linked templates should be modified.
                    - If V(replace), all templates that are not listed in the task will be unlinked.
                    - If V(merge), templates listed in the task will be linked to the host if not already linked. 
                    - If V(delete), all templates listed in the task will be unlinked from the host.
                    - For V(merge) and V(delete) strategies, any existing templates not linked in the task will be unaffected.
                type: str
                default: replace
                choices: [ replace, merge, delete ]
            macros:
                description:
                    - How the host's macros should be modified.
                    - If V(replace), all host macros that are not listed in the task will be removed.
                    - If V(merge), macros listed in the task will be linked to the host if not already linked. 
                    - If V(delete), all host macros listed in the task will be removed from the host.
                    - For V(merge) and V(delete) strategies, any existing host macros not linked in the task will be unaffected.
                type: str
                default: replace
                choices: [ replace, merge, delete ]
            interfaces:
                description:
                    - How the host's interfaces should be modified.
                    - If V(replace), all host interfaces that are not listed in the task will be removed.
                    - If V(merge), host interfaces listed in the task will be added to the host or merged with the existing host interfaces.
                    - If V(delete), all host interfaces listed in the task will be removed from the host.
                    - For V(merge) and V(delete) strategies, any existing host interfaces not linked in the task will be unaffected.
                type: str
                default: replace
                choices: [ replace, merge, delete ]
    hostgroups:
        description:
            - Host groups that will be applied to the host.
            - By default, all host groups that are not listed in the task will be unlinked.
            - See O(update_strategy) for how to control this behavior.
        type: list
        elements: str
        aliases: [ host_group, host_groups ]     
    templates:
        description:
            - Templates that will be applied to the host.
            - By default, all templates that are not listed in the task will be unlinked.
            - See O(update_strategy) for how to control this behavior.
        type: list
        elements: str
        aliases: [ link_templates, host_templates, template ]
    status:
        description: Host status (enabled or disabled).
        type: str
        choices: [ enabled, disabled ]
    description:
        description: Host description.
        type: str
    tags:
        description:
            - Host tags to replace the current host tags.
            - All tags that are not listed in the task will be removed.
        type: list
        elements: dict
        suboptions:
            tag:
                description: Host tag name.
                type: str
                required: true
            value:
                description: Host tag value.
                type: str
                default: ''
        aliases: [ host_tags ]    
    macros:
        description:
            - User macros that will be applied to the host.
            - By default, all macros that are not listed in the task will be removed.
            - If a secret macro is specified, the host will be updated every time the task is run.
            - See O(update_strategy) for how to control this behavior.
        type: list
        elements: dict
        suboptions:
            macro:
                description: Macro string.
                type: str
                required: true
            value:
                description:
                    - Value of the macro.
                    - Write-only if I(type=secret).
                type: str
                default: ''
            description:
                description: Description of the macro.
                type: str
                default: ''
            type:
                description: Type of the macro.
                type: str
                default: text
                choices: [ text, secret, vault_secret ]
        aliases: [ user_macros, user_macro ]
    ipmi_authtype:
        description: IPMI authentication algorithm.
        type: str
        choices: [ default, none, md2, md5, straight, oem, rmcp+ ]
    ipmi_privilege:
        description: IPMI privilege level.
        type: str
        choices: [ callback, user, operator, admin, oem ]
    ipmi_username:
        description: IPMI username.
        type: str
    ipmi_password:
        description: IPMI password.
        type: str
    tls_accept:
        description: Connections from host.
        type: list
        elements: str
        choices: [ unencrypted, psk, cert ]
    tls_connect:
        description: Connections to host.
        type: str
        choices: [ '', unencrypted, psk, cert ]
    tls_psk_identity:
        description:
            - PSK identity.
            - Required if I(tls_connect=psk) , or I(tls_accept) contains the 'psk'.
            - In case of updating an existing host, if the host already has PSK enabled, the parameter is not required.
            - If the parameter is defined, then every launch of the task will update the host,
              because Zabbix API does not have access to an existing PSK key and we cannot compare the specified key with the existing one.
        type: str
    tls_psk:
        description:
            - The pre-shared key, at least 32 hex digits.
            - Required if I(tls_connect=psk), or I(tls_accept) contains the 'psk'.
            - In case of updating an existing host, if the host already has PSK enabled, the parameter is not required.
            - If the parameter is defined, then every launch of the task will update the host,
              because Zabbix API does not have access to an existing PSK key and we cannot compare the specified key with the existing one.
        type: str
    tls_issuer:
        description: Certificate issuer.
        type: str
    tls_subject:
        description: Certificate subject.
        type: str
    proxy:
        description: Name of the proxy that is used to monitor the host.
        type: str
    inventory_mode:
        description: Host inventory population mode.
        choices: [ automatic, manual, disabled ]
        type: str
    inventory:
        description:
            - The host inventory object.
            - "All possible fields:"
            - type, type_full, name, alias, os, os_full, os_short, serialno_a, serialno_b, tag, asset_tag, macaddress_a,
              macaddress_b, hardware, hardware_full, software, software_full, software_app_a, software_app_b, software_app_c, software_app_d,
              software_app_e, contact, location, location_lat, location_lon, notes, chassis, model, hw_arch, vendor, contract_number,
              installer_name, deployment_status, url_a, url_b, url_c, host_networks, host_netmask, host_router, oob_ip, oob_netmask,
              oob_router, date_hw_purchase, date_hw_install, date_hw_expiry, date_hw_decomm, site_address_a, site_address_b, site_address_c,
              site_city, site_state, site_country, site_zip, site_rack, site_notes, poc_1_name, poc_1_email, poc_1_phone_a,
              poc_1_phone_b, poc_1_cell, poc_1_screen, poc_1_notes, poc_2_name, poc_2_email, poc_2_phone_a, poc_2_phone_b, poc_2_cell,
              poc_2_screen, poc_2_notes.
            - See U(https://www.zabbix.com/documentation/current/en/manual/api/reference/host/object#host-inventory) for an overview.
        type: dict
        aliases: [ inventory_zabbix, host_inventory ]
    interfaces:
        type: list
        elements: dict
        description:
            - Host interfaces that will be applied to the host.
            - Only one interface of each type is supported.
            - By default, all host interfaces that are not listed in the task will be removed.
            - See O(update_strategy) for how to control this behavior.
        suboptions:
            type:
                type: str
                description: Interface type.
                choices: [ agent, snmp, ipmi, jmx ]
                required: True
            useip:
                type: bool
                description: Whether the connection should be made through IP.
                default: True
            ip:
                type: str
                description:
                    - IP address used by the interface.
                    - Can be empty if the connection is made through DNS, otherwise is converted to loopback address.
                    - If O(update_strategy=merge), the loopback conversion will not be performed if value is empty. 
                default: ''
            dns:
                type: str
                description:
                    - DNS name used by the interface.
                    - Can be empty if the connection is made through IP.
                    - Require if I(useip=False).
                default: ''
            port:
                type: str
                description:
                    - Port number used by the interface.
                    - Can contain user macros.
                    - If V(None), will be set to the default port number for the O(type), except if O(update_strategy=merge) is set.
            details:
                description:
                    - Additional details object for interface.
                    - Required if I(type=snmp).
                type: dict
                suboptions:
                    version:
                        description: SNMP interface version.
                        type: str
                        choices: [ '1', '2', '3' ]
                    bulk:
                        description: Whether to use bulk SNMP requests.
                        type: bool
                    community:
                        description:
                            - SNMP community.
                            - Used only if I(version=1) or I(version=2).
                        type: str
                    max_repetitions:
                        description:
                            - Max repetition count is applicable to discovery and walk only.
                            - Used only if I(version=2) or I(version=3).
                            - Used only for Zabbix versions above 6.4.
                        type: str
                    contextname:
                        description:
                            - SNMPv3 context name.
                            - Used only if I(version=3).
                        type: str
                    securityname:
                        description:
                            - SNMPv3 security name.
                            - Used only if I(version=3).
                        type: str
                    securitylevel:
                        description:
                            - SNMPv3 security level.
                            - Used only if I(version=3).
                        type: str
                        choices: [ noAuthNoPriv, authNoPriv, authPriv ]
                    authprotocol:
                        description:
                            - SNMPv3 authentication protocol.
                            - Used only if I(version=3).
                        type: str
                        choices: [ md5, sha1, sha224, sha256, sha384, sha512 ]
                    authpassphrase:
                        description:
                            - SNMPv3 authentication passphrase.
                            - Used only if I(version=3).
                        type: str
                    privprotocol:
                        description:
                            - SNMPv3 privacy protocol.
                            - Used only if I(version=3).
                        type: str
                        choices: [ des, aes128, aes192, aes256, aes192c, aes256c ]
                    privpassphrase:
                        description:
                            - SNMPv3 privacy passphrase.
                            - Used only if I(version=3).
                        type: str
notes:
    - If I(tls_psk_identity) or I(tls_psk) is defined or macro I(type=secret), then every launch of the task will update the host,
      because Zabbix API does not have access to an existing PSK key or secret macros and we cannot compare the specified value with the existing one.
    - Only one interface of each type is supported.
'''

EXAMPLES = r'''
# To create host with minimum parameters
# Host group is required
- name: Create host
  zabbix.zabbix.zabbix_host:
    state: present
    host: Example host
    hostgroups:
      - Linux servers
  vars:
    ansible_network_os: zabbix.zabbix.zabbix
    ansible_connection: httpapi
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# To create host with maximum parameters
- name: Create host with maximum parameters
  zabbix.zabbix.zabbix_host:
    state: present
    host: Example host
    hostgroups:
      - Linux servers
    templates:
      - Zabbix agent active
    status: enabled
    description: 'Host example'
    name: 'Example host'
    tags:
      - tag: scope
        value: test
    macros:
      - macro: TEST_MACRO
        value: example
        description: Description of macro example
        type: text
    ipmi_authtype: default
    ipmi_privilege: user
    ipmi_username: admin
    ipmi_password: your_password
    tls_accept:
      - unencrypted
      - psk
      - certificate
    tls_psk_identity: my_example_identity
    tls_psk: SET_YOUR_PSK_KEY
    tls_issuer: Example Issuer
    tls_subject: Example Subject
    tls_connect: psk
    inventory_mode: automatic
    inventory:
      type: ""  # To specify an empty value
      serialno_b: example value
      hardware_full: |
        very very long
        multiple string value
    interfaces:
      - type: agent # To specify an interface with default parameters (the IP will be 127.0.0.1)
      - type: ipmi
      - type: jmx
        ip: 192.168.100.51
        dns: test.com
        useip: true
        port: 12345
      - type: snmp
        ip: 192.168.100.50
        dns: switch.local
        port: 169   # To specify a non-standard value
        details:
          version: 3
          bulk: true
          contextname: my contextname name
          securityname: my securityname name
          securitylevel: authPriv
          authprotocol: md5
          authpassphrase: SET_YOUR_PWD
          privprotocol: des
          privpassphrase: SET_YOUR_PWD
  vars:
    ansible_network_os: zabbix.zabbix.zabbix
    ansible_connection: httpapi
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# To update host to empty parameters
- name: Clean all parameters from host
  zabbix.zabbix.zabbix_host:
    state: present
    host: Example host
    hostgroups:    # Host group must be not empty
      - Linux servers
    templates: []
    status: enabled
    description: ''
    name: '' # The technical name will be used
    tags: []
    macros: []
    ipmi_authtype: default
    ipmi_privilege: user
    ipmi_username: ''
    ipmi_password: ''
    tls_accept:
      - unencrypted
    tls_issuer: ''
    tls_subject: ''
    tls_connect: unencrypted
    proxy: ''
    inventory_mode: disabled
    interfaces: []
  vars:
    ansible_network_os: zabbix.zabbix.zabbix
    ansible_connection: httpapi
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# To update only one parameter, you can specify just
# the hostname (used for searching) and the desired parameter.
# The rest of the host parameters will not be changed.
# For example, you want to turn off a host
- name: Update host status
  zabbix.zabbix.zabbix_host:
    host: Example host
    status: disabled
  vars:
    ansible_network_os: zabbix.zabbix.zabbix
    ansible_connection: httpapi
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# To update only one nested parameter, you can specify 
# either the hostname or hostid,  the desired parameter
# (and its ancestors), and the update strategy.
# The rest of the host parameters will not be changed.
# If the given parameter does not exist on the host,
# an attempt will be made to create it, subject to 
# all the requirements for that parameter.
- name: Update host interface
  zabbix.zabbix.zabbix_host:
    hostid: {{ hostvars['hostid'] }}
    update_strategy:
      interfaces: merge
    interfaces:
      - type: snmp
        ip: 10.10.10.5
        details:
          version: 2
  vars:
    ansible_network_os: zabbix.zabbix.zabbix
    ansible_connection: httpapi
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# To remove a host, you can use:
- name: Delete host
  zabbix.zabbix.zabbix_host:
    state: absent
    host: Example host
  vars:
    ansible_network_os: zabbix.zabbix.zabbix
    ansible_connection: httpapi
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# To remove an particular hotsgroup from a host, but
# leave all others unaffected, use the delete update
# strategy.
- name: Remove hostgroup from host
  zabbix.zabbix.zabbix_host:
    host: Example host
    update_strategy: 
      hostgroups: delete
    hostgroups:
      - Defunct hosts
  vars:
    ansible_network_os: zabbix.zabbix.zabbix
    ansible_connection: httpapi
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# To remove an particular interface from a host without
# affecting any others, use the delete update
# strategy.
- name: Remove host interface from host
  zabbix.zabbix.zabbix_host:
    host: Example host
    update_strategy:
      interfaces: delete
    interfaces:
      - type: jmx
  vars:
    ansible_network_os: zabbix.zabbix.zabbix
    ansible_connection: httpapi
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# You can configure Zabbix API connection settings with the following parameters:
- name: Create host groups
  zabbix.zabbix.zabbix_host:
    state: present
    host: Example host
    hostgroups:
      - Linux servers
  vars:
    # Connection parameters
    ansible_host: zabbix-api.com                # Specifying Zabbix API address. You can also use 'delegate_to'.
    ansible_connection: httpapi                 # Specifying to use HTTP API plugin.
    ansible_network_os: zabbix.zabbix.zabbix    # Specifying which HTTP API plugin to use.
    ansible_httpapi_port: 80                    # Specifying the port for connecting to Zabbix API.
    ansible_httpapi_use_ssl: false              # Specifying the type of connection. True for https, False for http (by default).
    ansible_httpapi_validate_certs: false       # Specifying certificate validation.
    # User parameters for connecting to Zabbix API
    ansible_user: Admin                         # Username to connect to Zabbix API.
    ansible_httpapi_pass: zabbix                # Password to connect to Zabbix API.
    # Token for connecting to Zabbix API
    zabbix_api_token: your_secret_token         # Specify your token to connect to Zabbix API.
    # Path to connect to Zabbix API
    zabbix_api_url: '/zabbix'                   # The field is empty by default. You can specify your connection path (e.g., '/zabbix').
    # User parameters for basic HTTP authorization
    # These options only affect the basic HTTP authorization configured on the web server.
    http_login: my_http_login                   # Username for connecting to API in case of additional basic HTTP authorization.
    http_password: my_http_password             # Password for connecting to API in case of additional basic HTTP authorization.

    # Rename a host
- name: Rename host
  zabbix.zabbix.zabbix_host:
    state: present
    hostid: "{{ hostvars[hostid] }}"
    host: "{{ inventory_hostname ~ '_2' }}"
  vars:
    ansible_network_os: zabbix.zabbix.zabbix
    ansible_connection: httpapi
    ansible_user: Admin
    ansible_httpapi_pass: zabbix
'''

RETURN = r""" # """

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zabbix.zabbix.plugins.module_utils.zabbix_api import (
    ZabbixApi)
from ansible_collections.zabbix.zabbix.plugins.module_utils.helper import (
    tag_to_dict_transform, macro_types, ipmi_authtype_type,
    ipmi_privilege_type, default_values, tls_type, inventory_mode_types,
    inventory_fields, interface_types, snmp_securitylevel_types,
    snmp_authprotocol_types, snmp_privprotocol_types, Zabbix_version, snmp_parameters)


def validate_arg(ans_module, check_values, obj, key):
    """
    Check that the value of the property 'key' of obj exists in values 
    and fail if not.
    """
    if obj[key] is not None and check_values.get(
            obj[key]) is None:
        ans_module.fail_json(
            msg="Invalid argument for {0}: {1}".format(
                key,
                obj[key]
            ))


class Host(object):

    def __init__(self, module, zapi):
        self.module = module
        self.zapi = zapi
        self.zbx_api_version = self.zapi.api_version()
        # Prepare the update strategies
        if self.module.params.get('update_strategy') is None:
            self.module.params['update_strategy'] = {}
        if self.module.params['update_strategy'].get('hostgroups') is None:
            self.module.params['update_strategy']['hostgroups'] = 'replace'
        if self.module.params['update_strategy'].get('templates') is None:
            self.module.params['update_strategy']['templates'] = 'replace'
        if self.module.params['update_strategy'].get('macros') is None:
            self.module.params['update_strategy']['macros'] = 'replace'
        if self.module.params['update_strategy'].get('interfaces') is None:
            self.module.params['update_strategy']['interfaces'] = 'replace'

    def get_zabbix_host(self, hostid):
        """
        The function gets information about an existing host in Zabbix.

        :param hostid: hostid for search
        :type hostid: str|int

        :rtype: dict
        :returns:
            *   dict with host parameters if host exists
            *   empty dict if host does not exist
        """
        host = {}
        params = {
            'output': 'extend',
            'selectGroups': ['groupid', 'name'],
            'selectParentTemplates': ['templateid', 'name'],
            'selectTags': ['tag', 'value'],
            'selectMacros': ['macro', 'value', 'type', 'description'],
            'selectInterfaces': [
                'interfaceid', 'main', 'type', 'useip',
                'ip', 'dns', 'port', 'details'],
            'hostids': hostid}

        if self.module.params.get('inventory') is not None:
            params['selectItems'] = ['name', 'inventory_link']
            params['selectInventory'] = 'extend'

        try:
            host = self.zapi.send_api_request(
                method='host.get',
                params=params)
        except Exception as e:
            self.module.fail_json(
                msg="Failed to get existing host: {0}".format(e))

        if 'items' in host[0]:
            self.inventory_links = {}
            for each in host[0]['items']:
                if each['inventory_link'] != '0':
                    self.inventory_links[inventory_fields[each['inventory_link']]] = each['name']

        return host[0]

    def host_api_request(self, method, params):
        """
        The function sends a request to Zabbix API.

        :param method: method for request
        :type method: str
        :param params: parameters for request
        :type params: dict

        :rtype: bool
        :return: result of request
        """
        # Check mode
        if self.module.check_mode:
            self.module.exit_json(changed=True)

        try:
            self.zapi.send_api_request(
                method=method,
                params=params)
        except Exception:
            return False

        return True

    def check_elements(self, require, exist):
        """
        The function checks that all required elements are found in Zabbix.
        If any element from the required list is missing,
        the module will be stopped.

        :param method: list of required elements
        :type method: list
        :param params: list of existing elements
        :type params: list

        :rtype: bool
        :return: True if all required elements are found in Zabbix.

        notes::
            *  If an element from the required list is missing,
            the module will be stopped.
        """
        missing = list(set(require) - set(exist))
        if missing:
            self.module.fail_json(
                msg="Not found in Zabbix: {0}".format(
                    ', '.join(missing)))

        return True

    def check_macro_name(self, macro):
        """
        The function checks and normalizes the macro name.

        :param macro: macro name
        :type macro: str

        :rtype: str
        :return: normalized macro name

        notes::
            *  If spaces are found in the macro name,
            the module will be stopped.
        """
        for element in ['{', '$', '}']:
            macro = macro.replace(element, '')
        if ' ' in macro:
            self.module.fail_json(
                msg="Invalid macro name: {0}".format(macro))

        return '{$' + macro.upper() + '}'

    def generate_zabbix_host(self, exist_host=None):
        """
        The function generates the desired host parameters based on the module
        parameters.
        The returned dictionary can be used to create a host, as well as to
        compare with an existing host.

        :param exist_host: parameters of existing Zabbix host
        :type exist_host: dict

        :rtype: dict
        :return: parameters of desired host

        note::
            *  The 'exist_host' parameter is used to determine the current
               encryption, inventory, and host group settings on existing host.
        """
        host_params = {}

        host_params['host'] = self.module.params['host']

        # These parameters don't require additional processing
        param_wo_process = [
            'description', 'name', 'tags', 'ipmi_username', 'ipmi_password',
            'tls_psk', 'tls_psk_identity', 'tls_issuer', 'tls_subject']
        for each in param_wo_process:
            if self.module.params.get(each) is not None:
                host_params[each] = self.module.params[each]

        # host groups
        if self.module.params.get('hostgroups') is not None:
            strategy = self.module.params['update_strategy']['hostgroups']

            # Check host groups for empty
            if len(self.module.params['hostgroups']) == 0:
                self.module.fail_json(
                    msg="Cannot remove all host groups from a host")

            # Get existing groups from Zabbix
            groups_search = None
            if exist_host is not None and exist_host.get('groups') is not None:
                if len(exist_host['groups']) == 0:
                    # TODO: Reload host ?
                    self.module.fail_json(
                        msg="Existing host has no groups!")

                if strategy == 'merge':
                    groups_search = list(
                        set(exist_host['groups'])
                        + set(self.module.params['hostgroups']))
                elif strategy == 'delete':
                    groups_search = list(
                        set(exist_host['groups'])
                        - set(self.module.params['hostgroups']))
                    if len(groups_search) == 0:
                        self.module.fail_json(
                            msg="Cannot remove all host groups from a host")

            if groups_search is None:
                groups_search = self.module.params['hostgroups']

            groups = self.zapi.find_zabbix_hostgroups_by_names(groups_search)

            if self.check_elements(
                    self.module.params['hostgroups'],
                    [g['name'] for g in groups]):
                groups = [{'groupid': g['groupid']} for g in groups]
                host_params['groups'] = groups
        else:
            if exist_host is None:
                self.module.fail_json(
                    msg="Required parameter not found: hostgroups")

        # templates
        if self.module.params.get('templates') is not None:
            strategy = self.module.params['update_strategy']['templates']
            host_params['templates'] = []
            templates_search = None
            if (len(self.module.params['templates']) != 0
                    and exist_host is not None
                    and exist_host.get('templates') is not None):
                if strategy == 'merge':
                    templates_search = list(
                        set(exist_host['templates'])
                        + set(self.module.params['templates']))
                elif strategy == 'delete':
                    templates_search = list(
                        set(exist_host['templates'])
                        - set(self.module.params['templates']))

            if templates_search is None:
                templates_search = self.module.params['templates']

            templates = self.zapi.find_zabbix_templates_by_names(
                templates_search)

            if self.check_elements(
                    self.module.params['templates'],
                    [t['name'] for t in templates]):
                template_ids = [{'templateid': t['templateid']}
                                for t in templates]
                host_params['templates'] = template_ids

        # proxy
        if self.module.params.get('proxy') is not None:
            if len(self.module.params.get('proxy')) == 0:
                host_params['proxy_hostid'] = '0'
            else:
                proxy = self.zapi.find_zabbix_proxy_by_names(
                    self.module.params['proxy'])
                if len(proxy) > 0:
                    host_params['proxy_hostid'] = proxy[0]['proxyid']
                else:
                    self.module.fail_json(
                        msg="Proxy not found in Zabbix: {0}".format(
                            self.module.params.get('proxy')))

        # status
        if self.module.params.get('status'):
            if self.module.params['status'] == 'enabled':
                host_params['status'] = '0'
            else:
                host_params['status'] = '1'

        # macros
        if self.module.params.get('macros') is not None:
            host_params['macros'] = []
            strategy = self.module.params['update_strategy']['macros']

            for each in self.module.params['macros']:
                macro = {
                    'macro': self.check_macro_name(each['macro']),
                    'value': each.get('value'),
                    'type': macro_types.get(each['type']),
                    'description': each.get('description'),
                }

                exist_macro = None
                if (exist_host is not None
                        and exist_host.get('macros') is not None):
                    if strategy == 'merge':
                        for macro_search in exist_host['macros']:
                            if macro_search['macro'] == macro['macro']:
                                exist_macro = macro_search
                        if exist_macro is not None:
                            merged_macro = {}
                            merged_macro['macro'] = macro['macro']
                            if macro.get('value') is not None:
                                merged_macro['value'] = macro['value']
                            if macro.get('type') is not None:
                                merged_macro['type'] = macro['type']
                            if macro.get('description') is not None:
                                merged_macro['description'] = macro[
                                    'description']
                            host_params['macros'].append(merged_macro)
                    elif strategy == 'delete':
                        host_params['macros'] = list(
                            set(exist_host['macros'])
                            - set(self.module.params['macros']))
                        continue
                # Fallback if merge did not happen
                if strategy == 'replace' or exist_macro is None:
                    if macro['type'] is None:
                        self.module.fail_json(
                            msg="Unknown macro type: {0}".format(each['type']))
                    host_params['macros'].append(macro)
                    continue

        # IPMI
        if self.module.params.get('ipmi_authtype') is not None:
            host_params['ipmi_authtype'] = ipmi_authtype_type.get(
                self.module.params.get('ipmi_authtype'))
        if self.module.params.get('ipmi_privilege') is not None:
            host_params['ipmi_privilege'] = ipmi_privilege_type.get(
                self.module.params.get('ipmi_privilege'))

        # Check the current encryption settings if the host exists.
        # If the host exists and already has PSK encryption,
        # then the tls_psk and tls_psk_identity parameters are optional.
        if (self.module.params.get('tls_accept') is not None or
                self.module.params.get('tls_connect') is not None):
            exist_psk_keys = False
            if exist_host is not None:
                if (exist_host['tls_accept'] in ['2', '3', '6', '7'] or
                        exist_host['tls_connect'] == '2'):
                    exist_psk_keys = True

        # tls_accept
        if self.module.params.get('tls_accept') is not None:
            result_dec_num = 0
            for each in self.module.params.get('tls_accept'):
                result_dec_num += tls_type.get(each)
            # if empty list of types == unencrypted
            if result_dec_num == 0:
                result_dec_num = 1
            host_params['tls_accept'] = str(result_dec_num)
            # check PSK params
            if 'psk' in self.module.params.get('tls_accept'):
                if (('tls_psk_identity' not in host_params or
                        'tls_psk' not in host_params) and exist_psk_keys is False):
                    self.module.fail_json(msg="Missing TLS PSK params")

        # tls_connect
        if self.module.params.get('tls_connect') is not None:
            if self.module.params.get('tls_connect') == '':
                host_params['tls_connect'] = '1'
            else:
                host_params['tls_connect'] = str(tls_type.get(
                    self.module.params.get('tls_connect')))
            # check PSK params
            if host_params['tls_connect'] == '2':
                if (('tls_psk_identity' not in host_params or
                        'tls_psk' not in host_params) and exist_psk_keys is False):
                    self.module.fail_json(msg="Missing TLS PSK params")

        # inventory mode
        if self.module.params.get('inventory_mode') is not None:
            host_params['inventory_mode'] = inventory_mode_types[
                self.module.params.get('inventory_mode')]

        # future inventory mode
        future_inventory_mode = '0'
        if self.module.params.get('inventory_mode') is not None:
            future_inventory_mode = host_params['inventory_mode']
            inventory_disable_reason_msg = 'Inventory mode is set to disabled in the task'
        else:
            if exist_host is not None:
                future_inventory_mode = exist_host['inventory_mode']
                inventory_disable_reason_msg = 'Inventory mode is set to disabled on the host'

        # Inventory
        if self.module.params.get('inventory') is not None:
            if future_inventory_mode == '-1':
                self.module.fail_json(
                    msg="Inventory parameters not applicable. {0}".format(
                        inventory_disable_reason_msg))
            inventory = {}
            param_inventory = self.module.params.get('inventory')
            for each in param_inventory:
                if each in inventory_fields.values():
                    if (future_inventory_mode == '1'
                            and hasattr(self, 'inventory_links')
                            and each in self.inventory_links):
                        self.module.fail_json(
                            msg="Inventory field '{0}' is already linked to the item '{1}' and cannot be updated".format(
                                each, self.inventory_links[each]))
                    else:
                        inventory[each] = param_inventory[each]
                else:
                    self.module.fail_json(
                        msg="Unknown inventory param: {0} Available: {1}".format(
                            each, ', '.join(inventory_fields.values())))
            if inventory:
                host_params['inventory'] = inventory

        # interface
        if self.module.params.get('interfaces') is not None:
            # TODO: host_params['interfaces'] = self.ihelper.generate_interfaces(
            # TODO:     self.module.params['interfaces'],
            # TODO:     exist_host.get('interfaces'))
            strategy = self.module.params['update_strategy']['interfaces']
            host_params['interfaces'] = []
            # Count of the created interfaces by type, but we will only
            # ever have one of each.
            interface_by_type = dict((k, 0) for k in interface_types)
            for each in self.module.params.get('interfaces'):
                if interface_by_type[each['type']] != 0:
                    # Fail fast
                    self.module.fail_json(
                        msg=''.join([
                            "Detected {0} ".format(each['type']),
                            "interface already defined in the task. ",
                            "Module supports only 1 interface of each type. ",
                            "Please resolve conflict manually."]))
                exist_interface = None
                interface = None
                if (exist_host is not None
                        and exist_host.get('interfaces') is not None):
                    exist_interfaces = [i for i in exist_host['interfaces']
                                        if (interface_types[each['type']]
                                            == i['type'])]
                    if len(exist_interfaces) == 1:
                        exist_interface = exist_interfaces[0]
                    elif len(exist_interfaces) > 1:
                        # Courtesy to the user
                        self.module.fail_json(
                            msg=''.join([
                                "Possible db corruption, found ",
                                "{0} interfaces for type {1}".format(
                                    len(exist_interface),
                                    interface_types[each['type']])]))
                if exist_interface is not None:
                    if strategy == 'merge':
                        interface = {}
                        for o in ['main', 'useip']:
                            if each.get(o) is not None:
                                interface[o] = '1' if each[o] else '0'
                            elif exist_interface.get(o) is not None:
                                interface[o] = exist_interface[o]

                        for o in ['ip', 'dns', 'port']:
                            for det in [each, exist_interface]:
                                if det.get(o) is not None and det[o]:
                                    interface[o] = det[o]
                                    break
                    elif strategy == 'delete':
                        continue
                if strategy == 'replace' or interface is None:
                    interface = {}
                    # resolve type
                    interface['type'] = interface_types[each['type']]
                    interface['main'] = '1' if (each.get('main') is None
                                                or each.get('main')) else '0'
                    interface['useip'] = '1' if each.get('useip') else '0'
                    # ip
                    if (each['useip']
                            and (each.get('ip') is None or not each.get('ip'))):
                        interface['ip'] = '127.0.0.1'
                    else:
                        if each.get('ip') is not None:
                            interface['ip'] = each['ip']
                    # DNS
                    if (not each['useip']
                            and (each.get('dns') is None or not each.get('dns'))):
                        self.module.fail_json(
                            msg="Required parameter not found: dns")
                    else:
                        if each.get('dns') is not None:
                            interface['dns'] = each['dns']
                    # ports
                    if each['port'] is not None:
                        interface['port'] = each['port']
                    else:
                        interface['port'] = default_values[
                            'ports'][each['type']]
                # SNMP
                if each['type'] == 'snmp':
                    self.generate_snmp_details(
                        strategy, each, interface, exist_interface)
                if interface.get('details') is None:
                    interface['details'] = []
                if exist_interface is not None:
                    interface['interfaceid'] = exist_interface['interfaceid']
                host_params['interfaces'].append(interface)
                interface_by_type[each['type']] = 1

        return host_params

    def generate_snmp_details(
            self, strategy, given_interface, target_interface,
            exist_interface=None):
        """
        The function generates the desired SNMP interface details 
        parameters based on the module parameters.
        The returned dictionary can be used to create a host, as well 
        as to compare with an existing host.

        :param exist_host: parameters of existing Zabbix host
        :type exist_host: dict

        :rtype: dict
        :return: parameters of desired host

        note::
            *  The 'exist_host' parameter is used to determine the 
                current encryption, inventory, and host group settings 
                on existing host.
        """
        given_details = given_interface.get('details')
        exist_details = None
        target_details = None
        if exist_interface is not None:
            exist_details = exist_interface.get('details')
        if target_interface.get('details') is None:
            target_details = {}
            target_interface['details'] = target_details

        if strategy == 'merge' and exist_details is not None:
            # Don't add bulk, version, securitylevel, or the protocol
            # parameters to merge_params since they require special
            # handling or are dependencies
            merge_params = []
            if given_details.get('bulk') is not None:
                target_details['bulk'] = '1' if given_details['bulk'] else '0'
            elif exist_details.get('bulk') is not None:
                target_details['bulk'] = exist_details['bulk']
            if given_details.get('version') is not None:
                if given_details['version'] not in ['1', '2', '3']:
                    self.module.fail_json(
                        msg="Invalid SNMP version: {0}".format(
                            given_details['version']))
                exist_details['version'] = given_details['version']
            elif exist_details.get('version') is not None:
                # TODO: Validate SNMP version from Zabbix?
                target_details['version'] = exist_details['version']
            # v3
            if target_details['version'] == '3':
                merge_params.extend(['contextname', 'securityname'])
                if given_details.get('securitylevel') is not None:
                    validate_arg(
                        self.module, snmp_securitylevel_types, given_details,
                        'securitylevel')
                    exist_details['securitylevel'] = snmp_securitylevel_types[
                        given_details['securitylevel']]
                elif exist_details.get('securitylevel') is not None:
                    target_details['securitylevel'] = exist_details[
                        'securitylevel']
                # authNoPriv
                if target_details['securitylevel'] in ['1', '2']:
                    if given_details.get('authprotocol') is not None:
                        validate_arg(
                            self.module, snmp_authprotocol_types,
                            given_details, 'authprotocol')
                        authprotocol = snmp_authprotocol_types[
                            given_details['authprotocol']]
                        target_details['authprotocol'] = authprotocol
                    elif exist_details.get('authprotocol') is not None:
                        target_details['authprotocol'] = exist_details[
                            'authprotocol']
                    merge_params.append('authpassphrase')
                # authPriv
                if target_details['securitylevel'] == '2':
                    if given_details.get('privprotocol') is not None:
                        validate_arg(
                            self.module, snmp_privprotocol_types,
                            given_details, 'privprotocol')
                        privprotocol = snmp_privprotocol_types[
                            given_details['privprotocol']]
                        target_details['privprotocol'] = privprotocol
                    elif exist_details.get('privprotocol') is not None:
                        target_details['privprotocol'] = exist_details[
                            'privprotocol']
                    merge_params.append('privpassphrase')
            else:
                # v1 and v2c
                merge_params.append('community')

            # Fields dependent on Zabbix version
            if (Zabbix_version(self.zbx_api_version)
                    >= Zabbix_version('6.4.0')):
                if (exist_details['version'] in ['2', '3']
                        and given_details.get('max_repetitions') is not None):
                    merge_params.append('max_repetitions')
            for o in merge_params:
                for det in [given_details, exist_details]:
                    if det.get(o) is not None:
                        target_details[o] = det[o]
                        break

        if strategy == 'replace' or exist_details is None:
            if given_details is None:
                # TODO: Add unit test case for this error.
                self.module.fail_json(
                    msg=''.join(["Required parameter for SNMP interface not ",
                                "found: details"]))
            # Check the required fields for SNMP
            if given_details.get('version') is None:
                self.module.fail_json(
                    msg="Required parameter not found: version")
            if given_details['version'] in ['1', '2']:
                req_parameters = snmp_parameters[given_details['version']]
            elif given_details['version'] == '3':
                if given_details.get('securitylevel') is None:
                    self.module.fail_json(
                        msg="Required parameter not found: securitylevel")
                validate_arg(
                    self.module, snmp_securitylevel_types, given_details,
                    'securitylevel')
                req_parameters = snmp_parameters[
                    given_details['version']][given_details['securitylevel']]
            else:
                self.module.fail_json(msg="Invalid SNMP version: {0}".format(
                    given_details['version']))
            # If additional fields need to be added and some logic is
            # required, then this can be done here.
            # If the new field only depends on the version, then it
            # must be added to the helper.
            if given_details['version'] in ['2', '3'] and (
                    Zabbix_version(self.zbx_api_version)
                    >= Zabbix_version('6.4.0')):
                req_parameters.append('max_repetitions')

            input_arguments = [e for e in given_details
                               if given_details[e] is not None]
            more_parameters = list(set(input_arguments) - set(req_parameters))
            less_parameters = list(set(req_parameters) - set(input_arguments))
            # TODO: Create a combined error when both conditionals are true?
            if more_parameters:
                self.module.fail_json(
                    msg="Incorrect arguments for SNMPv{0}: {1}".format(
                        given_details['version'],
                        ', '.join(more_parameters)))
            if less_parameters:
                self.module.fail_json(
                    msg=''.join(["Required parameter not found for SNMPv",
                                "{0}: {1}".format(
                                    given_details['version'],
                                    ', '.join(less_parameters))]))
            # v1 and v2c
            target_details['version'] = given_details['version']
            target_details['bulk'] = '1' if given_details['bulk'] else '0'
            # Only for Zabbix versions above 6.4
            if Zabbix_version(self.zbx_api_version) >= Zabbix_version('6.4.0'):
                if (target_details['version'] == '2'
                        or target_details['version'] == '3'):
                    target_details['max_repetitions'] = given_details[
                        'max_repetitions']
            # v3
            if target_details['version'] == '3':
                target_details['contextname'] = given_details['contextname']
                target_details['securityname'] = given_details['securityname']
                target_details['securitylevel'] = snmp_securitylevel_types[
                    given_details['securitylevel']]
                target_details['authprotocol'] = '0'
                target_details['authpassphrase'] = ''
                target_details['privprotocol'] = '0'
                target_details['privpassphrase'] = ''
                # authNoPriv
                if target_details['securitylevel'] in ['1', '2']:
                    validate_arg(
                        self.module, snmp_authprotocol_types, given_details,
                        'authprotocol')
                    target_details['authprotocol'] = snmp_authprotocol_types[
                        given_details['authprotocol']]
                    target_details['authpassphrase'] = given_details[
                        'authpassphrase']
                # authPriv
                if target_details['securitylevel'] == '2':
                    validate_arg(
                        self.module, snmp_privprotocol_types, given_details,
                        'privprotocol')
                    target_details['privprotocol'] = snmp_privprotocol_types[
                        given_details['privprotocol']]
                    target_details['privpassphrase'] = given_details[
                        'privpassphrase']
            else:
                target_details['community'] = given_details['community']

    def compare_zabbix_host(self, exist_host, new_host):
        """
        The function compares the parameters of an existing host with the
        desired new host parameters.

        :param exist_host: parameters of existing Zabbix host
        :type exist_host: dict
        :param new_host: parameters of desired host
        :type new_host: dict

        :rtype: dict
        :return: difference between existing and desired parameters.
        """
        param_to_update = {}

        # These parameters don't require additional processing
        wo_process = ['status', 'description', 'ipmi_authtype', 'proxy_hostid',
                      'ipmi_privilege', 'ipmi_username', 'ipmi_password',
                      'inventory_mode', 'tls_accept', 'tls_psk_identity',
                      'tls_psk', 'tls_issuer', 'tls_subject', 'tls_connect']
        for each in wo_process:
            if (new_host.get(each) is not None and
                    new_host.get(each) != exist_host.get(each)):
                param_to_update[each] = new_host[each]

        # hostgroups
        if new_host.get('groups'):
            diff_groups = list(
                set([g['groupid'] for g in new_host['groups']]) ^
                set([g['groupid'] for g in exist_host['groups']]))
            if diff_groups:
                param_to_update['groups'] = new_host['groups']

        # templates
        if new_host.get('templates') is not None:
            diff_templ = list(
                set([g['templateid'] for g in new_host['templates']]) ^
                set([g['templateid'] for g in exist_host['parentTemplates']]))

            if diff_templ:
                param_to_update['templates'] = new_host['templates']
                # list of templates to clean
                templates_clear = list(
                    set([g['templateid'] for g in exist_host['parentTemplates']]) -
                    set([g['templateid'] for g in new_host['templates']]))
                if templates_clear:
                    param_to_update['templates_clear'] = [{'templateid': t} for t in templates_clear]

        # visible name
        if new_host.get('name') is not None:
            if len(new_host['name']) == 0:
                new_host['name'] = exist_host['host']
            if new_host.get('name') != exist_host['name']:
                param_to_update['name'] = new_host['name']

        # tags
        if new_host.get('tags') is not None:
            old_tags = tag_to_dict_transform(exist_host['tags'])
            new_tags = tag_to_dict_transform(new_host['tags'])

            if len(list(set(old_tags) ^ set(new_tags))) != 0:
                param_to_update['tags'] = new_host['tags']
            else:
                for tag in new_tags:
                    if len(list(set(new_tags[tag]) ^ set(old_tags[tag]))) > 0:
                        param_to_update['tags'] = new_host['tags']
                        break

        # macros
        if new_host.get('macros') is not None:
            # dict() for compatibility with python 2.6
            new_macro = dict((m['macro'], m) for m in new_host['macros'])
            old_macro = dict((m['macro'], m) for m in exist_host['macros'])

            if len(list(set(new_macro) ^ set(old_macro))) != 0:
                param_to_update['macros'] = new_host['macros']
            else:
                for macro in new_macro:
                    if new_macro[macro]['value'] != old_macro[macro].get('value'):
                        param_to_update['macros'] = new_host['macros']
                        break
                    if new_macro[macro]['type'] != old_macro[macro]['type']:
                        param_to_update['macros'] = new_host['macros']
                        break
                    if new_macro[macro]['description'] != old_macro[macro]['description']:
                        param_to_update['macros'] = new_host['macros']
                        break

        # inventory
        if new_host.get('inventory') is not None:
            new_inventory = {}
            if len(exist_host['inventory']) > 0:
                for each in new_host['inventory']:
                    if new_host['inventory'][each] != exist_host['inventory'].get(each):
                        new_inventory[each] = new_host['inventory'][each]
            else:
                new_inventory = dict(new_host['inventory'])
            if new_inventory:
                param_to_update['inventory'] = new_inventory

        # interfaces
        if new_host.get('interfaces') is not None:
            # Check the number of interfaces by type on the host
            interfaces_types_name = dict((v, k) for k, v in interface_types.items())
            exist_interfaces_by_type = dict((v, 0) for v in interface_types.values())
            for interface in exist_host['interfaces']:
                exist_interfaces_by_type[interface['type']] += 1

            for each in exist_interfaces_by_type:
                if exist_interfaces_by_type[each] > 1:
                    self.module.fail_json(
                        msg="Detected {0} {1} interfaces on the host. Module supports only 1 interface of each type. Please resolve conflict manually.".format(
                            exist_interfaces_by_type[each],
                            interfaces_types_name[each]))

            # Check the differences between interfaces
            interface_updating_flag = False
            new_interfaces = []
            if len(new_host['interfaces']) != len(exist_host['interfaces']):
                interface_updating_flag = True

            for each in new_host['interfaces']:
                for interface in exist_host['interfaces']:
                    if each['type'] == interface['type']:
                        total_interface = each
                        new_interfaces.append(total_interface)
                        if total_interface != interface:
                            interface_updating_flag = True
                        break
                else:
                    new_interfaces.append(each)
                    interface_updating_flag = True

            if interface_updating_flag:
                param_to_update['interfaces'] = new_interfaces

        return param_to_update


def main():
    """entry point for module execution"""

    spec = {
        'state': {
            'type': 'str',
            'default': 'present',
            'choices': ['present', 'absent']},
        'hostid': {'type': 'str', 'aliases': ['id']},
        'host': {'type': 'str', 'aliases': ['host_name']},
        'update_strategy': {
            'type': 'dict',
            'options': {
                'hostgroups': {
                    'type': 'str',
                    'default': 'replace',
                    'choices': ['replace', 'merge', 'delete']
                    },
                'templates': {
                    'type': 'str',
                    'default': 'replace',
                    'choices': ['replace', 'merge', 'delete']},
                'macros': {
                    'type': 'str',
                    'default': 'replace',
                    'choices': ['replace', 'merge', 'delete']},
                'interfaces': {
                    'type': 'str',
                    'default': 'replace',
                    'choices': ['replace', 'merge', 'delete']}}},
        'host': {
            'type': 'str',
            'aliases': ['host_name']},
        'hostgroups': {
            'type': 'list',
            'elements': 'str',
            'aliases': ['host_group', 'host_groups']},
        'templates': {
            'type': 'list',
            'elements': 'str',
            'aliases': ['link_templates', 'host_templates', 'template']},
        'status': {
            'type': 'str',
            'choices': ['enabled', 'disabled']},
        'description': {'type': 'str'},
        'name': {
            'type': 'str',
            'aliases': ['visible_name']},
        'tags': {
            'type': 'list',
            'elements': 'dict',
            'aliases': ['host_tags'],
            'options': {
                'tag': {'type': 'str', 'required': True},
                'value': {'type': 'str', 'default': ''}}},
        'macros': {
            'type': 'list',
            'elements': 'dict',
            'aliases': ['user_macros', 'user_macro'],
            'options': {
                'macro': {'type': 'str', 'required': True},
                'value': {'type': 'str', 'default': ''},
                'description': {'type': 'str', 'default': ''},
                'type': {
                    'type': 'str',
                    'choices': ['text', 'secret', 'vault_secret'],
                    'default': 'text'}}},
        'ipmi_authtype': {
            'type': 'str',
            'choices': ['default', 'none', 'md2', 'md5',
                        'straight', 'oem', 'rmcp+']},
        'ipmi_privilege': {
            'type': 'str',
            'choices': ['callback', 'user', 'operator', 'admin', 'oem']},
        'ipmi_username': {'type': 'str'},
        'ipmi_password': {'type': 'str', 'no_log': True},
        'tls_accept': {
            'type': 'list',
            'elements': 'str',
            'choices': ['unencrypted', 'psk', 'cert']},
        'tls_connect': {
            'type': 'str',
            'choices': ['', 'unencrypted', 'psk', 'cert']},
        'tls_psk_identity': {'type': 'str', 'no_log': True},
        'tls_psk': {'type': 'str', 'no_log': True},
        'tls_issuer': {'type': 'str'},
        'tls_subject': {'type': 'str'},
        'proxy': {'type': 'str'},
        'inventory_mode': {
            'type': 'str',
            'choices': ['automatic', 'manual', 'disabled']},
        'inventory': {
            'type': 'dict',
            'aliases': ['inventory_zabbix', 'host_inventory']},
        'interfaces': {
            'type': 'list',
            'elements': 'dict',
            'options': {
                'type': {
                    'type': 'str',
                    'required': True,
                    'choices': ['agent', 'snmp', 'ipmi', 'jmx']},
                'useip': {'type': 'bool', 'default': True},
                'ip': {'type': 'str', 'default': ''},
                'dns': {'type': 'str', 'default': ''},
                'port': {'type': 'str'},
                'details': {
                    'type': 'dict',
                    'options': {
                        'version': {'type': 'str', 'choices': ['1', '2', '3']},
                        'bulk': {'type': 'bool'},
                        'community': {'type': 'str'},
                        'max_repetitions': {'type': 'str'},
                        'contextname': {'type': 'str'},
                        'securityname': {'type': 'str'},
                        'securitylevel': {
                            'type': 'str',
                            'choices': ['noAuthNoPriv', 'authNoPriv', 'authPriv']},
                        'authprotocol': {
                            'type': 'str',
                            'choices': ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']},
                        'authpassphrase': {'type': 'str', 'no_log': True},
                        'privprotocol': {
                            'type': 'str',
                            'choices': ['des', 'aes128', 'aes192', 'aes256', 'aes192c', 'aes256c']},
                        'privpassphrase': {'type': 'str', 'no_log': True}}}}}}

    module = AnsibleModule(
        argument_spec=spec,
        required_together=[('tls_psk_identity', 'tls_psk')],
        required_one_of=[('hostid', 'host')],
        supports_check_mode=True)

    state = module.params['state']
    host_id = module.params['hostid']
    host_name = module.params['host']

    host = Host(module, ZabbixApi(module))

    # Find a host in Zabbix
    if host_id and len(host_id) > 0:
        result = host.zapi.find_zabbix_host_by_hostid(host_id)
    else:
        result = host.zapi.find_zabbix_host_by_host(host_name)

    if state == 'present':

        if len(result) > 0:
            # Get the parameters of an existing host
            exist_host_params = host.get_zabbix_host(result[0]['hostid'])
            # Generate new host parameters
            new_host_params = host.generate_zabbix_host(exist_host_params)

            # Compare all parameters
            compare_result = host.compare_zabbix_host(
                exist_host_params,
                new_host_params)

            if compare_result:
                # Update host
                compare_result['hostid'] = result[0]['hostid']

                update_result = host.host_api_request(
                    method='host.update',
                    params=compare_result)

                if update_result:
                    module.exit_json(
                        changed=True,
                        result="Successfully updated host: {0}".format(
                            host_name))
                else:
                    module.fail_json(
                        msg="Failed to update host: {0}".format(host_name))
            else:
                # No need to update
                module.exit_json(
                    changed=False,
                    result="No need to update host: {0}".format(host_name))

        else:
            # Create host
            module.warn("Ignoring read-only property: {0}".format(module.params['hostid']))
            new_host_params = host.generate_zabbix_host()

            result = host.host_api_request(
                method='host.create',
                params=new_host_params)
            if result:
                module.exit_json(
                    changed=True,
                    result="Successfully created host: {0}".format(host_name))
            else:
                module.fail_json(
                    msg="Failed to create host: {0}".format(host_name))

    else:
        if len(result) > 0:
            # delete host
            delete_result = host.host_api_request(
                method='host.delete',
                params=[result[0]['hostid']])
            if delete_result:
                module.exit_json(
                    changed=True,
                    result="Successfully delete host: {0}".format(host_name))
            else:
                module.fail_json(
                    msg="Failed to delete host: {0}".format(host_name))
        else:
            # No need to delete host
            module.exit_json(
                changed=False,
                result="No need to delete host: {0}".format(host_name))


if __name__ == '__main__':
    main()
