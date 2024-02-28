#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright: Zabbix Ltd
# GNU General Public License v2.0+ (see COPYING or https://www.gnu.org/licenses/gpl-2.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


from ansible_collections.zabbix.zabbix.plugins.modules import zabbix_host
from ansible_collections.zabbix.zabbix.plugins.module_utils.zabbix_api import (
    ZabbixApi)
from ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.common import (
    AnsibleFailJson)
from ansible_collections.zabbix.zabbix.plugins.module_utils.helper import (
    inventory_mode_types, snmp_authprotocol_types, snmp_privprotocol_types)
import pytest


def mock_api_version(self):
    """
    Mock function to get Zabbix API version. In this case,
    it doesn't matter which version of API is returned.
    """
    return '6.0.18'


@pytest.fixture
def fixture_zabbixapi(mocker):
    def mock_api_version(self):
        """
        Mock function to get Zabbix API version. In this case,
        it doesn't matter which version of API is returned.
        """
        return '6.0.18'
    mocker.patch("ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.test_zabbix_host_generation_pytest.ZabbixApi.api_version", mock_api_version)


@pytest.fixture
def fixture_zabbixapi_64(mocker):
    def mock_api_version(self):
        """
        Mock function to get Zabbix API version. In this case,
        it doesn't matter which version of API is returned.
        """
        return '6.4.5'
    # mock_zabbixapi = MagicMock()
    # mock_zabbixapi.api_version = mock_api_version
    # yield mock_zabbixapi
    mocker.patch("ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.test_zabbix_host_generation_pytest.ZabbixApi.api_version", mock_api_version)


@pytest.fixture(params=['6.0.18', '6.4.5'])
def fixture_zabbixapi_multi(mocker, request):
    def mock_api_version(self):
        """
        Mock function to get Zabbix API version. In this case,
        it doesn't matter which version of API is returned.
        """
        return request.param
    # mock_zabbixapi = MagicMock()
    # mock_zabbixapi.api_version = mock_api_version
    # yield mock_zabbixapi
    mocker.patch("ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.test_zabbix_host_generation_pytest.ZabbixApi.api_version", mock_api_version)


class TestInterfaces_pytest(object):
    """
    Class for testing the operation of the module with interface 
    parameters.

    Test areas:
    - ip/port defaults [all interface types]
    - ip/dns passthrough [all interface types]
    - dns requirement [all interface types]
    - improper dns requirement [all interface types]
    - invalid snmp version [snmp]
    - missing snmp version [snmp]
    - invalid useip values [agent ipmi jmx]
    - invalid useip values [snmp]
    - invalid bulk values [snmp]
    - required parameters [snmpv1 snmpv2]
    - required parameters > 6.4 [snmpv1 snmpv2]
    - additional (incorrect) parameters [snmpv1 snmpv2]
    - required parameters [snmpv3]
    - required parameters > 6.4 [snmpv3]
    - additional (incorrect) parameters [snmpv3]
    - invalid securitylevel [snmpv3]
    - missing securitylevel [snmpv3]
    """
    hostmodulepy = zabbix_host

    agent_snmp_ipmi_jmx_interface_creation_ip_port_defaults_test_cases = [
        # type, port, details
        (
            ('agent', '1'),
            (None, '10050'),
            (None, [])
        ),
        (
            ('snmp', '2'),
            (None, '161'),
            (
                {'version': '1', 'bulk': True, 'community': '111'},
                {'version': '1', 'bulk': '1', 'community': '111'}
            )
        ),
        (
            ('ipmi', '3'),
            (None, '623'),
            (None, [])
        ),
        (
            ('jmx', '4'),
            (None, '12345'),
            (None, [])
        )
    ]

    @pytest.mark.parametrize(
        "itype, iport, idetails",
        agent_snmp_ipmi_jmx_interface_creation_ip_port_defaults_test_cases)
    def test_agent_snmp_ipmi_jmx_interface_creation_ip_port_defaults(
            self, itype, iport, idetails, fixture_zabbixapi,
            fixture_connection, fixture_hostmodule):
        """
        Testing interface ip and port defaults in the creation of 
        new interfaces for a given host.

        Test cases:
        1. agent interface
        2. SNMP interface
        3. IPMI interface
        4. JMX interface

        Expected result: all test cases run successfully.
        """
        input = 0
        expected = 1
        exist_host = {'host': 'test_host', 'inventory_mode': '1',
                      'interfaces': []}

        input_param = {
            'host': 'test_host',
            'interfaces': [{
                'type': itype[input], 'port': iport[input], 'useip': True,
                'ip': '', 'dns': '',
                'details': idetails[input]}]}
        expected_result = {
            'host': 'test_host',
            'interfaces': [{
                'type': itype[expected], 'port': iport[expected], 'useip': '1',
                'ip': '127.0.0.1', 'dns': '',
                'details': idetails[expected], 'main': '1'}]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        result = host.generate_zabbix_host(exist_host)

        assert input_param['interfaces'][0]['ip'] == ''
        assert len(expected_result['interfaces']) == len(result['interfaces'])
        assert expected_result['interfaces'] == result['interfaces']
        # for expected in expected_result['interfaces']:
        #    assert expected in result['interfaces']

    agent_snmp_ipmi_jmx_interface_creation_param_passthru_test_cases = [
        (
            ('agent', '1'),  # type
            ('10.10.0.10', '10.10.0.10'),  # ip
            ('test_agent.com', 'test_agent.com'),  # dns
            (None, [])  # details
        ),
        (
            ('snmp', '2'),
            ('10.10.20.55', '10.10.20.55'),
            ('test_snmp.com', 'test_snmp.com'),
            ({'version': '1', 'bulk': True, 'community': '111'},
             {'version': '1', 'bulk': '1', 'community': '111'})),
        (
            ('ipmi', '3'),
            ('10.10.30.6', '10.10.30.6'),
            ('test_ipmi.com', 'test_ipmi.com'),
            (None, [])
        ),
        (
            ('jmx', '4'),
            ('10.10.5.2', '10.10.5.2'),
            ('test_jmx.com', 'test_jmx.com'),
            (None, [])
        )
    ]

    @pytest.mark.parametrize(
        "itype, ip, dns, idetails",
        agent_snmp_ipmi_jmx_interface_creation_param_passthru_test_cases)
    def test_agent_snmp_ipmi_jmx_interface_creation_param_passthru_defaults(
            self, itype, ip, dns, idetails, fixture_zabbixapi,
            fixture_connection, fixture_hostmodule):
        """
        Testing interface ip and dns value passthrough in the 
        creation of new interfaces for a given host.

        Test cases:
        1. agent interface
        2. SNMP interface
        3. IPMI interface
        4. JMX interface

        Expected result: all test cases run successfully.
        """
        input = 0
        expected = 1
        exist_host = {'host': 'test_host', 'inventory_mode': '1',
                      'interfaces': []}

        input_param = {
            'host': 'test_host',
            'interfaces': [{
                'type': itype[input], 'port': '1000', 'useip': True,
                'ip': ip[input], 'dns': dns[input],
                'details': idetails[input]}]}
        expected_result = {
            'host': 'test_host',
            'interfaces': [{
                'type': itype[expected], 'port': '1000', 'useip': '1',
                'ip': ip[expected], 'dns': dns[expected],
                'details': idetails[expected], 'main': '1'}]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        result = host.generate_zabbix_host(exist_host)

        assert len(expected_result['interfaces']) == len(result['interfaces'])
        assert expected_result['interfaces'] == result['interfaces']

    require_dns_test_cases = [
        {'type': 'agent', 'useip': False, 'ip': '10.10.10.10', 'dns': '',
            'port': '10051'},
        {'type': 'snmp', 'useip': False, 'ip': '30.30.30.30', 'dns': '',
            'port': '161', 'details': {
                'version': '1', 'bulk': True, 'community': '111'}},
        {'type': 'ipmi', 'useip': False, 'ip': '20.20.20.20', 'dns': '',
            'port': '650'},
        {'type': 'jmx', 'useip': False, 'ip': '30.30.30.30', 'dns': '',
            'port': '23456'}
    ]

    @pytest.mark.parametrize("input", require_dns_test_cases)
    def test_required_param_exception_dns(
            self, input, fixture_zabbixapi,
            fixture_connection, fixture_hostmodule):
        """
        Testing the creation of interfaces for monitoring via DNS. In 
        this case, the DNS name field is required.

        Expected result: an exception with an error message.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_param = {
            'host': 'test_host',
            'interfaces': [input]}
        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        with pytest.raises(
                AnsibleFailJson,
                match="Required parameter not found") as ansible_result:
            host.generate_zabbix_host(exist_host)
        assert ansible_result.value.args[0]['failed']
        assert 'dns' in ansible_result.value.args[0]['msg']

    def should_not_test_require_dns(
            self, fixture_zabbixapi, fixture_connection, fixture_hostmodule):
        """
        The dns property is still required even when useip is true.

        Expected result: an exception with an error message.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_param = {
            'host': 'test_host',
            'interfaces': [{'type': 'agent', 'useip': True,
                            'ip': '10.10.10.10', 'port': '10051'}]}
        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        with pytest.raises(KeyError) as key_err:
            host.generate_zabbix_host(exist_host)
        assert 'dns' in key_err.value.args[0]

    snmp_missing_notset_version_test_cases = [
        (
            {'bulk': True, 'community': '111',
             'securitylevel': 'noAuthNoPriv'},
            ['version']
        ),
        (
            {'version': None, 'bulk': True, 'community': '111',
             'securitylevel': 'noAuthNoPriv'},
            ['version']
        )
    ]

    @pytest.mark.parametrize(
        'input, keys',
        snmp_missing_notset_version_test_cases)
    def test_snmp_missing_notset_version(
            self, input, keys, fixture_zabbixapi, fixture_connection,
            fixture_hostmodule):
        """
        Testing the validity of the version parameter of 
        SNMP interfaces.
        Test cases:

        1. Missing parameter: version.
        2. Parameter not set: version.

        Expected result: all test cases KeyErrors.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_interface = {
            'type': 'snmp', 'useip': True,
            'ip': '127.0.0.1', 'dns': 'test_snmp.com', 'port': '161'}
        input_interface['details'] = input

        input_param = {
            'host': 'test_host',
            'interfaces': [input_interface]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        with pytest.raises(
                AnsibleFailJson,
                match="Required parameter not found") as ansible_result:
            host.generate_zabbix_host(exist_host)
        assert ansible_result.value.args[0]['failed']
        for parameter in keys:
            assert parameter in ansible_result.value.args[0]['msg']

    snmp_invalid_version_test_cases = [       
        ( # Test case 1
            {'version': '4', 'bulk': True, 'community': '111',
             'securitylevel': 'noAuthNoPriv'},
            '4'
        ),    
        ( # Test case 2
            {'version': 'garbage', 'bulk': True, 'community': '111',
             'securitylevel': 'noAuthNoPriv'},
            'garbage'
        )
    ]

    @pytest.mark.parametrize(
        'input, value',
        snmp_invalid_version_test_cases)
    def test_snmp_invalid_version(
            self, input, value, fixture_zabbixapi, fixture_connection,
            fixture_hostmodule):
        """
        Testing the validity of the version parameter of 
        SNMP interfaces.
        Test cases:

        1. Invalid argument: SNMP version = 4.
        1. Invalid argument: SNMP version = garbage.

        Expected result: all test cases KeyErrors.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_interface = {
            'type': 'snmp', 'useip': True,
            'ip': '127.0.0.1', 'dns': 'test_snmp.com', 'port': '161'}
        input_interface['details'] = input

        input_param = {
            'host': 'test_host',
            'interfaces': [input_interface]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        with pytest.raises(
                AnsibleFailJson,
                match="Invalid SNMP version") as ansible_result:
            host.generate_zabbix_host(exist_host)
        assert ansible_result.value.args[0]['failed']
        assert value in ansible_result.value.args[0]['msg']

    useip_bulk_test_values = [
        (True, '1'),
        ('garbage', '1'),
        ('0', '1'),
        (1, '1'),
        (0, '0')
    ]

    agent_ipmi_jmx_invalid_useip_test_cases = [
        (
            {'type': 'agent', 'useip': None, 'ip': '127.0.0.1',
             'dns': 'test_agent.com', 'port': '161'},
            {'type': '1', 'useip': None, 'ip': '127.0.0.1',
             'dns': 'test_agent.com', 'port': '161',
             'details': [], 'main': '1'}
        ),
        (
            {'type': 'ipmi', 'useip': None, 'ip': '127.0.0.1',
             'dns': 'test_ipmi.com', 'port': '161'},
            {'type': '3', 'useip': None, 'ip': '127.0.0.1',
             'dns': 'test_ipmi.com', 'port': '161',
             'details': [], 'main': '1'}
        ),
        (
            {'type': 'jmx', 'useip': None, 'ip': '127.0.0.1',
             'dns': 'test_jmx.com', 'port': '161'},
            {'type': '4', 'useip': None, 'ip': '127.0.0.1',
             'dns': 'test_jmx.com', 'port': '161',
             'details': [], 'main': '1'}
        )
    ]

    @pytest.mark.parametrize("useip", useip_bulk_test_values)
    @pytest.mark.parametrize(
        'input_dict, expected_dict',
        agent_ipmi_jmx_invalid_useip_test_cases)
    def test_agent_ipmi_jmx_invalid_useip(
            self, useip, input_dict, expected_dict, fixture_zabbixapi,
            fixture_connection, fixture_hostmodule):
        """
        Testing cases of invalid values for useip and bulk parameters
        of agent, IPMI, and JMX interfaces.
        Test cases:

        1. Interface useip with non-bool argument ('garbage').
        2. Interface useip with non-bool argument ('0').
        3. Interface useip with non-bool argument (1).
        4. Interface useip with non-bool argument (0).       

        Expected result: all test cases run successfully.
        """
        input = 0
        expected = 1
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_dict['useip'] = useip[input]
        expected_dict['useip'] = useip[expected]

        input_param = {
            'host': 'test_host',
            'interfaces': [input_dict]}
        expected_result = {
            'host': 'test_host',
            'interfaces': [expected_dict]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        result = host.generate_zabbix_host(exist_host)

        assert len(expected_result['interfaces']) == len(result['interfaces'])
        assert expected_result['interfaces'][0] == result['interfaces'][0]

    snmp_v1_v2_v3_invalid_useip_bulk_test_cases = [
        (
            {'type': 'snmp', 'useip': None, 'ip': '127.0.0.1',
             'dns': 'test_snmp.com', 'port': '161',
             'details': {
                 'version': '1', 'bulk': None, 'community': '111'}
             },
            {'type': '2', 'useip': None, 'ip': '127.0.0.1', 'port': '161',
             'dns': 'test_snmp.com', 'main': '1',
             'details': {'version': '1', 'bulk': None, 'community': '111'}}
        ),
        (
            {'type': 'snmp', 'useip': None, 'ip': '127.0.0.1',
             'dns': 'test_snmp.com', 'port': '161',
             'details': {
                 'version': '2', 'bulk': None, 'community': '111'}
             },
            {'type': '2', 'useip': None, 'ip': '127.0.0.1', 'port': '161',
             'dns': 'test_snmp.com', 'main': '1',
             'details': {'version': '2', 'bulk': None, 'community': '111'}}
        ),
        (
            {'type': 'snmp', 'useip': None, 'ip': '127.0.0.1',
             'dns': 'test_snmp.com', 'port': '161',
             'details': {
                 'version': '3', 'bulk': None, 'securitylevel': 'noAuthNoPriv',
                 'contextname': 'contextname', 'securityname': 'securityname'}
             },
            {'type': '2', 'useip': None, 'ip': '127.0.0.1', 'port': '161',
             'dns': 'test_snmp.com', 'main': '1',
             'details': {
                 'version': '3', 'bulk': None, 'securitylevel': '0',
                 'contextname': 'contextname', 'securityname': 'securityname',
                 'authprotocol': '0', 'authpassphrase': '',
                 'privprotocol': '0', 'privpassphrase': ''}}
        )
    ]

    @pytest.mark.parametrize("useip", useip_bulk_test_values)
    @pytest.mark.parametrize("bulk", useip_bulk_test_values)
    @pytest.mark.parametrize(
        'input_dict, expected_dict',
        snmp_v1_v2_v3_invalid_useip_bulk_test_cases)
    def test_snmp_v1_v2_v3_invalid_useip_bulk(
            self, useip, bulk, input_dict, expected_dict,
            fixture_zabbixapi, fixture_connection, fixture_hostmodule):
        """
        Testing cases of invalid values for useip and bulk parameters 
        of SNMP interfaces.
        Test cases:

        SNMPv1/SNMPv2/SNMPv3:
        1. Interface useip with non-bool argument ('garbage').
        2. Interface useip with non-bool argument ('0').
        3. Interface useip with non-bool argument (1).
        4. Interface useip with non-bool argument (0).

        5. Interface bulk with non-bool argument ('garbage').
        6. Interface bulk with non-bool argument ('0').
        7. Interface bulk with non-bool argument (1).
        8. Interface bulk with non-bool argument (0).

        Expected result: all test cases run successfully.
        """
        input = 0
        expected = 1
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_dict['useip'] = useip[input]
        expected_dict['useip'] = useip[expected]

        input_dict['details']['bulk'] = bulk[input]
        expected_dict['details']['bulk'] = bulk[expected]

        input_param = {
            'host': 'test_host',
            'interfaces': [input_dict]}
        expected_result = {
            'host': 'test_host',
            'interfaces': [expected_dict]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        result = host.generate_zabbix_host(exist_host)

        assert len(expected_result['interfaces']) == len(result['interfaces'])
        assert expected_result['interfaces'][0] == result['interfaces'][0]

    snmp_v1_v2_required_param_exception_test_cases = [
        (  # test case 1
            {'bulk': None, 'community': '111', 'max_repetitions': None,
             'contextname': None, 'securityname': None, 'securitylevel': None,
             'authprotocol': None, 'authpassphrase': None,
             'privprotocol': None, 'privpassphrase': None},
            ['bulk']
        ),
        (  # test case 2
            {'community': '111'},
            ['bulk']
        ),
        (  # test case 3
            {'bulk': True, 'community': None},
            ['community']
        ),
        (  # test case 4
            {'bulk': True},
            ['community']
        ),
        (  # test case 5
            {'bulk': None, 'community': None},
            ['bulk', 'community']
        ),
        (  # test case 6
            {},
            ['bulk', 'community']
        ),
        (  # test case 7
            {'community': None},
            ['bulk', 'community']
        ),
        (  # test case 8
            {'bulk': None},
            ['bulk', 'community']
        )
    ]

    @pytest.mark.parametrize('version', ['1', '2'])
    @pytest.mark.parametrize(
        'input, keys',
        snmp_v1_v2_required_param_exception_test_cases)
    def test_snmp_v1_v2_required_param_exception(
            self, version, input, keys, fixture_zabbixapi,
            fixture_connection, fixture_hostmodule):
        """
        Testing when required parameters of SNMP version 1 and 2 
        interfaces are missing/None.
        Test cases (see req_param_exception_v1_v2_test_cases):

        SNMPv1/SNMPv2:
        1. Interface version 1/2 bulk is None (one parameter in error).
        2. Interface version 1/2 bulk is missing (one parameter in 
            error).
        3. Interface version 1/2 community is None (one parameter in 
            error).
        4. Interface version 1/2 community is missing (one parameter 
            in error).
        5. Interface version 1/2 bulk is None and community is None 
            (both parameters  in error).
        6. Interface version 1/2 bulk is missing and community is 
            missing (both parameters  in error).
        7. Interface version 1/2 bulk is missing and community is None 
            (both parameters  in error).
        8. Interface version 1/2 bulk is None and community is missing 
            (both parameters  in error).   

        Expected result: all test cases raise exception.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_interface = {'type': 'snmp', 'useip': True, 'ip': '127.0.0.1',
                           'dns': 'test_snmp.com', 'port': '161'}
        input_interface['details'] = input
        input_interface['details']['version'] = version

        input_param = {
            'host': 'test_host',
            'interfaces': [input_interface]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        with pytest.raises(
                AnsibleFailJson,
                match="Required parameter not found") as ansible_result:
            host.generate_zabbix_host(exist_host)
        assert ansible_result.value.args[0]['failed']
        for parameter in keys:
            assert parameter in ansible_result.value.args[0]['msg']

    snmp_v1_v2_incorrect_args_exception_test_cases = [
        (  # test case 1
            {'bulk': True, 'community': '111', 'contextname': 'contextname'},
            ['contextname']
        ),
        (  # test case 2
            {'bulk': True, 'community': '111', 'max_repetitions': None,
             'contextname': 'contextname', 'securityname': None,
             'securitylevel': None,
             'authprotocol': None, 'authpassphrase': None,
             'privprotocol': None, 'privpassphrase': None},
            ['contextname']
        ),
        (  # test case 3
            {'bulk': True, 'contextname': 'contextname'},
            ['contextname']
        )
    ]

    @pytest.mark.parametrize('version', ['1', '2'])
    @pytest.mark.parametrize(
        'input, keys',
        snmp_v1_v2_incorrect_args_exception_test_cases)
    def test_snmp_v1_v2_incorrect_args_exception(
            self, version, input, keys, fixture_zabbixapi,
            fixture_connection, fixture_hostmodule):
        """
        Testing of disallowed parameters for SNMP version 1 and 2 
        interfaces.
        Test cases (see snmp_v1_v2_incorrect_args_exception_test_cases):

        SNMPv1/SNMPv2:
        1. Interface version 1/2 with additional parameter from SNMPv3 
            (context name).
        2. Interface version 1/2 with additional parameter from SNMPv3 
            (context name) and other SNMPv3 parameters set to None.
        3. Interface version 1/2 with additional parameter (context 
            name) and missing parameter (community).

        Expected result: all test cases raise exception.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_interface = {'type': 'snmp', 'useip': True, 'ip': '127.0.0.1',
                           'dns': 'test_snmp.com', 'port': '161'}
        input_interface['details'] = input
        input_interface['details']['version'] = version

        input_param = {
            'host': 'test_host',
            'interfaces': [input_interface]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        with pytest.raises(
                AnsibleFailJson,
                match="Incorrect arguments for") as ansible_result:
            host.generate_zabbix_host(exist_host)
        assert ansible_result.value.args[0]['failed']
        assert "Incorrect arguments for" in ansible_result.value.args[0]['msg']
        for parameter in keys:
            assert parameter in ansible_result.value.args[0]['msg']

    snmp_v2_64_req_params_exception_test_cases = [
        (  # Interface version 2 not specifying max_repetitions
            {'version': '2', 'bulk': False, 'community': 'public'},
            ['max_repetitions']
        ),
        (  # Interface version 2 not specifying max_repetitions
            {'version': '2', 'bulk': False, 'community': 'public',
             'max_repetitions': None},
            ['max_repetitions']
        )]

    @pytest.mark.parametrize(
        'input, keys', snmp_v2_64_req_params_exception_test_cases)
    def test_snmp_v2_64_req_params_exception(
            self, input, keys, fixture_zabbixapi_64,
            fixture_connection, fixture_hostmodule):
        """
        Testing SNMP version 2 for Zabbix version above 6.4. In this
        case, the 'max_repetitions' field is required.
        Test cases:

        1. Interface version 2 max_repetitions missing.
        1. Interface version 2 max_repetitions set to None.

        Expected result: all test cases raise exception.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_interface = {'type': 'snmp', 'useip': True, 'ip': '127.0.0.1',
                           'dns': 'test_snmp.com', 'port': '161'}
        input_interface['details'] = input

        input_param = {
            'host': 'test_host',
            'interfaces': [input_interface]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        with pytest.raises(
                AnsibleFailJson,
                match="Required parameter not found") as ansible_result:
            host.generate_zabbix_host(exist_host)
        assert ansible_result.value.args[0]['failed']
        for parameter in keys:
            assert parameter in ansible_result.value.args[0]['msg']

    snmp_v3_missing_or_invalid_parameters_test_cases = [
        (  # test case 1
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
                'securityname': 'securityname', 'securitylevel': 'garbage'},
            'garbage'
        ),
        (  # test case 2
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
                'securityname': 'securityname', 'securitylevel': 'authNoPriv',
                'authprotocol': 'garbage', 'authpassphrase': ''},
            'garbage'
        ),
        (  # test case 3
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
                'securityname': 'securityname', 'securitylevel': 'authPriv',
                'authprotocol': 'md5', 'authpassphrase': '',
                'privprotocol': 'garbage', 'privpassphrase': ''},
            'garbage'
        )
    ]

    @pytest.mark.parametrize(
        'input, keys',
        snmp_v3_missing_or_invalid_parameters_test_cases)
    def test_snmp_v3_missing_or_invalid_parameters(
            self, input, keys, fixture_zabbixapi, fixture_connection,
            fixture_hostmodule):
        """
       Testing details of SNMP version 3 interfaces.
        Test cases:

        SNMPv3:
        1. Interface version 3 security level is invalid (garbage).

        SNMPv3 (authNoPriv):
        2. Interface version 3 authentication protocol is invalid 
            (garbage).

        SNMPv3 (authPriv):
        3. Interface version 3 privacy protocol is invalid (garbage).

        Expected result: all test cases raise KeyError.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_interface = {'type': 'snmp', 'useip': True, 'ip': '127.0.0.1',
                           'dns': 'test_snmp.com', 'port': '161'}
        input_interface['details'] = input

        input_param = {
            'host': 'test_host',
            'interfaces': [input_interface]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        # with pytest.raises(KeyError) as key_err:
        #     host.generate_zabbix_host(exist_host)
        # # print(key_err.value.args[0])
        # assert keys in key_err.value.args[0]

        with pytest.raises(
                AnsibleFailJson,
                match="Invalid argument for") as ansible_result:
            host.generate_zabbix_host(exist_host)
        assert ansible_result.value.args[0]['failed']
        for parameter in keys:
            assert parameter in ansible_result.value.args[0]['msg']

    snmp_v3_req_params_exception_test_cases = [
        (  # test case 1
            {'version': '3', 'bulk': True},
            ['securitylevel']
        ),
        (  # test case 2
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
                'securityname': 'securityname', 'securitylevel': None},
            ['securitylevel']
        ),
        (  # test case 3
            {'version': '3', 'bulk': True,
                'securityname': 'securityname',
                'securitylevel': 'noAuthNoPriv'},
            ['contextname']
        ),
        (  # test case 4
            {'version': '3', 'bulk': None, 'contextname': None,
                'securityname': 'securityname',
                'securitylevel': 'noAuthNoPriv'},
            ['bulk', 'contextname']
        ),
        (  # test case 5
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
                'securityname': 'securityname',
                'securitylevel': 'authNoPriv',
                'authprotocol': None, 'authpassphrase': None},
            ['authprotocol']
        ),
        (  # test case 6
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
                'securityname': 'securityname', 'securitylevel': 'authNoPriv',
                'authpassphrase': None},
            ['authprotocol']
        ),
        (  # test case 7
            {'version': '3', 'bulk': True, 'contextname': None,
                'securityname': 'securityname', 'securitylevel': 'authNoPriv',
                'authprotocol': None, 'authpassphrase': None},
            ['contextname', 'authprotocol']
        ),
        (  # test case 8
            {'version': '3', 'bulk': True,
                'securityname': 'securityname', 'securitylevel': 'authNoPriv',
                'authpassphrase': None},
            ['contextname', 'authprotocol']
        ),
        (  # test case 9
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'authPriv',
             'authprotocol': None, 'authpassphrase': None,
             'privprotocol': 'des', 'privpassphrase': 'privpassphrase'},
            ['authprotocol', 'authpassphrase']
        ),
        (  # test case 10
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'authPriv',
             'privprotocol': 'des', 'privpassphrase': 'privpassphrase'},
            ['authprotocol', 'authpassphrase']
        ),
        (  # test case 11
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'authPriv',
             'authprotocol': 'md5', 'authpassphrase': 'authpassphrase',
             'privprotocol': None, 'privpassphrase': None},
            ['privprotocol', 'privpassphrase']
        ),
        (  # test case 12
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'authPriv',
             'authprotocol': 'md5', 'authpassphrase': 'authpassphrase',
             },
            ['privprotocol', 'privpassphrase']
        ),
        (  # test case 13
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'authPriv',
             'authprotocol': None, 'authpassphrase': None,
             'privprotocol': None, 'privpassphrase': None},
            ['authprotocol', 'authpassphrase',
             'privprotocol', 'privpassphrase']
        ),
        (  # test case 14
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'authPriv'},
            ['authprotocol', 'authpassphrase',
             'privprotocol', 'privpassphrase']
        )
    ]

    @pytest.mark.parametrize(
        'input, keys',
        snmp_v3_req_params_exception_test_cases)
    def test_snmp_v3_req_params_exception(
            self, input, keys, fixture_zabbixapi,
            fixture_connection, fixture_hostmodule):
        """        
        Testing detection of required parameters of SNMP version 3 
        interfaces.
        Test cases:

        SNMPv3 (noAuthNoPriv):
        1. Missing parameter: security level.
        2. Parameter not set: security level.
        3. Missing parameter: context name.
        4. Parameters set to None: bulk and context name.

        SNMPv3 (authNoPriv):
        5. Parameter not set: authentication protocol.
        6. Missing parameter: authentication protocol.
        7. Parameters set to None: authentication protocol and 
            context name.
        8. Missing parameters: authentication protocol and context name.

        SNMPv3 (authPriv):
        9. Parameters set to None: authentication protocol and 
            passphrase.
        10. Missing parameters: authentication protocol and passphrase.
        11. Parameters set to None: privacy protocol and passphrase.
        12. Missing parameters: privacy protocol and passphrase.
        13. Parameters set to None: authentication and privacy 
            parameters.
        14. Missing parameters: authentication and privacy parameters.

        Expected result: all test cases raise 'required parameter' 
        exception.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_interface = {'type': 'snmp', 'useip': True, 'ip': '127.0.0.1',
                           'dns': 'test_snmp.com', 'port': '161'}
        input_interface['details'] = input

        input_param = {
            'host': 'test_host',
            'interfaces': [input_interface]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        with pytest.raises(
                AnsibleFailJson,
                match="Required parameter not found") as ansible_result:
            host.generate_zabbix_host(exist_host)
        assert ansible_result.value.args[0]['failed']
        for parameter in keys:
            assert parameter in ansible_result.value.args[0]['msg']

    snmp_v3_64_req_params_exception_test_cases = [
        (  # Test case 1
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'noAuthNoPriv'},
            ['max_repetitions']
        ),
        (  # Test case 2
            {'version': '3', 'bulk': True, 'max_repetitions': None,
             'contextname': 'contextname', 'securityname': 'securityname',
             'securitylevel': 'noAuthNoPriv'},
            ['max_repetitions']
        ),
        (  # Test case 3
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'authNoPriv',
             'authprotocol': 'md5', 'authpassphrase': 'authpassphrase',
             },
            ['max_repetitions']
        ),
        (  # Test case 4
            {'version': '3', 'bulk': True, 'max_repetitions': None,
             'contextname': 'contextname', 'securityname': 'securityname',
             'securitylevel': 'authNoPriv',
             'authprotocol': 'md5', 'authpassphrase': 'authpassphrase',
             },
            ['max_repetitions']
        ),
        (  # Test case 5
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'authPriv',
             'authprotocol': 'md5', 'authpassphrase': 'authpassphrase',
             'privprotocol': 'des', 'privpassphrase': 'privpassphrase'},
            ['max_repetitions']
        ),
        (  # Test case 6
            {'version': '3', 'bulk': True, 'max_repetitions': None,
             'contextname': 'contextname', 'securityname': 'securityname',
             'securitylevel': 'authPriv',
             'authprotocol': 'md5', 'authpassphrase': 'authpassphrase',
             'privprotocol': 'des', 'privpassphrase': 'privpassphrase'},
            ['max_repetitions']
        )
    ]

    @pytest.mark.parametrize(
        'input, keys',
        snmp_v3_64_req_params_exception_test_cases)
    def test_snmp_v3_64_req_params_exception(
            self, input, keys, fixture_zabbixapi_64,
            fixture_connection, fixture_hostmodule):
        """
        Testing SNMP version 3 for Zabbix version above 6.4. In this 
        case, the 'max_repetitions' field is required.
        Test cases:

        SNMPv3 (noAuthNoPriv):
        1. Interface version 3 max_repetitions is missing
        2. Interface version 3 max_repetitions is None

        SNMPv3 (authNoPriv):
        3. Interface version 3 max_repetitions is missing
        4. Interface version 3 max_repetitions is None

        SNMPv3 (authPriv):
        5. Interface version 3 max_repetitions is missing
        6. Interface version 3 max_repetitions is None

        Expected result: all test cases ran successfully.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_interface = {'type': 'snmp', 'useip': True, 'ip': '127.0.0.1',
                           'dns': 'test_snmp.com', 'port': '161'}
        input_interface['details'] = input

        input_param = {
            'host': 'test_host',
            'interfaces': [input_interface]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        with pytest.raises(
                AnsibleFailJson,
                match="Required parameter not found") as ansible_result:
            host.generate_zabbix_host(exist_host)
        assert ansible_result.value.args[0]['failed']
        for parameter in keys:
            assert parameter in ansible_result.value.args[0]['msg']

    snmp_v3_incorrect_args_exception_test_cases = [
        (  # test case 1
            {'version': '3', 'bulk': True, 'community': '111',
             'contextname': 'contextname', 'securityname': None,
             'securitylevel': 'noAuthNoPriv',
             'authprotocol': None, 'authpassphrase': None,
             'privprotocol': None, 'privpassphrase': None},
            ['community']
        ),
        (  # test case 2
            {'version': '3', 'bulk': True, 'community': '111',
             'contextname': None, 'securityname': None,
             'securitylevel': 'noAuthNoPriv',
             'authprotocol': None, 'authpassphrase': None,
             'privprotocol': None, 'privpassphrase': None},
            ['community']
        ),
        (  # test case 3
            {'version': '3', 'bulk': True, 'community': '111',
             'contextname': 'contextname', 'securityname': 'securityname',
             'securitylevel': 'authNoPriv',
             'authprotocol': 'md5', 'authpassphrase': 'authpassphrase'},
            ['community']
        ),
        (  # test case 4
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'authNoPriv',
             'authprotocol': 'md5', 'authpassphrase': 'authpassphrase',
             'privprotocol': 'des', 'privpassphrase': 'privpassphrase'},
            ['privprotocol', 'privpassphrase']
        ),
        (  # test case 5
            {'version': '3', 'bulk': True, 'contextname': 'contextname',
             'securityname': 'securityname', 'securitylevel': 'authNoPriv',
             'authprotocol': None, 'authpassphrase': None,
             'privprotocol': 'des', 'privpassphrase': 'privpassphrase'},
            ['privprotocol', 'privpassphrase']
        ),
        (  # test case 6
            {'version': '3', 'bulk': True, 'community': 'test',
             'contextname': 'contextname', 'securityname': 'securityname',
             'securitylevel': 'authPriv',
             'authprotocol': 'md5', 'authpassphrase': 'authpassphrase',
             'privprotocol': 'des', 'privpassphrase': 'privpassphrase'},
            ['community']
        ),
        (  # test case 7
            {'version': '3', 'bulk': True, 'community': 'test',
             'contextname': 'contextname', 'securityname': 'securityname',
             'securitylevel': 'authPriv',
             'authprotocol': None, 'authpassphrase': None,
             'privprotocol': None, 'privpassphrase': None},
            ['community']
        )
    ]

    @pytest.mark.parametrize(
        'input, keys',
        snmp_v3_incorrect_args_exception_test_cases)
    def test_snmp_v3_incorrect_args_exception(
            self, input, keys, fixture_zabbixapi,
            fixture_connection, fixture_hostmodule):
        """
        Testing of disallowed parameters for SNMP version 3 interfaces.
        Test cases:

        SNMPv3 (noAuthNoPriv):       
        1. Interface version 3 with additional parameter from SNMPv1 
            (community).
        2. Interface version 3 with additional parameter (community) 
            from SNMPv1 and SNMPv3 Parameter not set (context name).

        SNMPv3 (authNoPriv):      
        3. Interface version 3 with additional parameter from SNMPv1 
            (community).
        4. Interface version 3 with privacy parameters for 'authPriv'.
        5. Interface version 3 without authentication parameters, but 
            with privacy parameters.

        SNMPv3 (authPriv):       
        6. Interface version 3 with additional parameter (community).
        7. Interface version 3 without authentication and privacy 
            parameters and with additional parameter (community).

        Expected result: all test cases run successfully.
        """
        exist_host = {'host': 'test_host', 'inventory_mode': '1'}

        input_interface = {'type': 'snmp', 'useip': True, 'ip': '',
                           'dns': '', 'port': None}
        input_interface['details'] = input

        input_param = {
            'host': 'test_host',
            'interfaces': [input_interface]}

        fixture_hostmodule.params = input_param
        host = self.hostmodulepy.Host(
            fixture_hostmodule,
            ZabbixApi(fixture_hostmodule))

        with pytest.raises(
                AnsibleFailJson,
                match="Incorrect arguments for") as ansible_result:
            host.generate_zabbix_host(exist_host)
        assert ansible_result.value.args[0]['failed']
        for parameter in keys:
            assert parameter in ansible_result.value.args[0]['msg']
