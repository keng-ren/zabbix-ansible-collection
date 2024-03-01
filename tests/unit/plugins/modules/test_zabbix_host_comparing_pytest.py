#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright: Zabbix Ltd
# GNU General Public License v2.0+ (see COPYING or https://www.gnu.org/licenses/gpl-2.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


from ansible_collections.zabbix.zabbix.plugins.modules import zabbix_host
from ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.common import (
    AnsibleFailJson)
from ansible_collections.zabbix.zabbix.plugins.module_utils.zabbix_api import (ZabbixApi)
import pytest


# @pytest.fixture
# def fixture_connection(mocker):
#     mocker.patch("ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.test_zabbix_host_comparing_pytest.zabbix_api.Connection")


def mock_api_version(self):
    """
    Mock function to get Zabbix API version. In this case,
    it doesn't matter which version of API is returned.
    """
    return '6.0.18'


@pytest.fixture
def fixture_zabbixapi(mocker, fixture_connection):
    def mock_api_version(self):
        """
        Mock function to get Zabbix API version. In this case,
        it doesn't matter which version of API is returned.
        """
        return '6.0.18'
    mocker.patch("ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.test_zabbix_host_comparing_pytest.ZabbixApi.api_version", mock_api_version)


@pytest.fixture
def fixture_zabbixapi_64(mocker, fixture_connection):
    def mock_api_version(self):
        """
        Mock function to get Zabbix API version. In this case,
        it doesn't matter which version of API is returned.
        """
        return '6.4.5'
    # mock_zabbixapi = MagicMock()
    # mock_zabbixapi.api_version = mock_api_version
    # yield mock_zabbixapi
    mocker.patch("ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.test_zabbix_host_comparing_pytest.ZabbixApi.api_version", mock_api_version)


@pytest.fixture(params=['6.0.18', '6.4.5'])
def fixture_zabbixapi_multi(mocker, request, fixture_connection):
    def mock_api_version(self):
        """
        Mock function to get Zabbix API version. In this case,
        it doesn't matter which version of API is returned.
        """
        return request.param
    # mock_zabbixapi = MagicMock()
    # mock_zabbixapi.api_version = mock_api_version
    # yield mock_zabbixapi
    mocker.patch("ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.test_zabbix_host_comparing_pytest.ZabbixApi.api_version", mock_api_version)


class TestWOProcessing(object):
    """
    Class for testing the comparison function for parameters that
    do not require preprocessing
    """
    module = zabbix_host

    param_wo_processing_test_cases = [
        (  # Test case 1
            {'host': 'test_host'},
            {
                'host': 'test_host', 'status': 'enabled',
                'description': '', 'ipmi_authtype': '-1',
                'proxy_hostid': '0', 'ipmi_privilege': '2',
                'ipmi_username': 'user', 'ipmi_password': 'pwd',
                'inventory_mode': '1', 'tls_accept': '1',
                'tls_psk_identity': 'psk_identity', 'tls_psk': 'tls_psk',
                'tls_issuer': 'tls_issuer', 'tls_subject': 'tls_subject',
                'tls_connect': '1'},
            {}
            ),
        (  # Test case 2
            {
                'host': 'test_host', 'status': 'disabled',
                'description': 'test', 'ipmi_authtype': '1',
                'proxy_hostid': '1', 'ipmi_privilege': '3',
                'ipmi_username': 'test_user', 'ipmi_password': 'test_pwd',
                'inventory_mode': '0', 'tls_accept': '4',
                'tls_psk_identity': 'test_identity', 'tls_psk': 'test_psk',
                'tls_issuer': 'test_issuer', 'tls_subject': 'test_subject',
                'tls_connect': '2'},
            {
                'host': 'test_host', 'status': 'enabled',
                'description': '', 'ipmi_authtype': '0',
                'proxy_hostid': '0', 'ipmi_privilege': '2',
                'ipmi_username': 'user', 'ipmi_password': 'pwd',
                'inventory_mode': '1', 'tls_accept': '1',
                'tls_psk_identity': 'psk_identity', 'tls_psk': 'tls_psk',
                'tls_issuer': 'tls_issuer', 'tls_subject': 'tls_subject',
                'tls_connect': '1'},
            {
                'status': 'disabled',
                'description': 'test', 'ipmi_authtype': '1',
                'proxy_hostid': '1', 'ipmi_privilege': '3',
                'ipmi_username': 'test_user', 'ipmi_password': 'test_pwd',
                'inventory_mode': '0', 'tls_accept': '4',
                'tls_psk_identity': 'test_identity', 'tls_psk': 'test_psk',
                'tls_issuer': 'test_issuer', 'tls_subject': 'test_subject',
                'tls_connect': '2'}
            ),
        (  # Test case 3
            {
                'host': 'test_host', 'status': 'enabled',
                'description': '', 'ipmi_authtype': '0',
                'proxy_hostid': '0', 'ipmi_privilege': '2',
                'ipmi_username': 'user', 'ipmi_password': 'pwd',
                'inventory_mode': '1', 'tls_accept': '1',
                'tls_psk_identity': 'psk_identity', 'tls_psk': 'tls_psk',
                'tls_issuer': 'tls_issuer', 'tls_subject': 'tls_subject',
                'tls_connect': '1'},
            {
                'host': 'test_host', 'status': 'enabled',
                'description': '', 'ipmi_authtype': '0',
                'proxy_hostid': '0', 'ipmi_privilege': '2',
                'ipmi_username': 'user', 'ipmi_password': 'pwd',
                'inventory_mode': '1', 'tls_accept': '1',
                'tls_psk_identity': 'psk_identity', 'tls_psk': 'tls_psk',
                'tls_issuer': 'tls_issuer', 'tls_subject': 'tls_subject',
                'tls_connect': '1'},
            {}
            ),
        (  # Test case 4
            {
                'host': 'test_host', 'status': 'enabled',
                'description': '', 'ipmi_authtype': '0',
                'proxy_hostid': '0', 'ipmi_privilege': '2',
                'ipmi_username': '', 'ipmi_password': '',
                'inventory_mode': '0', 'tls_accept': '1',
                'tls_psk_identity': '', 'tls_psk': '',
                'tls_issuer': '', 'tls_subject': '',
                'tls_connect': '1'},
            {
                'host': 'test_host', 'status': 'disabled',
                'description': 'test', 'ipmi_authtype': '1',
                'proxy_hostid': '1', 'ipmi_privilege': '3',
                'ipmi_username': 'user', 'ipmi_password': 'pwd',
                'inventory_mode': '1', 'tls_accept': '4',
                'tls_psk_identity': 'psk_identity', 'tls_psk': 'tls_psk',
                'tls_issuer': 'tls_issuer', 'tls_subject': 'tls_subject',
                'tls_connect': '4'},
            {
                'status': 'enabled',
                'description': '', 'ipmi_authtype': '0',
                'proxy_hostid': '0', 'ipmi_privilege': '2',
                'ipmi_username': '', 'ipmi_password': '',
                'inventory_mode': '0', 'tls_accept': '1',
                'tls_psk_identity': '', 'tls_psk': '',
                'tls_issuer': '', 'tls_subject': '',
                'tls_connect': '1'}
            )
        ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        param_wo_processing_test_cases)
    def test_param_wo_processing(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Checking the parameters that should be added without transformations.
        Test cases:
        1. New parameters not specified. No need to update.
        2. New parameters specified. Need to update.
        3. The newly specified parameters correspond to the current ones.
        No need to update.
        4. New parameters are empty. Need to update to an empty value.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)
        assert result == expected


class TestGroups(object):
    """Class for testing the comparison function for groups parameter"""
    module = zabbix_host

    groups_no_change_test_cases = [
        (  # Test case 1
            {'host': 'test_host',
             'groups': [{'groupid': '10', 'name': 'test'}]},
            {
                'host': 'test_host',
                'groups': [{'groupid': '10', 'name': 'test'}]},
            {}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        groups_no_change_test_cases)
    def test_groups_no_change(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the groups parameter.
        Test cases:
        1. Groups are equals.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)
        assert result == expected

    groups_changed_test_cases = [
        (  # Test case 1
            {'host': 'test_host',
             'groups': [
                 {'groupid': '10', 'name': 'test'},
                 {'groupid': '12', 'name': 'test2'}]},
            {
                'host': 'test_host',
                'groups': [
                    {'groupid': '10', 'name': 'test'}]},
            {
                'groups': [
                    {'groupid': '10', 'name': 'test'},
                    {'groupid': '12', 'name': 'test2'}]}
        ),
        (  # Test case 2
            {'host': 'test_host',
             'groups': [
                 {'groupid': '10', 'name': 'test'}]},
            {
                'host': 'test_host',
                'groups': [
                    {'groupid': '10', 'name': 'test'},
                    {'groupid': '12', 'name': 'test2'}]},
            {
                'groups': [{'groupid': '10', 'name': 'test'}]}
        ),
        (  # Test case 3
            {'host': 'test_host',
             'groups': [
                 {'groupid': '10', 'name': 'test'},
                 {'groupid': '14', 'name': 'test3'}]},
            {
                'host': 'test_host',
                'groups': [
                    {'groupid': '10', 'name': 'test'},
                    {'groupid': '12', 'name': 'test2'}]},
            {
                'groups': [
                    {'groupid': '10', 'name': 'test'},
                    {'groupid': '14', 'name': 'test3'}]}
        ),
        (  # Test case 4
            {'host': 'test_host',
             'groups': [
                 {'groupid': '15', 'name': 'test4'},
                 {'groupid': '16', 'name': 'test5'}]},
            {
                'host': 'test_host',
                'groups': [
                    {'groupid': '10', 'name': 'test'},
                    {'groupid': '12', 'name': 'test2'}]},
            {
                'groups': [
                    {'groupid': '16', 'name': 'test5'},
                    {'groupid': '15', 'name': 'test4'}]}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        groups_changed_test_cases)
    def test_groups_changed(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the groups parameter.
        Test cases:
        1. New group to add.
        2. One group to remove.
        3. Change one group.
        4. Change all groups.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert len(expected['groups']) == len(result['groups'])
        for group in result['groups']:
            assert group in expected['groups']


class TestTemplates(object):
    """Class for testing the comparison function for template parameter"""
    module = zabbix_host

    adding_templates_no_change_test_cases = [
        (
            {'host': 'test_host',
                'templates': [{'templateid': '10', 'name': 'test'}]},
            {
                'host': 'test_host',
                'parentTemplates': [{'templateid': '10', 'name': 'test'}]},
            {}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        adding_templates_no_change_test_cases)
    def test_adding_templates_no_change(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the templates parameter.
        Test cases:
        1. Templates are equals.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)
        assert result == expected

    adding_templates_changed_test_cases = [
        (
            {'host': 'test_host',
                'templates': [
                    {'templateid': '10', 'name': 'test'},
                    {'templateid': '12', 'name': 'test2'}]},
            {
                'host': 'test_host',
                'parentTemplates': [
                    {'templateid': '10', 'name': 'test'}]},
            {
                'templates': [
                    {'templateid': '10', 'name': 'test'},
                    {'templateid': '12', 'name': 'test2'}]}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        adding_templates_changed_test_cases)
    def test_adding_templates_changed(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the templates parameter.
        Test cases:
        1. New template to add.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert len(expected['templates']) == len(result['templates'])
        for group in result['templates']:
            assert group in expected['templates']

    deleting_templates_test_cases = [
        (  # Test case 1
            {'host': 'test_host',
                'templates': [
                    {'templateid': '10', 'name': 'test'}]},
            {
                'host': 'test_host',
                'parentTemplates': [
                    {'templateid': '10', 'name': 'test'},
                    {'templateid': '12', 'name': 'test2'}]},
            {
                'templates': [{'templateid': '10', 'name': 'test'}],
                'templates_clear': [{'templateid': '12'}]}
        ),
        (  # Test case 2
            {'host': 'test_host',
                'templates': [
                    {'templateid': '10', 'name': 'test'},
                    {'templateid': '14', 'name': 'test3'}]},
            {
                'host': 'test_host',
                'parentTemplates': [
                    {'templateid': '10', 'name': 'test'},
                    {'templateid': '12', 'name': 'test2'}]},
            {
                'templates': [
                    {'templateid': '10', 'name': 'test'},
                    {'templateid': '14', 'name': 'test3'}],
                'templates_clear': [{'templateid': '12'}]}
        ),
        (  # Test case 3
            {'host': 'test_host',
                'templates': [
                    {'templateid': '15', 'name': 'test4'},
                    {'templateid': '16', 'name': 'test5'}]},
            {
                'host': 'test_host',
                'parentTemplates': [
                    {'templateid': '10', 'name': 'test'},
                    {'templateid': '12', 'name': 'test2'}]},
            {
                'templates': [
                    {'templateid': '16', 'name': 'test5'},
                    {'templateid': '15', 'name': 'test4'}],
                'templates_clear': [
                    {'templateid': '10'},
                    {'templateid': '12'}]}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        deleting_templates_test_cases)
    def test_deleting_templates(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the templates parameter.
        Test cases:
        1. One template to remove.
        2. Change one template.
        3. Change all templates.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert len(expected['templates']) == len(result['templates'])

        assert len(expected['templates_clear']) == len(result['templates_clear'])

        for template in result['templates']:
            assert template in expected['templates']
        for cl_template in result['templates_clear']:
            assert cl_template in expected['templates_clear']


class TestVisibleName(object):
    """Class for testing the comparison function for visible name parameter"""
    module = zabbix_host

    visible_name_comparisons_test_cases = [
        (  # Test case 1
            {'host': 'test_host', 'name': 'Test host'},
            {'host': 'test_host', 'name': 'Test host'},
            {}
        ),
        (  # Test case 2
            {'host': 'test_host', 'name': 'New name'},
            {'host': 'test_host', 'name': 'Test host'},
            {'name': 'New name'}
        ),
        (  # Test case 3
            {'host': 'test_host', 'name': ''},
            {'host': 'test_host', 'name': 'Test host'},
            {'name': 'test_host'}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        visible_name_comparisons_test_cases)
    def test_visible_name_comparisons(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the visible name parameter.
        Test cases:
        1. Visible names are equals.
        2. New visible name.
        3. Empty visible name. Must be technical name.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)
        assert result == expected


class TestTags(object):
    """Class for testing the comparison function for tags parameter"""
    module = zabbix_host

    tags_no_change_test_cases = [
        (  # Test case
            {'host': 'test_host',
                'tags': [{'tag': 'test1', 'value': 'test1'}]},
            {
                'host': 'test_host',
                'tags': [{'tag': 'test1', 'value': 'test1'}]},
            {}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        tags_no_change_test_cases)
    def test_tags_no_change(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the tags parameter.
        Test cases:
        1. Tags are equals.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert result == expected

    tags_changed_test_cases = [
        (  # Test case 1
            {'host': 'test_host',
                'tags': [
                    {'tag': 'test1', 'value': 'test1'},
                    {'tag': 'test2', 'value': ''}]},
            {
                'host': 'test_host',
                'tags': [{'tag': 'test1', 'value': 'test1'}]},
            {
                'tags': [
                    {'tag': 'test1', 'value': 'test1'},
                    {'tag': 'test2', 'value': ''}]}
        ),
        (  # Test case 2
            {'host': 'test_host',
                'tags': [
                    {'tag': 'test1', 'value': 'test1'},
                    {'tag': 'test2', 'value': ''}]},
            {
                'host': 'test_host',
                'tags': []},
            {
                'tags': [
                    {'tag': 'test1', 'value': 'test1'},
                    {'tag': 'test2', 'value': ''}]}
        ),
        (  # Test case 3
            {'host': 'test_host',
                'tags': [{'tag': 'test1', 'value': 'test1'}]},
            {
                'host': 'test_host',
                'tags': [
                        {'tag': 'test1', 'value': 'test1'},
                        {'tag': 'test2', 'value': ''}]},
            {
                'tags': [{'tag': 'test1', 'value': 'test1'}]}
        ),
        (  # Test case 4
            {'host': 'test_host',
                'tags': []},
            {
                'host': 'test_host',
                'tags': [
                        {'tag': 'test1', 'value': 'test1'},
                        {'tag': 'test2', 'value': ''}]},
            {
                'tags': []}
        ),
        (  # Test case 5
            {'host': 'test_host',
                'tags': [
                    {'tag': 'test1', 'value': 'test1'},
                    {'tag': 'test3', 'value': 'test3'}]},
            {
                'host': 'test_host',
                'tags': [
                        {'tag': 'test1', 'value': 'test1'},
                        {'tag': 'test2', 'value': ''}]},
            {
                'tags': [
                    {'tag': 'test1', 'value': 'test1'},
                    {'tag': 'test3', 'value': 'test3'}]}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        tags_changed_test_cases)
    def test_tags_changed(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the tags parameter.
        Test cases:
        1. New tag.
        2. New tag in case of empty tags on host.
        3. Remove one tag.
        4. Remove all tags.
        5. Change one tag to other.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert len(expected['tags']) == len(result['tags'])

        for tag in result['tags']:
            assert tag in expected['tags']

    tag_changes_test_cases = [
        (  # Test case 1
            {'host': 'test_host',
                'tags': [{'tag': 'test1', 'value': 'test2'}]},
            {
                'host': 'test_host',
                'tags': [{'tag': 'test1', 'value': 'test1'}]},
            {
                'tags': [{'tag': 'test1', 'value': 'test2'}]}
        ),
        (  # Test case 2
            {'host': 'test_host',
                'tags': [{'tag': 'test1', 'value': ''}]},
            {
                'host': 'test_host',
                'tags': [{'tag': 'test1', 'value': 'test1'}]},
            {
                'tags': [{'tag': 'test1', 'value': ''}]}
        ),
        (  # Test case 3
            {'host': 'test_host',
                'tags': [{'tag': 'test2', 'value': 'test1'}]},
            {
                'host': 'test_host',
                'tags': [{'tag': 'test1', 'value': 'test1'}]},
            {
                'tags': [{'tag': 'test2', 'value': 'test1'}]}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        tag_changes_test_cases)
    def test_tag_changes(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the tags parameter.
        Test cases:
        1. Change value.
        2. Clear value.
        3. Change name.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert len(expected['tags']) == len(result['tags'])

        for tag in result['tags']:
            assert tag in expected['tags']


class TestMacros(object):
    """Class for testing the comparison function for macros parameter"""
    module = zabbix_host

    macros_no_change_test_cases = [
        (  # Test case 1
            {'host': 'test_host',
             'macros': [
                     {'macro': '{$TEST1}',
                      'value': 'test1',
                      'type': '0',
                      'description': 'description'}]},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                         'value': 'test1',
                         'type': '0',
                         'description': 'description'}]},
            {}
            )
        ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        macros_no_change_test_cases)
    def test_macros_no_change(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the macros parameter.
        Test cases:
        1. Macros are equals.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert result == expected

    macros_changed_test_cases = [
        (  # Test case 1
            {'host': 'test_host',
             'macros': [
                     {'macro': '{$TEST1}',
                      'value': 'test1',
                      'type': '0',
                      'description': 'description'},
                     {'macro': '{$TEST2}',
                      'value': 'test2',
                      'type': '1',
                      'description': 'description2'}]},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                         'value': 'test1',
                         'type': '0',
                         'description': 'description'}]},
            {
                'macros': [
                        {'macro': '{$TEST1}',
                         'value': 'test1',
                         'type': '0',
                         'description': 'description'},
                        {'macro': '{$TEST2}',
                         'value': 'test2',
                         'type': '1',
                         'description': 'description2'}]}
        ),
        (  # Test case 2
            {'host': 'test_host',
             'macros': [
                     {'macro': '{$TEST1}',
                      'value': 'test1',
                      'type': '0',
                      'description': 'description'}]},
            {
                'host': 'test_host',
                'macros': []},
            {
                'macros': [
                    {'macro': '{$TEST1}',
                     'value': 'test1',
                     'type': '0',
                     'description': 'description'}]}
        ),
        (  # Test case 3
            {'host': 'test_host',
             'macros': [
                     {'macro': '{$TEST1}',
                      'value': 'test1',
                      'type': '0',
                      'description': 'description'}]},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                         'value': 'test1',
                         'type': '0',
                         'description': 'description'},
                        {'macro': '{$TEST2}',
                         'value': 'test2',
                         'type': '1',
                         'description': 'description2'}]},
            {
                'macros': [
                        {'macro': '{$TEST1}',
                         'value': 'test1',
                         'type': '0',
                         'description': 'description'}]}
        ),
        (  # Test case 4
            {'host': 'test_host',
             'macros': []},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                         'value': 'test1',
                         'type': '0',
                         'description': 'description'}]},
            {'macros': []}
        ),
        (  # Test case 5
            {'host': 'test_host',
             'macros': [
                     {'macro': '{$TEST1}',
                      'value': 'test1',
                      'type': '0',
                      'description': 'description'},
                     {'macro': '{$TEST3}',
                      'value': 'test3',
                      'type': '1',
                      'description': 'description3'}]},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                         'value': 'test1',
                         'type': '0',
                         'description': 'description'},
                        {'macro': '{$TEST2}',
                         'value': 'test2',
                         'type': '1',
                         'description': 'description2'}]},
            {
                'macros': [
                        {'macro': '{$TEST1}',
                         'value': 'test1',
                         'type': '0',
                         'description': 'description'},
                        {'macro': '{$TEST3}',
                         'value': 'test3',
                         'type': '1',
                         'description': 'description3'}]}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        macros_changed_test_cases)
    def test_macros_changed(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the macros parameter.
        Test cases:
        1. New macro.
        2. New macro in case of empty macros on host.
        3. Remove one macro.
        4. Remove all macros.
        5. Change one macro to other.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        if 'macros' in result:
            assert len(expected['macros']) == len(result['macros'])

            for macro in result['macros']:
                assert macro in expected['macros']

    macro_changes_test_cases = [
        (  # Test case 1
            {'host': 'test_host',
                'macros': [
                    {'macro': '{$TEST1}',
                     'value': 'test2',
                     'type': '0',
                     'description': 'description'}]},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test1',
                            'type': '0',
                            'description': 'description'}]},
            {
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test2',
                            'type': '0',
                            'description': 'description'}]}
        ),
        (  # Test case 2
            {'host': 'test_host',
                'macros': [
                    {'macro': '{$TEST1}',
                     'value': 'test1',
                     'type': '1',
                     'description': 'description'}]},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test1',
                            'type': '0',
                            'description': 'description'}]},
            {
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test1',
                            'type': '1',
                            'description': 'description'}]}
        ),
        (  # Test case 3
            {'host': 'test_host',
                'macros': [
                    {'macro': '{$TEST1}',
                     'value': 'test1',
                     'type': '0',
                     'description': 'description_NEW'}]},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test1',
                            'type': '0',
                            'description': 'description'}]},
            {
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test1',
                            'type': '0',
                            'description': 'description_NEW'}]}
        ),
        (  # Test case 4
            {'host': 'test_host',
                'macros': [
                    {'macro': '{$TEST1}',
                     'value': '',
                     'type': '0',
                     'description': 'description'}]},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test1',
                            'type': '0',
                            'description': 'description'}]},
            {
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': '',
                            'type': '0',
                            'description': 'description'}]}
        ),
        (  # Test case 5
            {'host': 'test_host',
                'macros': [
                    {'macro': '{$TEST1}',
                     'value': 'test1',
                     'type': '0',
                     'description': ''}]},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test1',
                            'type': '0',
                            'description': 'description'}]},
            {
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test1',
                            'type': '0',
                            'description': ''}]}
        ),
        (  # Test case 6
            {'host': 'test_host',
                'macros': [
                    {'macro': '{$TEST1}',
                     'value': '',
                     'type': '1',
                     'description': ''}]},
            {
                'host': 'test_host',
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test1',
                            'type': '1',
                            'description': 'description'}]},
            {
                'macros': [
                        {'macro': '{$TEST1}',
                            'value': 'test1',
                            'type': '1',
                            'description': ''}]}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        macro_changes_test_cases)
    def test_macro_changes(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the macros parameter.
        Test cases:
        1. Change value.
        2. Change type.
        3. Change description.
        4. Clear value.
        5. Clear description.
        6. Change value in case of secret macros (existing macro value is empty).

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert len(expected['macros']) == len(result['macros'])

        for macro in result['macros']:
            assert macro in expected['macros']


class TestInterfaces(object):
    """Class for testing the comparison function for interfaces parameter"""
    module = zabbix_host

    interface_count_test_cases = [
        (  # Test case
            {
                'host': 'test_host',
                'interfaces': []},
            {
                'host': 'test_host',
                'interfaces': [{'type': '1'}]},
            {'interfaces': []}
        ),
        (  # Test case
            {
                'host': 'test_host',
                'interfaces': []},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1'},
                    {'type': '2'},
                    {'type': '3'},
                    {'type': '4'}]},
            {'interfaces': []}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        interface_count_test_cases)
    def test_interface_count(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the interface count on existing hosts.
        Test cases:
        1. One interface exists.
        2. One interface of each type exist.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)
        assert result == expected

    interface_count_exception_test_cases = [
        (  # Test case 1
            {
                'host': 'test_host',
                'interfaces': []},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1'},
                    {'type': '1'}]}
        ),
        (  # Test case 2
            {
                'host': 'test_host',
                'interfaces': []},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2'},
                    {'type': '2'}]}
        ),
        (  # Test case 3
            {
                'host': 'test_host',
                'interfaces': []},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '3'},
                    {'type': '3'}]}
        ),
        (  # Test case 4
            {
                'host': 'test_host',
                'interfaces': []},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '4'},
                    {'type': '4'}]}
        ),
        (  # Test case 5
            {
                'host': 'test_host',
                'interfaces': []},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1'},
                    {'type': '4'},
                    {'type': '4'}]}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist",
        interface_count_exception_test_cases)
    def test_interface_count_exception(
            self, new, exist, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing the interface count in case of several interfaces of some
        type.
        Test cases:
        1. Two agent interfaces exist.
        2. Two SNMP interfaces exist.
        3. Two IPMI interfaces exist.
        4. Two JMX interfaces exist.
        5. One agent and two JMX interfaces exist.

        Expected result: an exception with an error message.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        with pytest.raises(
                AnsibleFailJson,
                match=''.join([
                    "Module supports only 1 interface of each type. ",
                    "Please resolve conflict manually."])) as ansible_result:
            host.compare_zabbix_host(exist, new)
        assert ansible_result.value.args[0]['failed']

    interface_changes_test_cases = [
        (  # Test case 1
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '10051', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'}]},
            {
                'host': 'test_host',
                'interfaces': []},
            {
                'interfaces': [
                    {'type': '1', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '10051', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'}]}
        ),
        (  # Test case 2
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '10051', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'},
                    {'type': '3', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'}]},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1', 'interfaceid': '1000', 'useip': '0',
                        'port': '10051', 'dns': 'test_agent.com',
                        'ip': '127.0.0.1', 'details': [], 'main': '1'}]},
            {
                'interfaces': [
                    {'type': '1', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '10051', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'},
                    {'type': '3', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'}]}
        ),
        (  # Test case 3
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1', 'useip': '0', 'ip': '10.10.10.10',
                        'port': '10051', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'}]},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1', 'interfaceid': '1000', 'useip': '0',
                        'port': '10051', 'dns': 'test_agent.com',
                        'ip': '127.0.0.1', 'details': [], 'main': '1'}]},
            {
                'interfaces': [
                    {'type': '1', 'useip': '0', 'ip': '10.10.10.10',
                        'port': '10051', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'}]}
        ),
        (  # Test case 4
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1', 'useip': '0', 'ip': '10.10.10.10',
                        'port': '10051', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'},
                    {'type': '3', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '650', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'}]},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1', 'interfaceid': '1000', 'useip': '0',
                        'port': '10051', 'dns': 'test_agent.com',
                        'ip': '127.0.0.1', 'details': [], 'main': '1'},
                    {'type': '3', 'interfaceid': '1001', 'useip': '0',
                        'port': '650', 'dns': 'test_agent.com',
                        'ip': '127.0.0.1', 'details': [], 'main': '1'}]},
            {
                'interfaces': [
                    {'type': '1', 'useip': '0', 'ip': '10.10.10.10',
                        'port': '10051', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'},
                    {'type': '3', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '650', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'}]}
        ),
        (  # Test case 5
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1', 'useip': '0', 'ip': '10.10.10.10',
                        'port': '10051', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'}]},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1', 'interfaceid': '1000', 'useip': '0',
                        'port': '10051', 'dns': 'test_agent.com',
                        'ip': '127.0.0.1', 'details': [], 'main': '1'},
                    {'type': '3', 'interfaceid': '1001', 'useip': '0',
                        'port': '650', 'dns': 'test_agent.com',
                        'ip': '127.0.0.1', 'details': [], 'main': '1'}]},
            {
                'interfaces': [
                    {'type': '1', 'useip': '0', 'ip': '10.10.10.10',
                        'port': '10051', 'dns': 'test_agent.com',
                        'details': [], 'main': '1'}]}
        ),
        (  # Test case 6
            {
                'host': 'test_host',
                'interfaces': []},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '1', 'interfaceid': '1000', 'useip': '0',
                        'port': '10051', 'dns': 'test_agent.com',
                        'ip': '127.0.0.1', 'details': [], 'main': '1'},
                    {'type': '3', 'interfaceid': '1001', 'useip': '0',
                        'port': '650', 'dns': 'test_agent.com',
                        'ip': '127.0.0.1', 'details': [], 'main': '1'}]},
            {
                'interfaces': []}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        interface_changes_test_cases)
    def test_interface_changes(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing operations with interfaces.
        Test cases:
        1. Add new interface.
        2. Add another interface.
        3. Change one interface when one interface exists.
        4. Change one interface when two interfaces exist.
        5. Delete one interface when two interfaces exist.
        6. Clear all interfaces.


        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert len(expected['interfaces']) == len(result['interfaces'])

        for interface in result['interfaces']:
            assert interface in expected['interfaces']

    interface_snmp_no_change_test_cases = [
        (  # Test case 1
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'details': {
                            'version': '3', 'bulk': False,
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'privpassphrase': 'privpassphrase'}}]},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'interfaceid': '1000', 'details': {
                            'version': '3', 'bulk': False,
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'privpassphrase': 'privpassphrase'}}]},
            {}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        interface_snmp_no_change_test_cases)
    def test_interface_snmp_no_change(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing operations with SNMP interfaces.
        Test cases:
        1. Interfaces are equals.       

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert result == expected

    interface_snmp_changes_test_cases = [
        (  # Test case 1
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'details': {
                            'version': '3', 'bulk': False,
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'privpassphrase': 'privpassphrase'}}]},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'interfaceid': '1000', 'details': {
                            'bulk': False, 'version': '3',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'privpassphrase': 'privpassphrase'}}]},
            {}
        ),
        (  # Test case 2
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'details': {
                            'version': '3', 'bulk': False,
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'privpassphrase': 'privpassphrase'}}]},
            {
                'host': 'test_host',
                'interfaces': []},
            {
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'details':
                        {'contextname': 'contextname',
                            'securityname': 'securityname',
                            'version': '3', 'bulk': False,
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'privpassphrase': 'privpassphrase'}}]}
        ),
        (  # Test case 3
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '10.10.10.10',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'details': {
                            'version': '3', 'bulk': False,
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'privpassphrase': 'privpassphrase'}}]},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'interfaceid': '1000', 'details': {
                            'bulk': False, 'version': '3',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'privpassphrase': 'privpassphrase'}}]},
            {
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '10.10.10.10',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'details': {
                            'bulk': False, 'version': '3',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'privpassphrase': 'privpassphrase'}}]}
        ),
        (  # Test case 4
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'details': {
                            'version': '3', 'bulk': True,
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'privpassphrase': 'privpassphrase'}}]},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'interfaceid': '1000', 'details': {
                            'bulk': False, 'version': '3',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'privpassphrase': 'privpassphrase'}}]},
            {
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'details': {
                            'bulk': True, 'version': '3',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'privpassphrase': 'privpassphrase'}}]}
        ),
        (  # Test case 5
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '10.10.10.10',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'details': {
                            'version': '3', 'bulk': True,
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'privpassphrase': 'privpassphrase'}}]},
            {
                'host': 'test_host',
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '127.0.0.1',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'interfaceid': '1000', 'details': {
                            'bulk': False, 'version': '3',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'privpassphrase': 'privpassphrase'}}]},
            {
                'interfaces': [
                    {'type': '2', 'useip': '0', 'ip': '10.10.10.10',
                        'port': '161', 'dns': 'test_agent.com', 'main': '1',
                        'details': {
                            'bulk': True, 'version': '3',
                            'securitylevel': 'authPriv',
                            'authpassphrase': 'authpassphrase',
                            'contextname': 'contextname',
                            'securityname': 'securityname',
                            'privpassphrase': 'privpassphrase'}}]}
        )
    ]

    @pytest.mark.parametrize(
        "new, exist, expected",
        interface_snmp_changes_test_cases)
    def test_interface_snmp_changes(
            self, new, exist, expected, fixture_zabbixapi, fixture_hostmodule):
        """
        Testing operations with SNMP interfaces.
        Test cases:
        1. Interfaces are equals.
        2. Interfaces are equals but in a different order.
        3. Add one SNMP interface.
        4. Change parameter of SNMP interface.
        5. Change details of SNMP interface.
        6. Change parameters and details of SNMP interfaces.

        Expected result: all test cases run successfully.
        """
        host = self.module.Host(
            fixture_hostmodule, ZabbixApi(fixture_hostmodule))

        result = host.compare_zabbix_host(exist, new)

        assert len(expected['interfaces']) == len(result['interfaces'])

        for interface in result['interfaces']:
            assert interface in expected['interfaces']
