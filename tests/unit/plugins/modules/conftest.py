from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

from ansible_collections.zabbix.zabbix.plugins.module_utils.zabbix_api import (ZabbixApi)
from ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.common import (
    exit_json, fail_json)


@pytest.fixture
def fixture_apiversion(monkeypatch, request):
    def mock_api_version(self):
        """
        Mock function to get Zabbix API version. In this case,
        it doesn't matter which version of API is returned.
        """
        return '6.0.18'
    monkeypatch.setattr(ZabbixApi, 'api_version', mock_api_version)


@pytest.fixture
def fixture_apiversion_64(monkeypatch, request):
    def mock_api_version(self):
        """
        Mock function to get Zabbix API version. In this case,
        it doesn't matter which version of API is returned.
        """
        return '6.4.5'
    monkeypatch.setattr(ZabbixApi, 'api_version', mock_api_version)


@pytest.fixture(params=['6.0.18', '6.4.5'])
def fixture_apiversion_multi(monkeypatch, request):
    def mock_api_version(self):
        """
        Mock function to get Zabbix API version. In this case,
        it doesn't matter which version of API is returned.
        """
        return request.param
    monkeypatch.setattr(ZabbixApi, 'api_version', mock_api_version)


@pytest.fixture
def fixture_connection(mocker):
    mock_connection = mocker.patch("ansible_collections.zabbix.zabbix.plugins.module_utils.zabbix_api.Connection")
    yield mock_connection


@pytest.fixture
def fixture_hostmodule(mocker):
    mock_module_functions = mocker.Mock()
    mock_module_functions._socket_path = '/dev/null'
    mock_module_functions.fail_json = fail_json
    mock_module_functions.exit_json = exit_json
    yield mock_module_functions
