from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

from ansible_collections.zabbix.zabbix.plugins.module_utils.zabbix_api import (ZabbixApi)
from ansible_collections.zabbix.zabbix.tests.unit.plugins.modules.common import (
    exit_json, fail_json)


@pytest.fixture
def fixture_connection(mocker):
    mocker.patch("ansible_collections.zabbix.zabbix.plugins.module_utils.zabbix_api.Connection")


@pytest.fixture
def fixture_hostmodule(mocker):
    mock_module_functions = mocker.Mock()
    mock_module_functions._socket_path.return_value = '/dev/null'
    mock_module_functions.fail_json = fail_json
    mock_module_functions.exit_json = exit_json
    yield mock_module_functions

    # mock_ansiblemodule = MagicMock()
    # mock_ansiblemodule._socket_path = '/dev/null'
    # mock_ansiblemodule.fail_json = fail_json
    # mock_ansiblemodule.exit_json = exit_json
    # yield mock_ansiblemodule.start()
    # mock_ansiblemodule.stop()
