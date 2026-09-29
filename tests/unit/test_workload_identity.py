"""Test EDA workload identity token retrieval."""
#  Copyright 2025 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from unittest import mock

import pytest
from ansible_base.lib.workload_identity.eda import EDACredentialResolutionScope

from aap_eda.core.exceptions import CredentialPluginError
from aap_eda.core.utils.workload_identity import retrieve_workload_identity_jwt


def _make_input_source():
    organization = mock.Mock(name="my-org")
    organization.name = "my-org"
    organization.id = 1

    target_credential = mock.Mock()
    target_credential.name = "my-hmac-credential"
    target_credential.id = 2
    target_credential.organization = organization

    source_credential = mock.Mock()
    source_credential.name = "my-vault-oidc-credential"
    source_credential.id = 3

    input_source = mock.Mock()
    input_source.target_credential = target_credential
    input_source.source_credential = source_credential
    return input_source


@mock.patch("aap_eda.core.utils.workload_identity.flag_enabled", return_value=False)
def test_retrieve_workload_identity_jwt_flag_disabled(mock_flag_enabled):
    input_source = _make_input_source()

    with pytest.raises(CredentialPluginError, match="FEATURE_OIDC_WORKLOAD_IDENTITY_ENABLED"):
        retrieve_workload_identity_jwt(input_source, audience="https://vault.example.com")


@mock.patch("aap_eda.core.utils.workload_identity.get_workload_identity_client", return_value=None)
@mock.patch("aap_eda.core.utils.workload_identity.flag_enabled", return_value=True)
def test_retrieve_workload_identity_jwt_client_not_configured(mock_flag_enabled, mock_get_client):
    input_source = _make_input_source()

    with pytest.raises(CredentialPluginError, match="not configured"):
        retrieve_workload_identity_jwt(input_source, audience="https://vault.example.com")


@mock.patch("aap_eda.core.utils.workload_identity.get_workload_identity_client")
@mock.patch("aap_eda.core.utils.workload_identity.flag_enabled", return_value=True)
def test_retrieve_workload_identity_jwt_success(mock_flag_enabled, mock_get_client):
    input_source = _make_input_source()
    mock_client = mock.Mock()
    mock_client.request_workload_jwt.return_value = mock.Mock(jwt="eyJ.test.jwt")
    mock_get_client.return_value = mock_client

    result = retrieve_workload_identity_jwt(input_source, audience="https://vault.example.com")

    assert result == "eyJ.test.jwt"
    mock_client.request_workload_jwt.assert_called_once_with(
        claims={
            EDACredentialResolutionScope.CLAIM_ORGANIZATION_NAME: "my-org",
            EDACredentialResolutionScope.CLAIM_ORGANIZATION_ID: 1,
            EDACredentialResolutionScope.CLAIM_TARGET_CREDENTIAL_NAME: "my-hmac-credential",
            EDACredentialResolutionScope.CLAIM_TARGET_CREDENTIAL_ID: 2,
            EDACredentialResolutionScope.CLAIM_SOURCE_CREDENTIAL_NAME: "my-vault-oidc-credential",
            EDACredentialResolutionScope.CLAIM_SOURCE_CREDENTIAL_ID: 3,
        },
        scope=EDACredentialResolutionScope.name,
        audience="https://vault.example.com",
    )


@mock.patch("aap_eda.core.utils.workload_identity.get_workload_identity_client")
@mock.patch("aap_eda.core.utils.workload_identity.flag_enabled", return_value=True)
def test_retrieve_workload_identity_jwt_request_failure(mock_flag_enabled, mock_get_client):
    input_source = _make_input_source()
    mock_client = mock.Mock()
    mock_client.request_workload_jwt.side_effect = RuntimeError("boom")
    mock_get_client.return_value = mock_client

    with pytest.raises(CredentialPluginError, match="boom"):
        retrieve_workload_identity_jwt(input_source, audience="https://vault.example.com")
