"""Retrieve OIDC workload identity tokens for EDA credential resolution."""
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

import logging
import typing as tp

from ansible_base.lib.workload_identity.eda import EDACredentialResolutionScope
from ansible_base.resource_registry.workload_identity_client import (
    get_workload_identity_client,
)
from flags.state import flag_enabled

from aap_eda.core.exceptions import CredentialPluginError

if tp.TYPE_CHECKING:
    from aap_eda.core import models

LOGGER = logging.getLogger(__name__)

__all__ = ["retrieve_workload_identity_jwt"]


def retrieve_workload_identity_jwt(
    input_source: "models.CredentialInputSource", audience: str
) -> str:
    """Retrieve a JWT scoped for EDA credential resolution.

    The token authenticates the EDA server (not the caller) to the external
    secrets backend identified by ``audience``, so a synced Vault-OIDC
    credential can be resolved without ever storing a real secret value.

    Raises:
        CredentialPluginError: if the feature is disabled, the workload
            identity client isn't configured, or the token request fails.
    """
    source = input_source.source_credential
    target = input_source.target_credential

    if not flag_enabled("FEATURE_OIDC_WORKLOAD_IDENTITY_ENABLED"):
        raise CredentialPluginError(
            "Flag FEATURE_OIDC_WORKLOAD_IDENTITY_ENABLED is not enabled, "
            f"required for credential {source.name} used by {target.name}."
        )

    client = get_workload_identity_client()
    if client is None:
        raise CredentialPluginError("Workload identity client is not configured")

    claims = {
        EDACredentialResolutionScope.CLAIM_ORGANIZATION_NAME: (
            target.organization.name
        ),
        EDACredentialResolutionScope.CLAIM_ORGANIZATION_ID: (
            target.organization.id
        ),
        EDACredentialResolutionScope.CLAIM_TARGET_CREDENTIAL_NAME: target.name,
        EDACredentialResolutionScope.CLAIM_TARGET_CREDENTIAL_ID: target.id,
        EDACredentialResolutionScope.CLAIM_SOURCE_CREDENTIAL_NAME: source.name,
        EDACredentialResolutionScope.CLAIM_SOURCE_CREDENTIAL_ID: source.id,
    }

    try:
        response = client.request_workload_jwt(
            claims=claims,
            scope=EDACredentialResolutionScope.name,
            audience=audience,
        )
    except Exception as err:
        msg = (
            "Could not generate workload identity token for credential "
            f"{source.name} used by {target.name}. Error:\n{err}"
        )
        LOGGER.error(msg)
        raise CredentialPluginError(msg) from err

    return response.jwt
