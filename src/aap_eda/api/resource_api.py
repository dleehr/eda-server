#  Copyright 2024 Red Hat, Inc.
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

from ansible_base.feature_flags.models import AAPFlag

# RBAC models
from ansible_base.rbac.models import RoleDefinition
from ansible_base.resource_registry.registry import (
    ParentResource,
    ResourceConfig,
    ServiceAPIConfig,
    SharedResource,
)
from ansible_base.resource_registry.shared_types import (
    FeatureFlagType,
    OrganizationType,
    RoleDefinitionType,
    SharedCredential,
    TeamType,
    UserType,
)
from rest_framework import serializers

from aap_eda.core import models


class EdaSharedCredential(SharedCredential):
    """EdaCredential stores `inputs` as a single encrypted blob, not a plain
    dict attribute - source this field through the model's
    `resource_sync_inputs` property instead, which handles the encode/decode.
    """

    inputs = serializers.JSONField(source='resource_sync_inputs', default=dict)


class APIConfig(ServiceAPIConfig):
    service_type = "eda"


RESOURCE_LIST = (
    ResourceConfig(
        models.User,
        shared_resource=SharedResource(serializer=UserType, is_provider=False),
        name_field="username",
    ),
    ResourceConfig(
        models.Team,
        shared_resource=SharedResource(serializer=TeamType, is_provider=False),
        parent_resources=[
            ParentResource(
                model=models.Organization, field_name="organization"
            )
        ],
    ),
    ResourceConfig(
        models.Organization,
        shared_resource=SharedResource(
            serializer=OrganizationType, is_provider=False
        ),
    ),
    ResourceConfig(
        RoleDefinition,
        shared_resource=SharedResource(
            serializer=RoleDefinitionType, is_provider=False
        ),
    ),
    ResourceConfig(
        AAPFlag,
        shared_resource=SharedResource(
            serializer=FeatureFlagType, is_provider=False
        ),
    ),
    ResourceConfig(
        models.EdaCredential,
        shared_resource=SharedResource(
            serializer=EdaSharedCredential, is_provider=False
        ),
        parent_resources=[
            ParentResource(
                model=models.Organization, field_name="organization"
            )
        ],
    ),
)


def gate_eda_credential_resource_sync(sender, instance, **kwargs):
    """Only reverse-sync EdaCredentials whose CredentialType stores zero
    secret material at rest."""
    from ansible_base.resource_registry.utils.credential_eligibility import (
        is_secret_free_credential_type,
    )

    credential_type = instance.credential_type
    if credential_type is None or not is_secret_free_credential_type(
        credential_type.inputs or {}
    ):
        instance._skip_reverse_resource_sync = True
