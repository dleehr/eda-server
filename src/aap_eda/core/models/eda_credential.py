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

from django.db import models

from aap_eda.core.utils.crypto.fields import EncryptedTextField

from .base import BaseOrgModel, PrimordialModel, UniqueNamedModel

__all__ = ("EdaCredential",)


class EdaCredential(BaseOrgModel, UniqueNamedModel, PrimordialModel):
    router_basename = "edacredential"

    class Meta:
        db_table = "core_eda_credential"
        constraints = [
            models.CheckConstraint(
                check=~models.Q(name=""),
                name="ck_empty_eda_credential_name",
            )
        ]

    description = models.TextField(default="", blank=True, null=False)
    inputs = EncryptedTextField(default="", blank=True, null=False)
    managed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    modified_at = models.DateTimeField(auto_now=True, null=False)

    credential_type = models.ForeignKey(
        "CredentialType", on_delete=models.CASCADE, null=True
    )

    @property
    def resource_sync_inputs(self) -> dict:
        """Plain-dict view of `inputs`, for the resource-registry sync path.

        `inputs` is stored as a single encrypted YAML blob. Only credential
        types that store zero secret material at rest are ever synced (see
        `is_secret_free_credential_type`), so decoding here never exposes a
        real secret - but the resource-registry shared serializer still needs
        a plain dict, not the encrypted field's `SecretValue` wrapper.
        """
        from aap_eda.core.utils.credentials import inputs_from_store

        raw = self.inputs
        if hasattr(raw, "get_secret_value"):
            raw = raw.get_secret_value()
        if not raw:
            return {}
        return inputs_from_store(raw)

    @resource_sync_inputs.setter
    def resource_sync_inputs(self, value: dict) -> None:
        from aap_eda.core.utils.credentials import inputs_to_store

        self.inputs = inputs_to_store(value or {})

    @property
    def credential_type_name(self) -> str:
        """Name-based view of credential_type, for the resource-registry sync path.

        Only secret-free CredentialTypes (see is_secret_free_credential_type)
        are ever synced, and they're expected to already exist, identically
        named, on every service - so the shared serializer carries this as a
        plain name rather than a cross-service resource reference.
        """
        return self.credential_type.name

    @credential_type_name.setter
    def credential_type_name(self, value: str) -> None:
        from aap_eda.core.models.credential_type import CredentialType

        self.credential_type = CredentialType.objects.get(name=value)
