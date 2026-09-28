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

from dispatcherd.config import setup as dispatcher_setup
from django.apps import AppConfig
from django.conf import settings
from django.db.models.signals import pre_save

logger = logging.getLogger(__name__)


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "aap_eda.core"

    def connect_credential_resource_sync_gates(self):
        from aap_eda.api.resource_api import gate_eda_credential_resource_sync
        from aap_eda.core.models import EdaCredential

        pre_save.connect(
            gate_eda_credential_resource_sync,
            sender=EdaCredential,
            dispatch_uid="gate_eda_credential_resource_sync",
        )

    def ready(self):
        # make sure we apply DAB decorations in case they are not yet imported
        from aap_eda.api.views import dab_decorate  # noqa: F401

        # Enable default dispatcher config. Workers may override this
        dispatcher_setup(settings.DISPATCHERD_DEFAULT_SETTINGS)
        self.connect_credential_resource_sync_gates()
