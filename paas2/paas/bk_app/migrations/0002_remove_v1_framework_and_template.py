# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云PaaS平台社区版 (BlueKing PaaS
Community Edition) available.
Copyright (C) 2017-2018 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""

from __future__ import unicode_literals

from django.db import migrations, models
from bk_app.constants import SAAS_LIST


def delete_v1_framework_template(apps, schema_editor):
    SaaSApp = apps.get_model("saas", "SaaSApp")

    for app_code in ('bk_framework', 'bk_app_template'):
        try:
            saas_app = SaaSApp.objects.get(code=app_code)
            saas_app_id = saas_app.id
            # not deployed
            if not saas_app.app_id:
                saas_app.delete()
        except Exception as e:
            continue


class Migration(migrations.Migration):

    dependencies = [
        ('bk_app', '0001_load_bkapps_intial_data'),
    ]

    operations = [
        migrations.RunPython(delete_v1_framework_template),
    ]
