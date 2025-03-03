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

from django.db import migrations

from esb.bkcore.constants import FUNCTION_CONTROLLERS


def init_function_controller(apps, schema_editor):
    FunctionController = apps.get_model('bkcore', 'FunctionController')
    for func_ctl in FUNCTION_CONTROLLERS:
        func_code = func_ctl.pop('func_code')
        FunctionController.objects.get_or_create(func_code=func_code, defaults=func_ctl)


class Migration(migrations.Migration):

    dependencies = [
        ('bkcore', '0002_auto_20160712_2041'),
    ]

    operations = [
        migrations.RunPython(init_function_controller),
    ]
