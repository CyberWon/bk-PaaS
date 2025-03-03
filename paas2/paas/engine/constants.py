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

from django.utils.translation import ugettext as _

import re

CATEGORY_SERVER_TEST = "tapp"
CATEGORY_SERVER_PROD = "app"

SERVER_CATEGORY_CHOICES = [
    (CATEGORY_SERVER_TEST, _(u"测试服务器")),
    (CATEGORY_SERVER_PROD, _(u"正式服务器")),
]

THIRD_SERVER_CATEGORY_MQ = "rabbitmq"
THIRD_SERVER_CATEGORY_CHOICES = [
    (THIRD_SERVER_CATEGORY_MQ, _(u"RabbitMQ服务")),
]

IP_PATTERN = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

ENVIRONMENT_CHOICES = [("test", _(u"测试环境")), ("prod", _(u"正式环境"))]
