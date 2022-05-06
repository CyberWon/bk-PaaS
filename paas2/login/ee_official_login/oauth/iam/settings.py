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


IAM_URL=""

# IAM oauth2.0 登录URL
OAUTH_LOGIN_URL = IAM_URL+"oauth/authorize/"

# 通过认证Code获取Access_token的API URL
ACCESS_TOKEN_URL = IAM_URL+ "oauth/token/"

# 获取IAM 用户信息的API URL
SCOPE_URL = IAM_URL + "oauth/userinfo/"

# IAM OAuth 2.0 客户端 ID
CLIENT_ID = ""

# IAM OAuth 2.0 客户端 密钥
CLIENT_SECRET = ""
