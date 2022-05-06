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

import urllib
import random

import requests
from django.conf import settings as bk_settings

from common.log import logger
from . import settings as iam_setting


def gen_oauth_state_security_token(length=32):
    """
    生成随机的state，防止csrf
    """
    allowed_chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ0123456789"
    state = "".join(random.choice(allowed_chars) for _ in range(length))
    return state


def gen_oauth_login_url(extra_param):
    """
    生成跳转登录的URL
    """
    # 由于google校验redirect_uri是精准匹配的，所有redirect_uri中无法带参数，只能放置在state中处理
    extra_param = {} if extra_param is None or not isinstance(extra_param, dict) else extra_param
    extra_param["security_token"] = gen_oauth_state_security_token()
    state = "&".join(["%s=%s" % (k, v) for k, v in extra_param.items() if v is not None and v != ""])
    # 跳转到 google 登录的URL
    google_oauth_login_url = "%s?%s" % (
        iam_setting.OAUTH_LOGIN_URL,
        urllib.urlencode(
            {
                "response_type": "code",
                "client_id": iam_setting.CLIENT_ID,
                "redirect_uri":str(bk_settings.LOGIN_COMPLETE_URL) + 'iam/',
                "scope": "read",
                "state": state,
            }
        ),
    )
    return google_oauth_login_url, state


def get_access_token(code):
    """
    调用接口验证CODE，并获取access_token
    """
    params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": str(bk_settings.LOGIN_COMPLETE_URL)+"iam/",
        "client_id": iam_setting.CLIENT_ID,
        "client_secret": iam_setting.CLIENT_SECRET,
    }
    data = urllib.urlencode(params)

    headers={'Content-Type': 'application/x-www-form-urlencoded'}

    

    resp = requests.post(url=iam_setting.ACCESS_TOKEN_URL, headers=headers,data=data,auth=(iam_setting.CLIENT_ID,iam_setting.CLIENT_SECRET))
    if resp.status_code != 200:
        # 记录错误日志
        content = resp.content[:100] if resp.content else ""
        error_msg = (
            "http enterprise request error! type: %s, url: %s, data: %s, "
            "response_status_code: %s, response_content: %s"
        )
        logger.error(error_msg % ("POST", iam_setting.ACCESS_TOKEN_URL, str(params), resp.status_code, content))
        return None
    data = resp.json()
    return data.get("access_token")


def get_scope_data(access_token):
    """
    scope要求的数据
    """
    # params = {"access_token": access_token}
    headers = {"Authorization":"Bearer "+ access_token}
    resp = requests.get(iam_setting.SCOPE_URL,headers=headers)
    logger.info(resp.text)
    if resp.status_code != 200:
        # 记录错误日志
        content = resp.content[:100] if resp.content else ""
        error_msg = (
            "http enterprise request error! type: %s, url: %s, data: %s, "
            "response_status_code: %s, response_content: %s"
        )
        logger.error(error_msg % ("GET", iam_setting.SCOPE_URL, str(params), resp.status_code, content))
        return None
    data = resp.json()
    userinfo = {
        "username": data.get("username", ""),
        "display_name": data.get("name", ""),
        "email": data.get("email", ""),
        "telephone": data.get("telephone", ""),
    }
    return userinfo
