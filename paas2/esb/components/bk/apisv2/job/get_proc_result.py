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

import json

from django import forms

from components.component import Component
from common.forms import BaseComponentForm
from common.constants import API_TYPE_Q, HTTP_METHOD

# Import module from toolkit, do not use "from .toolkit.module import function" statement
# cause that will break hot-deploy feature.
from .toolkit import tools, configs


class GetProcResult(Component):
    suggest_method = HTTP_METHOD.GET
    label = u"进程操作结果查询"
    label_en = "Get proc result"

    sys_name = configs.SYSTEM_NAME
    api_type = API_TYPE_Q

    host = configs.host

    class Form(BaseComponentForm):
        bk_biz_id = forms.IntegerField(label="business id", required=True)
        bk_gse_taskid = forms.CharField(label="gse task id", required=True)

        def clean(self):
            data = self.cleaned_data
            return {
                "bk_biz_id": data["bk_biz_id"],
                "params": {
                    "bk_gse_taskid": data["bk_gse_taskid"],
                },
            }

    def handle(self):
        params = tools.get_action_params(
            action="get_proc_result",
            params=self.form_data,
            operator=self.current_user.username,
            app_code=self.request.app_code,
            request_id=self.request.request_id,
        )

        client = tools.JOBClient(self.outgoing.http_client)
        result = client.post(self.host, "/api/v2/get_proc_result", data=params, bk_language=self.request.bk_language)
        self.response.payload = self.format_result(result)

    def format_result(self, result):
        ret_data = result.get("data") or {}
        if "result" not in ret_data:
            return result

        new_data = {}
        for key, info in result["data"]["result"].items():
            try:
                new_data[key] = json.loads(info)
                if "content" in new_data[key]:
                    new_data[key]["content"] = json.loads(new_data[key]["content"])
            except Exception:
                new_data[key] = info
        result["data"]["result"] = new_data
        return result
