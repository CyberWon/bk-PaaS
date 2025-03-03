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


from django.contrib import admin

from saas.models import SaaSApp, SaaSAppVersion, SaaSUploadFile


class SaaSAppAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "created_time", "current_version", "current_test_version")
    search_fields = ("name", "code")
    list_filter = ("code",)


admin.site.register(SaaSApp, SaaSAppAdmin)


class SaaSAppVersionAdmin(admin.ModelAdmin):
    list_display = ("version", "saas_app", "upload_file", "updated_at")
    search_fields = ("version", "saas_app")
    list_filter = ("saas_app__code", "saas_app__name")


admin.site.register(SaaSAppVersion, SaaSAppVersionAdmin)


class SaaSUploadFileAdmin(admin.ModelAdmin):
    list_display = ("name", "size", "md5", "uploaded_at")
    search_fields = ("name", "size", "md5")
    exclude = ("file",)


admin.site.register(SaaSUploadFile, SaaSUploadFileAdmin)
