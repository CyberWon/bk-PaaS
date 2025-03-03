# encoding: utf-8
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

import mock
import pytest
from django.test import TestCase

from common import errors
from common.base_utils import FancyDict
from common.base_validators import ValidationError
from common.constants import COMPONENT_STATUSES
from common.errors import error_codes
from esb.bkcore.models import ESBChannel
from esb.channel.base import BaseChannel, ChannelManager, RequestHandler, ApiChannel


class TestChannelManager(TestCase):
    def register_channel_groups(self, manager, path, method, rewrite_channels=None):
        manager.register_channel_groups(
            {}, [(path, {"comp_codename": "test", "method": method})], rewrite_channels or {}
        )

    def register_channel_db(self, path, method):
        return ESBChannel.objects.create(path=path, method=method)

    def test_get_channel_by_path_from_db_which_matched(self):
        path = "/v2/db/"

        for registered_method, actual_method in [
            ("GET", "GET"),
            ("POST", "POST"),
            ("DELETE", "DELETE"),
            ("", "POST"),
            ("", "GET"),
        ]:
            channel_object = self.register_channel_db(path=path, method=registered_method)
            manager = ChannelManager()
            channel = manager.get_channel_by_path(path, actual_method)
            self.assertEqual(channel["channel"].pk, channel_object.pk)
            channel_object.delete()

    def test_get_channel_by_path_from_db_with_multi_channels(self):
        path = "/v2/db/"
        methods = [
            ("GET", "GET"),
            ("", "POST"),
            ("DELETE", "DELETE"),
        ]
        channels = []
        for registered_method, _ in methods:
            channel_object, created = ESBChannel.objects.get_or_create(path=path, method=registered_method)
            if created:
                channels.append(channel_object)

        for registered_method, actual_method in methods:
            manager = ChannelManager()
            channel = manager.get_channel_by_path(path, actual_method)
            self.assertEqual(channel["channel"].method, registered_method)

        for channel_object in channels:
            channel_object.delete()

    def test_get_channel_by_path_from_db_which_match_nothing(self):
        path = "/v2/db/"

        for registered_method, actual_method in [
            ("GET", "POST"),
            ("POST", "GET"),
            ("", "DELETE"),
        ]:
            channel_object = self.register_channel_db(path=path, method=registered_method)
            manager = ChannelManager()
            self.assertIsNone(manager.get_channel_by_path(path, actual_method))
            channel_object.delete()

    def test_get_channel_by_path_from_presets(self):
        path = "/v2/preset/"

        for registered_method, actual_method in [
            ("GET", "GET"),
            ("POST", "POST"),
            ("DELETE", "DELETE"),
            ("", "POST"),
            ("", "GET"),
            ("GET,POST", "POST"),
            ("GET,POST", "GET"),
        ]:
            manager = ChannelManager()
            self.register_channel_groups(manager, path, registered_method)
            channel = manager.get_channel_by_path(path, actual_method)
            self.assertIsNone(channel["channel"].pk)

    def test_get_channel_by_path_priority(self):
        path = "/v2/priority/"
        method = "GET"

        manager = ChannelManager()
        self.register_channel_groups(manager, path, method)
        channel_object = ESBChannel.objects.create(path=path, method=method)
        channel = manager.get_channel_by_path(path, method)
        self.assertEqual(channel["channel"].pk, channel_object.pk)

    def test_search_channel_by_repath_matched(self):
        path = "/v2/pareset/vars/{var}"
        method = "GET"

        manager = ChannelManager()
        self.register_channel_groups(manager, path, method)

        channel, path_vars = manager.search_channel_by_repath(path.format(var="test"), method)
        self.assertEqual(path_vars.val_dict["var"], "test")
        self.assertEqual(channel["raw_path"], path)

    def test_search_channel_by_repath_unmatch(self):
        path = "/v2/pareset/vars/{var}"
        method = "GET"

        manager = ChannelManager()
        self.register_channel_groups(manager, path, method)

        confing, path_vars = manager.search_channel_by_repath(path.format(var=""), method)
        self.assertIsNone(path_vars)


class TestBaseChannel:
    @pytest.fixture(autouse=True)
    def setup_fixtures(self):
        self.request = mock.MagicMock(META={"REMOTE_ADDR": "127.0.0.1"}, body="")
        self.comp_class = mock.MagicMock()
        self.comp = self.comp_class.return_value
        self.path = "/"
        self.channel = BaseChannel(self.comp_class, self.path)

    def test_patch_request_common(self):
        self.channel.patch_request_common(self.request)

        for attr in [
            "system_name",
            "component_name",
            "component_alias_name",
            "client_ip",
            "request_id",
            "component_status",
            "channel_type",
            "use_test_env",
            "api_type",
            "headers",
            "channel_conf",
            "authorization",
        ]:
            assert hasattr(self.request.g, attr), attr

    def test_invoke_exceptions(self):
        for raises, status, error_code in [
            (errors.CommonAPIError("test"), COMPONENT_STATUSES.ARGUMENT_ERROR, error_codes.COMMON_ERROR),
            (
                errors.RequestThirdPartyException(mock.MagicMock(), "test", "test"),
                COMPONENT_STATUSES.EXCEPTION,
                error_codes.REQUEST_THIRD_PARTY_ERROR,
            ),
            (
                errors.RequestSSLException(mock.MagicMock(), "test", "test"),
                COMPONENT_STATUSES.EXCEPTION,
                error_codes.REQUEST_SSL_ERROR,
            ),
            (
                errors.TestHostNotFoundException(),
                COMPONENT_STATUSES.EXCEPTION,
                error_codes.TEST_HOST_NOT_FOUND,
            ),
            (
                errors.RequestBlockedException(),
                COMPONENT_STATUSES.EXCEPTION,
                error_codes.REQUEST_BLOCKED,
            ),
            (
                Exception(),
                COMPONENT_STATUSES.EXCEPTION,
                error_codes.COMMON_ERROR,
            ),
        ]:
            self.comp.invoke.side_effect = raises

            response = self.channel.handle_request(self.request)
            result = json.loads(response.content)

            assert self.request.g.component_status == status
            assert result["code"] == error_code.code.code

    def test_invoke_comp(self):
        for result, status in [
            ({"result": False}, COMPONENT_STATUSES.FAILURE),
            ({"result": True}, COMPONENT_STATUSES.SUCCESS),
        ]:
            self.comp.invoke.return_value = result
            self.channel.handle_request(self.request)

            assert self.request.g.component_status == status

    def test_validate_error(self):
        request_validator = mock.MagicMock()
        request_validator.validate.side_effect = ValidationError()

        channel = BaseChannel(self.comp_class, self.path, request_validators=[request_validator])
        response = channel.handle_request(self.request)

        result = json.loads(response.content)

        assert self.request.g.component_status == COMPONENT_STATUSES.ARGUMENT_ERROR
        assert result["code"] == error_codes.COMMON_ERROR.code.code

    @pytest.mark.parametrize(
        "header, expected",
        [
            ("X_BK_TOKEN", "X-Bk-Token"),
        ]
    )
    def test_capitalize_header(self, header, expected):
        assert expected == BaseChannel.capitalize_header(header)

    @pytest.mark.parametrize(
        "callback, expected",
        [
            (None, False),
            ("", False),
            ("test_<>", False),
            ("#test_01", False),
            ("test 01", False),
            ("test_01", True),
        ]
    )
    def test_is_valid_jsonp_callback(self, callback, expected):
        assert expected == self.channel._is_valid_jsonp_callback(callback)


class TestApiChannel:
    @pytest.mark.parametrize(
        "app_code, authorization, expected",
        [
            (
                "",
                {"bk_app_code": "app1"},
                "app1"
            ),
            (
                "",
                {"app_code": "app2"},
                "app2"
            ),
            (
                "exist-app",
                {"bk_app_code": "app1"},
                "exist-app"
            ),
            (
                "",
                {},
                ""
            ),
        ]
    )
    def test_before_handle_request(self, fake_request, mocker, app_code, authorization, expected):
        request = fake_request
        request.g = FancyDict({
            "app_code": app_code,
            "authorization": authorization,
        })

        channel = ApiChannel(mock.MagicMock, "")
        channel.request = request

        channel.before_handle_request()
        assert request.g.app_code == expected


class TestRequestHandler:

    @pytest.mark.parametrize(
        "headers, params, expected",
        [
            ({}, {}, {}),
            (
                {"HTTP_X_BKAPI_AUTHORIZATION": json.dumps({"a": "b"})},
                {},
                {"a": "b"},
            ),
            (
                {},
                {"bk_app_code": "a", "bk_app_secret": "b", "c": "d"},
                {"bk_app_code": "a", "bk_app_secret": "b"},
            ),
            (
                {"HTTP_X_BKAPI_AUTHORIZATION": json.dumps({"a": "b"})},
                {"bk_app_code": "a", "bk_app_secret": "b", "c": "d"},
                {"a": "b"},
            ),
        ]
    )
    def test_get_request_authorization(self, request_factory, headers, params, expected):
        request = request_factory.get("", data=params, **headers)
        authorization = RequestHandler(request).get_request_authorization()
        assert authorization == expected

    @pytest.mark.parametrize(
        "headers, expected",
        [
            ({}, None),
            (
                {"HTTP_X_BKAPI_AUTHORIZATION": json.dumps({"a": "b"})},
                {"a": "b"},
            )
        ]
    )
    def test_get_authorization_from_header(self, request_factory, headers, expected):
        request = request_factory.get("", **headers)
        authorization = RequestHandler(request)._get_authorization_from_header()
        assert authorization == expected

    def test_get_authorization_from_header_error(self, request_factory):
        request = request_factory.get("", HTTP_X_BKAPI_AUTHORIZATION="test")
        with pytest.raises(Exception):
            RequestHandler(request)._get_authorization_from_header()

    @pytest.mark.parametrize(
        "params, expected",
        [
            (
                {
                    "bk_app_code": "app1",
                    "bk_app_secret": "secret1",
                    "app_code": "app2",
                    "app_secret": "app3",
                    "bk_token": "token",
                    "bk_username": "admin1",
                    "username": "admin2",
                },
                {
                    "bk_app_code": "app1",
                    "bk_app_secret": "secret1",
                    "app_code": "app2",
                    "app_secret": "app3",
                    "bk_token": "token",
                    "bk_username": "admin1",
                    "username": "admin2",
                },
            ),
            (
                {"a": "b"},
                {},
            ),
            (
                {
                    "bk_app_code": "app",
                    "bk_app_secret": "secret",
                    "a": "b",
                },
                {
                    "bk_app_code": "app",
                    "bk_app_secret": "secret",
                },
            ),
        ]
    )
    def test_get_authorization_from_params(self, request_factory, params, expected):
        request = request_factory.get("", data=params)
        authorization = RequestHandler(request)._get_authorization_from_params()
        assert authorization == expected
