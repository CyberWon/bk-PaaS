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
import pytest

from common.base_utils import FancyDict
from common.base_validators import ValidationError
from esb.bkauth.validators import UserAuthValidator, UserAuthWithBKTokenValidator, BaseUserAuthValidator


class TestBaseUserAuthValidator:
    def test_validate_bk_token(self, fake_request, mocker):
        mocker.patch(
            "esb.bkauth.validators.BaseUserAuthValidator._verify_bk_token",
            return_value="admin"
        )
        fake_request.g = FancyDict({"app_code": "fake-app-code"})
        validator = BaseUserAuthValidator()
        validator.validate_bk_token(fake_request, "fake-token")
        assert fake_request.g.current_user_username == "admin"
        assert fake_request.g.current_user_verified is True

    def test_verify_bk_token(self, fake_request, mocker):
        validator = BaseUserAuthValidator()

        mocker.patch(
            "components.bk.apis.bk_login.is_login.IsLogin.invoke",
            return_value={"result": False}
        )
        with pytest.raises(ValidationError):
            validator._verify_bk_token("fake-bk-token", "fake-app-code")

        mocker.patch(
            "components.bk.apis.bk_login.is_login.IsLogin.invoke",
            return_value={"result": True, "data": {"username": "admin"}}
        )
        result = validator._verify_bk_token("fake-bk-token", "fake-app-code")
        assert result == "admin"


class TestUserAuthValidator:
    def test_validate_with_access_token(self, fake_request, mocker):
        validator = UserAuthValidator()
        request = fake_request

        request.g = FancyDict({
            "kwargs": {},
            "app_code": "app-test",
            "authorization": {
                "bk_token": "fake-bk-token"
            },
        })

        # access_token is empty, validate with bk_token
        mocked_validate_bk_token = mocker.patch(
            "esb.bkauth.validators.UserAuthValidator.validate_bk_token",
            return_value=None,
        )
        assert validator.validate(request) is None
        mocked_validate_bk_token.assert_called_once()

        # validate with access_token
        request.g.update(authorization={"access_token": "fake-access-token"})
        mocker.patch("esb.bkauth.validators.AccessTokenValidator.validate", return_value=None)
        mocker.patch("esb.bkauth.validators.AccessTokenValidator.get_bk_username", return_value="admin")
        validator.validate(request)
        assert request.g.current_user_username == "admin"
        assert request.g.current_user_verified is True

        # AccessTokenValidator validate error
        request.g.update(authorization={"access_token": "fake-access-token"})
        mocker.patch("esb.bkauth.validators.AccessTokenValidator.validate", side_effect=ValidationError)
        with pytest.raises(ValidationError):
            validator.validate(request)

        # AccessTokenValidator get_bk_username error
        request.g.update(authorization={"access_token": "fake-access-token"})
        mocker.patch("esb.bkauth.validators.AccessTokenValidator.validate", return_value=None)
        mocker.patch("esb.bkauth.validators.AccessTokenValidator.get_bk_username", side_effect=ValidationError)
        with pytest.raises(ValidationError):
            validator.validate(request)

    def test_validate_with_bk_token(self, fake_request, mocker):
        request = fake_request

        request.g = FancyDict({
            "kwargs": {},
            "app_code": "app-test",
            "authorization": {
                "bk_token": "fake-bk-token",
            },
        })

        validator = UserAuthValidator()
        mocked_validate_bk_token = mocker.patch(
            "esb.bkauth.validators.UserAuthValidator.validate_bk_token",
            return_value=None,
        )
        assert validator.validate(request) is None
        mocked_validate_bk_token.assert_called_once()

    @pytest.mark.parametrize(
        "authorization, expected",
        [
            (
                {"bk_username": "admin"},
                "admin",
            ),
            (
                {"username": "admin"},
                "admin",
            ),
        ]
    )
    def test_validate_with_username(self, fake_request, mocker, authorization, expected):
        request = fake_request
        request.g = FancyDict({
            "kwargs": {},
            "app_code": "app-test",
            "authorization": authorization,
        })

        mocker.patch(
            "esb.bkauth.validators.FunctionControllerClient.is_skip_user_auth",
            return_value=True,
        )

        validator = UserAuthValidator()
        validator.validate(request)

        assert request.g.current_user_username == expected
        assert request.g.current_user_verified is False


class TestUserAuthWithBKTokenValidator:
    def test_validate(self, fake_request, mocker):
        request = fake_request
        request.g = FancyDict({
            "authorization": {
                "bk_token": "fake-bk-token",
            },
        })

        validator = UserAuthWithBKTokenValidator()
        mocked_validate_bk_token = mocker.patch(
            "esb.bkauth.validators.UserAuthWithBKTokenValidator.validate_bk_token",
            return_value=None,
        )
        assert validator.validate(request) is None
        mocked_validate_bk_token.assert_called_once()
