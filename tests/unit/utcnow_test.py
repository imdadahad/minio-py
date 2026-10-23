# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2014] - [2025] MinIO, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import json
import warnings
from datetime import datetime, timedelta, timezone
from unittest import TestCase, mock

from minio import time as minio_time
from minio.credentials import Credentials
from minio.models import PostPolicy
from minio.signer import get_credential_string, post_presign_v4

FIXED_NOW = datetime(2024, 5, 6, 7, 8, 9)


class _FrozenDatetime(datetime):
    """datetime whose utcnow() returns a fixed naive value."""

    @classmethod
    def utcnow(cls):
        return FIXED_NOW


def _utcnow_naive() -> datetime:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return datetime.utcnow()


class CredentialsIsExpiredTest(TestCase):
    def test_no_expiration_never_expires(self):
        creds = Credentials("access", "secret")
        self.assertFalse(creds.is_expired())

    def test_far_future_not_expired(self):
        creds = Credentials(
            "access", "secret",
            expiration=_utcnow_naive() + timedelta(hours=1),
        )
        self.assertFalse(creds.is_expired())

    def test_past_expired(self):
        creds = Credentials(
            "access", "secret",
            expiration=_utcnow_naive() - timedelta(hours=1),
        )
        self.assertTrue(creds.is_expired())

    def test_within_ten_second_margin_is_expired(self):
        creds = Credentials(
            "access", "secret",
            expiration=_utcnow_naive() + timedelta(seconds=5),
        )
        self.assertTrue(creds.is_expired())

    def test_ten_second_boundary(self):
        with mock.patch(
                "minio.credentials.credentials.datetime", _FrozenDatetime,
        ):
            just_inside = Credentials(
                "access", "secret",
                expiration=FIXED_NOW + timedelta(seconds=10) -
                timedelta(microseconds=1),
            )
            exactly_at = Credentials(
                "access", "secret",
                expiration=FIXED_NOW + timedelta(seconds=10),
            )
            just_outside = Credentials(
                "access", "secret",
                expiration=FIXED_NOW + timedelta(seconds=11),
            )
            self.assertTrue(just_inside.is_expired())
            self.assertFalse(exactly_at.is_expired())
            self.assertFalse(just_outside.is_expired())

    def test_aware_expiration_converted_to_naive_utc(self):
        tz = timezone(timedelta(hours=5))
        creds = Credentials(
            "access", "secret",
            expiration=datetime(2030, 1, 1, 5, 0, 0, tzinfo=tz),
        )
        self.assertEqual(creds.expiration, datetime(2030, 1, 1, 0, 0, 0))
        self.assertFalse(creds.is_expired())


class PostPolicyFormDataTest(TestCase):
    def _policy(self) -> PostPolicy:
        policy = PostPolicy("bucket", datetime(2030, 1, 1, tzinfo=timezone.utc))
        policy.add_equals_condition("key", "object")
        return policy

    def test_form_data_uses_current_utc_time(self):
        creds = Credentials("access", "secret")
        with mock.patch("minio.models.datetime", _FrozenDatetime):
            form_data = self._policy().form_data(creds, "us-east-1")

        self.assertEqual(form_data["x-amz-date"], "20240506T070809Z")
        self.assertEqual(
            form_data["x-amz-credential"],
            "access/20240506/us-east-1/s3/aws4_request",
        )
        self.assertEqual(form_data["x-amz-algorithm"], "AWS4-HMAC-SHA256")
        self.assertEqual(
            form_data["x-amz-signature"],
            post_presign_v4(
                form_data["policy"], "secret", FIXED_NOW, "us-east-1",
            ),
        )
        self.assertNotIn("x-amz-security-token", form_data)

        policy = json.loads(base64.b64decode(form_data["policy"]))
        self.assertIn(
            ["eq", "$x-amz-date", "20240506T070809Z"], policy["conditions"],
        )
        self.assertIn(
            ["eq", "$x-amz-credential", form_data["x-amz-credential"]],
            policy["conditions"],
        )

    def test_form_data_with_session_token(self):
        creds = Credentials("access", "secret", "token")
        with mock.patch("minio.models.datetime", _FrozenDatetime):
            form_data = self._policy().form_data(creds, "us-east-1")
        self.assertEqual(form_data["x-amz-security-token"], "token")
        policy = json.loads(base64.b64decode(form_data["policy"]))
        self.assertIn(
            ["eq", "$x-amz-security-token", "token"], policy["conditions"],
        )

    def test_form_data_real_clock(self):
        creds = Credentials("access", "secret")
        before = _utcnow_naive().replace(microsecond=0)
        form_data = self._policy().form_data(creds, "us-east-1")
        after = _utcnow_naive()
        stamp = datetime.strptime(
            form_data["x-amz-date"], "%Y%m%dT%H%M%SZ",
        )
        self.assertTrue(before <= stamp <= after)
        self.assertEqual(
            form_data["x-amz-credential"],
            get_credential_string("access", stamp, "us-east-1"),
        )


class UtcnowTest(TestCase):
    def _check(self):
        before = _utcnow_naive()
        value = minio_time.utcnow()
        after = _utcnow_naive()
        self.assertEqual(value.tzinfo, timezone.utc)
        self.assertEqual(value.utcoffset(), timedelta(0))
        self.assertTrue(
            before - timedelta(seconds=1)
            <= value.replace(tzinfo=None)
            <= after + timedelta(seconds=1),
        )

    def test_utcnow_default_path(self):
        self._check()

    def test_utcnow_fallback_without_datetime_utc(self):
        with mock.patch.object(minio_time, "_UTC_IMPORTED", False):
            with mock.patch.object(minio_time, "datetime", _FrozenDatetime):
                value = minio_time.utcnow()
            self.assertEqual(value, FIXED_NOW.replace(tzinfo=timezone.utc))
            self.assertEqual(value.tzinfo, timezone.utc)
            self._check()
