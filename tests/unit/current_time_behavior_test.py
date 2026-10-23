# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2025] MinIO, Inc.
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
from datetime import datetime, timedelta, timezone
from unittest import TestCase, mock
from urllib.parse import parse_qs, urlsplit

from minio import Minio
from minio import time as minio_time
from minio.credentials.credentials import Credentials
from minio.models import PostPolicy
from minio.signer import get_credential_string, post_presign_v4

from .minio_mocks import MockResponse


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CredentialsIsExpiredTest(TestCase):
    def test_no_expiration_never_expires(self):
        creds = Credentials("access", "secret")
        self.assertFalse(creds.is_expired())

    def test_past_expiration_is_expired(self):
        creds = Credentials(
            "access", "secret", expiration=_now() - timedelta(hours=1),
        )
        self.assertTrue(creds.is_expired())

    def test_far_future_expiration_is_not_expired(self):
        creds = Credentials(
            "access", "secret", expiration=_now() + timedelta(hours=1),
        )
        self.assertFalse(creds.is_expired())

    def test_expiration_inside_ten_second_margin_is_expired(self):
        creds = Credentials(
            "access", "secret", expiration=_now() + timedelta(seconds=3),
        )
        self.assertTrue(creds.is_expired())

    def test_expiration_outside_ten_second_margin_is_not_expired(self):
        creds = Credentials(
            "access", "secret", expiration=_now() + timedelta(seconds=120),
        )
        self.assertFalse(creds.is_expired())

    def test_naive_expiration_is_treated_as_utc(self):
        past = Credentials(
            "access", "secret",
            expiration=_now().replace(tzinfo=None) - timedelta(minutes=5),
        )
        future = Credentials(
            "access", "secret",
            expiration=_now().replace(tzinfo=None) + timedelta(minutes=5),
        )
        self.assertTrue(past.is_expired())
        self.assertFalse(future.is_expired())

    def test_non_utc_expiration_is_normalized_to_utc(self):
        zone = timezone(timedelta(hours=9))
        past = Credentials(
            "access", "secret",
            expiration=(_now() - timedelta(minutes=5)).astimezone(zone),
        )
        future = Credentials(
            "access", "secret",
            expiration=(_now() + timedelta(minutes=5)).astimezone(zone),
        )
        self.assertTrue(past.is_expired())
        self.assertFalse(future.is_expired())


class PostPolicyFormDataTest(TestCase):
    def _form_data(self, session_token=None):
        policy = PostPolicy("my-bucket", _now() + timedelta(days=1))
        policy.add_equals_condition("key", "my-object")
        creds = Credentials("ACCESS", "SECRET", session_token=session_token)
        before = _now().replace(microsecond=0)
        form_data = policy.form_data(creds, "us-east-1")
        after = _now()
        return form_data, before, after

    def test_form_data_date_is_current_time(self):
        form_data, before, after = self._form_data()
        amz_date = datetime.strptime(
            form_data["x-amz-date"], "%Y%m%dT%H%M%SZ",
        ).replace(tzinfo=timezone.utc)
        self.assertGreaterEqual(amz_date, before)
        self.assertLessEqual(amz_date, after)

    def test_form_data_credential_and_policy_use_same_date(self):
        form_data, _, _ = self._form_data()
        amz_date = form_data["x-amz-date"]
        self.assertEqual(
            form_data["x-amz-credential"],
            f"ACCESS/{amz_date[:8]}/us-east-1/s3/aws4_request",
        )
        policy = json.loads(base64.b64decode(form_data["policy"]))
        self.assertIn(
            ["eq", "$x-amz-date", amz_date], policy["conditions"],
        )
        self.assertIn(
            ["eq", "$x-amz-credential", form_data["x-amz-credential"]],
            policy["conditions"],
        )
        self.assertIn(["eq", "$bucket", "my-bucket"], policy["conditions"])
        self.assertIn(["eq", "$key", "my-object"], policy["conditions"])

    def test_form_data_signature_matches_signed_date(self):
        form_data, _, _ = self._form_data()
        amz_date = datetime.strptime(
            form_data["x-amz-date"], "%Y%m%dT%H%M%SZ",
        ).replace(tzinfo=timezone.utc)
        self.assertEqual(
            form_data["x-amz-credential"],
            get_credential_string("ACCESS", amz_date, "us-east-1"),
        )
        self.assertEqual(
            form_data["x-amz-signature"],
            post_presign_v4(
                form_data["policy"], "SECRET", amz_date, "us-east-1",
            ),
        )
        self.assertEqual(form_data["x-amz-algorithm"], "AWS4-HMAC-SHA256")

    def test_form_data_with_session_token(self):
        form_data, _, _ = self._form_data(session_token="TOKEN")
        self.assertEqual(form_data["x-amz-security-token"], "TOKEN")
        policy = json.loads(base64.b64decode(form_data["policy"]))
        self.assertIn(
            ["eq", "$x-amz-security-token", "TOKEN"], policy["conditions"],
        )


class PresignedUrlTimestampTest(TestCase):
    def _presign(self):
        client = Minio(
            endpoint="localhost:9000",
            access_key="my_access_key",
            secret_key="my_secret_key",
            secure=True,
        )
        client._get_region = mock.Mock(return_value="us-east-1")
        before = _now().replace(microsecond=0)
        url = client.presigned_get_object(
            bucket_name="mybucket", object_name="myfile.pdf",
        )
        after = _now()
        query = parse_qs(urlsplit(url).query)
        signed_at = datetime.strptime(
            query["X-Amz-Date"][0], "%Y%m%dT%H%M%SZ",
        ).replace(tzinfo=timezone.utc)
        return query, signed_at, before, after

    def test_presigned_url_is_signed_with_current_time(self):
        query, signed_at, before, after = self._presign()
        self.assertGreaterEqual(signed_at, before)
        self.assertLessEqual(signed_at, after)
        self.assertTrue(
            query["X-Amz-Credential"][0].startswith(
                f"my_access_key/{signed_at:%Y%m%d}/us-east-1/s3/",
            ),
        )

    def test_presigned_url_current_time_without_utc_constant(self):
        with mock.patch.object(minio_time, "_UTC_IMPORTED", False):
            query, signed_at, before, after = self._presign()
        self.assertGreaterEqual(signed_at, before)
        self.assertLessEqual(signed_at, after)
        self.assertTrue(
            query["X-Amz-Credential"][0].startswith(
                f"my_access_key/{signed_at:%Y%m%d}/us-east-1/s3/",
            ),
        )

    def _send_request(self):
        captured = {}

        def urlopen(method, url, headers=None, **_):
            captured["headers"] = dict(headers)
            return MockResponse(method, url, {}, 200)

        client = Minio(
            endpoint="localhost:9000",
            access_key="my_access_key",
            secret_key="my_secret_key",
            http_client=mock.Mock(urlopen=urlopen),
        )
        before = _now().replace(microsecond=0)
        self.assertTrue(
            client.bucket_exists(bucket_name="mybucket", region="us-east-1"),
        )
        after = _now()
        headers = {
            key.lower(): value for key, value in captured["headers"].items()
        }
        sent_at = datetime.strptime(
            headers["x-amz-date"], "%Y%m%dT%H%M%SZ",
        ).replace(tzinfo=timezone.utc)
        return headers, sent_at, before, after

    def test_request_date_header_is_current_time(self):
        headers, sent_at, before, after = self._send_request()
        self.assertGreaterEqual(sent_at, before)
        self.assertLessEqual(sent_at, after)
        self.assertIn(
            f"/{sent_at:%Y%m%d}/us-east-1/s3/", headers["authorization"],
        )

    def test_request_date_header_without_utc_constant(self):
        with mock.patch.object(minio_time, "_UTC_IMPORTED", False):
            headers, sent_at, before, after = self._send_request()
        self.assertGreaterEqual(sent_at, before)
        self.assertLessEqual(sent_at, after)
        self.assertIn(
            f"/{sent_at:%Y%m%d}/us-east-1/s3/", headers["authorization"],
        )
