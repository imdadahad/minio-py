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
from datetime import datetime, timedelta, timezone
from unittest import TestCase

from minio import Minio
from minio.credentials import Credentials
from minio.models import PostPolicy
from minio.signer import post_presign_v4

REGION = "us-east-1"
AMZ_DATE_FORMAT = "%Y%m%dT%H%M%SZ"


def _new_policy() -> PostPolicy:
    policy = PostPolicy(
        "mybucket",
        datetime.now(timezone.utc) + timedelta(days=1),
    )
    policy.add_starts_with_condition("key", "uploads/")
    return policy


def _signed_at(form_data: dict) -> datetime:
    return datetime.strptime(
        form_data["x-amz-date"], AMZ_DATE_FORMAT,
    ).replace(tzinfo=timezone.utc)


class PostPolicyFormDataTest(TestCase):
    def test_form_data_signing_time_is_current_utc_time(self):
        creds = Credentials(access_key="access", secret_key="secret")
        before = datetime.now(timezone.utc).replace(microsecond=0)
        form_data = _new_policy().form_data(creds, REGION)
        after = datetime.now(timezone.utc)

        signed_at = _signed_at(form_data)
        self.assertLessEqual(before, signed_at)
        self.assertLessEqual(signed_at, after)

    def test_form_data_credential_scope_uses_signing_date(self):
        creds = Credentials(access_key="access", secret_key="secret")
        form_data = _new_policy().form_data(creds, REGION)

        signed_at = _signed_at(form_data)
        self.assertEqual(
            form_data["x-amz-credential"],
            f"access/{signed_at.strftime('%Y%m%d')}/{REGION}/s3/aws4_request",
        )

    def test_form_data_policy_carries_signing_fields(self):
        creds = Credentials(access_key="access", secret_key="secret")
        form_data = _new_policy().form_data(creds, REGION)

        policy = json.loads(base64.b64decode(form_data["policy"]))
        self.assertIn(
            ["eq", "$x-amz-date", form_data["x-amz-date"]],
            policy["conditions"],
        )
        self.assertIn(
            ["eq", "$x-amz-credential", form_data["x-amz-credential"]],
            policy["conditions"],
        )
        self.assertIn(
            ["eq", "$x-amz-algorithm", "AWS4-HMAC-SHA256"],
            policy["conditions"],
        )

    def test_form_data_signature_matches_policy_and_signing_date(self):
        creds = Credentials(access_key="access", secret_key="secret")
        form_data = _new_policy().form_data(creds, REGION)

        expected = post_presign_v4(
            form_data["policy"],
            "secret",
            _signed_at(form_data),
            REGION,
        )
        self.assertEqual(form_data["x-amz-signature"], expected)

    def test_form_data_includes_session_token_when_present(self):
        creds = Credentials(
            access_key="access",
            secret_key="secret",
            session_token="session-token",
        )
        form_data = _new_policy().form_data(creds, REGION)

        self.assertEqual(form_data["x-amz-security-token"], "session-token")
        policy = json.loads(base64.b64decode(form_data["policy"]))
        self.assertIn(
            ["eq", "$x-amz-security-token", "session-token"],
            policy["conditions"],
        )

    def test_client_presigned_post_policy_returns_signed_form_data(self):
        client = Minio(
            endpoint="localhost:9000",
            access_key="access",
            secret_key="secret",
            region=REGION,
        )
        before = datetime.now(timezone.utc).replace(microsecond=0)
        form_data = client.presigned_post_policy(_new_policy())
        after = datetime.now(timezone.utc)

        signed_at = _signed_at(form_data)
        self.assertLessEqual(before, signed_at)
        self.assertLessEqual(signed_at, after)
        self.assertTrue(
            form_data["x-amz-credential"].startswith("access/"),
        )
        self.assertEqual(
            form_data["x-amz-signature"],
            post_presign_v4(
                form_data["policy"], "secret", signed_at, REGION,
            ),
        )
