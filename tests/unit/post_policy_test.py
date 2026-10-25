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
from datetime import datetime
from unittest import TestCase

from minio.credentials import Credentials
from minio.models import PostPolicy
from minio.signer import get_credential_string, post_presign_v4
from minio.time import to_iso8601utc


class PostPolicyFormDataTest(TestCase):
    def test_form_data_signing_fields_use_same_timestamp(self):
        expiration = datetime(2030, 6, 15, 9, 30, 0)
        policy = PostPolicy("example-bucket", expiration)
        policy.add_equals_condition("key", "uploads/object.txt")
        creds = Credentials(
            "ACCESSKEY",
            "SECRETKEY",
            session_token="SESSIONTOKEN",
        )

        form_data = policy.form_data(creds, "us-west-2")

        self.assertEqual(form_data["x-amz-algorithm"], "AWS4-HMAC-SHA256")
        self.assertEqual(form_data["x-amz-security-token"], "SESSIONTOKEN")

        amz_date = form_data["x-amz-date"]
        self.assertRegex(amz_date, r"^\d{8}T\d{6}Z$")

        credential = form_data["x-amz-credential"]
        signer_date = credential.split("/")[1]
        self.assertEqual(signer_date, amz_date[:8])
        self.assertEqual(
            credential,
            f"ACCESSKEY/{signer_date}/us-west-2/s3/aws4_request",
        )

        signing_time = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ")
        self.assertEqual(
            credential,
            get_credential_string(creds.access_key, signing_time, "us-west-2"),
        )
        self.assertEqual(
            form_data["x-amz-signature"],
            post_presign_v4(
                form_data["policy"],
                creds.secret_key,
                signing_time,
                "us-west-2",
            ),
        )

        decoded_policy = json.loads(
            base64.b64decode(form_data["policy"]).decode("utf-8"),
        )
        self.assertEqual(
            decoded_policy["expiration"],
            to_iso8601utc(expiration),
        )
        self.assertIn(["eq", "$bucket", "example-bucket"], decoded_policy["conditions"])
        self.assertIn(
            ["eq", "$key", "uploads/object.txt"],
            decoded_policy["conditions"],
        )
        self.assertIn(["eq", "$x-amz-date", amz_date], decoded_policy["conditions"])
