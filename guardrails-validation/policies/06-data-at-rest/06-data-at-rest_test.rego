################
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#################

package main

# This will check that if the rego policy works well in the below use cases.

test_kms_key_without_rotation_period {
    input := {"data":[
        {
            "asset_type": "cloudkms.googleapis.com/CryptoKey",
            "name": "test-kmskey",
            "resource": {
                "data": {
                }
            }
        }
    ]}
    results := deny with input as input
    count(results) == 1
}

test_kms_key_rotation_period_over_90days {
    input := {"data":[
        {
            "asset_type": "cloudkms.googleapis.com/CryptoKey",
            "name": "test-kmskey",
            "resource": {
                "data": {
                    "rotationPeriod": "31540000s"
                }
            }
        }
    ]}
    results := deny with input as input
    count(results) == 1
}

test_kms_key_rotation_period_not_over_90days {
    input := {"data":[
        {
            "asset_type": "cloudkms.googleapis.com/CryptoKey",
            "name": "test-kmskey",
            "resource": {
                "data": {
                    "rotationPeriod": "7776000s"
                }
            }
        }
    ]}
    results := deny with input as input
    count(results) == 0
}
