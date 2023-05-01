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

# This will verify that the GR#7 rego policy works as expected in different user cases.

empty(value) {
  count(value) == 0
}

no_violations {
  empty(deny)
}

test_no_accessConfigs {
    input := {"data":[
        {
            "asset_type": "compute.googleapis.com/Instance",
            "name": "test-instance",
            "resource": {
                "data": {
                    "networkInterfaces": [
                        {
                            "name": "nic0",
                        }
                    ]
                }
            }
        }
    ]}

    no_violations with input as input
}

test_accessConfigs_exists {
    input := {"data":[
        {
            "asset_type": "compute.googleapis.com/Instance",
            "name": "test-instance",
            "resource": {
                "data": {
                    "networkInterfaces": [
                        {
                            "accessConfigs": [],
                            "name": "nic0",
                        }
                    ]
                }
            }
        }
    ]}

    results := deny with input as input
    count(results) == 1
}
