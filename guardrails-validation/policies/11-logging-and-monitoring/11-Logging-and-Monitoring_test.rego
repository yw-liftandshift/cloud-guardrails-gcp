################
# Copyright 2021 Google LLC
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

# This will check that log sink exists to save the logs auditing and monitoring
# the example below uses name "log_sink", change this name to match the existing name

empty(value) {
  count(value) == 0
}

no_violations {
  empty(deny)
}

has_violations {
  not empty(deny)
}

test_org_sink_not_exists {
    input := {"data":[
        {
            "asset_type": "logging.googleapis.com/LogSink",
            "name": "test-sink",
            "resource": {
                "data": {
                    "name": "test-sink",
                    "includeChildren": true
                }
            },
            "ancestors": [
                "organizations/1234567890"
            ]
        }
    ]}

    has_violations with input as input
}

test_organ_logsink_exists_without_destination {
    input := {"data":[
        {
            "asset_type": "logging.googleapis.com/LogSink",
            "name": "test-org-sink",
            "resource": {
                "data": {
                    "name": "test-org-sink",
                    "includeChildren": true
                }
            },
            "ancestors": [
                "organizations/565977066779"
            ]
        }
    ]}

    has_violations with input as input
}

test_organ_logsink_exists_without_logbucket {
    input := {"data":[
        {
            "asset_type": "logging.googleapis.com/LogSink",
            "name": "test-org-sink",
            "resource": {
                "data": {
                    "name": "test-org-sink",
                    "includeChildren": true,
                    "destination": ""
                }
            },
            "ancestors": [
                "organizations/565977066779"
            ]
        }
    ]}

    has_violations with input as input
}

test_organ_logsink_exists_with_logbucket {
    input := {"data":[
        {
            "asset_type": "logging.googleapis.com/LogSink",
            "name": "test-org-sink",
            "resource": {
                "data": {
                    "name": "test-org-sink",
                    "includeChildren": true,
                    "destination": "logging.googleapis.com"
                }
            },
            "ancestors": [
                "organizations/565977066779"
            ]
        }
    ]}

    no_violations with input as input
}
