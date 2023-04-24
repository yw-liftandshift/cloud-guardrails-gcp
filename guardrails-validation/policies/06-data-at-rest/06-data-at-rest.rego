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

import future.keywords.in

# This will check that if a crypto key has a rotation period over the given limit.

kms_key_required_asset_type = "cloudkms.googleapis.com/CryptoKey"

max_allowed_rotation_period_seconds = 7776000 # seconds of 90days

# Deny if any kms key with manual or never-experied rotation.
deny[{"msg": message}] {
	some key in cryptoKeys
	not key.resource.data.rotationPeriod

	message := sprintf("Guardrail # 6: Resource '%v' contains a kms key with manual or never expired rotation.", [key.name])
}

# Deny if any kms key with rotation period over 90 days
deny[{"msg": message}] {
	some key in cryptoKeys
	key.resource.data.rotationPeriod
	endswith(key.resource.data.rotationPeriod, "s")
	to_number(trim_right(key.resource.data.rotationPeriod, "s")) > max_allowed_rotation_period_seconds

	message := sprintf("Guardrail # 6: Resource '%v' contains a kms key with rotation period %v over the maximal allowed time - %v seconds!", [key.name, key.resource.data.rotationPeriod, max_allowed_rotation_period_seconds])
}

cryptoKeys[key] {
	some item in input.data
	item.asset_type == kms_key_required_asset_type
	key := item
}
