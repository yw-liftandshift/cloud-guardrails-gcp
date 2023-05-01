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

# This will check that if any gce instance is providing internet access.

gce_instance_required_asset_type = "compute.googleapis.com/Instance"

# Deny if any gce instance has any access configs defined for any kind of internet access.
deny[{"msg": message}] {
	some key in instances
	key.resource.data.networkInterfaces[_].accessConfigs

	message := sprintf("Guardrail # 7: Resource '%v' supports intenet access!", [key.name])
}

instances[key] {
	some item in input.data
	item.asset_type == gce_instance_required_asset_type
	key := item
}
