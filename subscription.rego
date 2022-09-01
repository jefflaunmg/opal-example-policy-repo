package app.subscription

import future.keywords.contains
import future.keywords.in

default allow = false

# find corresponding resource group that contain resource in the request
eligible_res_groups contains data.resource_groups[i].id {
	some i, j

	k := data.resource_groups[i].resource_attr[j].key
	input_resource_attr := input.resource[k]

	data.resource_groups[i].resource_attr[j].value in input_resource_attr
}

# find all the policies in data source that have access right to the resource group
eligible_policies contains data.policies[i].id {
	some i
	data.policies[i].rules[j].resource_group_id in eligible_res_groups
	data.policies[i].rules[j].action == input.action
}

# check data source whether user has at least one policy required, and check expiry, return false if not exist or expired
# otherwise, return true
allow {
	data.users[i].id == input.subject.id
	data.users[i].policies[_].id in eligible_policies
}