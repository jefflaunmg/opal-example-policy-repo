package app.subscription

# import future.keywords.contains
# import future.keywords.if
# import future.keywords.in
# import future.keywords

default allow := false

# find corresponding resource group that contain resource in the request
eligible_res_groups[data.resource_groups[i].id] {
	some i, j

	k := data.resource_groups[i].resource_attr[j].key
	input_resource_attr := input.resource[k]

	data.resource_groups[i].resource_attr[j].value == input_resource_attr[_]
}

# find all the policies in data source that have access right to the resource group
eligible_policies[data.policies[i].id] {
	some i, j
	data.policies[i].rules[j].resource_group_id == eligible_res_groups[_]
	data.policies[i].rules[j].action == input.action
}

# check data source whether user has at least one policy required, and check expiry, return false if not exist or expired
# otherwise, return true
allow {
	data.users[i].user_id == input.subject.id
	data.users[i].policies[_].policy_id == eligible_policies[_]
}