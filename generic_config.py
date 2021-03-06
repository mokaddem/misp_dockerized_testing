#!/usr/bin/env python3
# -*- coding: utf-8 -*-

internal_network_name = 'custom_misp_testing_environment'

# NOTE: There will be an extra instances (the central node), where all the client synchronize with (push)
number_instances = 3

url_scheme = 'http'
central_node_name = 'misp-central'
prefix_client_node = 'misp-'
hostname_suffix = '.local'

# #### Sync config

secure_connection = False
central_node_org_name = 'Central Node'
client_node_org_name_prefix = 'Node '
admin_email_name = 'siteadmin'
orgadmin_email_name = 'orgadmin'
user_email_name = 'user'
