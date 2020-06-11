#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import unittest

import urllib3  # type: ignore
import logging
from pprint import pprint
import json

from pymisp import MISPEvent, MISPObject, MISPSharingGroup, Distribution

from .setup_sync import MISPInstances

logging.disable(logging.CRITICAL)
urllib3.disable_warnings()


LOTR_GALAXY_PATH = 'test-files/lotr-galaxy-cluster.json'
LOTR_TEST_CLUSTER_PATH = 'test-files/lotr-test-cluster.json'


class TestSync(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.maxDiff = None
        cls.misp_instances = MISPInstances()
        cls.lotr_clusters = []
        cls.lotr_test_cluster = {}

        #ready = False
        #while not ready:
        #    ready = True
        #    for i in cls.misp_instances.instances:
        #        settings = i.site_admin_connector.server_settings()
        #        if (not settings['workers']['default']['ok']
        #                or not settings['workers']['prio']['ok']):
        #            print(f'Not ready: {i}')
        #            ready = False
        #    time.sleep(1)

    # @classmethod
    # def tearDownClass(cls):
    #   for i in cls.instances:
    #        i.cleanup()

    def test_pull_clusters(self):
        '''Test galaxy_cluster pull'''
        try:
            misp_central = self.misp_instances.central_node
            self.import_lotr_galaxies(misp_central.org_admin_connector)
            misp1 = self.misp_instances.instances[0]
            misp1.site_admin_connector.server_pull(misp1.synchronisations[misp_central.name])
            time.sleep(15)
            pulled_clusters = self.get_clusters(misp1.org_admin_connector)
            self.compare_cluster_with_disk(pulled_clusters)
        finally:
            self.delete_lotr_clusters(misp_central.site_admin_connector)
            self.delete_lotr_clusters(misp1.site_admin_connector)

    def test_import_clusters(self):
        '''Test galaxy_cluster import'''
        try:
            misp_central = self.misp_instances.central_node
            self.import_lotr_galaxies(misp_central.org_admin_connector)
            imported_clusters = self.get_clusters(misp_central.org_admin_connector)
            self.compare_cluster_with_disk(imported_clusters)
        finally:
            self.delete_lotr_clusters(misp_central.site_admin_connector)

    def test_add_clusters(self):
        '''Test galaxy_cluster add'''
        try:
            misp_central = self.misp_instances.central_node
            self.import_lotr_galaxies(misp_central.org_admin_connector) # make sure the galaxy exists
            lotr_test_cluster = self.get_test_cluster_from_disk()
            galaxy_uuid = lotr_test_cluster['Galaxy']['uuid']
            relative_path = f'/galaxy_clusters/add/{galaxy_uuid}'
            misp_central.org_admin_connector.direct_call(relative_path, lotr_test_cluster)
            clusters = self.get_clusters(misp_central.org_admin_connector)
            for cluster in clusters:
                if cluster['GalaxyCluster']['uuid'] == lotr_test_cluster['GalaxyCluster']['uuid']:
                    self.compare_cluster(cluster, lotr_test_cluster)
        finally:
            self.delete_lotr_clusters(misp_central.site_admin_connector)

    def import_lotr_galaxies(self, instance):
        lotr_clusters = self.get_lotr_clusters_from_disk()
        relative_path = 'galaxies/import'
        instance.direct_call(relative_path, lotr_clusters)

    def delete_lotr_clusters(self, instance):
        lotr_uuids = ["93d4d641-a905-458a-83b4-18677a4ea534",
                      "fe1c605e-a8ca-47c9-83bf-a715ce6042dc",
                      "b8563f2f-dd0e-4c11-bdca-c2fe7774e779"]
        for galaxy_id in lotr_uuids:
            relative_path = f'galaxies/delete/{galaxy_id}'
            instance.direct_call(relative_path, {})

    def get_clusters(self, instance):
        filters = {
            "returnFormat": "json",
            "galaxy_uuid": [
                "93d4d641-a905-458a-83b4-18677a4ea534",
                "fe1c605e-a8ca-47c9-83bf-a715ce6042dc",
                "b8563f2f-dd0e-4c11-bdca-c2fe7774e779"
            ]
        }
        relative_path = 'galaxy_clusters/restSearch'
        return instance.direct_call(relative_path, filters)

    def get_lotr_clusters_from_disk(self):
        if len(self.lotr_clusters) == 0:
            with open(LOTR_GALAXY_PATH) as f:
                self.lotr_clusters = json.load(f)
        return self.lotr_clusters

    def get_test_cluster_from_disk(self):
        if len(self.lotr_test_cluster) == 0:
            with open(LOTR_TEST_CLUSTER_PATH) as f:
                self.lotr_test_cluster = json.load(f)
        return self.lotr_test_cluster

    def compare_cluster_with_disk(self, clusters):
        base_clusters = self.get_lotr_clusters_from_disk()
        clusters_arranged = {}
        for cluster in clusters:
            clusters_arranged[cluster['GalaxyCluster']['uuid']] = cluster
        for base_cluster in base_clusters:
            cluster = clusters_arranged[base_cluster['GalaxyCluster']['uuid']]
            # self.assertEqual(base_cluster['GalaxyCluster']['uuid'], cluster['GalaxyCluster']['uuid'])
            # self.assertEqual(base_cluster['GalaxyCluster']['version'], cluster['GalaxyCluster']['version'])
            # self.assertEqual(len(base_cluster['GalaxyCluster']['GalaxyElement']), len(cluster['GalaxyElement']))
            # self.assertEqual(len(base_cluster['GalaxyCluster']['GalaxyClusterRelation']), len(cluster['GalaxyClusterRelation']))
            self.compare_cluster(base_cluster, cluster)


    def compare_cluster(self, cluster1, cluster2):
        self.assertEqual(cluster1['GalaxyCluster']['uuid'], cluster2['GalaxyCluster']['uuid'])
        self.assertEqual(cluster1['GalaxyCluster']['version'], cluster2['GalaxyCluster']['version'])
        self.assertEqual(len(cluster1['GalaxyCluster']['GalaxyElement']), len(cluster2['GalaxyElement']))
        self.assertEqual(len(cluster1['GalaxyCluster']['GalaxyClusterRelation']), len(cluster2['GalaxyClusterRelation']))
        # self.assertEqual(len(base_cluster['GalaxyCluster']['GalaxyElement']), len(cluster['GalaxyCluster']['GalaxyElement']))
        # self.assertEqual(len(base_cluster['GalaxyCluster']['GalaxyClusterRelation']), len(cluster['GalaxyCluster']['GalaxyClusterRelation']))

    def test_simple_sync(self):
        '''Test simple event, push to one server'''
        event = MISPEvent()
        event.info = 'Event created on first instance - test_simple_sync'
        event.distribution = Distribution.all_communities
        event.add_attribute('ip-src', '1.1.1.1')
        try:
            source = self.misp_instances.instances[0]
            dest = self.misp_instances.instances[1]
            event = source.org_admin_connector.add_event(event)
            source.org_admin_connector.publish(event)
            source.site_admin_connector.server_push(source.synchronisations[dest.name], event)
            time.sleep(10)
            dest_event = dest.org_admin_connector.get_event(event.uuid)
            self.assertEqual(event.attributes[0].value, dest_event.attributes[0].value)

        finally:
            source.org_admin_connector.delete_event(event)
            dest.site_admin_connector.delete_event(dest_event)

    def test_sync_community(self):
        '''Simple event, this community only, pull from member of the community'''
        event = MISPEvent()
        event.info = 'Event created on first instance - test_sync_community'
        event.distribution = Distribution.this_community_only
        event.add_attribute('ip-src', '1.1.1.1')
        try:
            source = self.misp_instances.instances[0]
            dest = self.misp_instances.instances[1]
            event = source.org_admin_connector.add_event(event)
            source.org_admin_connector.publish(event)
            dest.site_admin_connector.server_pull(dest.synchronisations[source.name])
            time.sleep(10)
            dest_event = dest.org_admin_connector.get_event(event)
            self.assertEqual(dest_event.distribution, 0)
        finally:
            source.org_admin_connector.delete_event(event)
            dest.site_admin_connector.delete_event(dest_event)

    def test_sync_all_communities(self):
        '''Simple event, all communities, enable automatic push on two sub-instances'''
        event = MISPEvent()
        event.info = 'Event created on first instance - test_sync_all_communities'
        event.distribution = Distribution.all_communities
        event.add_attribute('ip-src', '1.1.1.1')
        try:
            source = self.misp_instances.instances[0]
            middle = self.misp_instances.instances[1]
            last = self.misp_instances.instances[2]
            server = source.site_admin_connector.update_server({'push': True}, source.synchronisations[middle.name].id)
            self.assertTrue(server.push)

            middle.site_admin_connector.update_server({'push': True}, middle.synchronisations[last.name].id)  # Enable automatic push to 3rd instance
            event = source.user_connector.add_event(event)
            source.org_admin_connector.publish(event)
            source.site_admin_connector.server_push(source.synchronisations[middle.name])
            time.sleep(30)
            middle_event = middle.user_connector.get_event(event.uuid)
            self.assertEqual(event.attributes[0].value, middle_event.attributes[0].value)
            last_event = last.user_connector.get_event(event.uuid)
            self.assertEqual(event.attributes[0].value, last_event.attributes[0].value)
        finally:
            source.org_admin_connector.delete_event(event)
            middle.site_admin_connector.delete_event(middle_event)
            last.site_admin_connector.delete_event(last_event)
            source.site_admin_connector.update_server({'push': False}, source.synchronisations[middle.name].id)
            middle.site_admin_connector.update_server({'push': False}, middle.synchronisations[last.name].id)

    def create_complex_event(self):
        event = MISPEvent()
        event.info = 'Complex Event'
        event.distribution = Distribution.all_communities
        event.add_tag('tlp:white')

        event.add_attribute('ip-src', '8.8.8.8')
        event.add_attribute('ip-dst', '8.8.8.9')
        event.add_attribute('domain', 'google.com')
        event.add_attribute('md5', '3c656da41f4645f77e3ec3281b63dd43')

        event.attributes[0].distribution = Distribution.your_organisation_only
        event.attributes[1].distribution = Distribution.this_community_only
        event.attributes[2].distribution = Distribution.connected_communities

        event.attributes[0].add_tag('tlp:red')
        event.attributes[1].add_tag('tlp:amber')
        event.attributes[2].add_tag('tlp:green')

        obj = MISPObject('file')

        obj.distribution = Distribution.connected_communities
        obj.add_attribute('filename', 'testfile')
        obj.add_attribute('md5', '3c656da41f4645f77e3ec3281b63dd44')
        obj.attributes[0].distribution = Distribution.your_organisation_only

        event.add_object(obj)

        return event

    def test_complex_event_push_pull(self):
        '''Test automatic push'''
        event = self.create_complex_event()
        try:
            source = self.misp_instances.instances[0]
            middle = self.misp_instances.instances[1]
            last = self.misp_instances.instances[2]
            source.site_admin_connector.update_server({'push': True}, source.synchronisations[middle.name].id)
            middle.site_admin_connector.update_server({'push': True}, middle.synchronisations[last.name].id)  # Enable automatic push to 3rd instance

            event = source.org_admin_connector.add_event(event)
            source.org_admin_connector.publish(event)
            time.sleep(15)
            event_middle = middle.user_connector.get_event(event.uuid)
            event_last = last.user_connector.get_event(event.uuid)
            self.assertEqual(len(event_middle.attributes), 2)  # attribute 3 and 4
            self.assertEqual(len(event_middle.objects[0].attributes), 1)  # attribute 2
            self.assertEqual(len(event_last.attributes), 1)  # attribute 4
            self.assertFalse(event_last.objects)
            # Test if event is properly sanitized
            event_middle_as_site_admin = middle.site_admin_connector.get_event(event.uuid)
            self.assertEqual(len(event_middle_as_site_admin.attributes), 2)  # attribute 3 and 4
            self.assertEqual(len(event_middle_as_site_admin.objects[0].attributes), 1)  # attribute 2
            # FIXME https://github.com/MISP/MISP/issues/4975
            # Force pull from the last one
            # last.site_admin_connector.server_pull(last.sync_servers[0])
            # time.sleep(6)
            # event_last = last.user_connector.get_event(event.uuid)
            # self.assertEqual(len(event_last.objects[0].attributes), 1)  # attribute 2
            # self.assertEqual(len(event_last.attributes), 2)  # attribute 3 and 4
            # Force pull from the middle one
            # middle.site_admin_connector.server_pull(last.sync_servers[0])
            # time.sleep(6)
            # event_middle = middle.user_connector.get_event(event.uuid)
            # self.assertEqual(len(event_middle.attributes), 3)  # attribute 2, 3 and 4
            # Force pull from the last one
            # last.site_admin_connector.server_pull(last.sync_servers[0])
            # time.sleep(6)
            # event_last = last.user_connector.get_event(event.uuid)
            # self.assertEqual(len(event_last.attributes), 2)  # attribute 3 and 4
        finally:
            source.org_admin_connector.delete_event(event)
            middle.site_admin_connector.delete_event(event_middle)
            last.site_admin_connector.delete_event(event_last)
            source.site_admin_connector.update_server({'push': False}, source.synchronisations[middle.name].id)
            middle.site_admin_connector.update_server({'push': False}, middle.synchronisations[last.name].id)

    def test_complex_event_pull(self):
        '''Test pull'''
        event = self.create_complex_event()
        try:
            source = self.misp_instances.instances[0]
            middle = self.misp_instances.instances[1]
            last = self.misp_instances.instances[2]

            event = source.org_admin_connector.add_event(event)
            source.org_admin_connector.publish(event)
            middle.site_admin_connector.server_pull(middle.synchronisations[source.name])
            time.sleep(15)
            last.site_admin_connector.server_pull(last.synchronisations[middle.name])
            time.sleep(15)
            event_middle = middle.user_connector.get_event(event.uuid)
            event_last = last.user_connector.get_event(event.uuid)
            self.assertEqual(len(event_middle.attributes), 3)  # attribute 2, 3 and 4
            self.assertEqual(len(event_middle.objects[0].attributes), 1)  # attribute 2
            self.assertEqual(len(event_last.attributes), 2)  # attribute 3, 4
            self.assertEqual(len(event_last.objects[0].attributes), 1)
            # Test if event is properly sanitized
            event_middle_as_site_admin = middle.site_admin_connector.get_event(event.uuid)
            self.assertEqual(len(event_middle_as_site_admin.attributes), 3)  # attribute 2, 3 and 4
            self.assertEqual(len(event_middle_as_site_admin.objects[0].attributes), 1)  # attribute 2
        finally:
            source.org_admin_connector.delete_event(event)
            middle.site_admin_connector.delete_event(event_middle)
            last.site_admin_connector.delete_event(event_last)

    def test_sharing_group(self):
        '''Test Sharing Group'''
        event = self.create_complex_event()
        try:
            source = self.misp_instances.instances[0]
            middle = self.misp_instances.instances[1]
            last = self.misp_instances.instances[2]
            source.site_admin_connector.update_server({'push': True}, source.synchronisations[middle.name].id)
            middle.site_admin_connector.update_server({'push': True}, middle.synchronisations[last.name].id)  # Enable automatic push to 3rd instance

            sg = MISPSharingGroup()
            sg.name = 'Testcases SG'
            sg.releasability = 'Testing'
            sharing_group = source.site_admin_connector.add_sharing_group(sg)
            source.site_admin_connector.add_org_to_sharing_group(sharing_group, middle.host_org.uuid)
            source.site_admin_connector.add_server_to_sharing_group(sharing_group, 0)  # Add local server
            # NOTE: the data on that sharing group *won't be synced anywhere*

            a = event.add_attribute('text', 'SG only attr')
            a.distribution = Distribution.sharing_group
            a.sharing_group_id = sharing_group.id

            event = source.org_admin_connector.add_event(event)
            source.org_admin_connector.publish(event)
            time.sleep(60)

            event_middle = middle.user_connector.get_event(event)
            self.assertTrue(isinstance(event_middle, MISPEvent), event_middle)
            self.assertEqual(len(event_middle.attributes), 2, event_middle)
            self.assertEqual(len(event_middle.objects), 1, event_middle)
            self.assertEqual(len(event_middle.objects[0].attributes), 1, event_middle)

            event_last = last.user_connector.get_event(event)
            self.assertTrue(isinstance(event_last, MISPEvent), event_last)
            self.assertEqual(len(event_last.attributes), 1)
            # Test if event is properly sanitized
            event_middle_as_site_admin = middle.site_admin_connector.get_event(event.uuid)
            self.assertEqual(len(event_middle_as_site_admin.attributes), 2)
            event_last_as_site_admin = last.site_admin_connector.get_event(event.uuid)
            self.assertEqual(len(event_last_as_site_admin.attributes), 1)
            # Get sharing group from middle instance
            sgs = middle.site_admin_connector.sharing_groups()
            self.assertEqual(len(sgs), 0)

            # TODO: Update sharing group so the attribute is pushed
            # self.assertEqual(sgs[0].name, 'Testcases SG')
            # middle.site_admin_connector.delete_sharing_group(sgs[0])
        finally:
            source.org_admin_connector.delete_event(event)
            middle.site_admin_connector.delete_event(event)
            last.site_admin_connector.delete_event(event)
            source.site_admin_connector.delete_sharing_group(sharing_group.id)
            middle.site_admin_connector.delete_sharing_group(sharing_group.id)
            source.site_admin_connector.update_server({'push': False}, source.synchronisations[middle.name].id)
            middle.site_admin_connector.update_server({'push': False}, middle.synchronisations[last.name].id)
