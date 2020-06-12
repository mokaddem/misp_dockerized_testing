#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import unittest

import urllib3  # type: ignore
import logging
from pprint import pprint
import json
import functools

from pymisp import MISPEvent, MISPObject, MISPSharingGroup, Distribution

from .setup_sync import MISPInstances

logging.disable(logging.CRITICAL)
urllib3.disable_warnings()


LOTR_GALAXY_PATH = 'test-files/lotr-galaxy-cluster.json'
LOTR_TEST_CLUSTER_PATH = 'test-files/lotr-test-cluster.json'

def setup_cluster_env(func):
    @functools.wraps(func)
    def wrapper(self,*args,**kwargs):
        try:
            misp_central = self.misp_instances.central_node
            self.import_lotr_galaxies(misp_central.org_admin_connector)
            func(self,*args,**kwargs)
        finally:
            self.delete_lotr_clusters(misp_central.site_admin_connector)
    return wrapper


class TestClusterSync(unittest.TestCase):

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

    @setup_cluster_env
    def test_pull_clusters(self):
        '''Test galaxy_cluster pull'''
        try:
            misp_central = self.misp_instances.central_node
            misp1 = self.misp_instances.instances[0]
            misp1.site_admin_connector.server_pull(misp1.synchronisations[misp_central.name])
            time.sleep(15)
            pulled_clusters = self.get_clusters(misp1.org_admin_connector)
            self.compare_cluster_with_disk(pulled_clusters, mirrorCheck=False)
            pulledClustersByUUID = { cluster['GalaxyCluster']['uuid']: cluster for cluster in pulled_clusters }

            # Check that distribution has been adpated accordingly
            lotr_test_cluster = self.get_lotr_clusters_from_disk()
            for cluster in lotr_test_cluster:
                pulled_cluster = pulledClustersByUUID.get(cluster['GalaxyCluster']['uuid'], False)
                if cluster['GalaxyCluster']['distribution'] == '0':
                    self.assertIs(pulled_cluster, False) # your organisation only should not be pulled
                if cluster['GalaxyCluster']['distribution'] == '1':
                    self.assertEqual(pulled_cluster['GalaxyCluster']['distribution'], '0')
                if cluster['GalaxyCluster']['distribution'] == '2':
                    self.assertEqual(pulled_cluster['GalaxyCluster']['distribution'], '1')
                if cluster['GalaxyCluster']['distribution'] == '4':
                    pass

            # Check for Orgc
            for cluster in lotr_test_cluster:
                pulled_cluster = pulledClustersByUUID.get(cluster['GalaxyCluster']['uuid'], False)
                if pulled_cluster is not False:
                    self.assertEqual(cluster['GalaxyCluster']['Orgc']['uuid'], cluster['GalaxyCluster']['Orgc']['uuid'])
                    for relation in cluster['GalaxyCluster']['GalaxyClusterRelation']:
                        pulled_relation = self.find_relation_in_cluster(relation, pulled_cluster['GalaxyCluster']['GalaxyClusterRelation'])
                        if relation['distribution'] == '0':
                            self.assertIs(pulled_relation, False) # your organisation only should not be pulled
                        if relation['distribution'] == '1':
                            self.assertEqual(pulled_relation['distribution'], '0')
                        if relation['distribution'] == '2':
                            self.assertEqual(pulled_relation['distribution'], '1')
                        if relation['distribution'] == '4':
                            pass
                else:
                    self.assertEqual(cluster['GalaxyCluster']['distribution'], '0')

        finally:
            # pass
            self.delete_lotr_clusters(misp1.site_admin_connector)

    @setup_cluster_env
    def test_import_clusters(self):
        '''Test galaxy_cluster import'''
        try:
            misp_central = self.misp_instances.central_node
            imported_clusters = self.get_clusters(misp_central.org_admin_connector)
            self.compare_cluster_with_disk(imported_clusters, mirrorCheck=True)
        finally:
            pass

    @setup_cluster_env
    def test_add_cluster(self):
        '''Test galaxy_cluster add'''
        try:
            misp_central = self.misp_instances.central_node
            lotr_test_cluster = self.get_test_cluster_from_disk()
            galaxy_uuid = lotr_test_cluster['GalaxyCluster']['Galaxy']['uuid']
            relative_path = f'/galaxy_clusters/add/{galaxy_uuid}'
            misp_central.org_admin_connector.direct_call(relative_path, data=lotr_test_cluster)

            uuid = lotr_test_cluster['GalaxyCluster']['uuid']
            addedCluster = self.get_cluster(misp_central.org_admin_connector, uuid)
            self.assertEqual(addedCluster['GalaxyCluster']['uuid'], uuid)
            self.compare_cluster(lotr_test_cluster, addedCluster, mirrorCheck=True)
        finally:
            pass

    @setup_cluster_env
    def test_edit_cluster(self):
        '''Test galaxy_cluster edit'''
        try:
            misp_central = self.misp_instances.central_node
            lotr_test_cluster = self.get_test_cluster_from_disk()
            galaxy_uuid = lotr_test_cluster['GalaxyCluster']['Galaxy']['uuid']
            relative_path = f'/galaxy_clusters/add/{galaxy_uuid}'
            misp_central.org_admin_connector.direct_call(relative_path, data=lotr_test_cluster)
            
            uuid = lotr_test_cluster['GalaxyCluster']['uuid']
            addedCluster = self.get_cluster(misp_central.org_admin_connector, uuid)
            self.assertEqual(addedCluster['GalaxyCluster']['uuid'], uuid)
            self.compare_cluster(lotr_test_cluster, addedCluster, mirrorCheck=True)

            addedCluster['GalaxyCluster']['description'] = 'baz'
            addedCluster['GalaxyCluster']['distribution'] = 0
            addedCluster['GalaxyCluster']['GalaxyElement'] = [
                {
                    "key": "weapon",
                    "value": "weaponModified"
                }
            ]
            relative_path = f'/galaxy_clusters/edit/{uuid}'
            misp_central.org_admin_connector.direct_call(relative_path, data=addedCluster)
            editedCluster = self.get_cluster(misp_central.org_admin_connector, uuid)
            self.assertEqual(editedCluster['GalaxyCluster']['uuid'], uuid)
            self.assertEqual(editedCluster['GalaxyCluster']['description'], 'baz')
            self.assertEqual(editedCluster['GalaxyCluster']['distribution'], '0')
            self.assertNotEqual(editedCluster['GalaxyCluster']['version'], lotr_test_cluster['GalaxyCluster']['version'])
            self.assertEqual(len(editedCluster['GalaxyCluster']['GalaxyElement']), 1)
            self.assertEqual(editedCluster['GalaxyCluster']['GalaxyElement'][0]['value'], 'weaponModified')
        finally:
            pass

    @setup_cluster_env
    def test_delete_cluster(self):
        try:
            misp_central = self.misp_instances.central_node
            lotr_test_cluster = self.get_test_cluster_from_disk()
            galaxy_uuid = lotr_test_cluster['GalaxyCluster']['Galaxy']['uuid']
            relative_path = f'/galaxy_clusters/add/{galaxy_uuid}'
            misp_central.org_admin_connector.direct_call(relative_path, data=lotr_test_cluster)
            cluster_uuid = lotr_test_cluster['GalaxyCluster']['uuid']
            addedCluster = self.get_cluster(misp_central.org_admin_connector, cluster_uuid)
            cluster_id = addedCluster['GalaxyCluster']['id']
            self.assertEqual(addedCluster['GalaxyCluster']['uuid'], cluster_uuid)

            relative_path = f'/galaxy_clusters/delete/{cluster_id}'
            misp_central.org_admin_connector.direct_call(relative_path, data={})
            deletedCluster = self.get_cluster(misp_central.org_admin_connector, cluster_uuid)
            self.assertNotIn('uuid', deletedCluster)
        finally:
            pass

    @setup_cluster_env
    def test_restsearch_cluster(self):
        '''Test galaxy_cluster restSearch'''
        try:
            misp_central = self.misp_instances.central_node
            lotr_test_cluster = self.get_test_cluster_from_disk()
            galaxy_uuid = lotr_test_cluster['GalaxyCluster']['Galaxy']['uuid']
            relative_path = f'/galaxy_clusters/add/{galaxy_uuid}'
            misp_central.org_admin_connector.direct_call(relative_path, data=lotr_test_cluster)
            cluster_uuid = lotr_test_cluster['GalaxyCluster']['uuid']
            added_cluster = self.get_cluster(misp_central.org_admin_connector, cluster_uuid)
            self.assertEqual(added_cluster['GalaxyCluster']['uuid'], cluster_uuid)
            tag_name = added_cluster['GalaxyCluster']['tag_name']

            filters = {
                "tag_name": tag_name
            }
            relative_path = 'galaxy_clusters/restSearch'
            clusterFromRestSearch = misp_central.org_admin_connector.direct_call(relative_path, data=filters)
            self.assertEqual(len(clusterFromRestSearch), 1)
            clusterFromRestSearch = clusterFromRestSearch[0]
            self.compare_cluster(added_cluster, clusterFromRestSearch, mirrorCheck=True)
        finally:
            pass

    def import_lotr_galaxies(self, instance):
        lotr_clusters = self.get_lotr_clusters_from_disk()
        relative_path = 'galaxies/import'
        instance.direct_call(relative_path, data=lotr_clusters)

    def delete_lotr_clusters(self, instance):
        lotr_uuids = ["93d4d641-a905-458a-83b4-18677a4ea534",
                      "fe1c605e-a8ca-47c9-83bf-a715ce6042dc",
                      "b8563f2f-dd0e-4c11-bdca-c2fe7774e779"]
        for galaxy_id in lotr_uuids:
            relative_path = f'galaxies/delete/{galaxy_id}'
            instance.direct_call(relative_path, {})

    def get_clusters(self, instance):
        filters = {
            "galaxy_uuid": [
                "93d4d641-a905-458a-83b4-18677a4ea534",
                "fe1c605e-a8ca-47c9-83bf-a715ce6042dc",
                "b8563f2f-dd0e-4c11-bdca-c2fe7774e779"
            ]
        }
        relative_path = 'galaxy_clusters/restSearch'
        return instance.direct_call(relative_path, data=filters)

    def get_cluster(self, instance, uuid):
        relative_path = f'galaxy_clusters/view/{uuid}'
        return instance.direct_call(relative_path)

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

    def compare_cluster_with_disk(self, clusters, mirrorCheck=False):
        base_clusters = self.get_lotr_clusters_from_disk()
        clusters_by_uuid = { cluster['GalaxyCluster']['uuid']: cluster for cluster in clusters }
        for base_cluster in base_clusters:
            cluster = clusters_by_uuid.get(base_cluster['GalaxyCluster']['uuid'], False)
            if mirrorCheck:
                self.assertIsNot(cluster, False)
            elif cluster is False:
                continue

            if 'GalaxyElement' in cluster:
                cluster['GalaxyCluster']['GalaxyElement'] = cluster['GalaxyElement']
            if 'GalaxyClusterRelation' in cluster:
                cluster['GalaxyCluster']['GalaxyClusterRelation'] = cluster['GalaxyClusterRelation']
            self.compare_cluster(base_cluster, cluster, mirrorCheck=mirrorCheck)


    def compare_cluster(self, cluster1, cluster2, mirrorCheck=False):
        to_check_cluster = ['uuid', 'version', 'value', 'type', 'extends_uuid', 'extends_version']
        to_check_element = ['key', 'value']
        to_check_relation = ['referenced_galaxy_cluster_uuid', 'referenced_galaxy_cluster_type', 'default']
        if mirrorCheck:
                to_check_relation.append('distribution')
        to_check_tag = ['name']

        for k in to_check_cluster:
            self.assertEqual(cluster1['GalaxyCluster'][k], cluster2['GalaxyCluster'][k])

        self.assertEqual(len(cluster1['GalaxyCluster']['GalaxyElement']), len(cluster2['GalaxyCluster']['GalaxyElement']))
        toCheckElement1 = [ self.extract_useful_fields(e, to_check_element) for e in cluster1['GalaxyCluster']['GalaxyElement']]
        toCheckElement2 = [ self.extract_useful_fields(e, to_check_element) for e in cluster2['GalaxyCluster']['GalaxyElement']]
        for elem1 in toCheckElement1:
            self.assertIn(elem1, toCheckElement2)

        if mirrorCheck: # distribution may affect the number of relations
            self.assertEqual(len(cluster1['GalaxyCluster']['GalaxyClusterRelation']), len(cluster2['GalaxyCluster']['GalaxyClusterRelation']))
        for rel1 in cluster1['GalaxyCluster']['GalaxyClusterRelation']:
            rel2 = self.find_relation_in_cluster(rel1, cluster2['GalaxyCluster']['GalaxyClusterRelation'])
            if rel1['distribution'] == '0':
                self.assertIs(rel2, False)
                continue
            else:
                self.assertIsNot(rel2, False)

            for k in to_check_relation:
                self.assertEqual(rel1[k], rel2[k])

            if 'Tag' in rel1:
                toCheckTag1 = [ self.extract_useful_fields(t, to_check_tag) for t in rel1['Tag']]
                toCheckTag2 = [ self.extract_useful_fields(t, to_check_tag) for t in rel2['Tag']]
                for tag1 in toCheckTag1:
                    self.assertIn(tag1, toCheckTag2)

    def extract_useful_fields(self, orig_dict, keys_to_extract):
        return { key: orig_dict[key] for key in keys_to_extract }

    def find_relation_in_cluster(self, relation, relations):
        for rel in relations:
            if (
                rel['referenced_galaxy_cluster_uuid'] == relation['referenced_galaxy_cluster_uuid'] and 
                rel['referenced_galaxy_cluster_type'] == relation['referenced_galaxy_cluster_type']
            ):
                return rel
        return False
