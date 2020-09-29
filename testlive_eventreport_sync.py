#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import unittest

import urllib3  # type: ignore
import logging
from pprint import pprint
import json
import copy
import uuid
import functools

from pymisp import MISPEvent, MISPObject, MISPSharingGroup, Distribution

# FIXME: Monkey patch
def repSG(self, *args, **kwargs):
    return f'<MISPSharingGroup: {self.name}>'
MISPSharingGroup.__repr__ = repSG

from misp_dockerized_testing.setup_sync import MISPInstances

logging.disable(logging.CRITICAL)
urllib3.disable_warnings()


WAIT_AFTER_SYNC = 6
DEBUG_NO_WIPE = not True
# DEBUG_NO_WIPE = True

def setup_event_pull_env(func):
    @functools.wraps(func)
    def wrapper(self,*args,**kwargs):
        try:
            misp_central = self.misp_instances.central_node
            self.wipe_all()
            self.event = self.create_event(misp_central.org_admin_connector)
            func(self,*args,**kwargs)
        finally:
            self.delete_event(misp_central.site_admin_connector, self.event)
            pass
    return wrapper

def setup_event_push_env(func):
    @functools.wraps(func)
    def wrapper(self,*args,**kwargs):
        try:
            misp1 = self.misp_instances.instances[0]
            self.wipe_all()
            self.event = self.create_event(misp1.org_admin_connector)
            func(self,*args,**kwargs)
        finally:
            self.delete_event(misp1.site_admin_connector, self.event)
            pass
    return wrapper

def setup_eventreport_pull_env(func):
    @setup_event_pull_env
    @functools.wraps(func)
    def wrapper(self,*args,**kwargs):
        try:
            misp_central = self.misp_instances.central_node
            self.add_dummy_reports_to_dummy_event(misp_central.org_admin_connector)
            func(self,*args,**kwargs)
        finally:
            pass
    return wrapper

def setup_eventreport_push_env(func):
    @setup_event_push_env
    @functools.wraps(func)
    def wrapper(self,*args,**kwargs):
        try:
            misp1 = self.misp_instances.instances[0]
            self.add_dummy_reports_to_dummy_event(misp1.org_admin_connector)
            func(self,*args,**kwargs)
        finally:
            pass
    return wrapper


class EventReportUtility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if 'misp_instances' in dir(cls):
            return
        cls.maxDiff = None
        cls.misp_instances = MISPInstances()
        cls.eventUUID = 'b1a49e7a-3184-4acc-ae02-c417d2cd7390'
        cls.event = None
        cls.testReport = None
        cls.sharing_groups = []

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

    def setup_sharinggroup_env(self):
        instance = self.misp_instances.instances[0]
        central = self.misp_instances.central_node
        central_server_id = instance.synchronisations[central.name].id
        sharing_groups = []

        sg = MISPSharingGroup()
        sg.name = 'SG - Node 1'
        sg.releasability = 'Node 1 & Central but sync with Node1 server only'
        sg.description = ','.join(['node1'])
        sg.roaming = False
        sharing_group = instance.site_admin_connector.add_sharing_group(sg)
        instance.site_admin_connector.add_org_to_sharing_group(sharing_group, central.host_org.uuid)
        instance.site_admin_connector.add_server_to_sharing_group(sharing_group, 0)  # Add local server
        sharing_groups.append(sharing_group)

        sg = MISPSharingGroup()
        sg.name = 'SG - Node1 & Central'
        sg.releasability = 'Node1 and Central nodes'
        sg.description = ','.join(['node1', 'central'])
        sg.roaming = False
        sharing_group = instance.site_admin_connector.add_sharing_group(sg)
        instance.site_admin_connector.add_server_to_sharing_group(sharing_group, 0)
        instance.site_admin_connector.add_org_to_sharing_group(sharing_group, central.host_org.uuid)
        instance.site_admin_connector.add_server_to_sharing_group(sharing_group, central_server_id)
        sharing_groups.append(sharing_group)

        sg = MISPSharingGroup()
        sg.name = 'SG - All'
        sg.releasability = 'All nodes'
        sg.description = ','.join(['node1', 'node2', 'node3', 'central'])
        sg.roaming = True
        sharing_group = instance.site_admin_connector.add_sharing_group(sg)
        instance.site_admin_connector.add_org_to_sharing_group(sharing_group, central.host_org.uuid)
        for nodes in self.misp_instances.instances[1:]:
            instance.site_admin_connector.add_org_to_sharing_group(sharing_group, nodes.host_org.uuid)
        sharing_groups.append(sharing_group)

        self.sharing_groups = sharing_groups
        return sharing_groups

    def delete_sharinggroup_env(self):
        # sgs = self.misp_instances.central_node.site_admin_connector.sharing_groups()
        for sg in self.sharing_groups:
            self.misp_instances.central_node.site_admin_connector.delete_sharing_group(sg.id)
            for instance in self.misp_instances.instances:
                instance.site_admin_connector.delete_sharing_group(sg.id)
    
    def check_sharinggroup_existence_after_sync(self, base_sharinggroups):
        central = self.misp_instances.central_node
        sgs_nodes = { f'node{i+1}': [sg.uuid for sg in instance.site_admin_connector.sharing_groups()] for i, instance in enumerate(self.misp_instances.instances) }
        sgs_nodes['central'] = [ sg.uuid for sg in central.site_admin_connector.sharing_groups() ]

        for sg in base_sharinggroups:
            for node_name in sgs_nodes.keys():
                if node_name in sg.description:
                    self.assertIn(sg.uuid, sgs_nodes[node_name], f'The sharinggroup `{sg.name}` should be on server `{node_name}`')
        return sgs_nodes

    def check_after_sync(self, report, synced_report, isPush=False):
        report = self.insertPrefixIfNeeded(report)
        synced_report = self.insertPrefixIfNeeded(synced_report)
        isPull = not isPush

        if report['EventReport']['distribution'] == '0':
            self.assertIs(synced_report, False, msg='your organisation only should not be pulled/pushed')
            return

        if report['EventReport']['distribution'] == '1':
            if isPush:
                self.assertIs(synced_report, False, msg='This community should not be pushed (unless server is a `local` server)')
                return
            elif isPull:
                self.assertEqual(synced_report['EventReport']['distribution'], '0', msg='Distribution level should have been downgraded')

        self.assertIsNot(synced_report, False, 'The report should have been synced')
        if report['EventReport']['distribution'] == '2':
            self.assertEqual(synced_report['EventReport']['distribution'], '1', msg='Distribution level should have been downgraded')
        elif report['EventReport']['distribution'] == '3':
            self.assertEqual(synced_report['EventReport']['distribution'], '3', msg='Distribution level should not have been downgraded')
        elif report['EventReport']['distribution'] == '4':
            pass
        elif report['EventReport']['distribution'] == '5':
            self.assertEqual(synced_report['EventReport']['distribution'], '5', msg='Distribution level should not have been downgraded')

    def compare_report(self, report1, report2, isSync = False):
        if not isSync:
            self.assertIs(report1, not False)
            self.assertIs(report2, not False)
        if report1 is False or report2 is False:
            return # Can't compare non-existing reports
        fieldsToCheck = ['uuid', 'name', 'content', 'timestamp', 'deleted']
        report1 = self.insertPrefixIfNeeded(report1)
        report2 = self.insertPrefixIfNeeded(report2)
        for field in fieldsToCheck:
            self.assertEqual(report1['EventReport'][field], report2['EventReport'][field], msg=f'Key `{field}` not equal')

    @classmethod
    def insertPrefixIfNeeded(cls, report):
        if report is not False and 'EventReport' not in report:
            report = {
                'EventReport': report
            }
        return report

    def get_dummy_report(self):
        report = {
            'name': 'Test Event report',
            'content': 'This is an event report. Hello World!',
            'uuid': '2b55358b-b8f7-465c-bbd6-6736db6c27ae',
            'event_id': '',
            'distribution': 1,
            'sharing_group_id': 0,
            'deleted': 0,
            'timestamp': str(int(time.time()))
        }
        return report

    def add_dummy_reports_to_dummy_event(self, instance):
        for distribution in [0, 1, 2, 3, 5]:
            report = self.get_dummy_report()
            report['distribution'] = distribution
            report['uuid'] = str(uuid.uuid4())
            report['name'] = f"{report['name']} - distri {report['distribution']}"
            eventID = self.event.id
            report = self.add_event_report(instance, report, eventID)

    def create_event(self, instance):
        event = MISPEvent()
        event.info = 'Event for EventReport'
        event.distribution = Distribution.all_communities
        event.uuid = self.eventUUID
        returnedEvent = instance.add_event(event, pythonify=True)
        if type(returnedEvent) is dict:
            self.assertNotIn('errors', returnedEvent)
        self.assertEqual(returnedEvent.uuid, event.uuid)
        return returnedEvent

    def delete_event(self, instance, event):
        if DEBUG_NO_WIPE:
            return
        instance.delete_event(event)
        relative_path = 'eventBlocklists/massDelete'
        data = {
            'ids': str([x for x in range(1000)])
        }
        instance.direct_call(relative_path, data=data)

    def get_event(self, instance, eventID):
        relative_path = f'events/view/{eventID}'
        return instance.direct_call(relative_path)

    def add_event_report(self, instance, report, eventID):
        relative_path = f'eventReports/add/{eventID}'
        data = report
        addedReport = instance.direct_call(relative_path, data=data)
        self.assertIn('EventReport', addedReport)
        return addedReport

    def get_event_report(self, instance, reportID):
        relative_path = f'eventReports/view/{reportID}'
        return instance.direct_call(relative_path)

    def get_event_reports_from_event(self, instance, eventID):
        relative_path = f'events/view/{eventID}'
        event = instance.direct_call(relative_path)
        if 'EventReport' in event['Event']:
            return event['Event']['EventReport']
        else:
            return []

    def wipe_all(self):
        if DEBUG_NO_WIPE:
            return
        self.delete_sharinggroup_env()
        self.delete_event(self.misp_instances.central_node.site_admin_connector, self.eventUUID)
        for instance in self.misp_instances.instances:
            self.delete_event(instance.site_admin_connector, self.eventUUID)


class TestReportSync(EventReportUtility):

    @setup_eventreport_pull_env
    def test_01_pull(self):
        '''Test event report pull - Pull an event and check that the report has been pulled'''
        try:
            source = self.misp_instances.central_node
            dest = self.misp_instances.instances[0]
            dest.site_admin_connector.update_server({'pull': True, 'push': False}, dest.synchronisations[source.name].id)
            source.org_admin_connector.publish(self.event)
            dest.site_admin_connector.server_pull(dest.synchronisations[source.name])
            time.sleep(1*WAIT_AFTER_SYNC)
            pulledEvent = self.get_event(dest.org_admin_connector, self.event.uuid)
            if type(pulledEvent) is dict:
                self.assertNotIn('errors', pulledEvent, msg='Event should have been sync')
            pulledReports = pulledEvent['Event'].get('EventReport', [])
            pulledReportsByUUID = { report['uuid']: report for report in pulledReports }
            reports = self.get_event_reports_from_event(source.org_admin_connector, self.event.uuid)

            self.assertNotEqual(len(reports), 0)
            self.assertNotEqual(len(pulledReports), 0)
            for report in reports:
                self.compare_report(report, pulledReportsByUUID.get(report['uuid'], False), isSync=True)
                self.check_after_sync(report, pulledReportsByUUID.get(report['uuid'], False))
        finally:
            dest.site_admin_connector.update_server({'pull': False}, dest.synchronisations[source.name].id)
            self.wipe_all()


    @setup_eventreport_push_env
    def test_02_push(self):
        '''Test event report push - Push an event and check that it has been accepted on the remote end'''
        try:
            source = self.misp_instances.instances[0]
            dest = self.misp_instances.instances[1]

            source.site_admin_connector.update_server({'push': True}, source.synchronisations[dest.name].id)
            dest.site_admin_connector.update_server({'push': False}, dest.synchronisations[source.name].id) # Make sure to avoid further propagation
            source.org_admin_connector.publish(self.event)
            source.site_admin_connector.server_push(source.synchronisations[dest.name], 'full')
            time.sleep(1*WAIT_AFTER_SYNC)

            reports = self.get_event_reports_from_event(source.org_admin_connector, self.event.uuid)
            pushedReports = self.get_event_reports_from_event(dest.org_admin_connector, self.event.uuid)
            pushedReportsByUUID = { report['uuid']: report for report in pushedReports }

            self.assertNotEqual(len(reports), 0)
            self.assertNotEqual(len(pushedReports), 0)
            for report in reports:
                self.compare_report(report, pushedReportsByUUID.get(report['uuid'], False), isSync=True)
                self.check_after_sync(report, pushedReportsByUUID.get(report['uuid'], False), isPush=True)
        finally:
            source.site_admin_connector.update_server({'push': False}, source.synchronisations[dest.name].id)
            self.wipe_all()


    def test_03_sharing_group_sync(self):
        '''Test event report sharing group sync'''
        sharinggroups = []
        try:
            node1 = self.misp_instances.instances[0]
            instances_to_check = {
                'node2': self.misp_instances.instances[1],
                'node3': self.misp_instances.instances[2],
                'central': self.misp_instances.central_node
            }
            for _, instance in instances_to_check.items():
                node1.site_admin_connector.update_server({'push': True}, node1.synchronisations[instance.name].id)
            sharinggroups = self.setup_sharinggroup_env()

            event = self.create_event(node1.org_admin_connector)
            reports = []

            uuids = [str(uuid.uuid4()) for i in range(len(sharinggroups))]
            for i, sg in enumerate(sharinggroups):
                sgReport = self.get_dummy_report()
                sgReport['distribution'] = 4
                sgReport['sharing_group_id'] = sg.id
                sgReport['uuid'] = uuids[i]
                sgReport['name'] = f"{sgReport['name']} - sg {sg.name}"
                addedReport = self.add_event_report(node1.org_admin_connector, sgReport, event.id)
                reports.append(addedReport)
            node1.org_admin_connector.publish(event)
            time.sleep(WAIT_AFTER_SYNC*(len(sharinggroups)+1)) # sg are ordered by sync depth

            sgExistencePerNode = self.check_sharinggroup_existence_after_sync(sharinggroups)
            for report in reports:
                for node_name, instance in instances_to_check.items():
                    pushedReport = self.get_event_report(instance.org_admin_connector, report['EventReport']['uuid'])
                    if report['SharingGroup']['uuid'] in sgExistencePerNode[node_name]:
                        self.compare_report(report, pushedReport, isSync=True)
        finally:
            for _, instance in instances_to_check.items():
                node1.site_admin_connector.update_server({'push': False}, node1.synchronisations[instance.name].id)
            self.wipe_all()
