# -*- coding: utf-8 -*-
"""
Base classes and functions for region-specific services
"""

import copy
import re

from threading import Event, Thread
# Python2 vs Python3
try:
    from Queue import Queue
except ImportError:
    from queue import Queue

from opinel.utils.aws import build_region_list, connect_service, get_aws_account_id, handle_truncated_response
from opinel.utils.console import printException, printInfo

from AWSScout2.utils import format_service_name
from AWSScout2.configs.base import GlobalConfig
from AWSScout2.output.console import FetchStatusLogger





########################################
# Globals
########################################

api_clients = dict()

first_cap_re = re.compile('(.)([A-Z][a-z]+)')
all_caps_re = re.compile('([a-z0-9])([A-Z])')


########################################
# RegionalServiceConfig
########################################

class RegionalServiceConfig(object):
    """
    Single service configuration for non-global services

    :ivar regions:                      Dictionary of regions
    :ivar service:                      Name of the service
    """

    def __init__(self, service_metadata = {}):
        self.regions = {}
        self.service = type(self).__name__.replace('Config', '').lower() # TODO: use regex with EOS instead of plain replace
        if service_metadata != {}:
            self.targets = ()
            self.resource_types = {'global': [], 'region': [], 'vpc': []}
            self.newtargets = {'first_region': (), 'other_regions': ()}
            for resource in service_metadata['resources']:

                print(service_metadata['resources'][resource])

                only_first_region = False
                if re.match(r'.*?\.vpcs\.id\..*?', service_metadata['resources'][resource]['path']):
                    print('VPC resource')
                    self.resource_types['vpc'].append(resource)
                elif re.match(r'.*?\.regions\.id\..*?', service_metadata['resources'][resource]['path']):
                    self.resource_types['region'].append(resource)
                    print('Regional resource')
                else:
                    only_first_region = True
                    print('Global resource')
                    self.resource_types['global'].append(resource)

                resource_metadata = service_metadata['resources'][resource]
                if not only_first_region:
                    self.newtargets['other_regions'] += (                    (resource, resource_metadata['response'], resource_metadata['api_call'], {}, False),)
                self.newtargets['first_region'] += ((resource, resource_metadata['response'], resource_metadata['api_call'], {}, False),)

            #print('Targets !!')
            #print(str(self.newtargets))

                #resource_metadata = service_metadata['resources'][resource]
                #self.targets += ((resource, resource_metadata['response'], resource_metadata['api_call'], {}, False),)





    def init_region_config(self, region):
        """
        Initialize the region's configuration

        :param region:                  Name of the region
        """
        self.regions[region] = self.region_config_class(region_name = region, resource_types = self.resource_types)


    def fetch_all(self, credentials, regions = [], partition_name = 'aws', targets = None):
        """
        Fetch all the configuration supported by Scout2 for a given service

        :param credentials:             F
        :param service:                 Name of the service
        :param regions:                 Name of regions to fetch data from
        :param partition_name:          AWS partition to connect to
        :param targets:                 Type of resources to be fetched; defaults to all.

        """
        # Initialize targets
        if not targets:
            try:
                targets = type(self).targets # TODO: remove this case eventually
            except:
                targets = self.targets
        # Tweak params
        realtargets = ()
        for i, target in enumerate(self.newtargets['first_region']):
            params = self.tweak_params(target[3], credentials)
            realtargets = realtargets + ((target[0], target[1], target[2], params, target[4]),)
        self.newtargets['first_region'] = realtargets
        realtargets = ()
        for i, target in enumerate(self.newtargets['other_regions']):
            params = self.tweak_params(target[3], credentials)
            realtargets = realtargets + ((target[0], target[1], target[2], params, target[4]),)
        self.newtargets['other_regions'] = realtargets


        printInfo('Fetching %s config...' % format_service_name(self.service))
        self.fetchstatuslogger = FetchStatusLogger(self.newtargets['first_region'], True)
        api_service = 'ec2' if self.service.lower() == 'vpc' else self.service.lower()
        # Init regions
        regions = build_region_list(api_service, regions, partition_name) # TODO: move this code within this class
        self.fetchstatuslogger.counts['regions']['discovered'] = len(regions)
        # Threading to fetch & parse resources (queue consumer)
        q = self._init_threading(self._fetch_target, {}, 20)
        # Threading to list resources (queue feeder)
        qr = self._init_threading(self._fetch_region, {'api_service': api_service, 'credentials': credentials, 'q': q, 'targets': ()}, 10)
        # Go
        for i, region in enumerate(regions):

            qr.put((region, self.newtargets['first_region'] if i == 0 else self.newtargets['other_regions']))
        # Join
        qr.join()
        q.join()
        # Show completion and force newline
        self.fetchstatuslogger.show(True)

    def _init_threading(self, function, params={}, num_threads=10):
            # Init queue and threads
            q = Queue(maxsize=0) # TODO: find something appropriate
            if not num_threads:
                num_threads = len(targets)
            for i in range(num_threads):
                worker = Thread(target=function, args=(q, params))
                worker.setDaemon(True)
                worker.start()
            return q

    def _fetch_region(self, q, params):
        global api_clients
        try:
            while True:
                try:
                    region, targets = q.get()
                    #print('Targets for region %s : %s' % (region, str(targets)))
                    self.init_region_config(region)
                    api_client = connect_service(params['api_service'], params['credentials'], region, silent = True)
                    api_clients[region] = api_client
                    # TODO : something here for single_region stuff
                    self.regions[region].fetch_all(api_client, self.fetchstatuslogger, params['q'], targets) #  params['targets'])
                    self.fetchstatuslogger.counts['regions']['fetched'] += 1
                except Exception as e:
                    printException(e)
                finally:
                    q.task_done()
        except Exception as e:
            printException(e)
            pass

    def _fetch_target(self, q, params):
        try:
            while True:
                try:
                    method, region, target = q.get()
                    method(params, region, target)
                    target = method.__name__.replace('parse_', '') + 's'
                    self.fetchstatuslogger.counts[target]['fetched'] += 1
                    self.fetchstatuslogger.show()
                except Exception as e:
                    printException(e)
                finally:
                    q.task_done()
        except Exception as e:
            printException(e)
            pass

    def finalize(self):
        for t in self.fetchstatuslogger.counts:
            setattr(self, '%s_count' % t, self.fetchstatuslogger.counts[t]['fetched'])
        delattr(self, 'fetchstatuslogger')
        for r in self.regions:
            if hasattr(self.regions[r], 'fetchstatuslogger'):
                delattr(self.regions[r], 'fetchstatuslogger')


    def tweak_params(self, params, credentials):
        if type(params) == dict:
            for k in params:
                params[k] = self.tweak_params(params[k], credentials)
        elif type(params) == list:
            newparams = []
            for v in params:
                newparams.append(self.tweak_params(v, credentials))
            params = newparams
        else:
            if params == '_AWS_ACCOUNT_ID_':
                params = get_aws_account_id(credentials)
        return params



########################################
# RegionConfig
########################################

class RegionConfig(GlobalConfig):
    """
    Base class for ...
    """

    def __init__(self, region_name, resource_types = {}):
        self.region = region_name
        for resource_type in resource_types['region'] + resource_types['global']:
            setattr(self, resource_type, {})
            setattr(self, '%s_count' % resource_type, 0)
        if len(resource_types['vpc']) > 0:
            setattr(self, 'vpcs', {})
            self.vpc_resource_types = resource_types['vpc']


    def fetch_all(self, api_client, fetchstatuslogger, q, targets):
        self.fetchstatuslogger = fetchstatuslogger
        if targets != None:
            # Ensure targets is a tuple
            if type(targets) != list and type(targets) != tuple:
                targets = tuple(targets,)
            elif type(targets) != tuple:
                targets = tuple(targets)
#        else:
#            targets = tuple(['%s' % method.replace('fetch_','').title() for method in methods])
        for target in targets:
            self._fetch_targets(api_client, q, target, {})


    def _fetch_targets(self, api_client, q, target, list_params):
        # Handle & format the target type
        target_type, response_attribute, list_method_name, list_params, ignore_list_error = target
        list_method = getattr(api_client, list_method_name)
        try:
            targets = handle_truncated_response(list_method, list_params, [response_attribute])[response_attribute]
        except Exception as e:
            if not ignore_list_error:
                printException(e)
            targets = []
        setattr(self, '%s_count' % target_type, len(targets))
        self.fetchstatuslogger.counts[target_type]['discovered'] += len(targets)
        region = api_client._client_config.region_name
        # Queue resources
        for target in targets:
            callback = getattr(self, 'parse_%s' % target_type[0:-1])
            if q:
                # Add to the queue
                q.put((callback, region, target))
