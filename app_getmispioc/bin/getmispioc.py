#!/usr/bin/env python
#
# Extract IOC's from MISP
#
# Author: Xavier Mertens <xavier@rootshell.be>
#
# Copyright: GPLv3 (http://gplv3.fsf.org/)
# Feel free to use the code, but please share the changes you've made
#

from __future__ import absolute_import, division, print_function, unicode_literals
import os, sys, subprocess

# Path to SPplunk-SDK
# See: http://dev.splunk.com/view/python-sdk/SP-CAAAEDG
try:
        sys.path.append('/usr/local/lib/python2.7/dist-packages')
        sys.path.append('/usr/lib64/python2.7/site-packages')
        sys.path.append('/opt/splunk-sdk-python/')
        from splunklib.searchcommands import dispatch, ReportingCommand, Configuration, Option, validators
except:
        print('Splunk-SDK not installed?')
        exit(1)

@Configuration(requires_preop=False)
class getmispioc(ReportingCommand):
        '''
        Extract IOC's from MISP
        '''
        server          = Option(doc="",require=False, validate=validators.Match("server",     r"^https?:\/\/[0-9a-zA-Z\.]+(?:\:\d+)?$"))
        authkey         = Option(doc="",require=False, validate=validators.Match("authkey",    r"^[0-9a-zA-Z]{40}$"))
        sslcheck        = Option(doc="",require=False, validate=validators.Match("sslcheck",   r"^[yYnN01]$"))
        eventid         = Option(doc="",require=False, validate=validators.Match("eventid",    r"^[0-9]+$"))
        last            = Option(doc="",require=False, validate=validators.Match("last",       r"^[0-9]+[hdwm]$"))
        onlyids         = Option(doc="",require=False, validate=validators.Match("onlyids",    r"^[yYnN01]+$"))
        category        = Option(doc="",require=False)
        type            = Option(doc="",require=False)

        @Configuration()
        def map(self, records):
                self.logger.debug('getmispioc.map')
                yield {}
                return

        def reduce(self, records):
                self.logger.debug('getmispioc.reduce')
                if self.sslcheck == None:
                        self.sslcheck = 'n'

                # Generate args
                my_args = {}
                if self.server:
                        my_args['server'] = self.server
                if self.authkey:
                        my_args['authkey'] = self.authkey
                if self.sslcheck:
                        my_args['sslcheck'] = self.sslcheck

                if self.onlyids == 'Y' or self.onlyids == 'y' or self.onlyids == '1':
                        onlyids = True
                else:
                        onlyids = False

                if self.eventid and self.last:
                        print('Options "eventid" and "last" are mutually exclusive')
                        exit(1)

                if self.eventid:
                       my_args['eventid'] = self.eventid
                elif self.last:
                        my_args['last'] = self.last
                else:
                        print('Missing "eventid" or "last" argument')
                        exit(1)

                _NEW_PYTHON_PATH = '/bin/python3'
                _SPLUNK_PYTHON_PATH = os.environ['PYTHONPATH']
                os.environ['PYTHONPATH'] = _NEW_PYTHON_PATH
                my_process = '/usr/local/bin/get-misp-ioc.py'

                # Remove LD_LIBRARY_PATH from the environment (otherwise, we will face some SSL issues
                env = dict(os.environ)
                del env['LD_LIBRARY_PATH']

                FNULL = open(os.devnull, 'w')
                p = subprocess.Popen([ os.environ['PYTHONPATH'], my_process, str(my_args)],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=FNULL, env=env)
                output = p.communicate()[0]
                results = {}
                for v in eval(output):
                        # Do not display deleted attributes
                        if v['deleted'] == False:
                                # If wpecified, do not display attributed with the non-ids flag set to False
                                if onlyids == True and v['to_ids'] == False:
                                        continue
                                if self.category != None and self.category != v['category']:
                                        continue
                                if self.type != None and self.type != v['type']:
                                        continue
                                results['value']        = v['value']
                                results['category']     = v['category']
                                results['type']         = v['type']
                                results['to_ids']       = str(v['to_ids'])
                                yield results

dispatch(getmispioc, sys.argv, sys.stdin, sys.stdout, __name__)
