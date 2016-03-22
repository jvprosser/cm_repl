#!/usr/lib64/cmf/agent/build/env/bin/python
# Licensed to Cloudera, Inc. under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  Cloudera, Inc. licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Command line interface to list sentry grants
Usage: %s [options]

Options:
 --help               help message
 --database <dbname>
 --table <name>

"""
# OMITTED -c --active currently active site [RTP|OMAHA]

import getopt
import inspect

import os
import re
import logging
import sys
from subprocess import call
import textwrap
import time
from time import mktime, strftime

import datetime
from datetime import timedelta

from cm_api.api_client import ApiResource
import cm_api.endpoints.services

from cm_api.endpoints.types import ApiHiveReplicationArguments,ApiHdfsReplicationArguments,ApiHiveReplicationResult,ApiHdfsReplicationResult

import urllib2
import base64
import json
import kerberos as k
import urllib2_kerberos as ul2k

#sys.path.append('')
from cm_repl_lib import init,getUsername,getNavData,getSentryGrants

LOG = logging.getLogger(__name__)




def setup_logging(level):
  ''' set up logging output path '''

  if level == 'DEBUG':
    level = logging.DEBUG
    procUser = getUsername()
    pid = os.getpid()
    tsString=datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
#    logging.basicConfig(filename='/tmp/' + procUser + '-' + tsString+ '-' + str(pid) + '-bdractivity.log')
    logging.basicConfig()
  else :
    level = logging.INFO
    logging.basicConfig()
  # end else
  logging.getLogger().setLevel(level)


def usage():
  doc = inspect.getmodule(usage).__doc__
  print >>sys.stderr, textwrap.dedent(doc % (sys.argv[0],))

def main(argv,cf):

  setup_logging(cf['LOGLEVEL'])

  # Argument parsing
  try:
    opts, args = getopt.getopt(argv[1:], '', #hD:t:sp:yl
                               ['database=','table=','help'])


  except getopt.GetoptError, err:
    print >>sys.stderr, err
    usage()
    return cf['RET_BADOPTS']

  cmHost   = cf['CM_DRSITE']
  service="hive"

  database = None
  table    = None


  for option, val in opts:
    LOG.debug( "option is " + option +" val is " + val)
    # i took the shortargs out of the options config, but left them here in case the
    # decision was made to bring them back in
    if option in ('-h','--help'):
      usage()
      return cf['RET_BADOPTS']
    elif option in ('-D','--database'):
      database = val
    elif option in ('-t','--table'):
      table =  val
    else:
      print >>sys.stderr, '\n\tUnknown flag:', option
      usage()
      return cf['RET_BADOPTS']

# check argument compatibility
  if args:
    print >>sys.stderr, '\n\tUnknown trailing argument:', args
    usage()
    return cf['RET_BADOPTS']
  if table == cf['DB_TEMPLATE_NAME']:
    print >>sys.stderr, '\n\tInvalid table name.'
    usage()
    return cf['RET_BADOPTS']
  if  table != None and database == None :
    print >>sys.stderr, '\n\tPlease specify a database and a table.'
    usage()
    return cf['RET_BADOPTS']
  if  database != None and table == None :
    table=''

#  if  database == None :
#    print >>sys.stderr, '\n\tPlease specify a database and an optional table.'
#    usage()
#    return RET_BADOPTS

  API = ApiResource(cmHost, cf['CM_PORT'],  version=cf['CM_VERSION'], username=cf['CM_USER'], password=cf['CM_PASSWD'], use_tls=True)
  LOG.debug('Connected to CM host on ' + cmHost)

  procUser = getUsername()
  LOG.debug('Process effective username is ' + procUser)

  cluster = API.get_cluster(cf['CLUSTER_NAME'])

  prod_nav = {'proto': cf['PROD_NAV_PROTO'],'host': cf['PROD_NAV_HOST'] ,'port': cf['PROD_NAV_PORT'] ,'user':cf['PROD_NAV_USER'], 'passwd' : cf['PROD_NAV_PASSWD']}
  dr_nav   = {'proto': cf['DR_NAV_PROTO'],  'host': cf['DR_NAV_HOST']   ,'port': cf['DR_NAV_PORT']   ,'user':cf['DR_NAV_USER']  , 'passwd' : cf['DR_NAV_PASSWD']}

  nowDateTime= datetime.datetime.now()
  yearFromNow = datetime.timedelta(weeks=+52)

  startEpoch=str(int(time.mktime((nowDateTime - yearFromNow).timetuple()))) + "000"    
  endEpoch=str(int(time.mktime(nowDateTime.timetuple()))) + "000"



  prodSentry = getSentryGrants(prod_nav,procUser,database,table,startEpoch,endEpoch,LOG)
  drSentry   = getSentryGrants(dr_nav  ,procUser,database,table,startEpoch,endEpoch,LOG)
   # convert to lowercase and remove extra whitespace

  if database == None:
    prodSentryCommands= [{'sql': re.sub(r'\s+',' ',f['serviceValues']['operation_text'].lower()), 'u': f['username'].lower(),
                          'd':f['serviceValues']['database_name'].lower(),
                          't':time.strptime(f['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')} for f in prodSentry if f['serviceValues'] ]
  
    drSentryCommands=   [{'sql': re.sub(r'\s+',' ',f['serviceValues']['operation_text'].lower()), 'u': f['username'].lower(),
                          'd':f['serviceValues']['database_name'].lower(),
                          't':time.strptime(f['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')} for f in drSentry if f['serviceValues'] ]
  else:
    prodSentryCommands= [{'sql': re.sub(r'\s+',' ',f['serviceValues']['operation_text'].lower()), 'u': f['username'].lower(),
                          'd':f['serviceValues']['database_name'].lower(),
                          't':time.strptime(f['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')} for f in prodSentry if f['serviceValues'] 
                         and f['serviceValues']['database_name'] == database and f['serviceValues']['table_name'] == table ]
  
    drSentryCommands=   [{'sql': re.sub(r'\s+',' ',f['serviceValues']['operation_text'].lower()),  'u': f['username'].lower(),
                          'd':f['serviceValues']['database_name'].lower(),
                          't':time.strptime(f['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')} for f in drSentry if f['serviceValues'] 
                         and f['serviceValues']['database_name'] == database and f['serviceValues']['table_name'] == table ]
  
  # reverse sort on date
  prodSentryCommands.sort(key=lambda r: r['t'],reverse=True )
  drSentryCommands.sort(key=lambda r: r['t']  ,reverse=True )

  LOG.debug( "\n\nNavigator Prod output: " + str(prodSentryCommands) )
  LOG.debug( "\n\nNavigator DR output: " + str(drSentryCommands) )


  print >>sys.stdout,  '\n\tProduction Sentry Grants Going Back 12 Months'
  print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'

  for r in prodSentryCommands :
    print >>sys.stdout, '\t{0}\t{1}\t{2}\t{3}'.format(strftime("%Y-%m-%d %H:%M:%S",r['t']),r['d'],r['u'],r['sql'])

  print >>sys.stdout,  '\n\tDR  Sentry Grants Going Back 12 Months'
  print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'

  for r in drSentryCommands :
    print >>sys.stdout, '\t{0}\t{1}\t{2}\t{3}'.format(strftime("%Y-%m-%d %H:%M:%S",r['t']),r['d'],r['u'],r['sql'])


  print >>sys.stdout, '\n'
  return 0

#
# The 'main' entry
#
if __name__ == '__main__':
  cf=init()
  t = main(sys.argv,cf)
  sys.exit(t)
