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
Command line interface to synchronize sentry grants
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
import pwd
import grp
import re
import logging
import sys
from subprocess import call
import textwrap
from time import mktime, strftime,gmtime
import time
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
import ConfigParser

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

def main(argv):

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

  database = None
  table    = None
  path     = None

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
  if  database == None or table == None:
    print >>sys.stderr, '\n\tPlease specify a database and a table.'
    usage()
    return cf['RET_BADOPTS']

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

# TODO: FILTER for allowed and success
  drSentry   = getSentryGrants(dr_nav  ,procUser,database,table,startEpoch,endEpoch,LOG)

#  LOG.debug( "\n\nNavigator RAW DR output: " + str(drSentry) )


 # convert to lowercase and remove extra whitespace

  drSentryCommands=   [{'sql': re.sub(r'\s+',' ',f['serviceValues']['operation_text'].lower()), 
                        't':time.strptime(f['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')} for f in drSentry if f['serviceValues'] 
                       and f['serviceValues']['database_name'] == database and f['serviceValues']['table_name'] == table ]

  # unless there are grants on the DR side for this entity, use the same startepoch as we do for prod
  if len(drSentryCommands) > 0:
    # get more recent first
    drSentryCommands.sort(key=lambda r: r['t']   ,reverse=True)
    startEpoch=str(int(time.mktime((drSentryCommands[0]['t'])))) + "000"


  prodSentry = getSentryGrants(prod_nav,procUser,database,table,startEpoch,endEpoch,LOG)

#  LOG.debug( "\n\nNavigator RAW  PROD output: " + str(prodSentry) )

  prodSentryCommands= [{'sql': re.sub(r'\s+',' ',f['serviceValues']['operation_text'].lower()), 
                        't':time.strptime(f['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')} for f in prodSentry if f['serviceValues'] 
                       and f['serviceValues']['database_name'] == database and f['serviceValues']['table_name'] == table ]

  prodSentryCommands.sort(key=lambda r: r['t'] ,reverse=True)


  print >>sys.stdout,  '\n\tProduction Sentry Grants '
  print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'

  if len(prodSentryCommands) > 0:
    for r in prodSentryCommands :
      print >>sys.stdout, '\t{0}\t{1}'.format(strftime("%Y-%m-%d %H:%M:%S",r['t']),r['sql'])
  else:
    print >>sys.stdout, '\tNone'
  print >>sys.stdout,  '\n'

  print >>sys.stdout,  '\n\tLast DR Sentry Grant'
  print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'

  if len(drSentryCommands) > 0:
    print >>sys.stdout, '\t{0}\t{1}'.format(strftime("%Y-%m-%d %H:%M:%S",drSentryCommands[0]['t']),drSentryCommands[0]['sql'])
  else:
    print >>sys.stdout, '\tNever'
  print >>sys.stdout,  '\n'

  LOG.debug( "\n\nNavigator Prod output: " + str(prodSentryCommands) )
  LOG.debug( "\n\nNavigator DR output: " + str(drSentryCommands) )


  startIndex=None
  beeline_cmdList=""
  # first find where the first dr grant falls in the prod list

  myfile = open(cf['NAV_LOG_FILE'],"a")
  
  count=0
  for r in prodSentryCommands :
    count+=1
    beeline_cmdList += r['sql'] + '; '
    myfile.write("{0}\t{1};\n ".format(strftime("%Y-%m-%d %H:%M", gmtime()),r['sql']))


  if beeline_cmdList != "":
    fullBeelineCmd = "use " + database+";" + beeline_cmdList
    LOG.debug( "\napplying this commmand: " + fullBeelineCmd)
    call(["beeline", "-u", "'" + cf['DR_BEELINE_URL'] + "'", "-e",fullBeelineCmd])
  else:
    print >>sys.stdout, "\t\nSentry grants are in sync.\n "

  return count

#
# The 'main' entry
#
if __name__ == '__main__':
  cf=init()
  sys.exit(main(sys.argv))
