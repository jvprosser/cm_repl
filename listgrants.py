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
import ConfigParser
import cm_repl


#
# Customize this path
#
config_path_list=['/','h','o','m','e','/','j','p','r','o','s','s','e','r','/','c','m','_','r','e','p','l','.','i','n','i']
CONFIG_PATH=''.join(config_path_list)

DR_NAV_USER    =['a','d','m','i','n']
DR_NAV_PASSWD  =['a','d','m','i','n']
               
PROD_NAV_USER  =['a','d','m','i','n']
PROD_NAV_PASSWD=['a','d','m','i','n']

dr_nav_user    =''.join(DR_NAV_USER  )
dr_nav_passwd  =''.join(DR_NAV_PASSWD)
               
prod_nav_user  =''.join(PROD_NAV_USER  )
prod_nav_passwd=''.join(PROD_NAV_PASSWD)


try :
  Config = ConfigParser.SafeConfigParser()
  dataset = Config.read(CONFIG_PATH)
  if len(dataset) != 1:
    print >>sys.stderr, '\n\tCould not find configuration.'
    sys.exit(255)
  else:
    cm_section=Config.sections()[0]
    sentry_section=Config.sections()[1]
    globals_section=Config.sections()[2]
except ConfigParser.Error, e :
  print >>sys.stderr, '\n\tCould not read configuration.'
  sys.exit(255)


DB_TEMPLATE_NAME= Config.get(cm_section, 'db_template_name')
CM_VERSION	= Config.get(cm_section, 'cm_version')
CM_USER	        = Config.get(cm_section, 'cm_user')
CM_PASSWD	= Config.get(cm_section, 'cm_passwd')
CM_PRIMARY	= Config.get(cm_section, 'cm_primary')
CM_DRSITE	= Config.get(cm_section, 'cm_drsite')
CM_PORT	        = Config.get(cm_section, 'cm_port')
CM_PEERNAME	= Config.get(cm_section, 'cm_peername')
CLUSTER_NAME	= Config.get(cm_section, 'cluster_name')
HIVE_SERVICE	= Config.get(cm_section, 'hive_service')

LOGLEVEL         = Config.get(sentry_section, 'getgrants_log_level')
PROD_NAV_PROTO   = Config.get(sentry_section, 'prod_nav_proto')  
PROD_NAV_HOST    = Config.get(sentry_section, 'prod_nav_host')   
PROD_NAV_PORT    = Config.get(sentry_section, 'prod_nav_port')   
DR_NAV_PROTO     = Config.get(sentry_section, 'dr_nav_proto')    
DR_NAV_HOST      = Config.get(sentry_section, 'dr_nav_host')     
DR_NAV_PORT      = Config.get(sentry_section, 'dr_nav_port')     
DR_BEELINE_URL   = Config.get(sentry_section, 'dr_beeline_url')     

RET_OK                      = Config.get(globals_section, 'ret_ok')
RET_BADOPTS                 = Config.get(globals_section, 'ret_badopts')
RET_NOENT                   = Config.get(globals_section, 'ret_noent')
RET_NOREP_EXISTS            = Config.get(globals_section, 'ret_norep_exists') 
RET_REP_ALREADY_UNDERWAY    = Config.get(globals_section, 'ret_rep_already_underway')
RET_REP_FAILED              = Config.get(globals_section, 'ret_rep_failed') 
RET_NO_DBTEMPLATE_EXISTS    = Config.get(globals_section, 'ret_no_dbtemplate_exists') 

def getUsername():
  """ get effective userid from process """
  return pwd.getpwuid(os.getuid()).pw_name

def getGroupname():
  """ get effective group from process """
  return grp.getgrgid(os.getgid()).gr_name

def getUserGroups(user):
  groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
  gid = pwd.getpwnam(user).pw_gid
  groups.append(grp.getgrgid(gid).gr_name)
  return groups


def getNavData(navData,navType,query):

  getReplUrl = navData['proto']+"://" + navData['host'] + ":" + navData['port'] + "/api/v8/"+navType +"/?query=" +  query
  resp=None
  LOG.debug( "Gettinging NAV URL: " + getReplUrl )
  try:
    # create a password manager
    password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
    
    # Add the username and password.
    # If we knew the realm, we could use it instead of None.
  
    password_mgr.add_password(None, getReplUrl, navData['user'], navData['passwd'])
    
    basicAuthHandler = urllib2.HTTPBasicAuthHandler(password_mgr)
  
    opener = urllib2.build_opener()
    opener.add_handler(basicAuthHandler)

    resp = opener.open(getReplUrl)
  except urllib2.HTTPError, e:
    print >>sys.stderr, '\n\tCould not retrieve location for database \'' + str(e)

    return None
  else :
    data = json.load(resp)
    output_json = json.dumps(data)

    return data


def getSentryGrants(navData,user,db,table,start,end):

#  query="username%3D%3D{0}%3Ballowed%3D%3Dtrue%3Bservice%3D%3Dsentry&startTime={1}&endTime={2}&limit=100&offset=0&format=JSON&attachment=false".format(user,start,end)
  query="allowed%3D%3Dtrue%3Bservice%3D%3Dsentry&startTime={0}&endTime={1}&limit=100&offset=0&format=JSON&attachment=false".format(start,end)

  data = getNavData(navData,"audits",query)

  return data

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

  setup_logging(LOGLEVEL)

  # Argument parsing
  try:
    opts, args = getopt.getopt(argv[1:], '', #hD:t:sp:yl
                               ['database=','table=','help'])


  except getopt.GetoptError, err:
    print >>sys.stderr, err
    usage()
    return RET_BADOPTS

  cmHost   = CM_DRSITE
  service="hive"

  database = None
  table    = None


  for option, val in opts:
    LOG.debug( "option is " + option +" val is " + val)
    # i took the shortargs out of the options config, but left them here in case the
    # decision was made to bring them back in
    if option in ('-h','--help'):
      usage()
      return RET_BADOPTS
    elif option in ('-D','--database'):
      database = val
    elif option in ('-t','--table'):
      table =  val
    else:
      print >>sys.stderr, '\n\tUnknown flag:', option
      usage()
      return RET_BADOPTS

# check argument compatibility
  if args:
    print >>sys.stderr, '\n\tUnknown trailing argument:', args
    usage()
    return RET_BADOPTS
  if table == DB_TEMPLATE_NAME:
    print >>sys.stderr, '\n\tInvalid table name.'
    usage()
    return RET_BADOPTS
  if  database == None or table == None:
    print >>sys.stderr, '\n\tPlease specify a database and a table.'
    usage()
    return RET_BADOPTS

  API = ApiResource(cmHost, CM_PORT,  version=CM_VERSION, username=CM_USER, password=CM_PASSWD, use_tls=True)
  LOG.debug('Connected to CM host on ' + cmHost)

  procUser = getUsername()
  LOG.debug('Process effective username is ' + procUser)

  cluster = API.get_cluster(CLUSTER_NAME)

  prod_nav = {'proto': PROD_NAV_PROTO,'host': PROD_NAV_HOST ,'port': PROD_NAV_PORT ,'user':prod_nav_user, 'passwd' : prod_nav_passwd}
  dr_nav   = {'proto': DR_NAV_PROTO,'host': DR_NAV_HOST ,'port': DR_NAV_PORT ,'user':dr_nav_user, 'passwd' : dr_nav_passwd}

  nowDateTime= datetime.datetime.now()
  yearFromNow = datetime.timedelta(weeks=+52)

  # get the schedule item's history so we can get the last successful run.
  # we will use that as the start time for searching the audit history for this database/table's sentry grant/revokes
  schedule = cm_repl.getHiveSchedule(cluster,service,database,table)
  if schedule == None:
    print >>sys.stderr, '\n\tNo replication schedule defined for this object. (Regex patterns not supported by this utility)'
    return RET_NOREP_EXISTS

  lastSuccessfulReplTimestamp  = cm_repl.getLastSuccessfulReplTimestamp(schedule)
  
  startEpoch=str(int(time.mktime((nowDateTime - yearFromNow).timetuple()))) + "000"    
  endEpoch=str(int(time.mktime(nowDateTime.timetuple()))) + "000"


# TODO: FILTER for allowed and success
  prodSentry = getSentryGrants(prod_nav,procUser,database,table,startEpoch,endEpoch)
  drSentry   = getSentryGrants(dr_nav  ,procUser,database,table,startEpoch,endEpoch)

 # convert to lowercase and remove extra whitespace
  prodSentryCommands= [{'sql': re.sub(r'\s+',' ',f['serviceValues']['operation_text'].lower()), 
                        't':time.strptime(f['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')} for f in prodSentry if f['serviceValues'] 
                       and f['serviceValues']['database_name'] == database and f['serviceValues']['table_name'] == table ]

  drSentryCommands=   [{'sql': re.sub(r'\s+',' ',f['serviceValues']['operation_text'].lower()), 
                        't':time.strptime(f['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')} for f in drSentry if f['serviceValues'] 
                       and f['serviceValues']['database_name'] == database and f['serviceValues']['table_name'] == table ]


  prodSentryCommands.sort(key=lambda r: r['t'],reverse=True )
  drSentryCommands.sort(key=lambda r: r['t']  ,reverse=True )

  LOG.debug( "\n\nNavigator Prod output: " + str(prodSentryCommands) )
  LOG.debug( "\n\nNavigator DR output: " + str(drSentryCommands) )


  print >>sys.stdout,  '\n\tProduction Sentry Grants '
  print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'

  for r in prodSentryCommands :
    print >>sys.stdout, '\t{0}\t{1}'.format(strftime("%Y-%m-%d %H:%M:%S",r['t']),r['sql'])

  print >>sys.stdout,  '\n\tDR  Sentry Grants '
  print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'

  for r in drSentryCommands :
    print >>sys.stdout, '\t{0}\t{1}'.format(strftime("%Y-%m-%d %H:%M:%S",r['t']),r['sql'])

  print >>sys.stdout, '\n'
  return 0

#
# The 'main' entry
#
if __name__ == '__main__':
  sys.exit(main(sys.argv))
