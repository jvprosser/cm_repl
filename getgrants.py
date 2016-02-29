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
Command line interface to get sentry grants
Usage: %s [options]

Options:
 --help               help message

 --verbose            Print status update when triggering a replication
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
import textwrap
import time
import datetime
from datetime import timedelta
from cm_api.api_client import ApiResource
import cm_api.endpoints.services
from cm_api.endpoints.types import ApiHiveReplicationArguments,ApiHdfsReplicationArguments
import urllib2
import base64
import json
#sys.path.append('/usr/lib64/cmf/agent/build/env/lib/python2.7/site-packages/kerberos-1.1.1-py2.7-linux-x86_64.egg/')
#sys.path.append('/usr/lib64/cmf/agent/build/env/lib/python2.7/site-packages/urllib2_kerberos-0.1.6-py2.7.egg/')
import kerberos as k
import urllib2_kerberos as ul2k
import ConfigParser

#
# Customize this path
#
CONFIG_PATH='../cm_repl.ini'

Config = ConfigParser.ConfigParser()
Config.read(CONFIG_PATH)
cm_section=Config.sections()[0]

LOGLEVEL= "DEBUG" #Config.get(cm_section, 'log_level')
DB_TEMPLATE_NAME= Config.get(cm_section, 'db_template_name')
CM_VERSION	= Config.get(cm_section, 'cm_version')
CM_USER	        = Config.get(cm_section, 'cm_user')
CM_PASSWD	= Config.get(cm_section, 'cm_passwd')
CM_PRIMARY	= Config.get(cm_section, 'cm_primary')
CM_DRSITE	= Config.get(cm_section, 'cm_drsite')
CM_PORT	        = Config.get(cm_section, 'cm_port')
CM_PEERNAME	= Config.get(cm_section, 'cm_peername')
CLUSTER_NAME	= Config.get(cm_section, 'cluster_name')
HTTPFS_HOST	= Config.get(cm_section, 'httpfs_host')
HTTPFS_PORT	= Config.get(cm_section, 'httpfs_port')
HTTPFS_PROTO	= Config.get(cm_section, 'httpfs_proto')
WEBHCAT_HOST	= Config.get(cm_section, 'webhcat_host')
WEBHCAT_PORT	= Config.get(cm_section, 'webhcat_port')
WEBHCAT_PROTO	= Config.get(cm_section, 'webhcat_proto')
HDFS_SERVICE	= Config.get(cm_section, 'hdfs_service')
HIVE_SERVICE	= Config.get(cm_section, 'hive_service')
HIVE_AUTOCREATE	= Config.get(cm_section, 'hive_autocreate')
#HDFS_AUTOCREATE	= Config.get(cm_section, 'hdfs_autocreate')
HDFS_AUTOCREATE = False
MAX_POLLING_RETRIES = Config.get(cm_section, 'max_polling_retries')
STATUS_POLL_DELAY   = Config.get(cm_section, 'status_poll_delay')

PROD_NAV_PROTO   = Config.get(cm_section, 'prod_nav_proto')  
PROD_NAV_HOST    = Config.get(cm_section, 'prod_nav_host')   
PROD_NAV_PORT    = Config.get(cm_section, 'prod_nav_port')   
DR_NAV_PROTO     = Config.get(cm_section, 'dr_nav_proto')    
DR_NAV_HOST      = Config.get(cm_section, 'dr_nav_host')     
DR_NAV_PORT      = Config.get(cm_section, 'dr_nav_port')     


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





NAV_HOST="jvp1-2.vpc.cloudera.com"
NAV_PORT="7187"
NAV_PROTO="https"

#  c.setopt(pycurl.URL, "http://jvp1-2:7187)
#  
#  b = StringIO.StringIO()
#  s = StringIO.StringIO()
#  c.setopt(pycurl.WRITEFUNCTION, b.write)
#  c.setopt(pycurl.FOLLOWLOCATION, 1)
#  c.setopt(pycurl.MAXREDIRS, 5)
#  c.setopt(pycurl.VERBOSE, 1)
#  c.setopt(pycurl.HTTPHEADER, ['Accept: application/json'])
#  # this will need to have username:password,for now.
#  c.setopt(pycurl.USERPWD, 'admin:admin')
#  c.perform()
#  body = b.getvalue()
#  
#  #print(body)
#  
#  json_object = json.loads(body)
#  
#  print" database|table|firstClassParentId|name|extractorRunId|tags|sourceId|deleted|userEntity|dataType|originalDescription|parentPath|originalName|sourceType|internalType|type|properties\
#  |identity|description"
#  
#  for fields in json_object:
#    dummy,db,table=fields['parentPath'].split("/");
#    print "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (db,table, fields['firstClassParentId'], fields['name'], fields['extractorRunId'], fields['tags'], \
#          fields['sourceId'], fields['deleted'], fields['userEntity'], fields['dataType'], fields['originalDescription'], fields['parentPath'], fields['originalName'], \
#          fields['sourceType'], fields['internalType'], fields['type'], fields['properties'], fields['identity'], fields['description'])
#  
#  https://jvp1-2.vpc.cloudera.com:7187/api/v8/audits/?query=service%3D%3Dsentry&startTime=1436456072000&endTime=1456761168000&limit=1001&offset=0&format=JSON&attachment=false


def getSentryGrants(proto,host,port,db,table,start,end):
#  getReplUrl = NAV_PROTO+"://" + NAV_HOST + ":" + NAV_PORT + "/api/v8/entities/?query=((type:FIELD))"
  getReplUrl = proto+"://" + host + ":" + port + "/api/v8/audits/?query=service%3D%3Dsentry&database%3D%3D" + db + "&table_name%3D%3D" + table +"&startTime="+start+\
               "&endTime="+end+"&limit=1001&offset=0&format=JSON&attachment=false"
#  getReplUrl = NAV_PROTO+"://" + NAV_HOST + ":" + NAV_PORT + "/api/v8/audits/?query=service%3D%3D*&startTime=1436456072000&endTime=1456761168000&limit=1001&offset=0&format=JSON&attachment=false"


  LOG.debug( "Polling NAV URL: " + getReplUrl )
  try:
  
    # create a password manager
    password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
    
    # Add the username and password.
    # If we knew the realm, we could use it instead of None.
  
    password_mgr.add_password(None, getReplUrl, "admin", "admin")
    
    basicAuthHandler = urllib2.HTTPBasicAuthHandler(password_mgr)
  
#    opener = urllib2.build_opener(handler)
    opener = urllib2.build_opener()
    opener.add_handler(basicAuthHandler)
#    opener.add_handler(ul2k.HTTPKerberosAuthHandler())
    resp = opener.open(getReplUrl)
  except urllib2.HTTPError, e:
    print >>sys.stderr, '\n\tCould not retrieve location for database \'' + str(e)

    return None
  else :
    data = json.load(resp)
    output_json = json.dumps(data)

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
                               ['database=','table=','path=','help','status','follow=','dry-run','list','verbose'])

  except getopt.GetoptError, err:
    print >>sys.stderr, err
    usage()
    return -1


  prod_nav_proto = PROD_NAV_PROTO
  prod_nav_host  = PROD_NAV_HOST 
  prod_nav_port  = PROD_NAV_PORT 

  dr_nav_proto  = DR_NAV_PROTO
  dr_nav_host   = DR_NAV_HOST 
  dr_nav_port   = DR_NAV_PORT    

  nowDateTime= datetime.datetime.now()
  yearFromNow = datetime.timedelta(weeks=+52)
  db = "*"
  table="*"
  nowEpoch=str(int(time.mktime(nowDateTime.timetuple()))) + "000"
  yearAgoEpoch=str(int(time.mktime((nowDateTime - yearFromNow).timetuple()))) + "000"

# FILTER for allowed and success
  prodSentry = getSentryGrants(prod_nav_proto,prod_nav_host,prod_nav_port,db,table,yearAgoEpoch,nowEpoch)
  drSentry   = getSentryGrants(dr_nav_proto,dr_nav_host,dr_nav_port,db,table,yearAgoEpoch,nowEpoch)

  prodSentryCommands= [{'sql':f['serviceValues']['operation_text'].toLower(),
                        't':time.strptime(f['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')} for f in prodSentry if f['serviceValues'] ]

  drSentryCommands=   [{'sql':f['serviceValues']['operation_text'].toLower(),
                        't':time.strptime(f['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')} for f in drSentry if f['serviceValues'] ]

  prodSentryCommands.sort(key=lambda r: r['t'])
  drSentryCommands.sort(key=lambda r: r['t'])

  LOG.debug( "Navigator Prod output: " + str(prodSentryCommands) )
  LOG.debug( "\n\nNavigator DR output: " + str(drSentryCommands) )

  finalList=[]
  firstProdMatchIndex = -1
  firstDrMatchIndex = 0

  # first find where the first dr grant falls in the prod list
  LOG.debug( "trying to Match dr output: " + str(prodSentryCommands[firstDrMatchIndex]) )      
  firstMatchIndex = next(index for (index, d) in enumerate(prodSentryCommands) if d['sql'] == drSentryCommands[0]['sql'])

  if firstMatchIndex != -1 :
      LOG.debug( "Matching Prod output: " + str(prodSentryCommands[firstMatchIndex]) )      


  return 0

#
# The 'main' entry
#
if __name__ == '__main__':
  sys.exit(main(sys.argv))
