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
 --path  - the path to snapshot
 --sname - the name of the snapshot
 --sloc - the location for where the snapshot will be

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
import datetime
from datetime import timedelta
from cm_api.api_client import ApiResource
import cm_api.endpoints.services

from cm_api.endpoints.types import ApiHdfSnaphot,ApiHdfSnaphotResult,

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

RET_OK                      = Config.get(globals_section, 'ret_ok')
RET_BADOPTS                 = Config.get(globals_section, 'ret_badopts')
RET_NOENT                   = Config.get(globals_section, 'ret_noent')


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


def createHDFSSnapshot(path, sName,sLoc) :

  cTime = datetime.datetime.now()
  snapshotArgs = {}



  hdfsSnapshot.path          = path
  hdfsSnapshot.snapshotName  = sName
  hdfsSnapshot.snapshotPath  = sLoc

  hdfsSnapshot.creationTime  = cTime

  hdfsSnapshot = ApiHdfsSnapshot(path,sname,sLoc,cTime))


LOG = logging.getLogger(__name__)

def setup_logging(level):
  ''' set up logging output path '''

  if level == 'DEBUG':
    level = logging.DEBUG
    procUser = getUsername()
    pid = os.getpid()
    tsString=datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
#    logging.basicConfig(filename='/tmp/' + procUser + '-' + tsString+ '-' + str(pid) + '-ssactivity.log')
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
                               ['path=','sname=','sloc=','help'])


  except getopt.GetoptError, err:
    print >>sys.stderr, err
    usage()
    return RET_BADOPTS

  cmHost   = CM_DRSITE
  service="hdfs"


  sloc = None
  sname    = None
  path     = None
  verbose  = False

  for option, val in opts:
    LOG.debug( "option is " + option +" val is " + val)
    # i took the shortargs out of the options config, but left them here in case the
    # decision was made to bring them back in
    if option in ('-h','--help'):
      usage()
      return RET_BADOPTS
    elif option in ('--sloc'):
      sloc = val
    elif option in ('--sname'):
      sname = val
    elif option in ('--path'):
      path =  val
    else:
      print >>sys.stderr, '\n\tUnknown flag:', option
      usage()
      return RET_BADOPTS

# check argument compatibility
  if args:
    print >>sys.stderr, '\n\tUnknown trailing argument:', args
    usage()
    return RET_BADOPTS

  if  path == None :
    print >>sys.stderr, '\n\tPlease specify a pathe.'
    usage()
    return RET_BADOPTS

  API = ApiResource(cmHost, CM_PORT,  version=CM_VERSION, username=CM_USER, password=CM_PASSWD, use_tls=True)
  LOG.debug('Connected to CM host on ' + cmHost)

  procUser = getUsername()
  LOG.debug('Process effective username is ' + procUser)

  cluster = API.get_cluster(CLUSTER_NAME)


  return RET_OK

#
# The 'main' entry
#
if __name__ == '__main__':
  sys.exit(main(sys.argv))
