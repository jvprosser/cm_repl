#!/bin/python
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
Command line interface to collect yarn job info
Usage: %s [options]

Options:
 --help               help message
 --period             how far back from now to look for completed jobs in minutes. default = 60
 --key                sort field. default = user


"""
from itertools import groupby
import getopt
import inspect
import pwd
import grp
import os
import re
import logging
import sys
from subprocess import call
import textwrap
import time
from time import mktime, strftime

import datetime
from datetime import timedelta,datetime

import collections
#from cm_api.api_client import ApiResource
#import cm_api.endpoints.services
#from cm_api.endpoints.types import ApiHiveReplicationArguments,ApiHdfsReplicationArguments,ApiHiveReplicationResult,ApiHdfsReplicationResult

import urllib2
import base64
import json
import kerberos as k
import urllib2_kerberos as ul2k

#sys.path.append('')
#from cm_repl_lib import init,getUsername,getNavData

LOG = logging.getLogger(__name__)


def init():

  config = {}

  config['CM_REPL_LOGLEVEL']    = "info"

  config['CM_VERSION']        = "12"
  config['CM_USER']        = "user.j"
  config['CM_PASSWD']        = "PASSWORD"
  config['CM_PORT']        = "7183"

  config['CLUSTER_NAME']= "production-data-cluster"

  config['YARN_HOST']        = "host.domain.com"
  config['YARN_PORT']        = "8088"

  config['LOGLEVEL']         = "INFO"

  config['RET_OK']                      = 0
  config['RET_BADOPTS']                 = 1
  config['RET_NOENT']                   = 2
  config['RET_NOREP_EXISTS']            = 3
  config['RET_REP_ALREADY_UNDERWAY']    = 4
  config['RET_REP_FAILED']              = 5
  config['RET_NO_DBTEMPLATE_EXISTS']    = 6

  return config


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


def setup_logging(level):
  ''' set up logging output path '''

  if level == 'DEBUG':
    level = logging.DEBUG
#    procUser = getUsername()
    pid = os.getpid()
    tsString=datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
#    logging.basicConfig(filename='/tmp/' + procUser + '-' + tsString+ '-' + str(pid) + '-bdractivity.log')
    logging.basicConfig()
  else :
    level = logging.INFO
    logging.basicConfig()
  # end else
  logging.getLogger().setLevel(level)

def extract(x): return {"user":x['user'], "memorySeconds":x['memorySeconds'], "vcoreSeconds":x['vcoreSeconds']
,"id":x['id']
,"name":x['name']
,"queue":x['queue']
,"progress":x['progress']
,"applicationType":x['applicationType']
,"allocatedMB":x['allocatedMB']
,"allocatedVCores":x['allocatedVCores']
,"runningContainers":x['runningContainers']
,"memorySeconds":x['memorySeconds']
,"vcoreSeconds":x['vcoreSeconds']
,"finishedTime":x['finishedTime']
,"startedTime":x['startedTime']
,"finalStatus":x['finalStatus']
}

def sum(x,y) : return {"memorySeconds":x['memorySeconds']+y['memorySeconds'], "vcoreSeconds": x['vcoreSeconds'] + y['vcoreSeconds']}

def unix_timestamp_secs():
  dt = datetime.now()
  epoch = datetime.utcfromtimestamp(0)
  return int((dt - epoch).total_seconds() * 1000.0)

def format_timestamp(t):
  return datetime.fromtimestamp(float(t)/1000).strftime("%Y%m%d-%H:%M:%S")

def format_elapsedime(millis):
  m, s = divmod(millis/1000, 60)
  h, m = divmod(m, 60)
  return  "%d:%02d:%02d" % (h, m, s)

# user|pool|jobid|vcore|mem|start time|end|stat|
def format_line(x):
  return '{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}'.format(x['user'],x['queue'],x['id'],x['allocatedVCores'],
                                                            x['allocatedMB'],x['runningContainers'],format_timestamp(x['startedTime']),
                                                            format_timestamp(x['finishedTime']),x['memorySeconds'],x['vcoreSeconds'],
                                                            x['name'],x['progress'],x['finalStatus'],x['applicationType'])

def print_header():
  print "date|user|queue|id|allocatedVCores|allocatedMB|runningContainers|startedTime|finishedTime|memorySeconds|vcoreSeconds|name|progress|finalStatus|applicationType"


def usage():
  doc = inspect.getmodule(usage).__doc__
  print >>sys.stderr, textwrap.dedent(doc % (sys.argv[0],))

def main(argv,cf):

  setup_logging(cf['LOGLEVEL'])

  # Argument parsing
  try:
    opts, args = getopt.getopt(argv[1:], '', #hp:k:
                               ['period=','key=','help'])



  except getopt.GetoptError, err:
    print >>sys.stderr, err
    usage()
    return cf['RET_BADOPTS']

  yarn_host   = cf['YARN_HOST']
  yarn_port   = cf['YARN_PORT']
  period =60
  nKey='queue'

  for option, val in opts:
    LOG.debug( "option is " + option +" val is " + val)
    # i took the shortargs out of the options config, but left them here in case the
    # decision was made to bring them back in
    if option in ('-h','--help'):
      usage()
      return cf['RET_BADOPTS']
    elif option in ('-p','--period'):
      period=int(val)
    elif option in ('-k','--key'):
      nKey=val
    else:
      print >>sys.stderr, '\n\tUnknown Flag:', option
      usage()
      return cf['RET_BADOPTS']


  LOG.info("Checking URL http://"+yarn_host+":" + yarn_port +"/ws/v1/cluster/apps")
  #handlers.append(ul2k.HTTPKerberosAuthHandler())

  #opener = urllib2.build_opener(*handlers)
  #urllib2.install_opener(opener)

  opener = urllib2.build_opener()
  opener.add_handler(ul2k.HTTPKerberosAuthHandler())

  yarnjson = json.load(opener.open("http://"+yarn_host+":" + yarn_port +"/ws/v1/cluster/apps"))
  #yarnjson = json.load(urllib2.urlopen("http://"+yarn_host+":" + yarn_port +"/ws/v1/cluster/apps"))

  output_json = json.dumps(yarnjson)

#  LOG.debug( "HTTPFS ACL OUTPUT: " + output_json)
#  print output_json
#  print '-----'

  alljobs= map(extract,yarnjson['apps']['app'])

#  print alljobs
  timenow =  unix_timestamp_secs()
  periodBegin = timenow -  (period *60)*1000

  runningOrFinished = my_list = filter(lambda x: x['progress'] < 100.0 or x['finishedTime'] > periodBegin, alljobs)

  od = sorted(runningOrFinished, key=lambda x: x[nKey])

  print_header()
  for row in od:
    print format_timestamp(timenow) + "|" + format_line(row)


#  for row in od:
#    print format_timestamp(timenow) + "|" + format_line(row)

#  for key, group in groupby(od, lambda x:x[nKey]):

#    print key,list(group)
#    print key, reduce(sum, (i for i in group))
#    for thing in group:
#      print key, reduce(sum, (i for i in group))
#      print key, reduce(sum, group)
#
#    print >>sys.stdout, '\n'
#  return 0

#
# The 'main' entry
#
if __name__ == '__main__':
  cf=init()
  t = main(sys.argv,cf)
  sys.exit(t)
