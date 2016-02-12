#!/usr/bin/env python
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
Usage: %s [options]

Options:
-h --help               help message
-t --table [table name] table name for hive backup
-D --db [database name] database for hive backup
-y --dry-run            do a dry run
-s --status             get status
-p --path [path (excluding hdfs://....)] for HDFS backup
-l --list               list replication schedules accessable by this user/group

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
sys.path.append('/usr/lib64/cmf/agent/build/env/lib/python2.7/site-packages/kerberos-1.1.1-py2.7-linux-x86_64.egg/')
sys.path.append('/usr/lib64/cmf/agent/build/env/lib/python2.7/site-packages/urllib2_kerberos-0.1.6-py2.7.egg/')
import kerberos as k
import urllib2_kerberos as ul2k
import ConfigParser

#
# Customize this path
#

CONFIG_PATH='./cm_repl.ini'

Config = ConfigParser.ConfigParser()
Config.read(CONFIG_PATH)
cm_section=Config.sections()[0]

LOGLEVEL= Config.get(cm_section, 'log_level')

CM_USER	        = Config.get(cm_section, 'cm_user')
CM_PASSWD	= Config.get(cm_section, 'cm_passwd')
CM_PRIMARY	= Config.get(cm_section, 'cm_primary')	
CM_DRSITE	= Config.get(cm_section, 'cm_drsite')	
CM_PORT	        = Config.get(cm_section, 'cm_port')	
CLUSTER_NAME	= Config.get(cm_section, 'cluster_name')	
HTTPFS_HOST	= Config.get(cm_section, 'httpfs_host')	
HTTPFS_PORT	= Config.get(cm_section, 'httpfs_port')	
WEBHCAT_HOST	= Config.get(cm_section, 'webhcat_host')	
WEBHCAT_PORT	= Config.get(cm_section, 'webhcat_port')	
HDFS_SERVICE	= Config.get(cm_section, 'hdfs_service')	
HIVE_SERVICE	= Config.get(cm_section, 'hive_service')	
DEVMODE	= Config.get(cm_section, 'devmode')	

def getUsername():
  """ get effective userid from process """
  return pwd.getpwuid(os.getuid()).pw_name

def getGroupname():
  """ get effective group from process """
  return grp.getgrgid(os.getgid()).gr_name


# {"AclStatus": {"owner": "hive", "stickyBit": false, "group": "hive", "entries": 
#     ["user:hive:rwx", "group:jprosser:rwx", "group::---", "group:hive:rwx"]}}
# {"FileStatus": {"aclBit": true, "group": "hive", "permission": "771", "blockSize": 0, 
# "accessTime": 0, "pathSuffix": "", "modificationTime": 1453998161924, "replication": 0, 
# "length": 0, "owner": "hive", "type": "DIRECTORY"}}
#
# determine if the user is either the owner of the path or has user/group write perms in the acls 
#
def getAccessPriv(user,group,path):
  isOK=False

  getReplUrl = "https://"+HTTPFS_HOST + ":" + HTTPFS_PORT + "/webhdfs/v1" + path + "?op=GETFILESTATUS"
  LOG.debug("Getting file status with: " + getReplUrl)
  opener = urllib2.build_opener()
  opener.add_handler(ul2k.HTTPKerberosAuthHandler())
  resp = opener.open(getReplUrl)
  fsData = json.load(resp)   
  output_json = json.dumps(fsData)
  LOG.debug( "HTTPFS OUTPUT: " + output_json)

  pOwner=fsData['FileStatus']['owner']
  pGroup=fsData['FileStatus']['group']
  perms=fsData['FileStatus']['permission']

  # if the owner or group as write privs
  if (pOwner == user and perms[0] in ['7','3','2'] ) or (pGroup == group and perms[0] in ['7','3','2']) :
    isOK=True
  else:
    getReplUrl = "https://"+HTTPFS_HOST + ":" + HTTPFS_PORT + "/webhdfs/v1" + path + "?op=GETACLSTATUS"
    LOG.debug("Getting ACLS with: " + getReplUrl)
    opener = urllib2.build_opener()
    opener.add_handler(ul2k.HTTPKerberosAuthHandler())
    resp = opener.open(getReplUrl)
    aclData = json.load(resp)   
  
    output_json = json.dumps(aclData)
    LOG.debug( "HTTPFS ACL OUTPUT: " + output_json)
    # get acls
    entryList = aclData['AclStatus']['entries']
    pattern='.*:'+group+':'
    x=re.compile(pattern)
    sub_list = filter(x.match, entryList)
    for f in sub_list:
      (pcoll,name,priv) = f.split(':')
      if 'w' in priv:
        isOK=True
  # end else
  return isOK

#
# curl --negotiate -u : -b ~/cookiejar.txt -c ~/cookiejar.txt  http://jvp1-2.vpc.cloudera.com:50111/templeton/v1/ddl/database/?user.name=hive
# get location of db from hive metatsore
#
def getDatabaseLocation(database):
#  getReplUrl = "http://jvp1-2.vpc.cloudera.com:" + WEBHCAT_PORT + "/templeton/v1/ddl/database/?user.name=hive"
  getReplUrl = "http://" + WEBHCAT_HOST + ":" + WEBHCAT_PORT + "/templeton/v1/ddl/database/" + database + "/"

  LOG.debug( "Polling WebHCat URL: " + getReplUrl )
  opener = urllib2.build_opener()
  opener.add_handler(ul2k.HTTPKerberosAuthHandler())
  LOG.debug(opener.__dict__)
  resp = opener.open(getReplUrl)

  data = json.load(resp)   
  output_json = json.dumps(data)
# {"owner": "hive", "ownerType": "USER", "location": "hdfs://jvp1-2.vpc.cloudera.com:8020/user/hive/warehouse/ilimisp01_eciw.db", "database": "ilimisp01_eciw"}

  LOG.debug( "WEBHCat output: " + output_json )
  ( url,path)  = re.split(r':[0-9][0-9]+(?=.*)', data['location'])
  LOG.debug("URL is " + url + " PATH IS " + path)
  return path


#
# poll CM until the action is completed or we run out of time.
#
def pollReplicationStatus(tries, delay,cluster,service,index):
    mdelay = delay  # make mutable
    backoff = 0
    time.sleep(delay)
    for n in range(tries):
        active = getScheduleStatus(cluster,service,index) 
        LOG.debug("Status was " + str(active))
        if active == True:
            polling_time = time.strftime('%a, %d %b %Y %H:%M:%S', time.localtime())
            LOG.debug('{0}. Sleeping for {1} seconds.'.format(polling_time, mdelay))
            time.sleep(mdelay)
            mdelay += backoff
        else:
          lastRes=getScheduleLastResult (cluster,service,index)
          LOG.debug('Last Result for {0}. was {1} .'.format(index, str(lastRes)))
          return lastRes
    # end of for loop
    return False
#    raise ExceededRetries('Failed to poll {0} within {1} tries.'.format(apifunction, tries))


#
# get the current activity status of this schedule item
# Data for 25. is {'canRetry': None, 'hdfsResult': None, 'name': u'HiveReplicationCommand', 'parent': None, '_resource_root': <cm_api.api_client.ApiResource object 
# 0xc8cf10>, 'children': <cm_api.endpoints.types.ApiList object at 0xe1c790>, 'success': None, 'serviceRef': <cm_api.endpoints.types.ApiServiceRef object at 0xe1c710
# , 'resultMessage': None, 'roleRef': None, 'resultDataUrl': u'/cmf/command/1186/download', 'clusterRef': None, 'startTime': datetime.datetime(2016, 2, 11, 17, 51, 26
# , 219000), 'hiveResult': <cm_api.endpoints.types.ApiHiveReplicationResult object at 0xe1c7d0>, 'active': True, 'endTime': None, 'id': 1186, 'hostRef': None} .

def getScheduleStatus (cluster,service,index) :
    serviceItem =  cluster.get_service(service)
    schedules=serviceItem.get_replication_schedules()

    output_dict = [x for x in schedules if x.id == index ] # and x.Active == True 

    LOG.debug('\n\nData for {0}. is {1} .'.format(index, output_dict[0].__dict__))
    LOG.debug('\n\nHISTORY Data for {0}. is {1} .'.format(index, output_dict[0].history[0].__dict__))
    LOG.debug('\n\nserviceRef Data for {0}. is {1} .'.format(index, output_dict[0].history[0].serviceRef.__dict__))
    if output_dict[0].history[0].hdfsResult != None:
      LOG.debug('\n\nhdfsResult Data for {0}. is {1} .'.format(index, output_dict[0].history[0].hdfsResult.__dict__))
      printHdfsResults(output_dict[0].history[0].hdfsResult,False)
    else:
      print >>sys.stdout,  '\tJob Metrics are not available at this point.'
    if output_dict[0].history[0].hiveResult != None:
      LOG.debug('\n\nhiveResult Data for {0}. is {1} .'.format(index, output_dict[0].history[0].hiveResult.__dict__))
      printHiveResults(output_dict[0].history[0].hiveResult,False)

    LOG.debug('Current active status for {0}. is {1} .'.format(index, output_dict[0].active))
    return output_dict[0].active

#
# get the success value of the last activity for this schedule item
#
def getScheduleLastResult (cluster,service,index) :
    serviceItem =  cluster.get_service(service)
    schedules=serviceItem.get_replication_schedules()

    output_dict = [x for x in schedules if x.id == index ] # and x.Active == True 

    if service==HIVE_SERVICE:
      result = output_dict[0].history[0].hiveResult
      LOG.debug('\n\nHiveResult Data for {0}. is {1} .'.format(index, result.__dict__))
      LOG.debug('\n\nHiveResult dataReplicationResult for {0}. is {1} .'.format(index, result.dataReplicationResult.__dict__))
      printHiveResults(result,True)

      print >>sys.stdout,  '\nResult Message: ' +  output_dict[0].history[0].resultMessage
    else:
      printHdfsResults(output_dict[0].history[0].hdfsResult,True)

    LOG.debug('\nLastRes for {0}. is {1} .'.format(index, output_dict[0].history[0].__dict__))
    return output_dict[0].history[0].success


# 'numFilesCopyFailed': 0, 'numBytesDryRun': 0, 'jobId': u'job_1454954079806_0072', 'numFilesSkipped': 1, 'numBytesExpected': 195, 'numFilesExpected': 1, 'setupError': None, 'dryRun': False, 'runAsUser': u'hdfs', 'failedFiles': [], 'progress': 100, 'jobDetailsUri': u'/cmf/services/13/applications/?startTime=1455218824750&endTime=1455218906206#filters=application_id=job_1454954079806_0072', 'numBytesCopied': 0

def printHdfsResults(result,printDetails):
  print >>sys.stdout,  '\n\n\tHdfs Replication Result'
  print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'
  print >>sys.stdout,  ''

  print >>sys.stdout,  'numBytesCopied      : ' + str(result.numBytesCopied     )
  print >>sys.stdout,  'numBytesCopyFailed  : ' + str(result.numBytesCopyFailed )
  print >>sys.stdout,  'numBytesSkipped     : ' + str(result.numBytesSkipped    )
  print >>sys.stdout,  'numFilesCopied      : ' + str(result.numFilesCopied     )
  print >>sys.stdout,  'numFilesDeleted     : ' + str(result.numFilesDeleted    )
  print >>sys.stdout,  'progress            : ' + str(result.progress    )
  print >>sys.stdout,  'jobdetails          : ' + str(result.jobDetailsUri    )

  if printDetails == True:
    for r in result.counters:
      print >>sys.stdout,  r['group'] +': ' + r['name'] + ' = ' + str(r['value'])

def printHiveResults(result,printDetails):
  print >>sys.stdout,  '\n\n\tHive Replication Result'
  print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'
  print >>sys.stdout,  ''
  if result.tableCount > 0:
    print >>sys.stdout,  'Tables'
    for r in result.tables:
      print >>sys.stdout,  r
    
  if result.errorCount > 0:
    print >>sys.stdout,  'Errors: '
    for r in result.errors:
      print >>sys.stdout,  r

  print >>sys.stdout,  '\n'

  if result.dataReplicationResult != None:
    print >>sys.stdout,  'numBytesCopied      : ' + str(result.dataReplicationResult.numBytesCopied     )
    print >>sys.stdout,  'numBytesCopyFailed  : ' + str(result.dataReplicationResult.numBytesCopyFailed )
    print >>sys.stdout,  'numBytesSkipped     : ' + str(result.dataReplicationResult.numBytesSkipped    )
    print >>sys.stdout,  'numFilesCopied      : ' + str(result.dataReplicationResult.numFilesCopied     )
    print >>sys.stdout,  'numFilesDeleted     : ' + str(result.dataReplicationResult.numFilesDeleted    )
    print >>sys.stdout,  'progress            : ' + str(result.dataReplicationResult.progress    )
    print >>sys.stdout,  'jobdetails          : ' + str(result.dataReplicationResult.jobDetailsUri    )
    
    if printDetails == True:
      for r in result.dataReplicationResult.counters:
        print >>sys.stdout,  r['group'] +': ' + r['name'] + ' = ' + str(r['value'])
    
#
# update certain attributes of a schedule
# currently not being used
#
def updateSchedule(cluster,service,index,attrs):

  removeMissingFiles = None
  skipTrash = None

  schedule = getSchedule(cluster,service,index)
  
  if 'deletePolicy' in attrs:
    if attrs['deletePolicy'] == 'keep':
      removeMissingFiles = 'false'
    else:
      removeMissingFiles = 'true'
      if attrs['deletePolicy'] == 'trash':
        skipTrash = 'true'
      else:
        skipTrash = 'false'

  if service == HIVE_SERVICE:
    if removeMissingFiles != None:
      schedule.hiveArguments.hdfsArguments.removeMissingFiles=removeMissingFiles
    if skipTrash != None:
      schedule.hiveArguments.hdfsArguments.skipTrash=skipTrash
    if 'numSlots' in attrs:
      schedule.hiveArguments.hdfsArguments.numMaps=attrs['numSlots']
    if 'pool' in attrs:
      schedule.hiveArguments.hdfsArguments.schedulerPoolName=attrs['pool']
    if 'skipCRC' in attrs:
      schedule.hiveArguments.hdfsArguments.skipChecksumChecks=attrs['skipCRC']
    if 'replStrategy' in attrs:
      schedule.hiveArguments.hdfsArguments.replicationStrategy= attrs['replStrategy']

  else:
    if removeMissingFiles != None:
      schedule.hdfsArguments.removeMissingFiles=removeMissingFiles
    if skipTrash != None:
      schedule.hdfsArguments.skipTrash=skipTrash
    if 'numSlots' in attrs:
      schedule.hdfsArguments.numMaps=attrs['numSlots']
    if 'pool' in attrs:
      schedule.hdfsArguments.schedulerPoolName=attrs['pool']
    if 'skipCRC' in attrs:
      schedule.hdfsArguments.skipChecksumChecks=attrs['skipCRC']
    if 'replStrategy' in attrs:
      schedule.hdfsArguments.replicationStrategy=attrs['replStrategy']
  # end else

  if 'alertOnStart' in attrs:
    schedule.alertOnStart = attrs['alertOnStart']
  if  'alertOnSuccess' in attrs:
    schedule.alertOnSuccess = attrs['alertOnSuccess']

  bdrService =  cluster.get_service(service)

  res = bdrService.update_replication_schedule(index,schedule)
  LOG.debug("update result " + str(res.__dict__))
  
  return res.id

#
# create a hive BDR schedule instance
#
def addHiveSchedule(cluster,database,table):

  # retrieve the database only job that we can use as a template.
    dbSchedule = getHiveSchedule(cluster,HIVE_SERVICE,database,'__template__')
    nowDateTime= datetime.datetime.now()
    yearFromNow = datetime.timedelta(weeks=+52)
#    hiveReplConf = { "interval": 0,"hiveArguments": {"sourceService":
#                                       {"clusterName": "cluster", "serviceName": "hive", "peerName": "JVP1"}, 
#                                       "force": "true", "dryRun": "false", "hdfsArguments": 
#                                       {"userName": "hdfs",
#                                        "dryRun": "false", "abortOnError": "true",
#                                        "preservePermissions": "true",
#                                        "mapreduceServiceName": "yarn",
#                                        "skipChecksumChecks": "false", "preserveXAttrs":
#                                        "true", "exclusionFilters": [], "skipTrash":
#                                        "false", "preserveBlockSize": "true",
#                                        "removeMissingFiles": "false",
#                                        "replicationStrategy": "DYNAMIC",
#                                        "preserveReplicationCount": "true"},
#                                       "replicateImpalaMetadata": "true",
#                                       "replicateData": "true", 
#                                       "tableFilters": [{"tableName": table, "database": database}]}}


#    hiveReplArgs = ApiHiveReplicationArguments(hiveReplConf)
    hiveReplArgs = dbSchedule.hiveArguments
    # need to figure out how the above command should work.
#    hiveReplArgs.sourceService= {'clusterName': 'cluster', 'serviceName': HIVE_SERVICE, 'peerName': 'JVP1'}
#    hiveReplArgs.force=True
#    hiveReplArgs.dryRun=False
#    hiveReplArgs.replicateImpalaMetadata=True
#    hiveReplArgs.replicateData=True
    hiveReplArgs.tableFilters = [{'tableName': table, 'database': database}]
#   hiveReplArgs.hdfsArguments={'userName': 'hdfs',
#                                       'dryRun': 'false', 'abortOnError': 'true',
#                                       'preservePermissions': 'true',
#                                       'mapreduceServiceName': 'yarn',
#                                       'skipChecksumChecks': 'false', 'preserveXAttrs':
#                                       'true', 'exclusionFilters': [], 'skipTrash':
#                                       'false', 'preserveBlockSize': 'true',
#                                       'removeMissingFiles': 'false',
#                                       'replicationStrategy': 'DYNAMIC',
#                                       'preserveReplicationCount': 'true'}

    hiveService =  cluster.get_service(HIVE_SERVICE)

    paused=True
    interval=0
    intervalUnit='DAY'
    res = hiveService.create_replication_schedule(
        nowDateTime, nowDateTime + yearFromNow, intervalUnit, interval, paused, hiveReplArgs,
        alert_on_start=True, alert_on_success=False, alert_on_fail=True,
        alert_on_abort=True)

    return res


#
# create a HDFS BDR schedule instance
#
def addHDFSSchedule(cluster,path):

    nowDateTime= datetime.datetime.now()
    yearFromNow = datetime.timedelta(weeks=+52)

    hdfsReplConf = {"interval": 0,"hdfsArguments":{
      'sourceService'            : {'clusterName': 'cluster', 'serviceName': HDFS_SERVICE, 'peerName': 'JVP1'},
      'sourcePath'               : path,
      'destinationPath'          : path,
      'mapreduceServiceName'     : 'yarn',
      'userName'                 : 'hdfs',
      'dryRun'                   : 'false', 
      'abortOnError'             : 'true',
      'preservePermissions'      : 'true',
      'skipChecksumChecks'       : 'false', 
      'preserveXAttrs'           :  True, 
      'exclusionFilters'         : [], 
      'skipTrash'                : False, 
      'preserveBlockSize'        : True,
      'removeMissingFiles'       : False,
      'replicationStrategy'      : 'DYNAMIC',
      'preserveReplicationCount' : True}}

    hdfsReplArgs = ApiHdfsReplicationArguments(hdfsReplConf)

    hdfsReplArgs.sourceService            = {'clusterName': 'cluster', 'serviceName': HDFS_SERVICE, 'peerName': 'JVP1'}
    hdfsReplArgs.sourcePath               = path
    hdfsReplArgs.destinationPath          = path
    hdfsReplArgs.mapreduceServiceName     = 'yarn'
    hdfsReplArgs.dryRun                   = 'false'
    hdfsReplArgs.abortOnError             = 'true'
    hdfsReplArgs.preservePermissions      = 'true'
    hdfsReplArgs.skipChecksumChecks       = 'false'
    hdfsReplArgs.preserveXAttrs           =  True
    hdfsReplArgs.exclusionFilters         = []
    hdfsReplArgs.skipTrash                = False
    hdfsReplArgs.preserveBlockSize        = True
    hdfsReplArgs.removeMissingFiles       = False
    hdfsReplArgs.replicationStrategy      = 'DYNAMIC'
    hdfsReplArgs.userName                 = 'hdfs'
    hdfsReplArgs.preserveReplicationCount = True

    hdfsService =  cluster.get_service(HDFS_SERVICE)

    paused=True
    interval=0
    intervalUnit='DAY'
    res = hdfsService.create_replication_schedule(
        nowDateTime, nowDateTime + yearFromNow, intervalUnit,interval,paused, hdfsReplArgs,
        alert_on_start=True, alert_on_success=False, alert_on_fail=True,
        alert_on_abort=True)

    return res


#
# trigger a schedule item to run
#
def runSchedule(cluster,service,index,dryRun):
    bdrService =  cluster.get_service(service)
    res = bdrService.trigger_replication_schedule(index,dry_run=dryRun)
    return res


#
# get all the schedules that the process runner has file access to
#
def getAccessableSchedules(cluster,procUser,procGroup):
  repls=[]
  hiveService =  cluster.get_service("hive")
  schedules=hiveService.get_replication_schedules()
  for x in schedules:
    path = getDatabaseLocation(x.hiveArguments.tableFilters[0].database)
    if getAccessPriv(procUser,procGroup,path) == True:
      repls.append('\tType: Hive\tID: ' + str(x.id) + '\tDatabase: ' + \
                   x.hiveArguments.tableFilters[0].database + '\tTable: ' + \
                   x.hiveArguments.tableFilters[0].tableName)
  # end for
  hdfsService =  cluster.get_service("hdfs")
  schedules=hdfsService.get_replication_schedules()
  for x in schedules:
    path = x.hdfsArguments.sourcePath
    if getAccessPriv(procUser,procGroup,path) == True:
      repls.append('\tType: HDFS\tID: ' + str(x.id) + '\tPath: ' + path)
  # end for
  return repls

#
# get the hive schedule for this database/table pair
#
def getHiveSchedule (cluster,service,database,table) :
    hiveService =  cluster.get_service("hive")
    schedules=hiveService.get_replication_schedules()
    
    output_dict = [x for x in schedules if x.hiveArguments.tableFilters[0].database  == database and 
                   x.hiveArguments.tableFilters[0].tableName == table] 

    if len(output_dict) == 0:
        return None
    else :
        return output_dict[0]

#
# get the hdfs schedule for this path
#
def getHdfsSchedule (cluster,service,path) :
    hdfsService =  cluster.get_service(service)
    schedules=hdfsService.get_replication_schedules()

    output_dict = [x for x in schedules if x.hdfsArguments.sourcePath ==  path]

    if len(output_dict) == 0:
        return None
    else :
        return output_dict[0]

#
# get a schedule object given its id
#
def getSchedule (cluster,service,id) :
    hdfsService =  cluster.get_service(service)
    schedules=hdfsService.get_replication_schedules()

    output_dict = [x for x in schedules if x.id == id]

    if len(output_dict) == 0:
        return None
    else :
        return output_dict[0]



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
    opts, args = getopt.getopt(argv[1:], 'hD:t:c:sp:yl',
                               ['database=','table=','path=','help','status','dry-run','list'])

  except getopt.GetoptError, err:
    print >>sys.stderr, err
    usage()
    return -1

  service  = None
  dryRun   = False
# the CM instance the utility will talk to in order to trigger replications.
# if failing back, this would be changed to CM_PRIMARY
  cmHost   = CM_DRSITE 

  action   = 'doBackup'
  database = None
  table    = None
  path     = None

  for option, val in opts:
    LOG.debug( "option is " + option +" val is " + val)

    if option in ('-h','--help'):
      usage()
      return -1
    elif option in ('-D','--database'):
      database = val
      service = HIVE_SERVICE
    elif option in ('-t','--table'):
      table =  val
    elif option in ('-y','--dry-run'):
      dryRun = True
    elif option in ('-s','--status'):
      action='getStatus'
    elif option in ('-k','--list'):
      action='listRepls'
# allows switching sites for failback. disabled for now.
#    elif option in ('-c'):
#      activeSite = val
    elif option in ('-p','--path'):
      path  = val
      service = HDFS_SERVICE

    else:
      print >>sys.stderr, '\n\tUnknown flag:', option
      usage()
      return -1

# check argument compatibility
  if args:
    print >>sys.stderr, '\n\tUnknown trailing argument:', args
    usage()
    return -1
  if action != 'listRepls':
    if path != None and (table != None or database != None) :
      print >>sys.stderr, '\n\tDo not specify HDFS and Hive replication arguments at the same time.'
      usage()
      return -1
    elif path == None and  database == None :
      print >>sys.stderr, '\n\tYou must specify either a path or database and table.\n \
      \tIf you specified the table using a regular expression, you must use that exact syntax enclosed in single quotes.'
      usage()
      return -1
    elif path == None and  ( database == None or table == None):
      print >>sys.stderr, '\n\tYou must specify a database and a table.\n \
      \tIf you specified the table using a regular expression, you must use that exact syntax enclosed in single quotes.'
      usage()
      return -1
  else:
    if path != None or table != None or database != None :
      print >>sys.stderr, '\n\tAccessable replications will be listed. Additional arguments ignored.'



#  # if the active site is RTP, then we want to schedule BDR activity from the DR site's CM host
#  if activeSite == 'RTP':
#    cmHost = CM_DRSITE
#   print >>sys.stderr, 'Replication from primary cluster '%s'.' % (cmHost)
#
#  elif activeSite == 'OMAHA':
#    cmHost = CM_PRIMARY
#    print >>sys.stderr, 'Replication from DR cluster '%s'.' % (cmHost)
#
#  else :
#   print >>sys.stderr, 'Cannot replicate from that cluster!'
#    return -1


  API = ApiResource(cmHost, CM_PORT,  version=11, username=CM_USER, password=CM_PASSWD, use_tls=True)
  LOG.debug('Connected to CM host on ' + cmHost)

  procUser = getUsername()
  LOG.debug('Process effective username is ' + procUser)
  procGroup= getGroupname()
  LOG.debug('Process effective group name is ' + procGroup)

  CLUSTER = API.get_cluster(CLUSTER_NAME)

  if action == 'listRepls':
    repls = getAccessableSchedules(CLUSTER,procUser,procGroup)
    if len(repls)  > 0:
      print >>sys.stdout,  '\n\n\tReplication Schedules'
      print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'
      for r in repls:
        print >>sys.stdout,  r 
      print >>sys.stdout,  '\n'
    else:
      print >>sys.stdout, '\n\tNo replications found.'
    return 0


# get details about the replication the user is interested in
  if service == HIVE_SERVICE:
    path = getDatabaseLocation(database)
    LOG.debug('DB location is ' + path)
    schedule = getHiveSchedule (CLUSTER,service,database,table) 
  else:
    schedule = getHdfsSchedule (CLUSTER,service,path) 

# check access privs and abort if none
  if getAccessPriv(procUser,procGroup,path) == False:
    print >>sys.stderr, '\n\tInvalid privs or item does not exist.\n' 
    return -1
  
  if schedule == None:
    if DEVMODE :
      if service == HIVE_SERVICE:
        LOG.info( 'Adding HIVE schedule with table name: ' + table )
        result = addHiveSchedule( CLUSTER, database, table )
        LOG.debug( result.__dict__ )
        LOG.info( 'Getting id for newly added schedule.')
        schedule = getHiveSchedule (CLUSTER,service,database,table) 
      else :
        result = addHDFSSchedule(CLUSTER,path)
        LOG.debug( result.__dict__ )
        LOG.info( 'Getting id for newly added schedule.')
        schedule = getHdfsSchedule (CLUSTER,service,path)
    else:
      print >>sys.stderr, '\n\tNo replication schedule defined for this object. '
      return -1

  bdrId = schedule.id

  if action == 'getStatus':
    active = getScheduleStatus(CLUSTER,service,bdrId)
    if active == True :
      print >>sys.stderr, '\n\tThere is currently a replication underway for this schedule.\n'
      return -1
    else :
      print >>sys.stderr, '\n\tThere is currently NO replication underway for this schedule.\n'
      getScheduleLastResult (CLUSTER,service,bdrId)
      return 0
      
  else:

    LOG.info( 'Scheduling run for id: ' + str(bdrId))
    result = runSchedule(CLUSTER,service,bdrId,dryRun)

    LOG.info( 'Start polling for status' )
    status = pollReplicationStatus(100, 3,CLUSTER,service,bdrId)
    if status ==  False:
      return -1

  return 0


#
# The 'main' entry
#
if __name__ == '__main__':
  sys.exit(main(sys.argv))
