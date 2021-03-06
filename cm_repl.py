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
Command line interface to create, launch, and check the status of BDR replications.
Usage: %s [options]

Options:
 --help               help message
 --table [table name] table name for hive backup
 --database [database name] database for hive backup
 --dry-run            do a dry run
 --status             get status
 --follow [n secs]    every n seconds, print the status of this job
 --path [path (excluding hdfs://....)] for HDFS backup
 --list               list replication schedules accessible by this user/group
 --verbose            Print status update when triggering a replication

Return Values:
  RET_OK = 0
  RET_BADOPTS = 1
  RET_NOENT = 2
  RET_NOREP_EXISTS = 3
  RET_REP_ALREADY_UNDERWAY = 4
  RET_REP_FAILED = 5
  RET_NO_DBTEMPLATE_EXISTS = 6
  
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
import kerberos as k
import urllib2_kerberos as ul2k
import ConfigParser

#sys.path.append('')
from cm_repl_lib import init,getUsername,getNavData,getGroupname,getUserGroups

cm_version=''

def filterAccessablePaths(cf,user,groupList,pathList):
  isOK=False

  fsOpener = urllib2.build_opener()
#  fsOpener.add_handler(ul2k.HTTPKerberosAuthHandler())

  # cache of paths we've checked, so we don't check them twice.
  validList=[]
  notValidList=[]
  for p in pathList:
    # if we haven't checked this path yet
    if next((item for item in validList if item['path'] == p['path']), None) == None and \
       next((item for item in notValidList if item['path'] == p['path']), None) == None:

      trimmedPath = re.sub('\*', '', p['path'])
      trimmedPath = re.sub('^ +', '', trimmedPath)
      LOG.debug("Getting file status for path: " + trimmedPath)

      #fsStatUrl = cf['HTTPFS_PROTO']+"://"+cf['HTTPFS_HOST'] + ":" + cf['HTTPFS_PORT'] + "/webhdfs/v1" + trimmedPath + "?user.name=ec2-user&op=GETFILESTATUS"
      fsStatUrl = cf['HTTPFS_PROTO']+"://"+cf['HTTPFS_HOST'] + ":" + cf['HTTPFS_PORT'] + "/webhdfs/v1" + trimmedPath + "?op=GETFILESTATUS"
      LOG.debug("Getting file status with: " + fsStatUrl)

      try:
        resp = fsOpener.open(fsStatUrl)
        fsData = json.load(resp)
        output_json = json.dumps(fsData)
        LOG.debug( "HTTPFS OUTPUT: " + output_json)
      except urllib2.HTTPError, e:
        print >>sys.stderr, '\n\tCould not check access for path \'' + trimmedPath + '\' Skipping...'
        notValidList.append(p)
        continue

      pOwner=fsData['FileStatus']['owner']
      pGroup=fsData['FileStatus']['group']
      perms=fsData['FileStatus']['permission']

      # if the owner or group has write privs
      if (pOwner == user and perms[0] in ['7','3','2'] ) or (pGroup in groupList and perms[1] in ['7','3','2']) :
        validList.append(p)
      else:
        #fsAclUrl = cf['HTTPFS_PROTO'] +"://"+ cf['HTTPFS_HOST'] + ":" + cf['HTTPFS_PORT'] + "/webhdfs/v1" + trimmedPath + "?user.name=ec2-user&op=GETACLSTATUS"
        fsAclUrl = cf['HTTPFS_PROTO'] +"://"+ cf['HTTPFS_HOST'] + ":" + cf['HTTPFS_PORT'] + "/webhdfs/v1" + trimmedPath + "?op=GETACLSTATUS"
        LOG.debug("Getting ACLS with: " + fsAclUrl)
        resp = fsOpener.open(fsAclUrl)
        aclData = json.load(resp)

        output_json = json.dumps(aclData)
        LOG.debug( "HTTPFS ACL OUTPUT: " + output_json)
        # get acls, build a regexp for our group. Sentry acl's will be on the group
        entryList = aclData['AclStatus']['entries']
        wasValid=False
        for group in groupList:
          LOG.debug( "Looking for group: " + group)
          pattern='.*:'+group+':'
          xpat=re.compile(pattern)
          # look for this group in the ACLs and check for write access
          sub_list = filter(xpat.match, entryList)

          if len(sub_list) > 0 :
            LOG.debug( "Got a hit for : " + group)
            for f in sub_list:
              (pcoll,name,priv) = f.split(':')
              if 'w' in priv:
                validList.append(p)
                wasValid=True
        #end for
        if  wasValid==False: # group was in list, but had no privs, or wasn't in list
          notValidList.append(p)

    else:
      # the item might be in the validList OR the notValidList, so we make sure it was in the validList
      if next((item for item in validList if item['path'] == p['path']), None) != None :
        validList.append(p)
    #end if
  # end for
  return validList

#
# curl --negotiate -u : -b ~/cookiejar.txt -c ~/cookiejar.txt  http://FQDN:50111/templeton/v1/ddl/database/?user.name=hive
# get location of db from hive metastore via REST
#
# if no HA
# {"owner": "hive", "ownerType": "USER", "location": "hdfs://FQDN:8020/user/hive/warehouse/ilimisp01_eciw.db", "database": "ilimisp01_eciw"}
# if HA
# {"owner": "hive", "ownerType": "USER", "location": "hdfs://namespace/user/hive/warehouse/ilimisp01_eciw.db", "database": "ilimisp01_eciw"}

def getDatabaseLocation(cf,database):
  #getReplUrl = cf['WEBHCAT_PROTO']+"://" + cf['WEBHCAT_HOST'] + ":" + cf['WEBHCAT_PORT'] + "/templeton/v1/ddl/database/" + database + "/?user.name=ec2-user"
  getReplUrl = cf['WEBHCAT_PROTO']+"://" + cf['WEBHCAT_HOST'] + ":" + cf['WEBHCAT_PORT'] + "/templeton/v1/ddl/database/" + database + "/"

  LOG.debug( "Polling WebHCat URL: " + getReplUrl )
  try:
    opener = urllib2.build_opener()
    opener.add_handler(ul2k.HTTPKerberosAuthHandler())
    resp = opener.open(getReplUrl)
  except urllib2.HTTPError, e:
    print >>sys.stderr, '\n\tCould not retrieve location for database \'' + database + '\' Skipping...'

    return None
  else :
    data = json.load(resp)
    output_json = json.dumps(data)
    LOG.debug( "WEBHCat output: " + output_json )
    parts=data['location'].split('/', 3 )
    return '/'+parts[3]


#
# poll CM until the action is completed or we run out of time.
#
def pollReplicationStatus(cf,cluster,service,schedule,verbose):
    tries = int(cf['MAX_POLLING_RETRIES'])
    delay = int(cf['STATUS_POLL_DELAY'])
    backoff = 0
    mdelay = float(delay) # make mutable float
    time.sleep(mdelay)
    for n in range(tries):
      schedule = getSchedule(cluster,service,schedule.id)
      #LOG.debug("schedule was " + str(schedule.__dict__))

      active = getScheduleStatus(schedule)
      LOG.debug("Status was " + str(active))
      if active == None or active == True:
        polling_time = time.strftime('%a, %d %b %Y %H:%M:%S', time.localtime())
        LOG.debug('{0}. Sleeping for {1} seconds.'.format(polling_time, mdelay))
        if verbose == True:
          printScheduleStatus (service,schedule)
        time.sleep(mdelay)
        mdelay += backoff
      else:
        if verbose == True:
          lastRes=printScheduleLastResult (cf,service,schedule)
        else :
          lastRes = getScheduleLastResult (schedule)
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

def getScheduleStatus (schedule) :
  if cm_version == 11 :
    return schedule.active
  else :
    if len(schedule.history) > 0:
      return schedule.history[0].active
    else : # this happens if its a new schedule and has no history.
      return False

def printScheduleStatus (service,schedule) :

    if len(schedule.history) > 0 and schedule.history[0].hdfsResult != None:
      printHdfsResults(schedule.history[0].hdfsResult,False)
    else:
      print >>sys.stdout,  '\tJob Metrics are not available at this point.'
    if len(schedule.history) > 0 and schedule.history[0].hiveResult != None:
      printHiveResults(schedule.history[0].hiveResult,False)

    return getScheduleStatus(schedule)


#
# get the success value of the last activity for this schedule item
#
def printScheduleLastResult (cf,service,schedule) :
  if len(schedule.history) > 0:
  
    if service==cf['HIVE_SERVICE']:
      #LOG.debug("schedule hive result  was " + str(schedule.history[0].hiveResult.__dict__))
      #LOG.debug("schedule hive.dataReplicationResult result  was " + str(schedule.history[0].hiveResult.dataReplicationResult.__dict__))
  
      if len(schedule.history) > 0 and schedule.history[0].resultMessage != None:
        print >>sys.stdout,  '\n\tFinal Result Message: ' +  schedule.history[0].resultMessage
      else:
        print >>sys.stdout,  '\n\tFinal Result Message: No Message Provided'
  
      if len(schedule.history) > 0 and schedule.history[0].hiveResult != None:
        printHiveResults(schedule.history[0].hiveResult,True)
  
        if schedule.history[0].hiveResult.dataReplicationResult != None:
          printHdfsResults(schedule.history[0].hiveResult.dataReplicationResult,True)
  
    else:
      #LOG.debug("schedule hdfs result  was " + str(schedule.history[0].hdfsResult.__dict__))
      if len(schedule.history) > 0 and schedule.history[0].hdfsResult != None:
        printHdfsResults(schedule.history[0].hdfsResult,True)
  else:
      print >>sys.stdout,  'No history for this schedule.'
  print >>sys.stdout,  '\n'
  return schedule.history[0].success

def getScheduleLastResult (schedule) :
    return schedule.history[0].success


def getLastSuccessfulReplTimestamp(schedule):
  last = next((item.startTime for item in schedule.history if item.success == True), None)
  return last


#
# print table of replication jobs for this user
#
#def  printReplicationSchedules(cluster,procUser,procGroup):
def  printReplicationSchedules(cf,schedules):

  if len(schedules)  > 0:
    sortedSchedules =  sorted(schedules, key=lambda k: k['service'])

    print >>sys.stdout,  '\n\n\tReplication Schedules'
    print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'
    for x in sortedSchedules :
      if x['service'] == cf['HIVE_SERVICE'] and x['schedule'].hiveArguments.tableFilters[0].tableName != cf['DB_TEMPLATE_NAME']:
        print >>sys.stdout, '\tType: ' + x['service'] + '\tID: ' + str(x['schedule'].id) + '\tDatabase: ' + '\'' + \
                 x['schedule'].hiveArguments.tableFilters[0].database +  '\'' +  '\tTable: ' +  '\'' + \
                 x['schedule'].hiveArguments.tableFilters[0].tableName  + '\''
      elif x['service'] == cf['HDFS_SERVICE']:
        print >>sys.stdout,'\tType: ' + x['service'] + '\tID: ' + str(x['schedule'].id) + '\tPath: ' +  '\'' + x['path'] + '\''
    # end for
    print >>sys.stdout,  '\n'
  else:
    print >>sys.stdout, '\n\tNo replications found.'

def printHdfsResults(result,printDetails):
  print >>sys.stdout,  '\n\n\tHdfs Replication Result'
  print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'

  print >>sys.stdout,  'numBytesCopied      : ' + str(result.numBytesCopied     )
  print >>sys.stdout,  'numBytesCopyFailed  : ' + str(result.numBytesCopyFailed )
  print >>sys.stdout,  'numBytesSkipped     : ' + str(result.numBytesSkipped    )
  print >>sys.stdout,  'numFilesCopied      : ' + str(result.numFilesCopied     )
  print >>sys.stdout,  'numFilesDeleted     : ' + str(result.numFilesDeleted    )
  print >>sys.stdout,  'progress            : ' + str(result.progress    )
  print >>sys.stdout,  'jobdetails          : ' + str(result.jobDetailsUri    )


#  if result.snapshottedDirs != None:
  print >>sys.stdout,'snapshottedDirs       : ' +  str(result.snapshottedDirs)
  print >>sys.stdout,  'numFilesDryRun      : ' + str(result.numFilesDryRun) 
  print >>sys.stdout,  'numBytesDryRun      : ' + str(result.numBytesDryRun) 

#  if result.jobId != None:
  print >>sys.stdout,  'jobId               : ' + str(result.jobId) 
  print >>sys.stdout,  'numFilesSkipped     : ' + str(result.numFilesSkipped) 
  print >>sys.stdout,  'numBytesExpected    : ' + str(result.numBytesExpected) 
  print >>sys.stdout,  'numFilesExpected    : ' + str(result.numFilesExpected) 
#  if result.setupError != None:
  print >>sys.stdout,  'setupError          : ' + str(result.setupError) 
  print >>sys.stdout,  'dryRun              : ' + str(result.dryRun) 
  print >>sys.stdout,  'runAsUser           : ' + str(result.runAsUser) 
#  if result.failedFiles != None:
  print >>sys.stdout,  'failedFiles         : ' + str(result.failedFiles)


  if printDetails == True and result.counters != None:
    for r in result.counters:
      print >>sys.stdout,  r['group'] +': ' + r['name'] + ' = ' + str(r['value'])


def printHiveResults(result,printDetails):
  print >>sys.stdout,  '\n\tHive Replication Result'
  print >>sys.stdout,  '-------------------------------------------------------------------------------------------------'
 
  print >>sys.stdout,  'dryRun              : ' + str(result.dryRun) 
  print >>sys.stdout,  'runAsUser           : ' + str(result.runAsUser) 
  print >>sys.stdout,  'impalaUDFs          : '  + str(result.impalaUDFs)
  print >>sys.stdout,  'tableCount          : '  + str(result.tableCount)
  print >>sys.stdout,  'phase               : '  + str(result.phase)
  print >>sys.stdout,  'errorCount          : ' + str(result.errorCount)

  if result.tables != None and result.tableCount > 0:
    print >>sys.stdout,  'Tables'
    for r in result.tables:
      print >>sys.stdout,  r

  if result.errors != None and result.errorCount > 0:
    print >>sys.stdout,  'Errors: '
    for r in result.errors:
     print >>sys.stdout,  r


#  if result.dataReplicationResult != None:
#    print >>sys.stdout,  'numBytesCopied      : ' + str(result.dataReplicationResult.numBytesCopied     )
#    print >>sys.stdout,  'numBytesCopyFailed  : ' + str(result.dataReplicationResult.numBytesCopyFailed )
#    print >>sys.stdout,  'numBytesSkipped     : ' + str(result.dataReplicationResult.numBytesSkipped    )
#    print >>sys.stdout,  'numFilesCopied      : ' + str(result.dataReplicationResult.numFilesCopied     )
#    print >>sys.stdout,  'numFilesDeleted     : ' + str(result.dataReplicationResult.numFilesDeleted    )
#    print >>sys.stdout,  'progress            : ' + str(result.dataReplicationResult.progress    )
#    print >>sys.stdout,  'jobdetails          : ' + str(result.dataReplicationResult.jobDetailsUri    )
#
#    if printDetails == True and result.dataReplicationResult.counters != None:
#      for r in result.dataReplicationResult.counters:
#        print >>sys.stdout,  r['group'] +': ' + r['name'] + ' = ' + str(r['value'])

#
# create a hive BDR schedule instance
#
def addHiveSchedule(cf,cluster,database,table):
  res = None
  # retrieve the database only job that we can use as a template.
  dbSchedule = getHiveSchedule(cluster,cf['HIVE_SERVICE'],database, cf['DB_TEMPLATE_NAME'])
  if dbSchedule != None :
    nowDateTime= datetime.datetime.utcnow()
    yearFromNow = datetime.timedelta(weeks=+52)
    hiveReplArgs = dbSchedule.hiveArguments
    hiveReplArgs.tableFilters = [{'tableName': table, 'database': database}]
    hiveService =  cluster.get_service(cf['HIVE_SERVICE'])
    paused=True
    interval=0
    intervalUnit='DAY'
    res = hiveService.create_replication_schedule(
      nowDateTime, nowDateTime + yearFromNow, intervalUnit, interval, paused, hiveReplArgs)
  return res


#
# create a HDFS BDR schedule instance
#
def addHDFSSchedule(cf,cluster,path):

    nowDateTime= datetime.datetime.utcnow()
    yearFromNow = datetime.timedelta(weeks=+52)

    hdfsReplConf = {"interval": 0,"hdfsArguments":{
      'sourceService'            : {'clusterName': 'cluster', 'serviceName': cf['HDFS_SERVICE'], 'peerName': cf['CM_PEERNAME']},
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

    hdfsReplArgs = ApiHdfsReplicationArguments(cf,hdfsReplConf)

    hdfsReplArgs.sourceService            = {'clusterName': 'cluster', 'serviceName': cf['HDFS_SERVICE'], 'peerName': cf['CM_PEERNAME']}
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
        nowDateTime, nowDateTime + yearFromNow, intervalUnit, interval, paused, hdfsReplArgs)

    return res


#
# trigger a schedule item to run
#
def runSchedule(cluster,service,index,dryRun):
    bdrService =  cluster.get_service(service)
    res = bdrService.trigger_replication_schedule(index,dry_run=dryRun)
    return res



# {"AclStatus": {"owner": "hive", "stickyBit": false, "group": "hive", "entries":
#     ["user:hive:rwx", "group:jprosser:rwx", "group::---", "group:hive:rwx"]}}
# {"FileStatus": {"aclBit": true, "group": "hive", "permission": "771", "blockSize": 0,
# "accessTime": 0, "pathSuffix": "", "modificationTime": 1453998161924, "replication": 0,
# "length": 0, "owner": "hive", "type": "DIRECTORY"}}
#
# determine if the user is either the owner of the path or has user/group write perms in the acls
#


def getAccessPriv(cf,user,groupList,path):
  isOK=False

  #getReplUrl = cf['HTTPFS_PROTO']+"://"+cf['HTTPFS_HOST'] + ":" + cf['HTTPFS_PORT'] + "/webhdfs/v1" + path + "?user.name=ec2-user&op=GETFILESTATUS"
  getReplUrl = cf['HTTPFS_PROTO']+"://"+cf['HTTPFS_HOST'] + ":" + cf['HTTPFS_PORT'] + "/webhdfs/v1" + path + "?op=GETFILESTATUS"
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
    #getReplUrl = cf['HTTPFS_PROTO']+"://"+cf['HTTPFS_HOST'] + ":" + cf['HTTPFS_PORT'] + "/webhdfs/V1" + path + "?user.name=ec2-user&op=GETACLSTATUS"
    getReplUrl = cf['HTTPFS_PROTO']+"://"+cf['HTTPFS_HOST'] + ":" + cf['HTTPFS_PORT'] + "/webhdfs/V1" + path + "?op=GETACLSTATUS"
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
# get all the schedules that the process runner has file access to
#
def getAccessableSchedules(cf,cluster,procUser,groupList):
  repls=[]
  pathList=[]
  hiveService =  cluster.get_service(cf['HIVE_SERVICE'])
  hiveSchedules=hiveService.get_replication_schedules()

  databases = {} # dict of dbname/dbpath so we don't call webhcat repeatedly for the same db
  for x in hiveSchedules:
    db = x.hiveArguments.tableFilters[0].database

    # have we already gotten the location for this db from webhcat?
    if db not in databases:
      dbLoc = getDatabaseLocation(cf,db)
      if dbLoc != None:
        databases[db] = dbLoc
      else:
        continue
    else:
      dbLoc = databases[db]
    pathList.append( {'schedule': x, 'service': cf['HIVE_SERVICE'],'path': dbLoc} )

  hdfsService =  cluster.get_service(cf['HDFS_SERVICE'])
  hdfsSchedules=hdfsService.get_replication_schedules()
  for x in hdfsSchedules:
    sPath = x.hdfsArguments.sourcePath

    # skip the hdfs entry if it corresponds to a hive db
    if sPath not in databases.values():
      pathList.append( {'schedule': x, 'service': cf['HDFS_SERVICE'],'path': sPath} )

  # returns the subset of (id,service,path) tuples that this user/group can write to.
  accessableSchedules = filterAccessablePaths(cf,procUser,groupList,pathList)
  return accessableSchedules


#
# get the hive schedule for this database/table pair
#
def getHiveSchedule (cluster,service,database,table) :
    hiveService =  cluster.get_service(service)
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
    if not path.endswith("/"):
      path = path+"/"
    LOG.debug( "looking for substrings of " + path)

    keeper=None
#    output_dict = [ x for x in schedules if newpath.find( x.hdfsArguments.sourcePath ) != -1 ]
    maxLen=0
    for x in schedules:
      if path.find( x.hdfsArguments.sourcePath ) != -1:
        if len( x.hdfsArguments.sourcePath ) > maxLen:
          keeper = x
          maxLen = len( x.hdfsArguments.sourcePath )
      

    LOG.debug( "found " + keeper.hdfsArguments.sourcePath)

    return keeper
    #return output_dict[0]

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
    tsString=datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
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


def main(cf,argv):

  setup_logging(cf['CM_REPL_LOGLEVEL'])

  # Argument parsing
  try:
    opts, args = getopt.getopt(argv[1:], '', #hD:t:sp:yl
                               ['database=','table=','path=','help','status','follow=','dry-run','list','verbose'])

  except getopt.GetoptError, err:
    print >>sys.stderr, err
    usage()
    return cf['RET_BADOPTS']

  service  = None
  dryRun   = False
# the CM instance the utility will talk to in order to trigger replications.
# if failing back, this would be changed to CM_PRIMARY
  cmHost   = cf['CM_DRSITE']
  followPeriod = int(cf['STATUS_POLL_DELAY'])
  action   = 'doBackup'
  database = None
  table    = None
  path     = None
  verbose  = False

  for option, val in opts:
    LOG.debug( "option is " + option +" val is " + val)
    # i took the shortargs out of the options config, but left them here in case the
    # decision was made to bring them back in
    if option in ('-h','--help'):
      usage()
      return cf['RET_OK']
    elif option in ('-D','--database'):
      database = val
      service = cf['HIVE_SERVICE']
    elif option in ('-t','--table'):
      table =  val
    elif option in ('-y','--dry-run'):
      dryRun = True
    elif option in ('-y','--verbose'):
      verbose = True
    elif option in ('-f','--follow'):
      action='followStatus'
      followPeriod = int(val)
    elif option in ('-s','--status'):
      action='getStatus'
    elif option in ('-k','--list'):
      action='listRepls'
# allows switching sites for failback. disabled for now.
#    elif option in ('-c'):
#      activeSite = val
    elif option in ('-p','--path'):
      path  = val
      service = cf['HDFS_SERVICE']

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
  if action != 'listRepls':
    if path != None and (table != None or database != None) :
      print >>sys.stderr, '\n\tDo not specify HDFS and Hive replication arguments at the same time.'
      usage()
      return cf['RET_BADOPTS']
    elif path == None and  database == None :
      print >>sys.stderr, '\n\tYou must specify either a path or database and table.\n \
      \tIf you specified the table using a regular expression, you must use that exact syntax enclosed in single quotes.'
      usage()
      return cf['RET_BADOPTS']
    elif path == None and  ( database == None or table == None):
      print >>sys.stderr, '\n\tYou must specify a database and a table.\n \
      \tIf you specified the table using a regular expression, you must use that exact syntax enclosed in single quotes.'
      usage()
      return cf['RET_BADOPTS']
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

  vm_version = cf['CM_VERSION']
  API = ApiResource(cmHost, cf['CM_PORT'],  version=cf['CM_VERSION'], username=cf['CM_USER'], password=cf['CM_PASSWD'], use_tls=False)
  LOG.debug('Connected to CM host on ' + cmHost)

  procUser = getUsername()
  LOG.debug('Process effective username is ' + procUser)
  procGroup= getGroupname()
  LOG.debug('Process effective group name is ' + procGroup)
  procUserGroups = getUserGroups(procUser)
  LOG.debug('All groups for user:' +  ', '.join(procUserGroups))
  cluster = API.get_cluster(cf['CLUSTER_NAME'])

  if action == 'listRepls':
    print >>sys.stdout,  '\n\tSearching replication schedules for user: ' + procUser + ' group(s): ' + ', '.join(procUserGroups)
    schedules = getAccessableSchedules(cf,cluster,procUser,procUserGroups)
    printReplicationSchedules(cf,schedules)
    return cf['RET_OK']

# get details about the replication the user is interested in
  if service == cf['HIVE_SERVICE']:
    path = getDatabaseLocation(cf,database)
    LOG.debug('DB location is ' + path)
    schedule = getHiveSchedule (cluster,service,database,table)
  else:
    schedule = getHdfsSchedule (cluster,service,path)
    path = schedule.hdfsArguments.sourcePath
    print >>sys.stderr, '\n\tUsing replication schedule with path: ' + path

# check access privs and abort if none
  validPath=filterAccessablePaths(cf,procUser,procUserGroups,[{'schedule': schedule, 'service': service,'path':path}])
  if len(validPath) == 0 :
    print >>sys.stderr, '\n\tInvalid privs or item does not exist.\n'
    return cf['RET_NOENT']


  if schedule == None:
      print >>sys.stderr, '\n\tNo replication schedule defined for this object. '
      return cf['RET_NOREP_EXISTS']

  LOG.debug('CHECKING IF REPLICATION IS ALREADY UNDERWAY')
  active = getScheduleStatus(schedule)

  if action == 'getStatus':
      if active == True :
        print >>sys.stderr, '\n\tThere is currently a replication underway for this schedule.\n'
        printScheduleStatus(service,schedule)
        return cf['RET_OK']
      else :
        print >>sys.stderr, '\n\tThere is currently NO replication underway for this schedule.\n'
        printScheduleLastResult (cf,service,schedule)
        return cf['RET_OK']

  if action == 'followStatus':
    if schedule == None:
      print >>sys.stderr, '\n\tNo replication schedule defined for this object. '
      return cf['RET_NOREP_EXISTS']
    else:
      print >>sys.stdout, '\tStart polling for status'
      verbose = True
      status = pollReplicationStatus(cf,cluster, service, schedule,verbose)
      if status ==  False:
        return cf['RET_REP_FAILED']
      return 0

  if schedule == None:
    if service == cf['HIVE_SERVICE'] and cf['HIVE_AUTOCREATE'] == 'True' :
      print >>sys.stdout, '\tAdding HIVE schedule with table name: ' + table
      result = addHiveSchedule(cf, cluster, database, table )
      if result == None:
        print >>sys.stderr, '\n\tNo replication template defined for database.'
        return cf['RET_NO_DBTEMPLATE_EXISTS']
      LOG.debug( 'Getting id for newly added schedule.')
      schedule = getHiveSchedule (cluster,service,database,table)
    elif cf['HDFS_AUTOCREATE'] == 'True' :
      print >>sys.stdout, '\tAdding HDFS schedule with path: ' + path
      result = addHDFSSchedule(cf,cluster,path)
      LOG.debug( 'Getting id for newly added schedule.')
      schedule = getHdfsSchedule (cluster,service,path)
    else:
      print >>sys.stderr, '\n\tNo Replication schedule defined for this object. '
      return cf['RET_NOREP_EXISTS']

  bdrId = schedule.id

  if active == True :
    print >>sys.stderr, '\n\tThere is currently a replication underway for this schedule.\n'
    printScheduleStatus(service,schedule)
    return cf['RET_REP_ALREADY_UNDERWAY']


  print >>sys.stdout, '\tScheduling run for id: ' + str(bdrId)
  result = runSchedule(cluster,service,bdrId,dryRun)
  schedule = getSchedule(cluster,service,bdrId)
  if verbose == True:
    print >>sys.stdout, '\tStart polling for status'
  status = pollReplicationStatus(cf ,cluster, service, schedule,verbose)
  if status ==  False:
    return cf['RET_REP_FAILED']

  return cf['RET_OK']

#
# The 'main' entry
#
if __name__ == '__main__':
  cf=init()
  val = main(cf,sys.argv)
  LOG.debug('main returned :' + str(val))
  os._exit(int(val))
