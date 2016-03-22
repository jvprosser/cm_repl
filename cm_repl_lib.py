#!/usr/lib64/cmf/agent/build/env/bin/python

import ConfigParser
import pwd
import grp
import os
import urllib2
import base64
import json
import kerberos as k
import urllib2_kerberos as ul2k

def init():

  config = {}

  #
  # Customize this path
  #
  config_path_list =['/','h','o','m','e','/','j','p','r','o','s','s','e','r','/','c','m','_','r','e','p','l','.','i','n','i']
  config['CONFIG_PATH']  =''.join(config_path_list)
  
  DR_NAV_USER  =['a','d','m','i','n']
  DR_NAV_PASSWD=['a','d','m','i','n']
               
  PROD_NAV_USER  =['a','d','m','i','n']
  PROD_NAV_PASSWD=['a','d','m','i','n']
  
  config['DR_NAV_USER']    =''.join(DR_NAV_USER  )
  config['DR_NAV_PASSWD']  =''.join(DR_NAV_PASSWD)
  config['PROD_NAV_USER']  =''.join(PROD_NAV_USER  )
  config['PROD_NAV_PASSWD']=''.join(PROD_NAV_PASSWD)
  
  
  try :
    Config = ConfigParser.SafeConfigParser()
    dataset = Config.read(config['CONFIG_PATH'])
    if len(dataset) != 1:
      print >>sys.stderr, '\n\tCould not find configuration.'
      sys.exit(255)
  except ConfigParser.Error, e :
    print >>sys.stderr, '\n\tCould not read configuration.'
    sys.exit(255)
  

  config['CM_REPL_LOGLEVEL']    = Config.get('CM_REPL', 'log_level')
  config['DB_TEMPLATE_NAME']    = Config.get('CM_REPL', 'db_template_name')
  config['CM_VERSION']	        = Config.get('CM_REPL', 'cm_version')
  config['CM_USER']	        = Config.get('CM_REPL', 'cm_user')
  config['CM_PASSWD']	        = Config.get('CM_REPL', 'cm_passwd')
  config['CM_PRIMARY']	        = Config.get('CM_REPL', 'cm_primary')
  config['CM_DRSITE']	        = Config.get('CM_REPL', 'cm_drsite')
  config['CM_PORT']	        = Config.get('CM_REPL', 'cm_port')
  config['CM_PEERNAME']	        = Config.get('CM_REPL', 'cm_peername')
  config['CLUSTER_NAME']	= Config.get('CM_REPL', 'cluster_name')

  config['HTTPFS_HOST']	        = Config.get('CM_REPL', 'httpfs_host')
  config['HTTPFS_PORT']	        = Config.get('CM_REPL', 'httpfs_port')
  config['HTTPFS_PROTO']	= Config.get('CM_REPL', 'httpfs_proto')
  config['WEBHCAT_HOST']	= Config.get('CM_REPL', 'webhcat_host')
  config['WEBHCAT_PORT']	= Config.get('CM_REPL', 'webhcat_port')
  config['WEBHCAT_PROTO']	= Config.get('CM_REPL', 'webhcat_proto')
  config['HDFS_SERVICE']	= Config.get('CM_REPL', 'hdfs_service')
  config['HIVE_SERVICE']	= Config.get('CM_REPL', 'hive_service')
  config['HIVE_AUTOCREATE']	= Config.get('CM_REPL', 'hive_autocreate')
  config['HDFS_AUTOCREATE']     = False
  config['MAX_POLLING_RETRIES'] = Config.get('CM_REPL', 'max_polling_retries')
  config['STATUS_POLL_DELAY']   = Config.get('CM_REPL', 'status_poll_delay')

  
  config['LOGLEVEL']         = Config.get('GET_GRANTS', 'getgrants_log_level')
  config['PROD_NAV_PROTO']   = Config.get('GET_GRANTS', 'prod_nav_proto')  
  config['PROD_NAV_HOST']    = Config.get('GET_GRANTS', 'prod_nav_host')   
  config['PROD_NAV_PORT']    = Config.get('GET_GRANTS', 'prod_nav_port')   
  config['DR_NAV_PROTO']     = Config.get('GET_GRANTS', 'dr_nav_proto')    
  config['DR_NAV_HOST']      = Config.get('GET_GRANTS', 'dr_nav_host')     
  config['DR_NAV_PORT']      = Config.get('GET_GRANTS', 'dr_nav_port')     
  config['DR_BEELINE_URL']   = Config.get('GET_GRANTS', 'dr_beeline_url')     
  config['NAV_LOG_FILE']     = Config.get('GET_GRANTS', 'nav_log_file')  

  config['RET_OK']                      = Config.get('GLOBALS', 'ret_ok')
  config['RET_BADOPTS']                 = Config.get('GLOBALS', 'ret_badopts')
  config['RET_NOENT']                   = Config.get('GLOBALS', 'ret_noent')
  config['RET_NOREP_EXISTS']            = Config.get('GLOBALS', 'ret_norep_exists') 
  config['RET_REP_ALREADY_UNDERWAY']    = Config.get('GLOBALS', 'ret_rep_already_underway')
  config['RET_REP_FAILED']              = Config.get('GLOBALS', 'ret_rep_failed') 
  config['RET_NO_DBTEMPLATE_EXISTS']    = Config.get('GLOBALS', 'ret_no_dbtemplate_exists') 

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


def getNavData(navData,navType,query,LOG):

  getReplUrl = navData['proto']+"://" + navData['host'] + ":" + navData['port'] + "/api/v5/"+navType +"/?query=" +  query
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


def getSentryGrants(navData,user,db,table,start,end,LOG):

#  query="username%3D%3D{0}%3Ballowed%3D%3Dtrue%3Bservice%3D%3Dsentry&startTime={1}&endTime={2}&limit=100&offset=0&format=JSON&attachment=false".format(user,start,end)
  query="allowed%3D%3Dtrue%3Bservice%3D%3Dsentry&startTime={0}&endTime={1}&limit=1000&offset=0&format=JSON&attachment=false".format(start,end)

  data = getNavData(navData,"audits",query,LOG)

  return data
