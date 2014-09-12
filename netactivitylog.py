__author__ = 'Moroz Oleg'

# Analyze current active hosts and compare to previous state
# Log state changes
# version 0.9.4

import logging
import logging.handlers
import os
import ConfigParser

logFileName = "netstatechanges.log"
dbFileName = "laststate.db"
exceptionsFileName = "except.list"
confFileName = "netact.conf"
curArp = []
lastArp = {}
exceptArp = []
cfgArr = {}

curDirPath = os.path.dirname(os.path.realpath(__file__))
logFullFileName = curDirPath + "/" + logFileName
dbFullFileName = curDirPath + "/" + dbFileName
exceptFullFileName = curDirPath + "/" + exceptionsFileName
confFullFileName = curDirPath + "/" + confFileName

def initLogger():
    global logger
    global logLevelArr
    logger = logging.getLogger("net_activity")
    logger.setLevel(logging.DEBUG)
    logLevelArr = {
        'debug' : logging.DEBUG,
        'info' : logging.INFO,
        'warn' : logging.WARNING,
        'error' : logging.ERROR,
        'crit' : logging.CRITICAL
    }

    formater = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fileLogger = logging.FileHandler(logFullFileName)
    fileLogger.setLevel(logLevelArr[cfgArr['log_file_level']])
    fileLogger.setFormatter(formater)

    consoleLogger = logging.StreamHandler()
    consoleLogger.setLevel(logLevelArr[cfgArr['log_cons_level']])
    consoleLogger.setFormatter(formater)

    rotateLogger = logging.handlers.TimedRotatingFileHandler(logFullFileName, 'W0', 1, 14)

    logger.addHandler(fileLogger)
    logger.addHandler(consoleLogger)
    logger.addHandler(rotateLogger)

    logger.debug("Log file name: %s" % logFullFileName)
    logger.debug("DB file name: %s" % dbFullFileName)

def setDefaults():
    cfgArr['awk'] = '/usr/bin/awk'
    cfgArr['arp'] = '/usr/sbin/arp'
    cfgArr['ping'] = '/sbin/ping'
    cfgArr['log_file_level'] = 'info'
    cfgArr['log_cons_level'] = 'warn'
    #cfgArr['log_cons_level'] = 'debug' # only for configuration load debugging

def updateLoggerConfigration():
    logger.debug("Updating logger configuration")
    for h in logger.handlers:
        if type(h) is logging.FileHandler:
            logger.debug("Update file logger level to %s" % cfgArr['log_file_level'])
            h.setLevel(logLevelArr[cfgArr['log_file_level']])
        if type(h) is logging.StreamHandler:
            logger.debug("Update console logger level to %s" % cfgArr['log_cons_level'])
            h.setLevel(logLevelArr[cfgArr['log_cons_level']])

def loadConf(cfgFileName):
    logger.debug("Try to load configuration from %s" % cfgFileName)
    if os.path.isfile(cfgFileName):
        logger.debug("Configuration file found -- loading...")
        config = ConfigParser.ConfigParser()
        config.read(cfgFileName)
        logger.debug("Enumerating section in configuration")
        for sec in config.sections():
            logger.debug("Found section: %s . Enumerating options" % sec)
            for opt in config.options(sec):
                logger.debug("Found option: %s" % opt)
                cfgArr[opt] = config.get(sec, opt)
                logger.debug("Option %s set to value %s" % (opt, cfgArr[opt]))
    logger.debug("Configuration loaded: %r" % cfgArr)
    updateLoggerConfigration()

def getActiveHosts():
    logger.debug("Getting active arp table")
    strCmd = "%s -a | %s '{print $1,$2}'" % (cfgArr['arp'], cfgArr['awk'])
    logger.debug("Get active hosts command : %s" % strCmd)
    f = os.popen(strCmd)
    for s in f:
        logger.debug("Parsing: %s" % s.strip())
        strName, strIP = s.split()
        strClearIP = strIP[1:-1]
        logger.debug("Hostname: %s ; IP: %s" % (strName, strClearIP))
        #logger.debug("Append %s to active hosts list" % s)
        #curArp.append(s)
        if strName == '?':
            logger.debug("Add IP %s to active hosts list" % strClearIP)
            curArp.append(strClearIP)
        else:
            logger.debug("Add hostname %s to active hosts list" % strName)
            curArp.append(strName)

def checkActiveHosts():
    logger.debug("Checking for real active hosts...")
    for h in curArp:
        logger.debug("Checking host %s" % h)
        pingCmd = "%s -qc 1 -W 3 %s | %s '/packets/ {print $4}'" % (cfgArr['ping'] ,h, cfgArr['awk'])
        logger.debug("Ping command: %s" % pingCmd)
        pingReceived = os.popen(pingCmd).read().strip()
        logger.debug("Ping result: %r" % pingReceived)
        if pingReceived != '1':
            logger.debug("Removing from active hosts: %s" % h)
            curArp.remove(h)
    logger.debug("Final active hosts list %r" % curArp)

def loadLastState(DBFileName):
    logger.debug("Try to load last states from file: %s" % DBFileName)
    if os.path.isfile(DBFileName):
        logger.debug("File exists... opening...")
        f = open(DBFileName)
        for s in f:
            logger.debug("Get string from file: %s" % s.strip())
            strHost, strState = s.split()
            logger.debug("Host: %s ; State: %s" % (strHost, strState))
            lastArp[strHost] = strState
        f.close()
    logger.debug("Loaded states: %r" % lastArp)

def compareHostStates():
    logger.debug("Checking active hosts list...")
    for h in curArp:
        logger.debug("Check for last state for %s" % h)
        if h in lastArp:
            logger.debug("Last state for %s found. State: %s" % (h, lastArp[h]))
            if lastArp[h] == '0':
                logger.info("Host %s become active" % h)
                lastArp[h] = '1'
        else:
            logger.warning("No last state found for %s - saving state" % h)
            logger.info("Host %s become active" % h)
            lastArp[h] = '1'
    logger.debug("Checking for hosts that go to inactive state")
    for h in lastArp.keys():
        if lastArp[h] == '1':
            logger.debug("Check previously active host %s" % h)
            if h in curArp:
                logger.debug("Host %s still active..." % h)
            else:
                logger.info("Host %s become inactive" % h)
                lastArp[h] = '0'
    logger.debug("Updated state: %r", lastArp)

def saveLastState(DBFileName):
    logger.debug("Saving last state")
    f = open(DBFileName, 'w')
    for h in lastArp.keys():
        f.write("%s %s\n" % (h, lastArp[h]))
    f.close()

def handleExceptions(exceptFile):
    logger.debug("Try to load exceptions file from %s" % exceptFile)
    if os.path.isfile(exceptFile):
        logger.debug("File exist. Loading...")
        f = open(exceptFile)
        for s in f:
            logger.debug("Readed : %s" % s.strip())
            exceptArp.append(s.strip())
        f.close()
        logger.debug("Exception list: %r" % exceptArp)
    if len(exceptArp) > 0 :
        for e in exceptArp:
            logger.debug("Handling exception : %s" % e)
            if e in curArp:
                logger.debug("Removing %s from active list" % e)
                curArp.remove(e)
            if e in lastArp.keys():
                logger.debug("Removing %s from state list" % e)
                del lastArp[e]

setDefaults()
initLogger()
loadConf(confFullFileName)
getActiveHosts()
loadLastState(dbFullFileName)
handleExceptions(exceptFullFileName)
checkActiveHosts()
compareHostStates()
saveLastState(dbFullFileName)