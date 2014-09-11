__author__ = 'Moroz Oleg'

# Analyze current active hosts and compare to previous state
# Log state changes
# version 0.8.0

import logging
import os

logFileName = "netstatechanges.log"
dbFileName = "laststate.db"
exceptionsFileName = "except.list"
curArp = []
lastArp = {}
exceptArp = []

curDirPath = os.path.dirname(os.path.realpath(__file__))
logFullFileName = curDirPath + "/" + logFileName
dbFullFileName = curDirPath + "/" + dbFileName
exceptFullFileName = curDirPath + "/" + exceptionsFileName

logger = logging.getLogger("net_activity")
logger.setLevel(logging.DEBUG)

formater = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

fileLogger = logging.FileHandler(logFullFileName)
fileLogger.setLevel(logging.INFO)
fileLogger.setFormatter(formater)

consoleLogger = logging.StreamHandler()
consoleLogger.setLevel(logging.WARNING)
consoleLogger.setFormatter(formater)

logger.addHandler(fileLogger)
logger.addHandler(consoleLogger)

logger.debug("Log file name: %s" % logFullFileName)
logger.debug("DB file name: %s" % dbFullFileName)

def getActiveHosts():
    logger.debug("Getting active arp table")
    f = os.popen("arp -a | awk '! /10.1.1.255/ {print $1,$2}'")
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
        pingCmd = "ping -qc 1 -W 3 %s | awk '/packets/ {print $4}'" % h
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

getActiveHosts()
loadLastState(dbFullFileName)
handleExceptions(exceptFullFileName)
checkActiveHosts()
compareHostStates()
saveLastState(dbFullFileName)