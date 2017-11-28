"""
This script implement algorithm from
THESIS "Automatic Detection of Click Fraud in Online Advertisements" AGARWAL
Calculate the belief of fraud

http://repositories.tdl.org/ttu-ir/bitstream/handle/2346/46429/AGARWAL-THESIS.pdf

Import library using pyds (https://github.com/reineking/pyds)

Require: Python3, numpy, scipy, redis (https://github.com/andymccurdy/redis-py)

Author: TrucLK
"""
from pyds import MassFunction
from itertools import product
import redis
import sys
import pprint
import time

################################################
class Config(object):
    """
    Redis for store click history
    """
    redis_host='127.0.0.1'
    redis_port=6379
    redis_db=0
    
    #Time for redis key expire
    time_to_expire=1800
    
    #Visitor length of checking
    visit_length=1800
    
    #weight is an empirically derived value that signifies the strength of the evidence in supporting the user is fraud
    
    #caution changing it will change the maximum value of result.
    IDWeight = 0.5    
    UAWeight = 0.4    
    IPWeight = 0.4


class EcLogger(object):
    """
    This is object relate to log
    """

    def __init__(self):
        self.ro = redis.Redis(host=Config.redis_host, port=Config.redis_port, db=Config.redis_db)
    def record(self,hit):
        
        """
        Add click to history for checking
        """

        clickid = self.ro.incr('ec:clicknum')
        
        self.ro.zadd('click:ip:' + hit.ip, clickid, int(hit.time))
        self.ro.expire('click:ip:' + hit.ip, Config.time_to_expire)
        self.ro.zadd('click:cookie:' + hit.cookie, clickid, int(hit.time))
        self.ro.expire('click:cookie:'+ hit.cookie, Config.time_to_expire)
        self.ro.zadd('click:config:' + hit.pubid + ':' + hit.config, clickid, int(hit.time))
        self.ro.expire('click:config:' + hit.pubid + ':' + hit.config, Config.time_to_expire)
        pass
        
    def getClickNumFromIp(self,hit):
        """
        Get click time from this IP address in this session
        """
        count = 0
        count = self.ro.zcount('click:ip:'+hit.ip,int(hit.time) - Config.visit_length,int(hit.time))
        if (count == 0):
            count = 1
        return count
        
    def getClickNumFromCookie(self,hit):
        """
        Get click time from this anonymous id in this session
        """
        count = self.ro.zcount('click:cookie:'+hit.cookie,int(hit.time) - Config.visit_length,int(hit.time))
        if (count == 0):
            count = 1
        return count
        
    def getClickNumFromConfig(self,hit):
        """
        Get cliock time from this user agent in this session
        """
        count = self.ro.zcount('click:config:'+ hit.pubid + ':' + hit.config,int(hit.time) - Config.visit_length,int(hit.time))
        if (count == 0):
            count = 1
        return count
        
class Hit(object):
    """
    It's a simple container.
    """
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        super(Hit, self).__init__()     
    
class ClickProcessingUnit(object):
    """
    Mass functions for Click Fraud Detection
    """
    def __init__(self,hit, ecLogger):
        self.hit = hit
        self.ecLogger = ecLogger
        
class ClickProcessingUnitIp(ClickProcessingUnit):
    """
    Evidence number of clicks on the ad by ip address
    Create mass function for ip address checking
    """
    def process(self):
        numberclick = self.ecLogger.getClickNumFromIp(self.hit)
        coefficient_value = Config.IPWeight

        a = coefficient_value * (1 - 1/numberclick)
        b = 0 
        ab = 1 - a
        
        massfunction = MassFunction({'a':a , 'b':b, 'ab':ab})
        return massfunction;

class ClickProcessingUnitCookie(ClickProcessingUnit):
    """
    Evidence number of clicks on the ad by user ID
    Create mass function for id cookie checking
    """
    def process(self):
        numberclick = self.ecLogger.getClickNumFromCookie(self.hit)
        coefficient_value = Config.IDWeight

        a = coefficient_value * (1 - 1/numberclick)
        b = 0 
        ab = 1 - a
        
        massfunction = MassFunction({'a':a , 'b':b, 'ab':ab})
        return massfunction;

class ClickProcessingUnitConfig(ClickProcessingUnit):
    """
    Evidence number of clicks on the ad by user agent
    Create mass function for user agent checking
    """        
    def process(self):
        numberclick = self.ecLogger.getClickNumFromConfig(self.hit)
        coefficient_value = Config.UAWeight

        a = coefficient_value * (1 - 1/numberclick)
        b = 0 
        ab = 1 - a
        
        massfunction = MassFunction({'a':a , 'b':b, 'ab':ab})
        return massfunction

class ClickProcessing(object):
    """
    Main click processing function 
    """
    def __init__(self,hit, ecLogger):
        self.hit = hit
        self.ecLogger = ecLogger
    def process(self):
        processingList = self.getListOfProcessing()
        m = None
        #Loop for list of processing class
        for processing in processingList:
            #Init first mass function
            if not m:                
                m = processing.process()
            else:
                #Dempster's rule of combination create a new mass function
                m = m & processing.process()
        return m
        
    def getListOfProcessing(self):
        """
        Config list of processing
        """
        dict1 = []
        dict1.append(ClickProcessingUnitIp(self.hit,self.ecLogger))
        dict1.append(ClickProcessingUnitCookie(self.hit,self.ecLogger))
        dict1.append(ClickProcessingUnitConfig(self.hit,self.ecLogger))
        return dict1



if __name__ == '__main__':
    """
    Add click from command line argument
    """
    try:
        hit = hit = Hit(
                        ip = sys.argv[1],
                        time = sys.argv[2],
                        config = sys.argv[3],
                        cookie = sys.argv[4],
                        pubid = sys.argv[5],
                    )        
        ecLogger = EcLogger()
        processing = ClickProcessing(hit,ecLogger)
        ecLogger.record(hit)
        m = processing.process()
        print(m.bel('a'))
        sys.exit(0)
    except Exception:
        print(0.01)
        sys.exit(0)
