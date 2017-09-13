import logging
import logging.handlers

LOCALDNS = (
		"8.8.8.8",53
)


logging.basicConfig(
		level=logging.INFO,
		format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
		datefmt='%a, %d %b %Y %H:%M:%S',
		filename = '/dev/null' ,
		filemode='a'
) 

logfile = "/data0/sdns/logs/dns.log"



xh = logging.handlers.TimedRotatingFileHandler(logfile,"h",24,200)
xh.suffix = "%Y%m%d-%H%M.log" 
xh.setLevel(logging.DEBUG) 
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s') 
xh.setFormatter(formatter) 
logging.getLogger('').addHandler(xh)
