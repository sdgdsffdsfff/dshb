#!/usr/bin/env python
# -*- coding: utf-8 -*-
### BEGIN INIT INFO
# Provides:          dshb
# Required-Start:    $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start or stop the dshb.py.
### END INIT INFO

import sys, os, time, atexit
import datetime
import ConfigParser
import socket
import fcntl
import struct
import re
import traceback
import logging
from SocketServer import StreamRequestHandler, TCPServer, ThreadingTCPServer
from threading import Thread
from signal import SIGTERM

# 常量
LOG_FILE = '/usr/local/dshb/dshb.log'
CONFIG_FILE = '/usr/local/dshb/dshb.conf'
PID_FILE='/var/run/dshb.pid'
HEARTBEAT_REQUEST = 'HB'
REPLACE_REQUEST = 'RP'
STATUS_FILE = '/home/status/dhcp.status'

# 全局变量。以backup角色运行时，开启socket server，接受main主机发来的请求。
# 设置一个socket超时
hb_timeout = 12
up_interval = 0
backup_ip = ''
backup_port = 0
backup_if = ''
main_ip = ''
main_if = ''


# 日志配置
logging.basicConfig(level=logging.DEBUG,
        format='%(asctime)s [line:%(lineno)d] %(levelname)s %(message)s',
        filename=LOG_FILE,
        filemode='a+')

# console = logging.StreamHandler()
# console.setLevel(logging.DEBUG)
# formatter = logging.Formatter('[line:%(lineno)d] %(levelname)-7s %(message)s')
# console.setFormatter(formatter)
# logging.getLogger('').addHandler(console)

# configparser 封装
class Config:
    def __init__(self, path):
        self.parser = ConfigParser.ConfigParser()
        self.path = path
        self.role = ''
        self.state = ''
        self.main_ip = ''
        self.main_if = ''
        self.backup_ip = ''
        self.backup_port = ''
        self.backup_if = ''
        self.up_interval = 0

    def read(self): 
        self.parser.read(self.path)
        self.role = self.parser.get('service', 'role')
        self.state = self.parser.get('service', 'state')
        self.up_interval = self.parser.getint('service', 'update_interval')
        self.main_ip = self.parser.get('main', 'IP')
        self.main_if = self.parser.get('main', 'interface')
        self.backup_ip = self.parser.get('backup', 'IP')
        self.backup_port = self.parser.getint('backup', 'port')
        self.backup_if = self.parser.get('backup', 'interface')
        
    def write(self):
        self.parser.set('service', 'role', self.role)
        self.parser.set('service', 'state', self.state)
        self.parser.set('service', 'update_interval', self.up_interval)
        self.parser.set('main', 'IP', self.main_ip)
        self.parser.set('main', 'interface', self.main_if)
        self.parser.set('backup', 'IP', self.backup_ip)
        self.parser.set('backup', 'port', self.backup_port)
        self.parser.set('backup', 'interface', self.backup_if)
        self.parser.write(open(self.path, 'w'))


# socketserver 的请求处理类
class MyStreamRequestHandler(StreamRequestHandler):
    def _heartbeat_process(self):
        self.wfile.write("HB_BACK")

    def _replace_process(self):
        self.wfile.write("RP_BAKC")
        self.LogDb('enter replace process')
        self.Log("main host down, i will online")
        self.finish()
        config_online()
        dshb_reboot()
        
    def LogTemplate(self, s):
        return '[id.' + str(id(self.request)) + ']:  ' + str(s)

    def Log(self, s):
        ss =  self.LogTemplate(s)
        logging.info(ss)

    def LogErr(self, s):
        ss =  self.LogTemplate(s)
        logging.error(ss)

    def LogDb(self, s):
        ss = self.LogTemplate(s)
        logging.debug(ss)

    """
    # 调用系统命令，ping不通时阻塞时间大概5秒钟
    """
    @staticmethod
    def ping(ip):
        try:
            data = os.system("ping -c 1 %s > /dev/null 2>&1" % ip)
            if data == 0:
                return True
            else:
                return False
        except:
            return False

    """
    # 重写handle方法
    """
    def handle(self):
        global main_ip
        global hb_timeout
        self.Log('accept connection from %s' % (self.client_address[0]))
        if self.client_address[0] != main_ip:
            logging.debug('client address: %s' %(self.client_address[0]))
            self.wfile.write('you have no permission!')
            return
        data = self.rfile.readline().strip().upper()
        if not data:
            self.LogErr("receive null")
            return
        self.Log('request data: [%s]' % (data))
        while data:
            try:
                self.timestamp = time.time()
                process = self._request_process.get(data[:2])
                if not process:
                    self.LogErr("unkown request")
                else:
                    process()
                data = self.rfile.readline().strip().upper()
            except socket.timeout:
                self.LogErr("caught socket.timeout exception")  
                break
            except:
                self.LogErr(traceback.format_exc())
                break
        if MyStreamRequestHandler.ping(main_ip) == False:
            self.LogErr('ping host %s revieve null, wait 10 second' % (main_ip))
            sleep(10)
            if MyStreamRequestHandler.ping(main_ip) == False:
                self.LogErr('ping host %s still revieve null after 10 second' % (main_ip))
                self._replace_process()
        else:
            self.Log('session end')

    """
    # 重写setup方法
    """
    def setup(self):
        global hb_timeout
        StreamRequestHandler.setup(self)
        self.request.settimeout(hb_timeout)
        self._request_process = {
            HEARTBEAT_REQUEST:self._heartbeat_process,
            REPLACE_REQUEST:self._replace_process
        }
        self.timestamp = None

    """
    # 重写finish方法
    """
    def finish(self):
        StreamRequestHandler.finish(self)
        self.request.close()

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915, # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
        )[20:24])

def set_ip_address(ifname, ip):
    #os.system('ip addr flush %s' % ifname)
    #os.system('ip addr add %s dev %s' % (ip, ifname))
    pattern = re.compile(r'iface eth0')
    net_config_file = '/etc/network/interfaces'
    f = open(net_config_file)
    lines = f.readlines()
    f.close()
    for i, line in enumerate(lines):
        if pattern.match(line):
            next_line = lines[i + 1].strip()
            if next_line[:7] == 'address':
                lines[i + 1] = 'address ' + ip + '\n'
            break
    f = open(net_config_file, 'w')
    for line in lines:
        f.write(line)
    f.close()
    os.system('service networking restart')

def dshb_reboot():
    logging.info('--------dshb will reboot-------')
    os.execvp('python', ['', sys.argv[0]])

def reboot_if_state_change(state):
    while True:
        cfg = Config(CONFIG_FILE)
        cfg.read()
        if cfg.state != state:
            logging.info('config role change')
            dshb_reboot()
        time.sleep(60)


def send_heartbeat_request():
    global backup_ip, backup_port, hb_timeout
    logging.debug('enter send hb thread')
    buffsize = 1024
    addr = (backup_ip, backup_port)
    timeout_error_logged = False
    other_error_logged = False
    while True:
        cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli_sock.settimeout(hb_timeout)
        try:            
            cli_sock.connect(addr)  
            while True:
                cli_sock.send(HEARTBEAT_REQUEST + '\n')
                data = cli_sock.recv(buffsize)
                if not data:break
                time.sleep(hb_timeout/3)
            logging.error('send heartbeat request to %s, but revieve null' % (backup_ip))
            cli_sock.close()
            timeout_error_logged = False
            other_error_logged = False
        except socket.timeout:
            if not timeout_error_logged:
                logging.error("caught socket.timeout exception")
                timeout_error_logged = True
            cli_sock.close()
            time.sleep(5)
            continue
        except:
            if not other_error_logged:
                logging.error(traceback.format_exc())
                other_error_logged = True
            cli_sock.close()
            time.sleep(5)
            
def send_replace_request():
    global backup_ip, backup_port, hb_timeout
    logging.debug('send rp request')
    buffsize = 1024
    addr = (backup_ip, backup_port)
    send_success = False
    for i in range(3):      
        cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli_sock.settimeout(hb_timeout * 2)
        try:
            cli_sock.connect(addr)
            cli_sock.send(REPLACE_REQUEST + '\n')
            data = cli_sock.recv(buffsize)
            if data:
                cli_sock.close()
                logging.debug('server response replace request')
                send_success = True
                break
            cli_sock.close()
            time.sleep(hb_timeout/3)
        except socket.timeout:
            logging.error("caught socket.timeout exception")
            cli_sock.close()
        except:
            logging.debug(traceback.format_exc())
            cli_sock.close()
    if not send_success:
        logging.error('send replace request to %s  failed' % (backup_ip))
    return send_success

def chk_status():
    global up_interval
    tomcat_status = True
    database_status = True
    down_message = ''
    try:
        fd = open(STATUS_FILE)
        line = fd.readlines()[-1]
        status_strings = line.split('|')

        #tomcat
        time_string = status_strings[0].strip()
        log_tm = time.strptime(time_string, '%Y-%m-%d %H:%M:%S')
        log_date_time = datetime.datetime(log_tm.tm_year,
                                        log_tm.tm_mon,
                                        log_tm.tm_mday,
                                        log_tm.tm_hour,
                                        log_tm.tm_min,
                                        log_tm.tm_sec)
        now_date_time = datetime.datetime.now()
        delta = (now_date_time - log_date_time).seconds
        logging.debug('deltatime: %d' %(delta))
        if delta > up_interval:
            if try_restart_tomcat() == False:
                tomcat_status = False
                logging.debug('tomcat restarting failed')   
        db_string = status_strings[1].strip()

        # database
        if db_string.split(':')[1] != '1':
            database_status = False
        logging.debug('database status: %s' %(db_string.split(':')[1]))
    except:
        logging.error(traceback.format_exc())

    host_status = tomcat_status and database_status
    if not host_status:
        logging.error('%s:[%s]' %(STATUS_FILE, status_strings))
    return host_status

def try_restart_tomcat():
    if os.system('service tomcat6 restart') != 0:
        time.sleep(3)
        if os.system('service tomcat6 restart') != 0:
            return False
    return True


# 将配置文件中的角色设置为online
def config_online():
    cfg = Config(CONFIG_FILE)
    cfg.read()
    cfg.role = 'online'
    cfg.write()

def config_offline():
    cfg = Config(CONFIG_FILE)
    cfg.read()
    cfg.role = 'offline'
    cfg.write()

# backup角色运行，开启socketserver时刻接受主机的请求信息
def run_as_backup_offline():
    logging.info("begin run as backup offline")
    global backup_ip
    global backup_port
    server_address = (backup_ip, backup_port)
    server = ThreadingTCPServer(server_address, MyStreamRequestHandler)
    server.serve_forever()
    logging.error(traceback.format_exc())

# main角色运行，client端向backup机发送心跳及热备替换请求
def run_as_main_online():
    global hb_timeout
    logging.info("begin run as main online")
    thread_heartbeat = Thread(target = send_heartbeat_request, args = (), name = 'heartbeat client')
    thread_heartbeat.start()
    while True:
        if chk_status() == False:
            if send_replace_request():
                break
        time.sleep(3)
    config_offline()
    dshb_reboot()

# backup收到热备替换请求上线替换主机运行
def run_as_backup_online():
    global backup_if, main_ip
    logging.info("begin run as backup online")
    ip = get_ip_address(backup_if)
    if ip != main_ip:
        logging.info("change ip to main host ip")
        set_ip_address(backup_if, main_ip)
    reboot_if_state_change('online')


def run_as_main_offline():
    global main_if, backup_if
    logging.info("begin run as main offline")
    ip = get_ip_address(main_if)
    if ip != backup_ip:
        logging.info("change ip to backup host ip")
        set_ip_address(main_if, backup_ip)
    reboot_if_state_change('offline')
        

class Daemon:
    def __init__(self, pidfile):
        self.pidfile = pidfile

    def _daemonize(self):
        #脱离父进程
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        #脱离终端
        os.setsid()
        #修改当前工作目录  
        os.chdir("/")
        #重设文件创建权限
        os.umask(0)

        #第二次fork，禁止进程重新打开控制终端
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        sys.stdout.flush()
        sys.stderr.flush()

        #注册程序退出时的函数，即删掉pid文件
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile,'w+').write("%s\n" % pid)

    def delpid(self):
        os.remove(self.pidfile)
    def start(self):
        """
        Start the daemon
        """
        # Check for a pidfile to see if the daemon already runs
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            message = "dshb is already running at %d\n"
            sys.stderr.write(message % pid)
            sys.exit(1)

        # Start the daemon
        self._daemonize()
        #message = "start dshb\n"
        #sys.stdout.write(message)
        self._run()
    def stop(self):
        # Get the pid from the pidfile
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            message = "dshb is not running\n"
            sys.stderr.write(message)
            return # not an error in a restart
        # Try killing the daemon process    
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                sys.exit(1)
    def status(self):
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            message = "dshb is running at pid: %d\n"
            sys.stdout.write(message % pid)
        else:
            message = "dshb is not running\n"
            sys.stderr.write(message)
            sys.exit(1)
    def restart(self):
        self.stop()
        self.start()
    def _run(self):
        pass


class MyDaemon(Daemon):
    def __init__(self, pidfile):
        Daemon.__init__(self, pidfile)

    def _run(self):
        main_run()
        



def main_run():
    global main_ip, main_if, backup_ip, backup_if, backup_port
    global role, state, up_interval
    logging.info('-------------dshb start-------------')
    try:
        cfg = Config(CONFIG_FILE)
        cfg.read()
        main_ip = cfg.main_ip
        main_if = cfg.main_if
        backup_ip = cfg.backup_ip
        backup_port = cfg.backup_port
        backup_if = cfg.backup_if
        role = cfg.role
        state = cfg.state
        up_interval = cfg.up_interval
        
        if role == 'main' and state == 'online':
            run_as_main_online()
        elif role == 'main' and state == 'offline':
            run_as_main_offline()
        elif role == 'backup' and state == 'offline':
            run_as_backup_offline()
        elif role == 'backup' and state == 'online':
            run_as_backup_online()
        else:
            logging.error('role = %s set error, please check config file' %(role))
    except:
        logging.error(traceback.format_exc())
    logging.info('-------------dshb end --------------')

if __name__ == '__main__':
    daemon = MyDaemon(PID_FILE)
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        elif 'status' == sys.argv[1]:
            daemon.status()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart|status" % sys.argv[0]
        sys.exit(2)
