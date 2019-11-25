# coding=utf-8
import paramiko
import re

# 设置主机列表
host_list = [{'ip': '221.6.47.103', 'port': 22, 'username': 'root', 'password': 'pms123handle$%^'}]
# {'ip': '101.132.112.222', 'port': 22, 'username': 'root', 'password': 'XUE66666ning'},


ssh = paramiko.SSHClient()
# 设置为接受不在known_hosts 列表的主机可以进行ssh连接
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())



# 返回内存占用率
def findmem():
    for host in host_list:
        ssh.connect(hostname=host['ip'], port=host['port'], username=host['username'], password=host['password'])
        print(host['ip'])
        stdin, stdout, stderr = ssh.exec_command('cat /proc/meminfo')
        str_out = stdout.read().decode()
        str_err = stderr.read().decode()
        if str_err != "":
            print(str_err)
            continue
        str_total = re.search('MemTotal:.*?\n', str_out).group()
        totalmem = re.search('\d+', str_total).group()
        str_free = re.search('MemFree:.*?\n', str_out).group()
        freemem = re.search('\d+', str_free).group()
        use = 1 - round(float(freemem) / float(totalmem), 2)
        ssh.close()
    return use


# 返回硬盘占用率
def findsta():
    for host in host_list:
        ssh.connect(hostname=host['ip'], port=host['port'], username=host['username'], password=host['password'])
        # print(host['ip'])
        stdin, stdout, stderr = ssh.exec_command('df -k ')
        str_out = stdout.read().decode("utf-8")
        str_err = stderr.read().decode("utf-8")

        if str_err != "":
            # print(str_err)
            continue
        s = str_out.split("\n")
        print s.pop(0)
        print s.pop(-1)
        use = []
        blocks = 0
        used = 0
        for i in s:
            u = i.split()
            # print (u)
            blocks += float(u[1])
            used += float(u[2])
            use.append(u[4])
        userate = used / blocks
        ssh.close()
    return userate


def DNSquery(ip, biaoshi):
    for host in host_list:
        ssh.connect(hostname=host['ip'], port=host['port'], username=host['username'], password=host['password'])
        stdin, stdout, stderr = ssh.exec_command('dig @' + ip + '  ' + biaoshi)
        str_out = stdout.read().decode("utf-8")
        str_err = stderr.read().decode("utf-8")
        if str_err != "":
            print(str_err)
            continue
        s = str_out.split("\n")
        ippattern = '((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}'
        iplist = []
        count = 0
        for i in s:
            count = count + 1
            if (i == ";; ANSWER SECTION:"):
                for j in range(count, len(s)):
                    if s[j] == "":
                        break
                    if (re.search(ippattern, s[j]) != None):
                        iplist.append(re.search(ippattern, s[j]).group(0))

        ssh.close()

    return iplist


def Naptrquery(ip, biaoshi):
    for host in host_list:
        ssh.connect(hostname=host['ip'], port=host['port'], username=host['username'], password=host['password'])
        stdin, stdout, stderr = ssh.exec_command('dig @' + ip + ' ' + biaoshi + '   NAPTR')
        str_out = stdout.read().decode("utf-8")
        str_err = stderr.read().decode("utf-8")
        if str_err != "":
            print(str_err)
            continue
        s = str_out.split("\n")
        addresspattern = '[a-zA-Z]+Address'
        httppattern = 'http\S+'
        datalist = {}
        count = 0
        # print  str_out
        for i in s:
            count = count + 1
            if (i == ";; ANSWER SECTION:"):
                for j in range(count, len(s)):
                    if (re.search(addresspattern, s[j]) != None and re.search(httppattern, s[j]) != None):
                        address = re.search(addresspattern, s[j]).group(0)
                        http = re.search(httppattern, s[j]).group(0)
                        datalist[address] = http

        ssh.close()
    return datalist

if __name__ == '__main__':
    print findsta()