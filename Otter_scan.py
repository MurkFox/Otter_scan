# -*- coding:utf-8 -*-
"""
_____   __    __
/\  __`\/\ \__/\ \__
\ \ \/\ \ \ ,_\ \ ,_\    __   _ __           ____    ___     __      ___
 \ \ \ \ \ \ \/\ \ \/  /'__`\/\`'__\        /',__\  /'___\ /'__`\  /' _ `\
  \ \ \_\ \ \ \_\ \ \_/\  __/\ \ \/        /\__, `\/\ \__//\ \L\.\_/\ \/\ \
   \ \_____\ \__\\ \__\ \____\\ \_\        \/\____/\ \____\ \__/.\_\ \_\ \_\
    \/_____/\/__/ \/__/\/____/ \/_/  _______\/___/  \/____/\/__/\/_/\/_/\/_/
                                    /\______\
                                    \/______/
"""
from bs4 import BeautifulSoup
import requests
import logging
import argparse
import threadpool
from IPy import IP
import netaddr
import csv
import re
import json
from random import shuffle, choice
from dns import resolver
import sys
from libnmap.parser import NmapParser
requests.packages.urllib3.disable_warnings()  # 去掉requests https 报错提示


def get_user_agent():
    user_agents = [
        "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
        "Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
        "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
        "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
        "Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
        "Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
        "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52", ]
    return choice(user_agents)


def title_grabe(url):
    try:
        headers = {'User-Agent': get_user_agent()}
        response = requests.get(url, headers=headers, timeout=5, verify=True, stream=True)
        if 'Content-Length' in response.headers.keys() and int(response.headers['Content-Length']) > 50000:
            print("%s is big page" % url)
            return 0
        res = []
        res.append(url)
        for k in response.headers.keys():
            if k.upper() == 'SERVER':
                header_server = response.headers[k].upper()
                res.append(header_server)
        if "SERVER" not in str(response.headers.keys()).upper():
            res.append("Unknown")
        res.append(str(response.status_code))

        ## 判断返回数据的编码格式，减少乱码几率
        if "ISO-8859-1" in response.encoding:
            response.encoding = 'utf-8'
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.get_text()
        if len(title) > 0:
            res.append(title)
        else:
            res.append("None")
        print(*res, sep="    ")
        with open("tmp.txt", "a+") as file:
            file.write(str(res)[1:-1])
            file.write("\n")
    except Exception as e:
        logging.warning(str(e))


class Scanner:
    def __init__(self):
        self.ip = args.ip
        self.url = args.url
        self.ports = args.ports
        self.ip_file = args.ip_file
        self.thread_num = int(args.thread_num)
        self.auto_404 = args.auto_404
        self.auto_waf = args.auto_waf
        self.auto_cdn = args.auto_cdn
        self.protocol = "http://"
        self.ip_list = []
        self.port_list = []
        self.url_list = []
        self.result = []
        LOG_FORMAT = "%(asctime)s %(name)s %(levelname)s %(message)s "  # 配置输出日志格式
        DATE_FORMAT = '%Y-%m-%d  %H:%M:%S %a '  # 配置输出时间的格式，注意月份和天数不要搞乱了
        logging.basicConfig(level=logging.DEBUG,
                            format=LOG_FORMAT,
                            datefmt=DATE_FORMAT,
                            filename=r"Otter_scan.log"  # 有了filename参数就不会直接输出显示到控制台，而是直接写入文件
                            )

    #  ip : / , -
    #  port : ,
    # file: ip , | csv | masscan
    def get_task(self):
        try:
            with open("tmp.txt", "w") as file:
                file.write("""Temporary storage of scan results
----------------------------------------------------\n""")
            if self.url:
                self.url_list.append(self.url)
            if self.ports:
                if "," in self.ports:
                    temp_port_list = self.ports.split(",")
                    for tmp in temp_port_list:
                        self.port_list.append(tmp)
                elif "-" in self.ports:
                    tmp_port = self.ports.split("-")
                    temp_port_list = range(int(tmp_port[0]), int(tmp_port[1]))
                    for i in temp_port_list:
                        self.port_list.append(str(i))
                else:
                    self.port_list.append(self.ports)
            if args.protocol:
                self.protocol = "https://"
            if self.ip:
                if "," in self.ip:
                    ip_args = self.ip.split(",")
                    for ip_cat in ip_args:
                        if "-" in ip_cat:
                            startip = ip_cat.split("-")[0]
                            endip = ip_cat.split("-")[1]
                            cidrs = netaddr.iprange_to_cidrs(startip, endip)
                            for cidr in cidrs:
                                ips = IP(str(cidr))
                                for x in ips:
                                    self.ip_list.append(str(x))
                        elif "/" in ip_cat:
                            ips = IP(ip_cat)
                            for x in ips:
                                self.ip_list.append(str(x))
                        else:
                            self.ip_list.append(ip_cat)
                else:
                    ip_args = args.ip
                    if "-" in ip_args:
                        startip = ip_args.split("-")[0]
                        endip = ip_args.split("-")[1]
                        cidrs = netaddr.iprange_to_cidrs(startip, endip)
                        for cidr in cidrs:
                            ips = IP(str(cidr))
                            for x in ips:
                                self.ip_list.append(str(x))
                    elif "/" in ip_args:
                        ips = IP(ip_args)
                        for x in ips:
                            a = 1
                            self.ip_list.append(str(x))
                    else:
                        self.ip_list.append(ip_args)
            logging.info(str(self.ip_list))
            if self.ip_file:
                filename = self.ip_file
                if ".csv" in filename:
                    csv_reader = csv.reader(open(filename, encoding='utf-8'))
                    task_list = []
                    ip_add = 0
                    port_add = 0
                    for row in csv_reader:
                        task_list.append(row)
                    for tmp in range(len(task_list[0])):
                        if task_list[0][tmp] == "ip":
                            ip_add = tmp
                        if task_list[0][tmp] == "port":
                            port_add = tmp
                    task_list.remove(task_list[0])
                    for task in task_list:
                        task_ip = task[ip_add]
                        task_port = task[port_add]
                        if "/" in task_ip:
                            ips = IP(task_ip)
                            ports = task_port
                            if "-" in ports:
                                tmp_port = ports.split("-")
                                ports = range(int(tmp_port[0]), int(tmp_port[1]))
                            else:
                                ports = ports.split(",")
                            for x in ips:
                                for port in ports:
                                    url = self.protocol + str(x) + ":" +str(port)
                                    self.url_list.append(url)
                        elif "-" in task_ip:
                            startip = task_ip.split("-")[0]
                            endip = task_ip.split("-")[1]
                            cidrs = netaddr.iprange_to_cidrs(startip, endip)
                            ports = task_port
                            if "-" in ports:
                                tmp_port = ports.split("-")
                                ports = range(int(tmp_port[0]), int(tmp_port[1]))
                            else:
                                ports = ports.split(",")
                            for cidr in cidrs:
                                ips = IP(str(cidr))
                                for x in ips:
                                    for port in ports:
                                        url = self.protocol + str(x) + ":" + str(port)
                                        self.url_list.append(url)
                        else:
                            task_ip = task[ip_add]
                            task_port = task[port_add]
                            ports = task_port
                            if "-" in ports:
                                tmp_port = ports.split("-")
                                ports = range(int(tmp_port[0]), int(tmp_port[1]))
                            else:
                                ports = ports.split(",")
                            for port in ports:
                                url = self.protocol + task_ip + ":" + str(port)
                                self.url_list.append(url)
                elif ".json" in filename:
                    with open(filename, 'r') as f:
                        for line in f:
                            if line.startswith('{ '):
                                line = line.replace(",\n", "\n")
                                temp = json.loads(line[:-1])
                                temp1 = temp["ports"][0]
                                url = self.protocol + temp["ip"] + ":" + str(temp1["port"])
                                self.url_list.append(url)
                elif ".xml" in filename:
                    nmap_report = NmapParser.parse_fromfile(filename)
                    Hosts = nmap_report.hosts
                    for host in Hosts:
                        for serv in host.services:
                            if serv.state == "open" and "http" in serv.service:
                                url = self.protocol + host.address + ":" + str(serv.port)
                                self.url_list.append(url)
                else:
                    with open(filename, 'r') as file:
                        lines = file.readlines()
                        test_data = lines[0][:-1]
                        if re.search("(http|https)://", test_data):
                            for lin in lines:
                                text = lin.replace("\n","")
                                self.url_list.append(text)
                        elif ":" in test_data:
                            for lin in lines:
                                text = lin.replace("\n","")
                                url = self.protocol + text
                                self.url_list.append(url)
                        elif re.search("\d\s+\d", test_data):
                            for lin in lines:
                                text = lin.replace("\n","")
                                data = text.split(" ")
                                if "/" in data[0]:
                                    ips = IP(data[0])
                                    if "-" in data[1]:
                                        tmp_port = data[1].split("-")
                                        ports = range(int(tmp_port[0]), int(tmp_port[1]))
                                    else:
                                        ports = data[1].split(",")
                                    for x in ips:
                                        for port in ports:
                                            url = self.protocol + str(x) + ":" + str(port)
                                            self.url_list.append(url)
                                elif "-" in data[0]:
                                    startip = data[0].split("-")[0]
                                    endip = data[0].split("-")[1]
                                    cidrs = netaddr.iprange_to_cidrs(startip, endip)
                                    if "-" in data[1]:
                                        tmp_port = data[1].split("-")
                                        ports = range(int(tmp_port[0]), int(tmp_port[1]))
                                    else:
                                        ports = data[1].split(",")
                                    for cidr in cidrs:
                                        ips = IP(str(cidr))
                                        for x in ips:
                                            for port in ports:
                                                url = self.protocol + str(x) + ":" + str(port)
                                                self.url_list.append(url)
                                else:
                                    add = data[0]
                                    if "-" in data[1]:
                                        tmp_port = data[1].split("-")
                                        ports = range(int(tmp_port[0]), int(tmp_port[1]))
                                    else:
                                        ports = data[1].split(",")
                                    for port in ports:
                                        url = self.protocol + add + ":" +str(port)
                                        self.url_list.append(url)

            logging.info(str(self.url_list))
            if len(self.ip_list) > 0 and len(self.port_list) > 0:
                for ip in self.ip_list:
                    for port in self.port_list:
                        url = self.protocol + ip + ":" + port
                        self.url_list.append(url)
            if len(self.url_list) > 0:
                print("""任务数据加载成功 %d
------------------------------------------------------"""%len(self.url_list))
            else:
                print("""没有加载到任务，请重新输入目标参数
------------------------------------------------------""")
                sys.exit()


        except Exception as e:
            print(str(e))
            logging.warning(str(e))

    def auto_waf_idf(self):
        try:
            waf_file = "waf_signature"
            with open(waf_file, 'r') as loader:
                waf_data = json.load(loader)
                waf_match = {0: None}
                waf_info = {'company': None,
                            'waf_type': None,
                            'bypass_known': None}
                waf_test = ["/<script>select.git", "/union'%3C%3E%20and%201=1",  ## 可触发waf机制的一些payload
                            "/AND 1",
                            "//**/AND/**/1",
                            "/AND 1=1",
                            "/AND 1 LIKE 1",
                            ]
                url_list = []
                for res_url in self.result:  # result sample: [["http://127.0.0.1:8080","apache","我的网站"],["url","server","title"]]
                    url_list.append(res_url[0])
                for target in url_list:
                    for payload in waf_test:
                        url = target + payload
                        resp = requests.get(url, verify=False)
                        page, code, headers = resp.text, resp.status_code, resp.headers
                        if code >= 400:
                            match = 0
                            for waf_name, waf_signature in waf_data.items():
                                if "regex" in waf_signature:
                                    if re.search(waf_signature['regex'], page, re.I):
                                        match = match + 1
                                        logging.info("目标命中 WAF 关键词指纹")
                                if "code" in waf_signature:
                                    if waf_signature['code'] == str(code):
                                        match = match + 1
                                        logging.info("目标命中 WAF 响应码")
                                if "headers" in waf_signature:
                                    if re.search(waf_signature["headers"], str(headers), re.I):
                                        match = match + 1
                                        logging.info("目标命中 WAF headers")
                                if match > max(waf_match, key=waf_match.get):
                                    waf_info['company'] = waf_name
                                    waf_info['waf_type'] = waf_signature.get('name', "Unknown")
                                    if 'bypass_known' not in waf_signature:
                                        waf_info['bypass_known'] = None
                                    else:
                                        waf_info['bypass_known'] = waf_signature['bypass_known']
                                    waf_match.clear()
                                    waf_match[match]: waf_info
                                    print("""%s 存在 WAF 安全防护措施，WAF详细信息如下 :
%s""" % (target, str(waf_info)))
                    if waf_info['company'] == None:  # \033 绿色
                        print("恭喜, %s 没有检测到 WAF 启用!" % target)


        except Exception as e:
            logging.warning(str(e))

    def auto_cdn_check(self):
        try:
            cdn_name = ""
            checked_doamin = []
            with open("cname", "r", encoding="utf-8") as cname_file:
                cname_list = json.load(cname_file)
            url_list = []
            for res_url in self.result:
                url_list.append(res_url[0])
            for url in url_list:
                domain = self.domain_stripper(url)
                if len(domain) > 0 and domain not in checked_doamin:
                    checked_doamin.append(domain)  # 去重
                    ans = resolver.resolve(domain, 'CNAME')
                    for i in ans.response.answer:
                        for j in i.items:
                            for cdn in cname_list:
                                if cdn in j.to_text():
                                    cdn_name = cname_list[cdn]['name']
                                    print("""%s 已启用CDN，CDN信息如下 :
    %s""" % (url, str(cname_list[cdn])))
                else:
                    continue
                if cdn_name == "":
                    print("恭喜, %s 没有启用CDN!" % url)
        except Exception as e:
            print(str(e))
            logging.warning(str(e))

    def result_get(self):
        with open("tmp.txt", "r") as file:
            lines = file.readlines()[2:]
            res = []
            for lin in lines:
                lin = lin.replace("\n", "")
                lin = lin.replace("'", "")
                lin = lin.split(", ")
                res.append(lin)
            if len(res) > 0:
                self.result = res
            else:
                logging.warning("任务已结束，但没有扫描结果")

    def domain_stripper(self, domain):  # 域名提取
        # Regex to
        if not re.search("((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))",
                         domain):
            extract_domain = re.search("htt[a-z]+:\/\/([a-zA-Z0-9_.-]+)[/]?", domain)
            if extract_domain.group(1):
                domain_name = extract_domain.group(1)
                return domain_name
            else:
                logging.warning("Url provided is invalid! \n")
                print("%s 不存在域名或域名格式不正确" % domain)
                return ""
        else:
            logging.warning("Url provided is invalid! \n")
            print("%s 不存在域名或域名格式不正确" % domain)
            return ""

    def ip_port_scan(self):
        print("""扫描任务启动中 
------------------------------------------------------""")
        shuffle(self.url_list)
        taskpool = threadpool.ThreadPool(self.thread_num)
        requests = threadpool.makeRequests(title_grabe, self.url_list)
        for req in requests:
            taskpool.putRequest(req)

        # 等待所有任务执行完成
        taskpool.wait()
        self.result_get()
        if len(self.result) > 0:
            if self.auto_waf:
                print("""开始检测目标WAF部署情况
------------------------------------------------------""")
                self.auto_waf_idf()

            if self.auto_cdn:
                print("""------------------------------------------------------
开始检测目标是否启用CDN
------------------------------------------------------""")
                self.auto_cdn_check()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('-i', '--ip',
                        dest='ip',
                        help='多个参数使用","作为分隔符，支持一下格式 samples: 127.0.0.1, 127.0.0.1/24, 127.0.0.1-127.0.0.5')
    parser.add_argument('-u', '--url',
                        dest='url',
                        help='输入单条url，脚本会直接对该url进行相关测试')
    parser.add_argument('-r', '--read',
                        dest='ip_file',
                        help='支持masscan-json的数据导出，支持nmap-xml的数据导出。支持csv，txt 详情参考samples.txt')
    parser.add_argument('-t', '--thread',
                        dest='thread_num', default=50,
                        help='设置任务进程数，默认50，不建议太高，超过200会发生一些稀奇古怪的编码问题')
    parser.add_argument('-p', '--ports',
                        dest='ports', default="80",
                        help='支持多个端口，用","隔开，也可以使用"-"划分端口段')
    parser.add_argument('-ssl', '--http-ssl',
                        dest='protocol', action="store_true",
                        help='扫描时使用https协议')
    parser.add_argument('-ad404', '--auto-detect-404',
                        dest='auto_404', action="store_true",
                        help='检测网站是否启用智能404，默认不检测')
    parser.add_argument('-adw', '--auto-detect-waf',
                        dest='auto_waf', action="store_true",
                        help='检测网站是否启用waf，默认不检测（触发waf规则可能封禁IP）')
    parser.add_argument('-adc', '--auto-detect-cdn',
                        dest='auto_cdn', action="store_true",
                        help='检测网站是否启用cdn，默认不检测')

    print(""" 
   ___  _   _                                
  / _ \| |_| |_ ___ _ __ ___  ___ __ _ _ __  
 | | | | __| __/ _ \ '__/ __|/ __/ _` | '_ \ 
 | |_| | |_| ||  __/ |  \__ \ (_| (_| | | | |
  \___/ \__|\__\___|_|  |___/\___\__,_|_| |_| v 1.0.2
                                                        
""")
    args = parser.parse_args()
    # Output the collected arguments
    Scan_task = Scanner()
    Scan_task.get_task()
    Scan_task.ip_port_scan()
