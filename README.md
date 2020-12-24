### Otter_scan 

```
   ___  _   _                                
  / _ \| |_| |_ ___ _ __ ___  ___ __ _ _ __  
 | | | | __| __/ _ \ '__/ __|/ __/ _` | '_ \ 
 | |_| | |_| ||  __/ |  \__ \ (_| (_| | | | |
  \___/ \__|\__\___|_|  |___/\___\__,_|_| |_| 

```

#### 功能
-   获取网站 title Server

```
任务数据加载成功,共计58
------------------------------------------------------
扫描任务启动中 
------------------------------------------------------
http://192.168.0.132:81    NGINX/1.1.10    200    欢迎来到XSS挑战
http://192.168.0.188:80    Unknown
http://192.168.0.86:8080    
http://192.168.0.59:80    200    USB设备共享器 | USB Share
```

-   基于指纹规则，识别是否启用waf、cdn 

```
任务数据加载成功 1
------------------------------------------------------
扫描任务启动中 
------------------------------------------------------
http://www.xxx.com:80    PANYUN/2.0.0    200    安全客 - 安全资讯平台
开始检测目标WAF部署情况
------------------------------------------------------
http://www.xxx.com:80 存在 WAF 安全防护措施，WAF详细信息如下 :
{'company': '360 PANYUN', 'waf_type': '360 PANYUN', 'bypass_known': None}
------------------------------------------------------
开始检测目标是否启用CDN
------------------------------------------------------
http://www.xxx.com:80 已启用CDN，CDN信息如下 :
{'name': '360磐云', 'link': 'https://panyun.360.cn/Login/index'}

```

-   结果除了会打印在shell里，还会保存在工作目录下 tmp.txt中，但下次任务启动后，上次任务数据就会被清空，格式如下：

```
Temporary storage of scan results
----------------------------------------------------
'http://192.168.0.132:81', 'NGINX/1.1.10', '200', '欢迎来到XSS挑战'
'http://192.168.0.188:80', 'Unknown', '200', 'USB设备共享器 | USB Share'
'http://192.168.0.86:8080', 'APACHE-COYOTE/1.1', '200', 'Apache Tomcat'
'http://192.168.0.59:80', 'NGINX/1.10.3 (UBUNTU)', '200', 'Apache2 Ubuntu Default Page: It works'
'http://192.168.0.183:80', 'APACHE/2.4.6 (CENTOS) PHP/5.4.16', '403', 'Apache HTTP Server Test Page powered by CentOS'
'http://192.168.0.83:80', 'NGINX/1.11.13', '200', 'Heartbleed Test'
'http://192.168.0.68:80', 'NGINX/1.18.0 (UBUNTU)', '200', 'Welcome to nginx!'
'http://192.168.0.18:80', 'NGINX/1.5.6', '502', 'Error'
'http://192.168.0.60:80', 'APACHE/2.4.18 (UBUNTU)', '200', 'Apache2 Ubuntu Default Page: It works'
'http://192.168.0.61:80', 'NGINX', '200', '我的网站'
'http://192.168.0.200:80', 'MICROSOFT-IIS/6.0', '200', 'Under Construction'
'http://192.168.0.50:80', 'NGINX/1.17.9', '502', '502 Bad Gateway'
'http://192.168.0.72:80', 'Unknown', '200', 'Everything'
'http://192.168.0.157:80', 'MICROSOFT-IIS/7.5', '200', 'IIS7'
```

#### 参数格式
-   -i IP  --ip IP       
    -   多个ip地址使用","作为分隔符，支持一下格式 samples: 127.0.0.1, 127.0.0.1/24, 127.0.0.1-127.0.0.5
-   -u URL, --url URL     
    -   输入单条url，脚本会直接对该url进行相关测试
-   -t THREAD_NUM, --thread THREAD_NUM
    -   设置任务进程数，默认50，不建议太高，超过200会发生一些稀奇古怪的编码问题
-   -r IP_FILE, --read IP_FILE
    -   支持masscan-json 数据导出（masscan -p 80 -r IP.txt -oJ masscan.json）,由于 masscan 不会进行服务识别，所以 Otter_scan会把所有端口开放的结果组合成任务数据进行测试
    -   支持 nmap-xml数据导出 （nmap -n -Pn -sV -p 80,8080 IP -oX test.xml），nmap支持服务识别，所以Otter_scan会提取nmap扫描结果中端口开放且服务为 http的结果作为任务数据

    ```
    nmap_report = NmapParser.parse_fromfile(filename)
    Hosts = nmap_report.hosts
    for host in Hosts:
         for serv in host.services:
            if serv.state == "open" and "http" in serv.service:
                url = self.protocol + host.address + ":" + str(serv.port)
                self.url_list.append(url)
    ```
    -   详情参考samples.txt（在一个文件中，ip port的格式需保持一致）
    -   支持 csv 格式，ip和port列分别以 “ip” 、“port”命名
        ```
        for tmp in range(len(task_list[0])):
            if task_list[0][tmp] == "ip":
                ip_add = tmp
            if task_list[0][tmp] == "port":
                port_add = tmp
        ```
-   -p PORTS, --ports PORTS
    -    支持多个端口，用","隔开，也可以使用"-"划分端口段(默认 80 端口)
-   -ssl, --http-ssl
    -   扫描时使用https协议
-    -ad404, --auto-detect-404
        -    检测网站是否启用智能404，默认不检测（待添加）
-   -adw, --auto-detect-waf
    -   检测网站是否启用waf，默认不检测（触发waf规则可能封禁IP）
-   -adc, --auto-detect-cdn
    -   检测网站是否启用cdn，默认不检测
#### samples:
```
Otter_scan.exe -i 192.168.0.0/24 -p 80,8080,9000-9010 -adw -adc

Otter_scan.exe -ssl -i 192.168.0.0/24 -p 80,8080,9000-9010 -adw

Otter_scan.exe -r masscan.json -adw

Otter_scan.exe -ssl -r ip_port.csv -adw
```

#### 1.0.3 新增功能
-   -r 输入文本支持每行只存在ip。并通过 -p参数传入端口

```
192.168.0.18
192.168.0.13
```

-   新增目录扫描功能，用户可使用 -ads ，在网站存活扫描结束后，自动对存活网站进行快速的敏感目录扫描（目前并不支持智能404识别，相关功能，考虑在后期更新中加入）

```
command ： Otter_scan.exe -r test.txt -p 80,8080 -ads

   ___  _   _
  / _ \| |_| |_ ___ _ __ ___  ___ __ _ _ __
 | | | | __| __/ _ \ '__/ __|/ __/ _` | '_ \
 | |_| | |_| ||  __/ |  \__ \ (_| (_| | | | |
  \___/ \__|\__\___|_|  |___/\___\__,_|_| |_| v 1.0.3


任务数据加载成功 4
------------------------------------------------------
扫描任务启动中
------------------------------------------------------
http://192.168.0.18:80    NGINX/1.5.6    502    Error
http://192.168.0.13:80    Unknown    200    主页面 - 四维WiKi
------------------------------------------------------
开始检测目标是否存在敏感目录
------------------------------------------------------
目录爆破加载任务 30
http://192.168.0.18:80/admin/    502
http://192.168.0.18:80/Server/    502
http://192.168.0.18:80/WEB-INF/web.xml    502
http://192.168.0.18:80/manage/    502
http://192.168.0.18:80/webmaster/    502
http://192.168.0.18:80/public/    502
http://192.168.0.18:80/api/v1/    502
http://192.168.0.18:80/PhpMyAdmin/    502
http://192.168.0.18:80/.git/    502
http://192.168.0.18:80/robots.txt    502
```
-    目录扫描结果会保存在同目录下的 tmp_dir_scan.txt 文件中
    
