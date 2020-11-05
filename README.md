### Otter_scan 

```
   ___  _   _                                
  / _ \| |_| |_ ___ _ __ ___  ___ __ _ _ __  
 | | | | __| __/ _ \ '__/ __|/ __/ _` | '_ \ 
 | |_| | |_| ||  __/ |  \__ \ (_| (_| | | | |
  \___/ \__|\__\___|_|  |___/\___\__,_|_| |_| v 1.0.1

```

#### 功能
-   获取网站 title Server
-   基于指纹规则，识别是否启用waf、cdn
#### 参数格式
-   -i IP  --ip IP       
    -   多个ip地址使用","作为分隔符，支持一下格式 samples: 127.0.0.1, 127.0.0.1/24, 127.0.0.1-127.0.0.5
-   -u URL, --url URL     
    -   输入单条url，脚本会直接对该url进行相关测试
-   -t THREAD_NUM, --thread THREAD_NUM
    -   设置任务进程数，默认50，不建议太高，超过200会发生一些稀奇古怪的编码问题
-   -r IP_FILE, --read IP_FILE
    -   支持从masscan的json数据导出（后期会加入对nmap/zmap导出数据的支持）。支持csv，txt 详情参考samples.txt（在一个文件中，ip port的格式需保持一致）
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


    
