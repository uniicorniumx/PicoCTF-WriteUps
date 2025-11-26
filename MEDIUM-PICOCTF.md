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
