# PicoCTF Writeups — Summarized (83 Challenges) - 
Difficulty: EASY 

This README is a collection of short summaries for the 83 PicoCTF challenges I've worked through.  
I’m not going into full writeups here — the goal is simply to show what each challenge was about, how I approached it, and what ideas or techniques solved it.

I’ve also included each challenge’s ID so you can match them directly with the ones on the PicoCTF platform.

---

# Forensics

### ID 530 — Riddle Registry
A metadata investigation challenge. The trick is simply looking inside the file using tools like `strings` or `exiftool` to find embedded text or hints.

### ID 524 — Hidden in plainsight
A beginner steganography puzzle. The flag hides inside the image data, so inspecting layers or running stego tools reveals it quickly.

### ID 523 — Flag in Flame
A corrupted image. By repairing the header or running `binwalk` to extract hidden appended data, the flag becomes visible.

### ID 519 — Corrupted file
A damaged file with the wrong signature. Identifying the correct file type and fixing the header with a hex editor solves it.

### ID 505 — DISKO 1
A simple disk image. Mount or explore it and look around — there’s usually a readable file placed in an obvious directory.

### ID 460 — RED
The flag was hidden inside one of the RGB channels. Extracting or splitting channels reveals readable text.

### ID 459 — Ph4nt0m 1ntrud3r
You’re given suspicious logs or a PCAP. The solution is to scroll through and identify obviously malicious activity or anomalies.

### ID 450 — Verify
A checksum mismatch challenge. You compare the file’s hash to the expected value using `sha256sum`/`md5sum`.

### ID 444 — Scan Surprise
A QR code is hidden in the file. Extract it with tools like `zbarimg` and read the decoded message.

### ID 408 — CanYouSee
A small trick involving EXIF data. The hint or flag sits inside a metadata field — easily retrieved with `exiftool`.

### ID 423 — Secret of the Polyglot
A file that behaves like two different formats at once. Reviewing the header closely exposes how the flag is embedded.

### ID 186 — information
run `strings` on the file and scroll. The readable output includes the flag.

### ID 44 — Glory of the Garden
Hidden in the metadata challenge. The flag appears when inspecting additional data past the normal file end.

---

# Web Exploitation

### ID 520 — Crack the Gate 1
A client-side fake-authentication check. Changing a parameter like `isLoggedIn` (via Burp Suite or browser tools) bypasses the login instantly.

### ID 492 — SSTI1
A simple Server-Side Template Injection challenge. Entering `{{7*7}}` or similar expressions confirms code execution.

### ID 476 — head-dump
The web server leaks information through HTTP headers. Curl/Burp makes it easy to see what’s being exposed.

### ID 469 — Cookie Monster Secret Recipe
A cookie manipulation challenge. Decoding or editing the cookie grants access to hidden content.

### ID 427 — WebDecode
You’re given obfuscated JavaScript. Beautifying or base64-decoding the script exposes the logic (and the flag).

### ID 426 — Unminify
Minified JS hides the answer. Once beautified, the important lines stand out.

### ID 419 — IntroToBurp
A beginner challenge using Burp Suite. Intercept a request, modify a parameter, and the server returns the flag.

### ID 275 — Inspect HTML
The flag is literally in the HTML. Just scroll through comments or script tags.

### ID 278 — Local Authority
The site relies on insecure client-side validation. Sending a crafted request or tampering with values bypasses the restrictions.

### ID 274 — Includes
Inspecting included JS/CSS files reveals hidden content or direct hints.

### ID 18 — Inspect0r
Follow a chain of hints across HTML, CSS, and JS files to reach the final flag.

### ID 4 — where are the robots
Open `/robots.txt` and check the disallowed paths — one of them contains the flag.

### ID 66 — dont-use-client-side
Classic “never trust the client.” Bypass the JavaScript checks and send the request manually.

### ID 46 — logon
A cookie or parameter controls the login state; manipulating it logs you in.

### ID 173 — Cookies
The cookie contains encoded data (base64). Decoding it reveals the flag.

### ID 132 — GET aHEAD
Use a HEAD request instead of GET. The server responds with the hidden information.

### ID 161 — Scavenger Hunt
A guided puzzle: follow links and clues across multiple pages until the flag appears.

### ID 406 — Bookmarklet
The entire challenge is hidden inside an obfuscated JavaScript bookmarklet. Once prettified, the script clearly shows how it decodes the flag.

---

# Cryptography

### ID 475 — hashcrack
A weak hash that can be cracked with Hashcat/John the Ripper using a simple wordlist.

### ID 470 — EVEN RSA CAN BE BROKEN???
An RSA key generated with weak parameters. Factoring the modulus or exploiting math weaknesses recovers the plaintext.

### ID 144 — Mod 26
A Caesar shift. Rotating through the alphabet reveals the message.

### ID 62 — 13
Classic ROT13 substitution. Instantly decoded with any ROT13 tool.

### ID 68 — The Numbers
An A1Z26 cipher (1 = A, 2 = B, etc.). Converting the numbers reveals the flag.

### ID 418 — interencdec
A layered encoding exercise (base64 + Caesar or similar). Decode step by step.

### ID 243 — Textbook RSA
A deliberately weak RSA challenge. Using the provided values, applying RSA math (available online) yields the flag.

---

# Reverse Engineering

### ID 472 — Flag Hunters
Inspecting the binary with `strings` or Ghidra shows how the program constructs or compares the flag.

### ID 471 — FANTASY CTF
A small program where constants inside the code form the flag. Reading the code directly solves it.

### ID 7 — vault-door-training
The program compares your input to a hardcoded string. Extract the correct string from the verification function.

### ID 104 — Transformation
The input goes through XOR, rotation, or arithmetic changes. Reversing those operations reveals the flag.

---

# Binary Exploitation

### ID 490 — PIE TIME
A basic ASLR/PIE challenge. Leak addresses or memory, then extract the flag.

### ID 438 — heap 0
Inspect heap allocations with debugging tools. The flag sits in one of the chunks.

### ID 433 — format string 0
A format string vulnerability (`%x`, `%p`, etc.) lets you leak stack memory containing the flag.

---

# General Skills

### ID 527 — Log Hunt
Use `grep` to locate the log entry containing the flag.

### ID 463 — Rust fixme 3
A Rust script that refuses to compile because of type or import issues. Fixing them makes the script run and print the flag.

### ID 462 — Rust fixme 2
A smaller Rust debugging task. Fix the minor compiler errors, run it, and the flag appears.

### ID 461 — Rust fixme 1
Another broken Rust script. Repair the basic syntax/logic to get the correct output.

### ID 414 — endianness
Convert values between little-endian and big-endian to interpret the data correctly.

### ID 425 — Time Machine
Use Git to browse older commits — one of them contains the flag.

### ID 424 — Super SSH
SSH into the remote machine, explore the filesystem, and collect the flag.

### ID 442 — Binary Search
Navigate directories efficiently or search with `find` to locate the target file.

### ID 411 — Commitment Issues
Explore Git history (`git log`, `git reflog`) to find the deleted flag.

### ID 410 — Collaborative Development
Compare branches and merges to uncover where the flag was introduced or removed.

### ID 405 — Blame Game
Use `git blame` to identify which line of a file contains the flag.

### ID 404 — binhexa
Convert between hex, binary, and ASCII to interpret encoded messages.

### ID 250 — runme.py
Run the Python script with the correct input to get the flag.

### ID 241 — fixme2.py
A Python script with simple logical/syntax errors. Fix the issues and rerun it to print the flag.

### ID 240 — fixme1.py
Fix the basic Python scripting bugs and rerun to print the correct output.

### ID 239 — convertme.py
A challenge about converting numbers between bases using Python.

### ID 238 — Codebook
Decode a message with a simple Python dictionary or substitution logic.

### ID 242 — Glitch Cat
Connect via netcat and decode the remote service’s response.

### ID 189 — Magikarp Ground Mission
SSH into a remote server and follow instructions to uncover the flag.

### ID 176 — Tab, Tab, Attack
Use shell auto-completion to discover hidden files or paths.

### ID 170 — Wave a Flag
Run the program or inspect it with `strings` to reveal helpful output.

### ID 166 — Python Wrangling
Use the provided Python script to decode or process the given file.

### ID 156 — Nice netcat…
Connect via netcat and read or decode streamed ASCII data.

### ID 320 — First Find
Use `find` to locate files based on name patterns.

### ID 322 — Big Zip
Unzip a nested chain of compressed files until the final one is reached.

### ID 371 — repetitions
Decode multiple layers of repeated base64 encoding.

### ID 67 — Bases
Convert between binary, hex, decimal, and Base64 formats.

### ID 85 — First Grep
Use `grep` to filter files for matching text.

### ID 86 — 2warm
A warm-up exercise involving basic integer or ASCII conversions.

### ID 58 — Warmed Up
Convert hex to ASCII or similar simple transformations.

### ID 22 — Lets Warm Up
A beginner ASCII and numeric interpretation challenge.

### ID 37 — strings it
Run `strings` on a binary to find readable output containing the flag.

### ID 482 — n0s4n1ty 1
A simple web challenge designed to look more confusing than it is. Once you read the client-side code properly, the real check becomes obvious.

### ID 34 — what's a net cat?
A netcat warm-up. Connect to the host/port with `nc` and the server prints the flag.

### ID 163 — tunn3l v1s10n
A networking challenge where the data is encoded in a predictable way. Decoding it reveals the flag.

### ID 147 — Inspiration
A hint-following puzzle. The challenge scatters clues that, when followed in order, lead straight to the flag.
