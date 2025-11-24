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
curl -X POST http://XXXXXXXX.XXXXX.XXX:XXXXX/verify-otp \
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
