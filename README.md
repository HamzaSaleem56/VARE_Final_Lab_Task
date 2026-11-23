# Comparative Malware Analysis and Reverse Engineering

Final lab task — static analysis of three malware samples from the PMAT-labs repository.

**Author:** Ahmed Saleem
**Date:** 23 November 2026

---

## The task

Conduct an independent investigation of three malware samples from the PMAT-labs repository: `Malware.Calc.exe`, `SillyPutty` and `Malware.PackedAndNotPacked.exe`.

The work is **strictly static**. No sample was executed, double-clicked or given execute permission, and no connection was made to any suspicious host or command-and-control server.

Sections covered in the report:

1. Safe handling and initial investigation — hashes, file details, VirusTotal lookups
2. Strings, FLOSS and initial behavioural investigation
3. PE structure, sections, imports and entropy
4. Ghidra analysis of each sample
5. Sample-specific findings and verdicts
6. Advanced comparison and hypothesis testing
7. Comparative summary across all samples
8. Exam-day section
9. Investigation log
10. References

---

## What is in this repository

| File | What it is |
|---|---|
| `Comparative Malware Analysis and Reverse Engineering.pdf` | The full report, 42 pages, 57 figures |
| `Ghidra-Projects.zip` | The three Ghidra projects (Calc, SillyPutty, PackedAndNotPacked) |

---

## Samples analysed

| Sample | File | Size (bytes) | SHA-256 |
|---|---|---|---|
| Calc | Malware.Calc.exe.malz | 73,802 | `300bb9ac1f607f99e3fbc7814b42552913ef4bcd2d2752f0f909908ae3e46aaf` |
| SillyPutty | putty.exe | 1,545,216 | `0c82e654c09c8fd9fdf4899718efa37670974c9eec5a8fc18a167f93cea6ee83` |
| NotPacked | Malware.NotPacked.exe.malz | 73,802 | `3b4773db51a514ef19515b0323fb46691176be163f2a6a71c643f65d9a211867` |
| Packed | Malware.Packed.exe.malz | 48,128 | `3279fb36cf70bdc4d5ccf02e6be855681a39602a9506fbf4cee0bc92323e6a9d` |

A copy of Packed was decompressed with UPX for byte comparison (SHA-256 `def07c8b9062936303fb1bf7ab19d53e8ebe0bfe877ca4e7388a8544b6c9199d`). That copy is a working file, not a supplied sample.

---

## Main findings

**All three samples carry the same added code template.** Each resolves Windows APIs at run time by walking the PEB and hashing names with a rotate-right-13 routine, so nothing malicious appears in the import table. Each then passes a command to `WinExec`, found by the hash `0x876f8b31`. Only the command differs.

**Calc and NotPacked** are modified copies of ApacheBench (`ab.exe`, 2.2.14) with an obfuscated entry point: 182 one-byte filler instructions before a jump into the added code. The command is `calc.exe`.

In Calc the full path from the entry to the `WinExec` call is traced by cross-references in Ghidra:

```
entry 004019ea
  -> 182 filler bytes -> JMP 004070b3
  -> FUN_004070c1          (PEB walk, ror13 hashing)
  -> CALL thunk_FUN_0040745b at 004070c1
  -> JMP FUN_0040745b at 00407449
  -> FUN_0040745b          (VirtualAlloc, hash 0xe553a458)
  -> FUN_004075a0
  -> CALL FUN_0040762d at 004075a6
  -> FUN_0040762d          (PUSH 0x876f8b31 = WinExec, command at 0040765d = "calc.exe")
```

NotPacked follows the same shape, with `FUN_00401776 -> FUN_00401ad8` and `00401c62 -> FUN_00401ce9`.

**SillyPutty** is a genuine PuTTY 0.76 with an added section. Its entry at `00522000` loads kernel32, looks up `CreateThread` and starts a thread at `00522047`. That thread passes a hidden PowerShell command to `WinExec`. The command decodes (statically, without running it) to a reverse shell that connects to `bonus2.corporatebonusapplication.local` on port 8443 over TLS and runs every command it receives.

**Packed** is NotPacked compressed with UPX. A memory search of the packed file still finds the VirtualAlloc hash at `00412415`, the WinExec hash at `00412608` and the text `calc.exe` at `00412625`, all inside the compressed UPX1 section.

---

## Limits of this analysis

Stated plainly in the report rather than glossed over:

- Nothing was executed, so no sample can be shown to actually reach its `WinExec` call at run time, and the reverse shell was never attempted.
- Who wrote the shared code template, and whether one author made all three samples, cannot be established from static analysis.
- The unpacked copy of Packed was imported into Ghidra but its auto-analysis was not completed, so the 198 changed read-only bytes remain unexplained.
- FLOSS could not finish its decoding passes on `putty.exe`; the VM's out-of-memory killer stopped it three times. No decoded-string result is claimed for that file.
- The detection features in Section 6 were not tested against clean software, so no false-alarm rate is given.

---

## Environment

Kali Linux 2026.4 in VMware, 2 GB RAM, network adapters set to Host-only and LAN segment, shared folders disabled. A snapshot named "Before Malware Analysis (PMAT Labs)" was taken before any sample work. Ghidra 12.2.
