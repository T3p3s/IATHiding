# IATHiding

#### Overview
This project demonstrates a technique to hide LoadLibraryW from the Import Address Table (IAT) by implementing a custom API resolution mechanism. Instead of relying on direct imports, the algorithm uses:

A custom implementation of GetProcAddress and GetModuleHandle.
MurmurHash to hash API function names and resolve them dynamically.
Manual module traversal to locate necessary functions without relying on static imports.
By doing this, tools like dumpbin.exe /IMPORTS or PE analysis tools will not reveal LoadLibraryW or other critical APIs in the IAT.

#### How It Works
1. MurmurHash Hashing:

  - Instead of storing function names in plaintext, they are hashed using MurmurHash.
  - This prevents string-based signature detection.

2. Custom GetProcAddress & GetModuleHandle:

  - Manually enumerates loaded modules to retrieve function addresses.
  - Matches hashed function names to their real counterparts dynamically.

3. IAT Evasion:

  - LoadLibraryW is called dynamically via the custom resolver instead of being linked in the IAT.
  - This ensures that dumpbin.exe /IMPORTS does not display LoadLibraryW or other dynamically loaded functions.

#### Security & Obfuscation Benefits

  - Prevents Static Analysis: Tools like IDA Pro, Ghidra, and PEView won't see LoadLibraryW in the import table.
  - Anti-Reversing Technique: Since function resolution is done at runtime, traditional IAT hooking techniques fail.
  - Resistant to String Signatures: Using MurmurHash instead of plain strings makes it harder for malware analysis tools to detect the functions being resolved.
    
#### Usage

1. Compile the project with your preferred compiler (cl.exe, gcc, clang).
2. Run the executable and observe that LoadLibraryW is successfully invoked without being in the IAT.
3. Verify using dumpbin.exe /IMPORTS <executable> – you won't see LoadLibraryW.

#### Disclaimer
This project is for educational purposes only. It demonstrates defensive coding techniques for obfuscation and security research. Do not use it for malicious activities.
