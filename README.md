# PcaSvc Executed

Retrieves the last execution information from the **PcaSvc** Service & **PcaClient** for every process.

## What does it do?

- Parses the last execution from PcaClient for every process
- Parses the last execution from PcaSvc
- Performs digital signature checks for each file present
  - Reports "Deleted" if the file is not found
  - Detects specific digital signatures (e.g., Slinky and Vape)
- Applies generic checks to each present file

## Generics:

1. **Generic A**: Basic strings for autoclickers
2. **Generic A2**: Basic imports for autoclickers
3. **Generic B**: Generic protection detection for non-C# files
4. **Generic B2**: Generic protection detection for non-C# files
5. **Generic B3**: Generic protection detection for non-C# files
6. **Generic C**: Basic generic protection detection for C# files
7. **Generic D**: Well done generic protection detection for C# files

Note: All generics should be relatively safe, but don't panic if they trigger. A2 generic may cause occasional "false flags", which are not intended to be fixed to maintain detection of real cheats.

## TODO:

- [x] Add a digital signature check to each file
- [x] Improve generics for C# files
- [x] Add file info checker, strings, imports, YARA rules
- [ ] Add a journal replacement checker to each file
- [ ] Add a GUI/WebGUI
