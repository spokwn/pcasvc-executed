# PcaSvc Executed

Retrieves the last execution information from the **PcaSvc** Service & **PcaClient** for every process.

## What does it do?

- Parses the last execution from PcaClient for every process
- Parses the last execution from PcaSvc
- Performs digital signature checks for each file present
  - Reports "Deleted" if the file is not found
  - Detects specific digital signatures (e.g., Slinky and Vape)
- Applies generic checks to each present file
- Checks for replaces using journal for every file.
  
## Generics:

1. **Generic A**: Basic strings for autoclickers
2. **Generic A2**: Import combination for autoclickers
3. **Generic A3**: Generic detection for C# autoclickers
4. **Generic B**: Generic protection detection for non-C# files
5. **Generic B2**: Generic protection detection for non-C# files
6. **Generic B3**: Generic protection detection for non-C# files
7. **Generic B4**: Generic protection detection for non-C# files
8. **Generic B5**: Generic protection detection for non-C# files
9. **Generic B6**: Generic protection detection for non-C# files
10. **Generic B7**: Generic protection detection for non-C# files
11. **Generic C**: Basic generic protection detection for C# files
12. **Generic D**: Well done generic protection detection for C# files
13. **Generic E**: Basic generic protection detection for C# and compiled python files
14. **Generic F**: Advanced generic detection for packed executables.
15. **Generic F2**: Advanced generic detection for packed executables.
16. **Generic F3**: Advanced generic detection for packed executables.
17. **Generic F4**: Advanced generic detection for packed executables.
18. **Generic F5**: Advanced generic detection for packed executables.
19. **Generic F6**: Advanced generic detection for very packed executables.
20. **Generic F7**: Advanced generic detection for SUPER packed executables.
21. **Generic G**: Advanced generic detection for suspicious injector executables.
22. **Generic G2**: Advanced generic detection for suspicious injector executables.
23. **Generic G3**: Advanced generic detection for suspicious injector executables.
24. **Generic G4**: Advanced generic detection for suspicious injector executables.
25. **Generic G5**: Advanced generic detection for suspicious injector executables.
26. **Generic G6**: Advanced generic detection for suspicious injector executables.
27. **Generic G7**: Advanced generic detection for suspicious PE injector executables.
28. **Generic G8**: Advanced generic detection for suspicious PE injector executables.
29. **Specific A**: Detects some free cheats using strings, this cheats are mostly the ones who didnt flag any generic at some point.
30. **Specific B**: Detects some paid cheats using advanced methods, it currently just detects 2, but aren't needed as generic already detected them.

Note: All generics should be relatively safe, but don't panic if they trigger. A2 and F generics may cause occasional "false flags", which are not intended to be fixed to maintain detection of real cheats, though they were improved lately.

## TODO:

- [x] Add a digital signature check to each file
- [x] Improve generics for C# files
- [x] Add file info checker, strings, imports, YARA rules
- [x] Add a journal replacement checker to each file
- [ ] Add a GUI/WebGUI

## NOTE: 

this project got deleted & reuploaded bc i messed up and published the "private" generics and specifics, my bad for losing old versions.
