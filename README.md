# PcaSvc Executed

Get the last execution from the **PcaSvc** Service & **PcaClient** from every process.

## What does it do?

Currently it as said before, parses the last execution from pcaclient form every process and also from pcasvc.
I've added a digital signature checker foreach file present, if its not present it will say "Deleted", it also detect the digital signature of slinky and vape.
I've added a generic checker foreach file appearing that is present.

## Generics:

1. Generic A: basic strings for autoclickers.
2. Generic A2: basic imports for autoclickers.
3. Generic B: generic protection detect for non C# files.
4. Generic B2: generic protection detect for non C# files.
5. Generic B3: generic protection detect for non C# files.
6. Generic C: very poor generic protection detect for C# files.

All of them should be kinda safe, but dont panic just from seeing them.
Still, the A2 generic will sometimes cause a "false flag", tho its not intended to be fixed, beacause it can break the detection for real cheats.

## TODO:

1. ~Add a digital signature check to each file.~
2. Add a GUI/WebGUI.
3. ~Add file info checker, strings, imports, yara rules~.
4. Add a journal replacement checker to each file.
5. Improve generics for C# files.
