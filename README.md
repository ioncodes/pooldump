# pooldump
Attempts to dump all nonpaged `BigPool`s from kernel.

## Usage
```shell
mkdir C:\tmp
kdmapper.exe pooldump.sys
```

## EasyAntiCheat Dumping
This tool can be used to extract the DLL that EACs manualmaps into the game process. Before launching the driver start your EAC protected game and then scan for the `eac0` or `eac1` segment. You'll will most likely need to remove the first ~7 bytes (up until the `MZ` header).
