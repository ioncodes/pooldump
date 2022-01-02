call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

cd pooldump && msbuild /property:Configuration=Debug /property:Platform=x64 || exit /b
cd ..

copy pooldump\x64\Debug\pooldump.sys C:\Users\luca\Documents\Projects\kdbg-driver-workstation\guest\layle.sys

cd C:\Users\luca\Documents\Projects\kdbg-driver-workstation
.\kdbg.bat