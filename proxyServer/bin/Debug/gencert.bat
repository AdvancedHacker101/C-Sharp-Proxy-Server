@echo off
cd "F:\Visual Studio 2017\Projects\proxyServer\proxyServer\bin\Debug"
F:
makecert.exe test2.cer -a sha1 -n "CN = ah101" -sr LocalMachine -ss My -sky signature -pe -len 2048
echo Operation Completed!