@echo off
cd "F:\Visual Studio 2017\Projects\proxyServer\proxyServer\bin\Debug"
F:
makecert.exe certs\general.xcer -a sha256 -n "CN = example.com" -sky signature -pe -len 2048
echo Operation Completed!