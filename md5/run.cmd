.\fastcoll_v1.0.0.5.exe -p C:\Windows\System32\calc.exe -o 1.exe 2.exe
certutil -hashfile 1.exe MD5
certutil -hashfile 2.exe MD5
certutil -hashfile 1.exe SHA1
certutil -hashfile 2.exe SHA1
