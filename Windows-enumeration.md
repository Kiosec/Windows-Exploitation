# Windows-Exploitation

## Windows enumeration

#### Who
```
whoami
echo %username%
whoami /priv
```

#### Users and groups
```
➤ What users/localgroups are on the machine?
net users
net localgroups

➤ More info about a specific user. Check if user has privileges.
net user user1

➤ View Domain Groups
net group /domain

➤ View Members of Domain Group
net group /domain {Group Name}
```

#### System info
```
systeminfo
ver
hostname
```

#### Patch on the system
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

#### Network
```
ipconfig /all
route print
arp -A
```

#### Firewall
```
netsh firewall show state
netsh firewall show config
```

#### Vulnerable Drivers
```
Some driver might be vulnerable
driverquery
```

#### Detecte if Windows Defender is enabled on the machine (powershell command)
```
get-item 'hklm:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\'
```

##### Search a specific filename
```
dir /b/s proof.txt
```

## Search Cleartext Passwords

#### Basic search
```
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
```

#### Specific file
```
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

C:\Windows\Panther\
C:\Windows\Panther\Unattend\
C:\Windows\System32\
C:\Windows\System32\sysprep\

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini
```

#### Specific tools
```
➤ VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

➤ Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

➤ SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

➤ Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

#### Search for password in registry
```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

## Automated enumeration

Winpeas.exe :
https://github.com/carlospolop/PEASS-ng/releases/tag/20220220

## Bloodhound enumeration
```
➤ Install Bloodhound GUI
https://www.kalilinux.in/2021/01/install-bloodhound-on-kali-linux.html

➤ Install Bloodhound-python
pip3 install bloodhound

➤ Let's use bloodhound to visualise the domain and look for privilege escalation paths
bloodhound-python -d <DOMAIN> -u <USERNAME> -p <PASSWORD> -gc <COMPUTERNAME>.<DOMAIN> -c all -ns 10.0.0.1
→ EX:  bloodhound-python -d example.local -u svc-admin -p s3rvice -gc laptop01.example.local -c all -ns 10.0.0.1

➤ Upload the JSON file into Bloodhound GUI

```
