<p align="justify"><h1>DccwBypassUAC</h1>
This exploit abuses the functionality of "dccw.exe" so as to obtain an administrator shell (bypass UAC). It supports "x86" and "x64" architectures. It has been successfully tested on Windows 10 14393, Windows 10 15031 and Windows 10 15062.
<br>
In the following days more updates will be uploaded, even a Metasploit version.
<br>
<h2>1. DEVELOPMENT OF A NEW BYPASS UAC</h2>
<h3>1.1. VULNERABILITY SEARCH</h3>
To develop a new bypass UAC, first we have to find a vulnerability on the system and, to be more precise, a vulnerability in an auto-elevate process. To get a list of such processes we used the "Sysinternals" tool "Strings". After that, we could see some auto-elevate processes like "sysprep.exe", "cliconfig.exe", "inetmgr.exe", "consent.exe" or "CompMgmtLauncher.exe" that had (some of them still have) vulnerabilities that allow the execution of a "bypass UAC". So we start to study how other auto-elevate processes worked with the "Sysinternals" application "Process Monitor" ("ProcMon"), but focusing on the process "dccw.exe".<br>
<br>

![alt tag](https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/AutoElevate_Processes.png)

<br>
However, before starting with "ProcMon", first we check the manifest of such applications with another "Sysinternals" application called "Sigcheck", and, of course, in our case, "dccw.exe" is an auto-elevate process.<br>
<br>

![alt tag](https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/autoElevation_confirmed.png)

<br>
Then, we could start the execution flow of "dccw.exe" with "ProcMon" to see in something strange occurs, something we checked immediately. At some point, if we have executed "dccw.exe" as a 64 bits process in a 64 bits Windows machine it looks for the directory "C:\Windows\System32\dccw.exe.Local\" to load a specific DLL called "GdiPlus.dll", the same as it were executed in a 32 bits Windows machine, whereas if we execute it as a 32 bits in the same machine, the process will look for the directory "C:\Windows\SysWOW64\dccw.exe.Local\". Then, due to the fact that it does not exist (fig …), the process always looks for a folder in the path "C:\Windows\WinSxS\" to get the desired DLL, this folder has a name with the following structure:<br>
[architecture]_microsoft.windows.gdiplus_[sequencial_code]_[Windows_version]_none_[sequencial_number]<br>
<br>

![alt tag](https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/dccw_dotLocal_notFound.png)

<br>
If we take a look into "WinSxS" we could see more than one folder that matches with this structure, this means that "dccw.exe" can load the desired DLL from any of these folders. The only thing we are sure is that if the application is invoked as a 32 bits process, the folder name will start with the string "x86", while if we execute it as a 64 bits process, its name will start with the string "amd64".<br>
<br>

![alt tag](https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/gdiplus_folders.png)

<br>
This situation can be abused to perform a DLL hijacking and then execute code with high integrity without prompting for consent.<br>
<br>
<h3>1.2. VULNERABILITY VERIFICATION</h3>
Once we have found some error during the execution of an auto-elevate process we need to verify whether it can be abused or not. To do this we just will create the folder "dccw.exe.Local" in the desired path and into that folder we are going to create the folders located in "WinSxS" that could be invoked by the process, but without the DLL stored in that folders.<br>
Now, if we execute "dccw.exe" we will see that it has found the folder "dccw.exe.Local" and one of the "WinSxS" folders, but not the desired DLL, something that throws an error. Therefore, the vulnerability has been verified.<br>
<br>

![alt tag](https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/dccw_vuln_checking.png)

<h3>1.3.EXPLOIT DEVELOPMENT</h3>
At this point, we already know that we can perform a bypass UAC against "dccw.exe", but how?
<br>
<h4>1.3.1. Method</h4>
Well, we can adapt the method developed by Leo Davidson to exploit the discovered vulnerability. The problem of that method is the process injection that is performed to use the "IFileOperation", which can be detected by some antivirus software, so a better approach to use it is that one called "Masquerade PEB" developed by FuzzySecurity and used by Cn33liz in its own bypass UAC [17].<br>
Also, we have to modify the way "IFileOperation" is invoked in newer Windows 10 versions, since Leo Davidson method triggers UAC from build 15002. So the way we have to invoke such operation is the same as the original, but without the operation flags "FOF_SILENT", "FOFX_SHOWELEVATIONPROMPT" and "FOF_NOERRORUI" [6].
<br>
<h4>1.3.2.Initial Checks</h4>
Before executing the exploit, it is important to check some aspects to not execute it unsuccessfully and therefore trigger some alarms. The first thing we check is the Windows build version, since some versions do not support the exploit (those with a build version lower than 7000). After that, we verify that we do not have administrator rights yet, if it is not the case, there is no reason to execute the script. Then, we check the UAC settings so as to confirm that it is not set to "Always notify", since if it were set to that value, our exploit would be useless. Finally, we have to verify whether the exploit will be executed in a 32 bits or in a 64 bits Windows machine. This final checking is performed manually.
<br>
<h4>1.3.3. Interoperability</h4>
When an exploit is developed is important that can work in as many systems as possible, this includes 32 bits Windows systems. To achieve this, we need to compile our exploit for such systems, since we can also execute it in 64 bits systems.<br>
When our 32 bits exploit is executed in a 64 bits Windows machine, the way "dccw.exe" operates is a bit different due to the invocation of WOW64 (Windows subsystem that allows 64 bits machines to run 32 bits applications). This means the folder "dccw.exe.Local" will be looked for in "C:\Windows\SysWOW64\" directory, instead of "C:\Windows\System32\", but also the targeted "GdiPlus.dll" will be a 32 bits DLL, which implies that it will be looked for in a folder that matches with that name pattern "C:\Windows\WinSxS\x86_microsoft.windows.gdiplus_*". However, if it is executed in a 32 bits Windows system, the exploit will work as expected.<br>
Finally, it is important to remark that we need to consider all the paths that matches with the pattern "C:\Windows\WinSxS\x86_microsoft.windows.gdiplus_*" when the DLL hijack is performed in order to assure a 100% of effectiveness.
<br>
<h4>1.3.4. Malicious DLL</h4>
To execute a process with high integrity we need to develop a DLL that invokes it via DLL hijacking. However, it is not simple as it looks, because, if we only do that, neither "dccw.exe" nor our code will be executed. This is because "dccw.exe" depends on some functions of "GdiPlus.dll", so we need to implement such functions or redirect the execution to the legit DLL.<br>
The best option is forwarding the execution to the legit DLL, because in this way the size of our DLL will be lower. To do so, we use the program "ExportsToC++" to port all exports of "GdiPlus.dll" to C++ language, this will be implemented in our DLL [18].<br>
Now, it seems that the problem has been fixed, but if we forward the execution to a specific "GdiPlus.dll" in C:\Windows\WinSxS\", the DLL will work only in specific systems, due to the name of the internal folders of "WinSxS" changes every Windows build. To overcome this problem, we came up with an elegant solution, forwarding the execution to "C:\Windows\System32\GdiPlus.dll", due to the fact that the path is the same in all Windows versions.<br>
The last thing we have to do is stopping the execution of "dccw.exe" after executing our malicious code so as to avoid the window opening of that process.<br>
Now, once we have developed our malicious DLL, we need to drop it in the targeted machine. To do so, our DLL has been compressed and "base64" encoded into the exploit, so that can be decoded and decompressed during its execution to drop it as expected.<br>
Finally, our crafted "GdiPlus.dll" is copied to the vulnerable location using "IFileOperation" COM object as previously explained.
<br>
<h4>1.3.5. Detection Avoidance</h4>
When an attacker compromises a system, it wants to stay undetected as much time as possible, this means removes every hint of the actions that it performs. Because of that, all the temporary files that are created during the execution of the exploit are removed when they are not needed anymore.
<br>
<h4>1.3.6. Goal</h4>
Finally, we need to determine which process we want to execute with high integrity. In our case we chose the application "cmd.exe" because it allows us to perform as many operations as we want with high integrity, but in fact, we can execute whatever application we want.
<br>
<h2>2. USAGE</h2>
To execute the exploit you must point out the Windows architecture as argument, whether it is "x86" or "x64":<br>
&emsp;- C:\Users\L3cr0f> DccwBypassUAC.exe x64<br>
&emsp;- C:\Users\L3cr0f> DccwBypassUAC.exe x86<br>
<br>

![alt tag](https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/bypass_executed.png)

<h2>Acknowledgements</h2>
To develop the exploit, I have based on those created by:<br>
&emsp;- Fuzzysecurity: https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC.<br>
&emsp;- Cn33liz: https://github.com/Cn33liz/TpmInitUACBypass.<br>
&emsp;- hFireF0X: https://github.com/hfiref0x/UACME.<br>
Many thanks to you!<br></p>
