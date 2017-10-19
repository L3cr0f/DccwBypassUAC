<h1>DccwBypassUAC</h1>
<p align="justify">This exploit abuses the way "WinSxS" is managed by "dccw.exe" by means of a derivative Leo's Davidson "Bypass UAC" method so as to obtain an administrator shell without prompting for consent. It supports "x86" and "x64" architectures. Moreover, it has been successfully tested on Windows 8.1 9600, Windows 10 14393, Windows 10 15031 and Windows 10 15062.

If you want to see how to execute the script, take a look at the <a href="https://github.com/L3cr0f/DccwBypassUAC#3-usage">usage</a> section. Also, you can execute it in <a href="https://github.com/L3cr0f/DccwBypassUAC#4-metasploit-module">Metasploit</a> and getting a Meterpreter session with administrator rights.</p>

<h2>1. Development of a New Bypass UAC</h2>
<h3>1.1. Vulnerability Search</h3>
<p align="justify">To develop a new bypass UAC, first we have to find a vulnerability on the system and, to be more precise, a vulnerability in an auto-elevate process. To get a list of such processes we used the <i>Sysinternals'</i> tool called <i>Strings</i>. After that, we could see some auto-elevate processes like "sysprep.exe", "cliconfig.exe", "inetmgr.exe", "consent.exe" or "CompMgmtLauncher.exe" that had (some of them still have) vulnerabilities that allow the execution of a "bypass UAC". So, we started to study how other auto-elevate processes worked with the <i>Sysinternals'</i> application called <i>Process Monitor</i> (<i>ProcMon</i>), but focusing on "dccw.exe" process.</p>

<img src="https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/AutoElevate_Processes.png">

<p align="justify">However, before starting with <i>ProcMon</i>, first we checked the manifest of such applications with another <i>Sysinternals'</i> application called <i>Sigcheck</i>, and, of course, in our case "dccw.exe" is an auto-elevate process.</p>

<p align="center">
<img src="https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/autoElevation_confirmed.png">
</p>

<p align="justify">Then, we could start to follow the execution flow of "dccw.exe" with <i>ProcMon</i> to see fn something strange occurs, something we checked immediately. At some point, if we have executed "dccw.exe" as a 64 bits process in a 64 bits Windows machine it looks for the directory "C:\Windows\System32\dccw.exe.Local\" to load a specific DLL called "GdiPlus.dll", the same as it were executed in a 32 bits Windows machine, whereas if we execute it as a 32 bits in the same machine, the process will look for the directory "C:\Windows\SysWOW64\dccw.exe.Local\". Then, due to the fact that it does not exist, the process always looks for a folder in the path "C:\Windows\WinSxS\" to get the desired DLL, this folder has a name with the following structure:</p>
[architecture]_microsoft.windows.gdiplus_[sequencial_code]_[Windows_version]_none_[sequencial_number]<br>
<br>

<img src="https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/dccw_dotLocal_notFound.png">


<p align="justify">If we take a look into "WinSxS" directory, we could see more than one folder that matches with this structure, this means that "dccw.exe" can load the desired DLL from any of these folders. The only thing we are sure is that if the application is invoked as a x86 process, the folder name will start with the string "x86", while if we execute it as a x64 process, its name will start with the string "amd64".</p>

<img src="https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/gdiplus_folders.png">

<p align="justify">This situation can be abused to perform a DLL hijacking and then execute code with high integrity without prompting for consent.</p>

<h3>1.2. Vulnerability Verification</h3>
<p align="justify">Once we have found one error during the execution of an auto-elevate process, we need to verify whether it can be abused or not. To do this, we just created the folder "dccw.exe.Local" in the desired path and, into that folder, we created the folders located in "WinSxS" that could be invoked by the process to load "GdiPlus.dll", but without such DLL.</p>
<p align="justify">Now, if we execute "dccw.exe" we will see that the process has found the folder "dccw.exe.Local" and one of the "WinSxS" folders, but not the desired DLL, something that throws an error. This is what we expected, due to that situation can be exploited by an attacker as we mentioned before.</p>

<img src="https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/dccw_vuln_checking.png">

<h3>1.3. Exploit Development</h3>
<p align="justify">At this point, we already know that we can perform a bypass UAC on Windows 10 abusing "dccw.exe", but how?</p>

<h4>1.3.1. Method</h4>
<p align="justify">The most used method to bypass UAC is that one developed by <a href="https://www.pretentiousname.com/misc/win7_uac_whitelist2.html" target="_blank">Leo Davidson</a>. However, it performs a process injection to invoke the <i>IFileOperation</i> COM object, which can be detected by some antivirus software, so a better approach to use it is that one called <a href="https://www.fuzzysecurity.com/tutorials/27.html" target="_blank">Masquerade PEB</a> used by <i>Cn33liz</i> in its own bypass UAC.</p>
<p align="justify">Also, we have to modify the way <i>IFileOperation</i> is invoked in newer Windows 10 versions, since Leo Davidson method triggers UAC from build 15002. So, the way we have to invoke such operation is the same as the original, but without the operation flags "FOF_SILENT", "FOFX_SHOWELEVATIONPROMPT" and "FOF_NOERRORUI".</p>

<h4>1.3.2.Initial Checks</h4>
<p align="justify">Before executing the exploit, it is important to check some aspects to not execute it unsuccessfully and therefore trigger some alarms. The first thing we check is the Windows build version, since some versions are not vulnerable to our exploit (those with a build version lower than 7600). After that, we verify that we do not have administrator rights yet, if it is not the case, there is no reason to execute the script. Then, we check the UAC settings so as to confirm that it is not set to "Always notify", since if it were set to that value, our exploit would be useless. Finally, we verify if the user belongs to the administrators group, because, if not, the exploit would be unsuccessful.</p>

<h4>1.3.3. Interoperability</h4>
<p align="justify">When an exploit is developed is important that can work in as many systems as possible, this includes 32 bits Windows systems. To achieve this, we need to compile our exploit for such systems, since we can also execute it in 64 bits systems.</p>
<p align="justify">When our 32 bits exploit is executed in a 64 bits Windows machine, the way "dccw.exe" operates is a bit different due to the invocation of WOW64 (Windows subsystem that allows 64 bits machines to run 32 bits applications). This means the folder "dccw.exe.Local" will be looked for in "C:\Windows\SysWOW64\" directory, instead of "C:\Windows\System32\", but also the targeted "GdiPlus.dll" will be a 32 bits DLL, which implies that it will be looked for in a folder that matches with that name pattern "C:\Windows\WinSxS\x86_microsoft.windows.gdiplus_*". However, if it is executed in a 32 bits Windows system, the exploit will work as expected.</p>
<p align="justify">Finally, it is important to remark that we need to consider all the paths that matches with the pattern "C:\Windows\WinSxS\x86_microsoft.windows.gdiplus_*" when the DLL hijack is performed in order to assure a 100% of effectiveness.</p>

<h4>1.3.4. Malicious DLL</h4>
<p align="justify">To execute a process with high integrity we need to develop a DLL that will be invoked via DLL hijacking. However, it is not as simple as it looks, because if we only do that, neither "dccw.exe" nor our code will be executed. This is because "dccw.exe" depends on some functions of "GdiPlus.dll", so we need to implement or forward the execution of such functions to the legit DLL.</p>
<p align="justify">The best option is forwarding the execution to the legit DLL, because in this way the size of our DLL will be lower. To do so, we used the program <i>ExportsToC++</i> to port all exports of "GdiPlus.dll" to C++ language. Now, the problem is the huge number of exports "GdiPlus.dll" have, 631 to be precise, Nevertheless, "dccw.exe" does not import all of them, but a few. To know which functions are imported by "dccw.exe" from "GdiPlus.dll" we reversed engineering it with "IDA Pro". Finally, only 15 functions are imported from "GdiPlus.dll", so we only need to include those in our DLL.</p>

<p align="center">
<img src="https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/dccw_GdiPlus.png">
</p>

<p align="justify">Now, it seems that the problem has been fixed, but if we forward the execution to a specific "GdiPlus.dll" in C:\Windows\WinSxS\", the DLL will work only in some systems, since the name of the internal folders of "WinSxS" changes every Windows build. To overcome this problem, we came up with the idea of forwarding the execution to "C:\Windows\System32\GdiPlus.dll", due to the fact that the path is the same in all Windows 10 systems</p>
<p align="justify">The last thing we have to do is stopping the execution of "dccw.exe" after executing our malicious code so as to avoid the window opening of that process.</p>
<p align="justify">Now, once we have developed our malicious DLL, we need to drop it in the targeted machine. To do so, our DLL has been compressed and "base64" encoded into the exploit, so that can be decoded and decompressed at runtime to drop it as expected.</p>
<p align="justify">Finally, our crafted "GdiPlus.dll" is copied to the targeted location using <i>IFileOperation</i> COM object as previously mentioned.</p>

<h4>1.3.5. Detection Avoidance</h4>
<p align="justify">When an attacker compromises a system, it wants to stay undetected as much time as possible, this means removing every trace of the actions that it performs. Because of that, all the temporary files that are created during the execution of the exploit are removed when they are not needed anymore.</p>

<h4>1.3.6. Goal</h4>
<p align="justify">Finally, we need to determine which process we want to execute at high integrity. In our case, we chose the application "cmd.exe" because it allows us to perform as many operations at high integrity as we want once we will have administrator rights, but, in fact, we can execute whatever application we want.</p>

<h2>2. Requirements</h2>
To get a successfully execution of the exploit the targeted machine must comply the following requirements:<br>
&emsp;- It must be a Windows 8 or 10, no matter what build version.<br>
&emsp;- The UAC settings must not be set to "Always notify".<br>
&emsp;- The compromised user must belong to the "Administrators group".<br>

<h2>3. Usage</h2>
<p align="justify">To execute the exploit you must be sure that the targeted machine meets the <a href="https://github.com/L3cr0f/DccwBypassUAC#2-requirements">requirements</a>. Then, you simply have to execute the exploit like any other command-line script:</p>
&emsp;- C:\Users\L3cr0f> DccwBypassUAC.exe
<br>
<br>
<p align="center">
<img src="https://github.com/L3cr0f/DccwBypassUAC/blob/release/Pictures/DccwBypassUAC_PoC.gif">
</p>

<h2>4. Metasploit Module</h2>
<p align="justify">The Metasploit module of this PoC use DLL injection instead of Masquerading PEB and it is available in:</p>
&emsp;- Metasploit Framework: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/bypassuac_injection_winsxs.rb<br>
&emsp;- L3cr0f's Metasploit modules repository: https://github.com/L3cr0f/Metasploit-modules#bypassuac_injection_winsxs<br>

<h2>5. Disclaimer</h2>
<p align="justify">This exploit has been developed to show how an attacker could gain privileges into a system, not to use it for malicious purposes. This means that I do not take any responsibility if someone uses it to perform criminal activities.</p>

<h2>6. Microsoft Position</h2>
<p align="justify"><b>User Access Control (UAC)</b> is a technology introduced with Windows Vista that provides a method of separating standard user privileges and tasks from those that require Administrator access. If a Standard User is using the system and attempts to perform an action for which the user has no authorization, a prompt from Windows appears and asks the Administrator account’s password. If an Administrator is using the system and attempts to do the same task, there is only a warning prompt. That prompt is known as a "Consent Prompt" because the administrator is only asked to agree to the action before proceeding. <b>A weakness that would allow to bypass the "Consent Prompt" is not considered a security vulnerability, since that is not considered a security boundary</b>.<p>

<p align="justify">However, Microsoft also states that "<b>User Account Control (UAC) is a fundamental component of Microsoft's overall security vision</b>".</p>

<p align="justify">Sources:<br>
&emsp;- <a href="https://msdn.microsoft.com/en-us/library/cc751383.aspx">Definition of a security vulnerability</a>.<br>
&emsp;- <a href="https://docs.microsoft.com/en-us/windows/access-protection/user-account-control/how-user-account-control-works">How User Account Control works</a>.</p>

<h2>7. Acknowledgements</h2>
To develop the exploit, I have based on those created by:<br>
&emsp;- Fuzzysecurity: https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC.<br>
&emsp;- Cn33liz: https://github.com/Cn33liz/TpmInitUACBypass.<br>
&emsp;- hFireF0X: https://github.com/hfiref0x/UACME.<br>
Many thanks to you!