# Startup Folder Persistence Lab (MITRE ATT&CK T1547.001)

## Objective
Learn how attackers establish persistence by placing a program or shortcut inside the Windows Startup folder so that it automatically executes whenever a user logs on.

## MITRE ATT&CK
- Tactic: Persistence
- Technique: T1547.001 - Registry Run Keys / Startup Folder

## Lab Environment
- Windows 10
- Sysmon
- Splunk

## Attack Simulation

Command:

```cmd
copy C:\Windows\System32\notepad.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\notepad.exe"
```

## What the Command Does
- Copies notepad.exe into the Startup folder.
- Windows automatically executes items in this folder after the user logs on.
- Notepad will launch every time the user signs in.

## Verification

Open the Startup folder:

```cmd
explorer "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
```

## Detection

Monitor process creation and file creation events.

Example Splunk queries:

```spl
index=* "Programs\\Startup"
```

```spl
index=* EventCode=11 TargetFilename="*\\Programs\\Startup\\*"
```

## Investigation Questions
- Who created the file in the Startup folder?
- Which process copied the file?
- What executable was placed there?
- Is the file legitimate or suspicious?
- Was the file recently created?

## Indicators of Suspicious Activity
- Executables copied into the Startup folder
- Scripts (.bat, .vbs, .ps1) placed in Startup
- Files created from cmd.exe or powershell.exe
- Unusual executables launched after user logon

## Defensive Recommendations
- Monitor Startup folder modifications.
- Alert on executable creation in Startup locations.
- Investigate newly added files in Startup folders.
- Restrict unnecessary write access to startup locations.

## Skills Demonstrated
- Windows Persistence
- Startup Folder Analysis
- Splunk Threat Hunting
- MITRE ATT&CK Mapping
- SOC Investigation
