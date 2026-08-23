; Inno Setup script for the nettool installer.
;
; Build it with:  iscc gui\windows\nettool.iss
; or, for the whole pipeline (GUI, CLI, icon, installer):
;                 pwsh gui\windows\build-installer.ps1
;
; The installer carries the GUI, the Python CLI it drives, and a shortcut that
; asks for elevation. It does NOT carry Npcap: that is a signed kernel driver
; with its own licence, and bundling someone else's driver in an unsigned
; installer is not a favour to anyone. The installer offers to open npcap.com
; instead, and everything that does not capture works without it.

#define AppName "nettool"
#define AppPublisher "nettool"
#define AppURL "https://github.com/aaronsiegel185-dev/networktool"
#define AppExeName "nettool-gui.exe"
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{7C3F5B21-9E44-4A6D-9E2E-5B7C1D0A3F18}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
OutputDir=..\..\dist
OutputBaseFilename=nettool-{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Per-machine, because capture needs elevation anyway and a per-user install
; would only postpone the prompt.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
; The repository declares MIT (gui/Cargo.toml) but carries no LICENSE file yet.
; Show it when it exists rather than failing the build over it.
#if FileExists(AddBackslash(SourcePath) + "..\..\LICENSE")
  LicenseFile=..\..\LICENSE
#endif
SetupIconFile=nettool.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "addtopath"; Description: "Add nettool to &PATH (for the command line)"; GroupDescription: "Command line:"

[Files]
Source: "..\target\release\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; The CLI the GUI shells out to, shipped whole so a system Python is optional.
Source: "..\..\dist\cli\nettool.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
; Source form, used when nettool.exe was not built and a system Python is present.
Source: "..\..\nettool\*"; DestDir: "{app}\nettool"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,*.pyc"
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{#AppName} (as Administrator)"; Filename: "{app}\{#AppExeName}"; Comment: "Needed for packet capture"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Check: NeedsAddPath(ExpandConstant('{app}')); Tasks: addtopath

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Start {#AppName}"; Flags: nowait postinstall skipifsilent
Filename: "https://npcap.com"; Description: "Get Npcap (needed for packet capture)"; \
    Flags: nowait postinstall skipifsilent shellexec unchecked; Check: not NpcapInstalled

[Code]
function NpcapInstalled: Boolean;
begin
  { Npcap installs its DLL beside the driver rather than in System32, so this is
    the file that actually decides whether capture will work. }
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'))
         or FileExists(ExpandConstant('{sys}\wpcap.dll'));
end;

function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKLM,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and (not NpcapInstalled) then
    MsgBox('nettool is installed.' #13#13
         + 'Packet capture (Capture, Mirror / VLAN, LLDP / CDP) also needs the '
         + 'Npcap driver, which is not bundled. Install it from https://npcap.com '
         + 'with "WinPcap API-compatible mode" ticked.' #13#13
         + 'Everything else - interfaces, routes, Wi-Fi, ping, traceroute, port '
         + 'scan - works without it.',
      mbInformation, MB_OK);
end;
