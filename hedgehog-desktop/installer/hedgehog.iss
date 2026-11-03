; Inno Setup script for Gorse on Windows. Built by the Windows release job:
;   iscc /DAppVersion=0.2.17 /DStageDir=..\..\staging-app hedgehog-desktop\installer\hedgehog.iss
; Installs the window app and the checker it runs side by side, adds a Start
; menu entry and an uninstaller. Per-user by default, so no administrator
; prompt; an administrator may choose an all-users install.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef StageDir
  #define StageDir "..\..\staging-app"
#endif

[Setup]
AppId={{7B1C7A8E-3E1B-4C8C-9D1C-0A5E7E9C0001}
AppName=Gorse
AppVersion={#AppVersion}
AppVerName=Gorse {#AppVersion}
AppPublisher=QKey Co.
AppPublisherURL=https://www.gorse.is
AppSupportURL=https://www.gorse.is/support
AppUpdatesURL=https://www.gorse.is/download
DefaultDirName={autopf}\Gorse
DefaultGroupName=Gorse
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=.
OutputBaseFilename=Gorse-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=Gorse
UninstallDisplayIcon={app}\Gorse.exe
MinVersion=10.0
; Shows the EULA with an accept/decline page before anything is installed.
LicenseFile={#StageDir}\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#StageDir}\Gorse.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\gorse-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\LICENSE-THIRD-PARTY"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\SHA256SUMS"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Gorse"; Filename: "{app}\Gorse.exe"
Name: "{group}\Uninstall Gorse"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Gorse"; Filename: "{app}\Gorse.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Gorse.exe"; Description: "Open Gorse now"; Flags: nowait postinstall skipifsilent
