; bruhswer Windows installer  -  Inno Setup 6
;
; Built with:  ISCC.exe installer\bruhswer.iss
;
; DESIGN RULES, taken from the hardening brief and not negotiable:
;
;   * No Administrator. PrivilegesRequired=lowest and the install goes under the
;     user's own %LOCALAPPDATA%. Nothing this installer does needs elevation, so it
;     does not ask for it. An installer that requests admin "just in case" trains
;     users to grant it, which is the opposite of what a security tool should teach.
;   * No service, no scheduled task, no background updater, no localhost listener,
;     no Run key, no startup entry. The only persistence is the shortcuts the user
;     asked for.
;   * Nothing unrelated is installed or changed. No QEMU, no WSL, no Hyper-V, no
;     drivers, no redistributables. Defender, SmartScreen, the firewall and every
;     other Windows setting are left exactly as they were.
;   * bruhswer's firewall rules are NOT applied here. They need Administrator and an
;     explicit, reversible decision by the user, so they stay in the separate
;     elevated one-shot where the user can read what it does first.
;   * The uninstaller is conservative. It removes what this installer wrote, and
;     asks - separately and explicitly - before touching browsing data the user
;     created.
;
; PYTHON IS A PREREQUISITE, DELIBERATELY.
; bruhswer is not frozen into a standalone .exe. Freezing would bundle a second
; Python interpreter and a packaging toolchain into the trusted stack of a tool whose
; whole argument is that it adds no new trust roots, and it would make the shipped
; artefact far harder to audit against the source. Instead the installer VALIDATES
; that a suitable Python and Microsoft Edge are present and refuses, with a clear
; explanation, if they are not.

#define AppName        "bruhswer"
#define AppVersion     "0.11.0"
; Shown as the Publisher in Windows "Installed apps". Note this is NOT a code-signing
; identity and must not be read as one: the release is unsigned, and a publisher
; string in an installer is just a label anyone can type.
;
; v0.9.0 shipped with "The bruhswer authors" here. That published binary is left
; exactly as it is - its SHA-256 is published and re-uploading a different file under
; the same tag would silently invalidate a checksum someone may already have recorded.
; This name takes effect from the next release.
#define AppPublisher   "Bhargavaram Krishnapur"
#define AppURL         "https://github.com/Codex-Crusader/bruhswer-the-homebrew-pseudo-browser"
#define AppExeName     "bruhswer.py"
#define MinPython      "3.11"

[Setup]
AppId={{7B4B2F3E-9C1D-4E6A-8F2B-BRUHSWER0001}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/blob/main/SECURITY.md
AppUpdatesURL={#AppURL}/releases
VersionInfoVersion=0.9.2.0
VersionInfoDescription=bruhswer - browse the internet, trust absolutely nothing

; Per-user install. No elevation prompt, no shared install location.
; NO PrivilegesRequiredOverridesAllowed. It was set to `dialog`, which offers the
; user an elevated install mode - directly contradicting this installer's own claim
; that it never asks for Administrator. An installer that says it does not elevate
; must not carry a switch that lets it elevate.
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
AllowNoIcons=yes

OutputDir=Output
OutputBaseFilename=bruhswer-{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible

LicenseFile=..\LICENSE
InfoBeforeFile=BEFORE-YOU-INSTALL.txt

; Uninstall entry
UninstallDisplayName={#AppName} {#AppVersion}
UninstallFilesDir={app}\uninstall

; The release is UNSIGNED. Stated here as well as in the release notes, because a
; SmartScreen warning with no explanation is how users learn to click through
; SmartScreen warnings.
;SignTool=

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &Desktop shortcut"; \
    GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "startmenuicon"; Description: "Create a &Start Menu shortcut"; \
    GroupDescription: "Shortcuts:"

[Files]
; The application itself.
Source: "..\bruhswer\bruhswer.py";  DestDir: "{app}\bruhswer"; Flags: ignoreversion
Source: "..\bruhswer\app\*";        DestDir: "{app}\bruhswer\app"; \
    Flags: ignoreversion recursesubdirs createallsubdirs; \
    Excludes: "__pycache__\*,*.pyc"

; The elevated one-shots. REQUIRED at runtime: bruhswer's own uninstall and Host
; Guard flows print these exact relative paths for the user to run, so shipping the
; app without them would leave those instructions pointing at nothing.
Source: "..\bruhswer\tools\bruhswer-netpolicy.ps1";        DestDir: "{app}\bruhswer\tools"; Flags: ignoreversion
Source: "..\bruhswer\tools\bruhswer-hostguard.ps1";        DestDir: "{app}\bruhswer\tools"; Flags: ignoreversion
Source: "..\bruhswer\tools\bruhswer-cleanup-rejected.ps1"; DestDir: "{app}\bruhswer\tools"; Flags: ignoreversion

; Documentation. Small, and it means the security model travels with the install
; rather than living only on a web page the user may never open.
Source: "..\LICENSE";     DestDir: "{app}"; Flags: ignoreversion
Source: "..\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";   DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\*.md";   DestDir: "{app}\docs"; Flags: ignoreversion

; NOT PACKAGED, deliberately: tests\, the maintenance tools in bruhswer\tools\*.py,
; the historical research spikes in the top-level tools\, .venv\, .idea\, any browser
; profile, any quarantine content, and any log. None of it belongs on an end user's
; machine, and some of it would be actively wrong to ship.

[Icons]
Name: "{group}\{#AppName}"; Filename: "{code:GetPythonW}"; \
    Parameters: """{app}\bruhswer\{#AppExeName}"""; \
    WorkingDir: "{app}\bruhswer"; Comment: "Browse the internet. Trust absolutely nothing."; \
    Tasks: startmenuicon
Name: "{group}\{#AppName} security check"; Filename: "{code:GetPythonConsole}"; \
    Parameters: """{app}\bruhswer\{#AppExeName}"" --check"; \
    WorkingDir: "{app}\bruhswer"; Comment: "Run every verification and print the result"; \
    Tasks: startmenuicon
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"; Tasks: startmenuicon
Name: "{autodesktop}\{#AppName}"; Filename: "{code:GetPythonW}"; \
    Parameters: """{app}\bruhswer\{#AppExeName}"""; \
    WorkingDir: "{app}\bruhswer"; Comment: "Browse the internet. Trust absolutely nothing."; \
    Tasks: desktopicon

[Run]
Filename: "{code:GetPythonW}"; Parameters: """{app}\bruhswer\{#AppExeName}"""; \
    WorkingDir: "{app}\bruhswer"; \
    Description: "Launch {#AppName} now"; \
    Flags: nowait postinstall skipifsilent

; NO [UninstallDelete] SECTION, deliberately.
;
; It was tried and it was wrong. Python writes a __pycache__ directory next to EVERY
; package it imports, so running bruhswer once creates ten of them - one per
; subpackage. A static list named two, and a real uninstall test found twenty-one
; .pyc files and ten directories left behind on the user's disk.
;
; Listing each subpackage would work until someone adds the eleventh, and then break
; silently. The recursive sweep in RemovePycacheDirs below removes directories named
; exactly __pycache__ under the install folder and nothing else, so it stays correct
; as the package layout changes while still refusing to wipe {app} wholesale.

[Code]

{ Inno has no built-in "read this path's attributes" helper, so the Win32 call is
  imported directly. It is needed to tell a real directory from a junction, which is
  what stops the uninstaller following a reparse point out of its own install tree. }
function GetFileAttributesW(lpFileName: String): DWord;
  external 'GetFileAttributesW@kernel32.dll stdcall';

const
  INVALID_FILE_ATTRIBUTES = $FFFFFFFF;

var
  CachedPythonW: String;
  CachedPythonC: String;

{ ---------------------------------------------------------------- Python discovery }

function TryPath(const Path: String; var Found: String): Boolean;
begin
  Result := FileExists(Path);
  if Result then
    Found := Path;
end;

{ Locate an interpreter. The py launcher is preferred: it is the documented,
  version-independent entry point and survives a Python upgrade, whereas a direct
  pythonw.exe path breaks the shortcuts the moment the user moves to a new minor
  version. }
function FindPython(const Windowed: Boolean): String;
var
  Exe, WinDir, Found: String;
begin
  Found := '';
  if Windowed then Exe := 'pyw.exe' else Exe := 'py.exe';

  WinDir := ExpandConstant('{win}');
  if TryPath(WinDir + '\' + Exe, Found) then
  begin
    Result := Found;
    exit;
  end;
  if TryPath(ExpandConstant('{localappdata}') +
             '\Programs\Python\Launcher\' + Exe, Found) then
  begin
    Result := Found;
    exit;
  end;

  { Fall back to a direct interpreter path from the registry. }
  if Windowed then Exe := 'pythonw.exe' else Exe := 'python.exe';
  if RegQueryStringValue(HKEY_CURRENT_USER,
       'SOFTWARE\Python\PythonCore\3.13\InstallPath', '', Found) and
     TryPath(Found + Exe, Found) then begin Result := Found; exit; end;
  if RegQueryStringValue(HKEY_CURRENT_USER,
       'SOFTWARE\Python\PythonCore\3.12\InstallPath', '', Found) and
     TryPath(Found + Exe, Found) then begin Result := Found; exit; end;
  if RegQueryStringValue(HKEY_CURRENT_USER,
       'SOFTWARE\Python\PythonCore\3.11\InstallPath', '', Found) and
     TryPath(Found + Exe, Found) then begin Result := Found; exit; end;
  if RegQueryStringValue(HKEY_LOCAL_MACHINE,
       'SOFTWARE\Python\PythonCore\3.13\InstallPath', '', Found) and
     TryPath(Found + Exe, Found) then begin Result := Found; exit; end;
  if RegQueryStringValue(HKEY_LOCAL_MACHINE,
       'SOFTWARE\Python\PythonCore\3.12\InstallPath', '', Found) and
     TryPath(Found + Exe, Found) then begin Result := Found; exit; end;
  if RegQueryStringValue(HKEY_LOCAL_MACHINE,
       'SOFTWARE\Python\PythonCore\3.11\InstallPath', '', Found) and
     TryPath(Found + Exe, Found) then begin Result := Found; exit; end;

  Result := '';
end;

function GetPythonW(Param: String): String;
begin
  if CachedPythonW = '' then
    CachedPythonW := FindPython(True);
  Result := CachedPythonW;
end;

function GetPythonConsole(Param: String): String;
begin
  if CachedPythonC = '' then
    CachedPythonC := FindPython(False);
  Result := CachedPythonC;
end;

{ ------------------------------------------------------------ prerequisite checks }

function EdgeInstalled(): Boolean;
begin
  Result := FileExists('C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
         or FileExists('C:\Program Files\Microsoft\Edge\Application\msedge.exe');
end;

{ Refuse rather than install something that cannot run. An installer that succeeds
  and leaves a shortcut which does nothing is a worse experience than a clear refusal
  at the start, and it is the same fail-closed rule bruhswer itself follows. }
{ ASK THE INTERPRETER ITS VERSION. Finding pyw.exe proves a launcher exists, not
  that it will select a Python new enough to run bruhswer - the py launcher's default
  could be 3.9, and the app uses 3.11+ syntax. The previous version of this check
  only tested for existence and would have installed a shortcut that failed with a
  SyntaxError the first time it was clicked, which is precisely the "succeeds and
  leaves something that does not work" outcome this installer is supposed to avoid. }
function PythonVersionIsSupported(): Boolean;
var
  Console, Params: String;
  ResultCode: Integer;
begin
  Console := FindPython(False);
  if Console = '' then
  begin
    Result := False;
    exit;
  end;
  Params := '-c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"';
  if not Exec(Console, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    { Could not run it at all. Treat as unsupported rather than assuming the best. }
    Result := False;
    exit;
  end;
  Result := (ResultCode = 0);
end;

function InitializeSetup(): Boolean;
begin
  Result := True;

  if (FindPython(True) <> '') and (not PythonVersionIsSupported()) then
  begin
    MsgBox('A Python installation was found, but it is older than '
           + '{#MinPython} or could not be run.'
           + #13#10#13#10
           + 'bruhswer uses language features from Python {#MinPython}, so an older '
           + 'interpreter would fail the moment you launched it.'
           + #13#10#13#10
           + 'Install Python {#MinPython} or newer from python.org and run this '
           + 'installer again.',
           mbCriticalError, MB_OK);
    Result := False;
    exit;
  end;

  if FindPython(True) = '' then
  begin
    MsgBox('bruhswer needs Python ' + '{#MinPython}' + ' or newer, and none was found.'
           + #13#10#13#10
           + 'Install Python from python.org (tick "Add python.exe to PATH" and keep '
           + 'the py launcher), then run this installer again.'
           + #13#10#13#10
           + 'bruhswer is not bundled with its own Python on purpose: shipping a '
           + 'second interpreter would add a component you cannot easily audit to a '
           + 'tool whose main claim is that it adds no new trust roots.',
           mbCriticalError, MB_OK);
    Result := False;
    exit;
  end;

  if not EdgeInstalled() then
  begin
    MsgBox('bruhswer needs Microsoft Edge, and it was not found in either of the '
           + 'standard locations.'
           + #13#10#13#10
           + 'bruhswer does not implement a browser. It runs Edge, because Edge is '
           + 'in-box, Microsoft-signed, and its renderers run in an AppContainer on '
           + 'this platform. Without it there is nothing to protect.',
           mbCriticalError, MB_OK);
    Result := False;
    exit;
  end;
end;

{ ------------------------------------------------------------------- uninstall }

{ Remove Python bytecode caches created by RUNNING the app, which the installer
  itself never wrote and therefore does not know about.

  Scoped as tightly as it can be: it only ever deletes a directory whose name is
  exactly __pycache__, and only beneath the install folder. Anything else the user
  put in the install folder is left completely alone.

  NOTE: no Inno constant in braces may appear inside a Pascal comment - the closing
  brace of the constant ends the comment early and the rest becomes code. }
procedure RemovePycacheDirs(const Dir: String);
var
  FR: TFindRec;
  Child: String;
begin
  if not FindFirst(Dir + '\*', FR) then
    exit;
  try
    repeat
      if ((FR.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0)
         and (FR.Name <> '.') and (FR.Name <> '..') then
      begin
        { REPARSE POINTS ARE SKIPPED ENTIRELY, and this is the load-bearing line.
          A junction or directory symlink looks exactly like a directory to
          FindFirst. Without this test, a junction planted under the install folder
          - which anything running as the user can create - would make both the
          recursion and the DelTree below act on its TARGET instead, somewhere
          outside the install tree. That would turn the uninstaller into a
          delete-anything primitive, and would make this procedure's own comment
          about staying "beneath the install folder" false. Skipping the link means
          the link itself is left for Inno to remove, and nothing is followed. }
        if (FR.Attributes and FILE_ATTRIBUTE_REPARSE_POINT) = 0 then
        begin
          Child := Dir + '\' + FR.Name;
          if FR.Name = '__pycache__' then
            DelTree(Child, True, True, True)
          else
            RemovePycacheDirs(Child);
        end;
      end;
    until not FindNext(FR);
  finally
    FindClose(FR);
  end;
end;

{ Delete one of bruhswer's own data folders, refusing if it is a reparse point.

  Same reasoning as above: DelTree on a junction would follow it out of the data
  directory. These paths are bruhswer's own constants, so a reparse point at one of
  them is not a normal state - it is either a deliberate redirection or damage, and
  in both cases refusing is the correct answer. }
procedure DeleteDataFolder(const Path: String);
var
  Attribs: DWord;
begin
  if not DirExists(Path) then
    exit;
  Attribs := GetFileAttributesW(Path);
  if Attribs = INVALID_FILE_ATTRIBUTES then
    exit;
  if (Attribs and FILE_ATTRIBUTE_REPARSE_POINT) <> 0 then
    exit;
  DelTree(Path, True, True, True);
end;

{ The user's browsing data is NOT removed silently. It is a separate, explicit
  question that defaults to keeping the data, and it says exactly what would go. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  { Sweep the bytecode caches BEFORE Inno removes its own files. Doing it first means
    the directories are empty by the time Inno prunes them, so the install folder is
    left genuinely gone rather than as an empty skeleton. }
  if CurUninstallStep = usUninstall then
  begin
    RemovePycacheDirs(ExpandConstant('{app}'));
    exit;
  end;

  if CurUninstallStep <> usPostUninstall then
    exit;

  DataDir := ExpandConstant('{localappdata}') + '\BRUHWSER';
  if not DirExists(DataDir) then
    exit;

  { A SILENT UNINSTALL NEVER DELETES BROWSING DATA.

    /SUPPRESSMSGBOXES answers this MsgBox with YES, and MB_DEFBUTTON2 does not change
    that - it sets the default focused button for a HUMAN, not the suppressed reply.
    So a silent uninstall destroyed a persistent profile and everything still in
    quarantine, having asked nobody. It did exactly that during 0.11.0's install
    verification, to a real 110 MB profile.

    Silent means nobody was asked. "Nobody was asked" must not resolve to "yes, delete
    it" for the one action here that cannot be undone. An interactive uninstall still
    offers the choice, which is where a choice belongs. }
  if UninstallSilent then
  begin
    Log('Silent uninstall: browsing data kept at ' + DataDir);
    exit;
  end;

  if MsgBox('bruhswer has been removed.'
            + #13#10#13#10
            + 'Its browsing data is still on this PC:'
            + #13#10 + '    ' + DataDir
            + #13#10#13#10
            + 'That folder holds your persistent browser profile, anything still in '
            + 'quarantine, and bruhswer''s own logs.'
            + #13#10#13#10
            + 'Delete it as well?'
            + #13#10#13#10
            + 'Choose No to keep it. Quarantined downloads you have not exported '
            + 'would be destroyed.',
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
  begin
    DeleteDataFolder(DataDir + '\profiles');
    DeleteDataFolder(DataDir + '\quarantine');
    DeleteDataFolder(DataDir + '\logs');

    { The Host Guard rollback record is KEPT even here. If Host Guard changed this
      PC's firewall profile or SMB settings, that file is the only record of what the
      settings were before. Deleting it would strand the change permanently. }
    if DirExists(DataDir + '\state') then
      MsgBox('Browsing data deleted.'
             + #13#10#13#10
             + 'One thing was deliberately kept:'
             + #13#10 + '    ' + DataDir + '\state'
             + #13#10#13#10
             + 'It holds the record of any change Host Guard made to this PC''s '
             + 'firewall or SMB settings, and it is the only way to undo them. '
             + 'Run this before deleting it:'
             + #13#10#13#10
             + '    bruhswer-hostguard.ps1 -Action revert',
             mbInformation, MB_OK);
  end;
end;

{ bruhswer's firewall rules outlive the application on purpose, so the user is told
  they are there. Removing them needs Administrator, and this uninstaller does not
  have it and does not ask for it. }
function InitializeUninstall(): Boolean;
begin
  Result := True;
  MsgBox('Before removing bruhswer:'
         + #13#10#13#10
         + 'If you applied bruhswer''s network policy, two Windows Firewall rules '
         + 'named BRUHWSER-edge-* are still in place. They stop Microsoft Edge '
         + 'reaching your router and other devices on your network.'
         + #13#10#13#10
         + 'THEY WILL SURVIVE THIS UNINSTALL. Leaving them behind means Edge stays '
         + 'blocked with nothing left on the PC to explain why.'
         + #13#10#13#10
         + 'Remove them first, from an Administrator PowerShell:'
         + #13#10#13#10
         + '    bruhswer-netpolicy.ps1 -Action remove'
         + #13#10#13#10
         + 'This uninstaller will not change your firewall itself - that needs '
         + 'Administrator, and it is not going to ask you for it.',
         mbInformation, MB_OK);
end;
