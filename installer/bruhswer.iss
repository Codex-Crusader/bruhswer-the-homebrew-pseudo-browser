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
#define AppVersion     "0.12.1"
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
; Must track AppVersion. This was hardcoded and left at 0.9.2.0 through three
; releases - Explorer's own Properties > Details tab would have shown a build two
; versions behind the one actually installed.
VersionInfoVersion={#AppVersion}.0
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
function CleanupKitPath(): String;
begin
  Result := ExpandConstant('{localappdata}') + '\BRUHWSER\cleanup';
end;

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
             + 'firewall or SMB settings, and it is the only way to undo them.'
             + #13#10#13#10
             + 'The script that reads it, and written instructions, are at:'
             + #13#10 + '    ' + CleanupKitPath()
             + #13#10#13#10
             + 'Run this from there, as Administrator, before deleting anything:'
             + #13#10#13#10
             + '    .\bruhswer-hostguard.ps1 -Action revert',
             mbInformation, MB_OK);
  end;
end;

{ --- leaving the machine clean -------------------------------------------------

  bruhswer's firewall rules and any Host Guard change outlive the application. Three
  things were wrong with how that used to be handled, and all three are fixed here.

  1. IT GUESSED. The old warning opened "If you applied bruhswer's network policy",
     which the uninstaller never checked. Every user got the same paragraph whether
     they had rules or not, so the ones who did had no way to tell it applied to them.
     Reading firewall rules needs no Administrator, so it now looks.

  2. IT POINTED AT A FILE IT WAS ABOUT TO DELETE. The instruction was to run
     bruhswer-netpolicy.ps1, which ships under the install folder and is removed with
     everything else. Anyone following that advice AFTER uninstalling found no such
     file, and the same was true of the hostguard revert advice. The scripts are now
     copied somewhere that survives, and the message gives the full path.

  3. IT OFFERED NO WAY OUT. "Open an Administrator PowerShell and type this" is a wall
     for most people, and the cost of not doing it is Edge silently unable to reach the
     LAN forever. The uninstaller now offers to do it, via a normal UAC prompt. It still
     does not elevate itself or act without being asked - the user clicks Yes on a
     dialog Windows draws, which is consent, not a bypass. }

function NetPolicyApplied(): Boolean;
var
  Code: Integer;
begin
  { netsh exits non-zero when no rule matches the name. Read-only, no elevation. }
  Result := Exec(ExpandConstant('{sys}\netsh.exe'),
                 'advfirewall firewall show rule name="BRUHWSER-edge-deny-ipv4-private"',
                 '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

function HostGuardChanged(): Boolean;
begin
  Result := FileExists(ExpandConstant('{localappdata}')
                       + '\BRUHWSER\state\hostguard-rollback.json');
end;

{ Copy the elevated one-shots somewhere the uninstall does not touch, with a written
  guide beside them. Returns the folder, or '' if nothing could be copied. }
function WriteCleanupKit(Guide: String): String;
var
  Dest, Tools: String;
  Copied: Boolean;
begin
  Dest := CleanupKitPath();
  Tools := ExpandConstant('{app}') + '\bruhswer\tools\';
  if not ForceDirectories(Dest) then
  begin
    Result := '';
    exit;
  end;
  Copied := CopyFile(Tools + 'bruhswer-netpolicy.ps1',
                     Dest + '\bruhswer-netpolicy.ps1', False);
  if CopyFile(Tools + 'bruhswer-hostguard.ps1',
              Dest + '\bruhswer-hostguard.ps1', False) then
    Copied := True;
  if not SaveStringToFile(Dest + '\HOW-TO-CLEAN-UP.txt', Guide, False) then
    if not Copied then
    begin
      Result := '';
      exit;
    end;
  Result := Dest;
end;

function CleanupGuide(Net, Host: Boolean): String;
var
  S: String;
begin
  S := 'Removing the changes bruhswer made to this PC' + #13#10
     + '=============================================' + #13#10#13#10
     + 'bruhswer itself has been uninstalled. These changes are system-wide, so they'
     + #13#10 + 'were left in place rather than removed silently. Each one needs'
     + #13#10 + 'Administrator, which is why they are not done for you.' + #13#10#13#10
     + 'Open PowerShell as Administrator, cd to this folder, and run what applies.'
     + #13#10#13#10;
  if Net then
    S := S + '1. FIREWALL RULES  (found on this PC)' + #13#10
       + '   Two rules named BRUHWSER-edge-* stop Microsoft Edge reaching your router'
       + #13#10 + '   and other devices on your network. Edge still reaches the'
       + #13#10 + '   internet. Nothing else is affected - the rules name msedge.exe'
       + #13#10 + '   only. If you leave them, Edge stays blocked on your LAN with'
       + #13#10 + '   nothing left on the PC to explain why.' + #13#10#13#10
       + '       .\bruhswer-netpolicy.ps1 -Action remove' + #13#10#13#10;
  if Host then
    S := S + '2. HOST GUARD CHANGES  (a rollback record was found)' + #13#10
       + '   Host Guard may have turned off File and Printer Sharing on Public'
       + #13#10 + '   networks and required SMB signing. Both make this PC safer, so'
       + #13#10 + '   keeping them is reasonable. Revert only if you want the original'
       + #13#10 + '   settings back.' + #13#10#13#10
       + '       .\bruhswer-hostguard.ps1 -Action revert' + #13#10#13#10
       + '   The record it needs is at:' + #13#10
       + '       ' + ExpandConstant('{localappdata}')
       + '\BRUHWSER\state\hostguard-rollback.json' + #13#10
       + '   Do not delete that file before reverting; it is the only copy of what'
       + #13#10 + '   the settings were before.' + #13#10#13#10;
  S := S + 'When you are done you can delete this folder:' + #13#10
     + '    ' + CleanupKitPath() + #13#10;
  Result := S;
end;

function InitializeUninstall(): Boolean;
var
  Net, Host: Boolean;
  Kit, Script: String;
  Code: Integer;
begin
  Result := True;

  Net := NetPolicyApplied();
  Host := HostGuardChanged();

  { WRITE THE KIT EVEN WHEN SILENT. A silent uninstall must not pop a dialog at an
    automated caller, but saving a file is not a dialog - and a scripted uninstall that
    leaves no instructions behind is the same dangling-advice defect this whole block
    exists to fix, just reached without a human present. Only the interactive offer is
    skipped below. }
  if Net or Host then
    Kit := WriteCleanupKit(CleanupGuide(Net, Host));

  if UninstallSilent then
    exit;

  if not (Net or Host) then
  begin
    { Nothing was found, so say so. The old code delivered a warning about firewall
      rules to people who had none, which is how a warning stops being read. }
    MsgBox('bruhswer made no system-wide changes to remove.'
           + #13#10#13#10
           + 'No BRUHWSER firewall rules are present and no Host Guard rollback '
           + 'record was found, so uninstalling leaves nothing behind.',
           mbInformation, MB_OK);
    exit;
  end;

  if Net then
  begin
    if MsgBox('bruhswer changed your firewall, and that change OUTLIVES this uninstall.'
              + #13#10#13#10
              + 'Two rules named BRUHWSER-edge-* stop Microsoft Edge reaching your '
              + 'router and other devices on your network. Edge still reaches the '
              + 'internet, and no other program is affected.'
              + #13#10#13#10
              + 'Leave them and Edge stays blocked on your local network, with '
              + 'nothing left on this PC to explain why.'
              + #13#10#13#10
              + 'Remove them now?'
              + #13#10#13#10
              + 'Windows will ask for Administrator. bruhswer does not elevate '
              + 'itself; you are approving it.',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON1) = IDYES then
    begin
      Script := ExpandConstant('{app}') + '\bruhswer\tools\bruhswer-netpolicy.ps1';
      if ShellExec('runas', 'powershell.exe',
                   '-NoProfile -ExecutionPolicy Bypass -File "' + Script
                   + '" -Action remove',
                   '', SW_SHOW, ewWaitUntilTerminated, Code) then
      begin
        if NetPolicyApplied() then
          MsgBox('The rules are STILL PRESENT.'
                 + #13#10#13#10
                 + 'Removal did not complete - it may have been cancelled at the '
                 + 'Administrator prompt. The instructions and the script are at:'
                 + #13#10#13#10 + '    ' + Kit,
                 mbError, MB_OK)
        else
          MsgBox('Firewall rules removed, and verified gone.'
                 + #13#10#13#10
                 + 'Edge can reach your local network again.',
                 mbInformation, MB_OK);
      end
      else
        MsgBox('Could not start the removal - the Administrator prompt was '
               + 'refused or cancelled.'
               + #13#10#13#10
               + 'The script and written instructions are at:'
               + #13#10#13#10 + '    ' + Kit,
               mbError, MB_OK);
    end;
  end;

  if Kit <> '' then
    MsgBox('Instructions for anything still left have been saved where the '
           + 'uninstall cannot remove them:'
           + #13#10#13#10 + '    ' + Kit + '\HOW-TO-CLEAN-UP.txt'
           + #13#10#13#10
           + 'The scripts they refer to are in that folder too, because the copies '
           + 'under Program Files are about to be deleted with everything else.',
           mbInformation, MB_OK);
end;
