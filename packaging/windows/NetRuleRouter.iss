; NetRuleRouter EXE installer (Inno Setup 6). Built by scripts\package-windows.ps1
; from the package folder it has just produced; see docs/en/packaging-windows.md.
;
; Defines (ISCC /D): PackageDir, AppVersion, VersionNumeric, OutputDir,
; OutputBaseFilename. Optional: Variant (full | headless), Arch (x64 | arm64).
;
; Service and data steps run through scripts\setup-actions.ps1, which reuses the
; console and the user scripts; nothing here registers or removes anything itself.
;
; Unattended install with prepared files (full paths):
;   Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /PROVISION=<rules for the main route>
;     /PROVISION_SECONDARY=<rules> /PROVISION_SETTINGS=<settings export>
;     /SECONDARY_UNSET=direct|block
; The files are checked before anything is installed: a refused one ends Setup
; with exit code 7, the service binary's own code (10-14) in the setup log. A
; file that fails when it is copied after the install ends with that code itself.

; The architecture identifiers used below arrived in 6.3.
#if VER < EncodeVer(6,3,0) || VER >= EncodeVer(7,0,0)
  #error Inno Setup 6.3 or newer within version 6 is required
#endif
#ifndef PackageDir
  #error PackageDir is not defined: build through scripts\package-windows.ps1
#endif
#ifndef Variant
  #define Variant "full"
#endif
#ifndef Arch
  #define Arch "x64"
#endif

#if Arch == "x64"
  ; x64os, not x64compatible: wintun.dll and the driver behind it are native code.
  #define ArchAllowed "x64os"
#elif Arch == "arm64"
  #define ArchAllowed "arm64"
#else
  ; 32-bit Windows is not supported.
  #error Arch must be x64 or arm64
#endif

#if Variant == "full"
  #define MainExe "NetRuleRouter.exe"
#else
  #define MainExe "nrr-cli.exe"
#endif

[Setup]
; Never changes: an upgrade finds the previous installation by it.
AppId={{A7629E15-413C-4ACE-BD45-FE227D6CDEA1}
AppName=NetRuleRouter
AppVersion={#AppVersion}
AppVerName=NetRuleRouter {#AppVersion}
AppPublisher=NetRuleRouter
AppContact=fmalkov91@gmail.com
VersionInfoVersion={#VersionNumeric}
VersionInfoProductName=NetRuleRouter
; The service runs as LocalSystem from this folder and refuses one an ordinary
; user can write to, so the location is not offered for change.
DefaultDirName={autopf}\NetRuleRouter
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed={#ArchAllowed}
ArchitecturesInstallIn64BitMode={#ArchAllowed}
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseFilename}
SetupIconFile={#PackageDir}\assets\icons\app\app.ico
UninstallDisplayIcon={app}\{#MainExe}
UninstallDisplayName=NetRuleRouter
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
; Restart Manager closes a running window and tray; restarting them would run
; them elevated, as Setup.
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Messages]
english.ConfirmUninstall=Remove %1 from this computer?
russian.ConfirmUninstall=Удалить %1 с этого компьютера?

[CustomMessages]
english.LaunchApp=Start NetRuleRouter
russian.LaunchApp=Запустить NetRuleRouter
english.ServiceStopFailed=The NetRuleRouter background service did not stop, so its files cannot be replaced. Restart Windows and run Setup again.
russian.ServiceStopFailed=Фоновая служба NetRuleRouter не остановилась, поэтому её файлы нельзя заменить. Перезагрузите Windows и запустите установку снова.
english.ServiceRegisterFailed=NetRuleRouter is installed, but its background service could not be registered or started. Open NetRuleRouter to see what is wrong, or run "nrr-cli diag doctor" in the installation folder. Details: %1
russian.ServiceRegisterFailed=NetRuleRouter установлена, но её фоновую службу не удалось зарегистрировать или запустить. Откройте NetRuleRouter, чтобы увидеть причину, или выполните "nrr-cli diag doctor" в папке установки. Подробности: %1
english.ProvisionRefused=A file given to Setup was refused (code %1), so nothing was installed. The reason is in the setup log.
russian.ProvisionRefused=Файл, переданный установке, отклонён (код %1), поэтому ничего не установлено. Причина указана в журнале установки.
english.ProvisionNotStaged=NetRuleRouter is installed, but the files given to Setup could not be prepared for the service (code %1). Details: %2
russian.ProvisionNotStaged=NetRuleRouter установлена, но переданные установке файлы не удалось подготовить для службы (код %1). Подробности: %2
english.UninstallModeTitle=How should NetRuleRouter be removed?
russian.UninstallModeTitle=Как удалить NetRuleRouter?
english.UninstallModeText=Either way the background service is removed and the network settings it changed are put back.
russian.UninstallModeText=В обоих случаях фоновая служба удаляется, а изменённые ею сетевые настройки возвращаются в исходное состояние.
english.UninstallModeProgram=Remove the program%nSettings, rules and service data stay, so installing it again picks up where you left off.
russian.UninstallModeProgram=Удалить программу%nНастройки, правила и данные службы сохранятся, и после повторной установки всё продолжит работать как раньше.
english.UninstallModeComplete=Remove completely%nAlso erase the service's data and your own NetRuleRouter settings. Data of other Windows accounts is listed, not deleted; rule files you saved in your own folders are kept.
russian.UninstallModeComplete=Удалить полностью%nТакже стереть данные службы и ваши собственные настройки NetRuleRouter. Данные других учётных записей Windows перечисляются, но не удаляются; файлы правил, сохранённые вами в своих папках, останутся.
english.UninstallAuditTitle=Also erase the audit trail?
russian.UninstallAuditTitle=Стереть и журнал аудита?
english.UninstallAuditText=The audit trail is the security record of every change made to routing on this computer. Keep it unless you are sure nobody will need it.
russian.UninstallAuditText=Журнал аудита - это защищённая запись всех изменений маршрутизации на этом компьютере. Сохраните его, если не уверены, что он больше никому не понадобится.
english.UninstallAuditErase=Erase the audit trail
russian.UninstallAuditErase=Стереть журнал аудита
english.UninstallAuditKeep=Keep the audit trail
russian.UninstallAuditKeep=Сохранить журнал аудита
english.UninstallIncomplete=Not every removal step finished. If the network misbehaves, restart Windows. The details, including any data left in other Windows accounts, are in %1
russian.UninstallIncomplete=Не все шаги удаления завершились. Если сеть работает неправильно, перезагрузите Windows. Подробности, в том числе данные, оставшиеся у других учётных записей Windows, - в файле %1
english.UninstallOthersLeft=NetRuleRouter is removed. Other Windows accounts on this computer still keep their own NetRuleRouter settings; each of them can delete those folders when signed in. The folders are listed in %1
russian.UninstallOthersLeft=NetRuleRouter удалена. У других учётных записей Windows на этом компьютере остались их собственные настройки NetRuleRouter; каждый пользователь может удалить эти папки, войдя в свою учётную запись. Список папок - в файле %1

[Files]
Source: "{#PackageDir}\*"; DestDir: "{app}"; Excludes: "\.nrr-package"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "setup-actions.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
; Extracted to {tmp} to stop the service before any file is replaced.
Source: "setup-actions.ps1"; Flags: dontcopy
Source: "{#PackageDir}\scripts\lib\service-paths.ps1"; Flags: dontcopy
; Checks prepared files before anything is installed.
Source: "{#PackageDir}\nrr-service.exe"; Flags: dontcopy

#if Variant == "full"
[Icons]
Name: "{autoprograms}\NetRuleRouter"; Filename: "{app}\NetRuleRouter.exe"; WorkingDir: "{app}"

[Run]
Filename: "{app}\NetRuleRouter.exe"; Description: "{cm:LaunchApp}"; Flags: postinstall nowait skipifsilent runasoriginaluser
#endif

[Code]
var
  RemoveData, RemoveAudit: Boolean;
  { The service binary's code when staging the prepared files failed; 0 otherwise. }
  ProvisionExitCode: Integer;

{ /NAME=value from the command line, '' when absent. }
function SetupParam(const Name: String): String;
begin
  Result := Trim(ExpandConstant('{param:' + Name + '|}'));
end;

function HasProvisioning(): Boolean;
begin
  Result := (SetupParam('PROVISION') <> '') or (SetupParam('PROVISION_SECONDARY') <> '') or
    (SetupParam('PROVISION_SETTINGS') <> '') or (SetupParam('SECONDARY_UNSET') <> '');
end;

{ The provision verbs' options for what was given. }
function ProvisionOptions(): String;
begin
  Result := '';
  if SetupParam('PROVISION') <> '' then
    Result := Result + ' --primary ' + AddQuotes(SetupParam('PROVISION'));
  if SetupParam('PROVISION_SECONDARY') <> '' then
    Result := Result + ' --secondary ' + AddQuotes(SetupParam('PROVISION_SECONDARY'));
  if SetupParam('PROVISION_SETTINGS') <> '' then
    Result := Result + ' --settings ' + AddQuotes(SetupParam('PROVISION_SETTINGS'));
  if SetupParam('SECONDARY_UNSET') <> '' then
    Result := Result + ' --secondary-unset ' + AddQuotes(SetupParam('SECONDARY_UNSET'));
end;

{ The same values as setup-actions.ps1 -ProvisionSpec takes them. }
function ProvisionSpec(): String;
begin
  Result := 'primary=' + SetupParam('PROVISION') + '|secondary=' + SetupParam('PROVISION_SECONDARY') +
    '|settings=' + SetupParam('PROVISION_SETTINGS') + '|secondary-unset=' + SetupParam('SECONDARY_UNSET');
end;

{ Checked by the service binary itself, before a single file is replaced. }
function CheckProvisioning(): Integer;
var
  Code: Integer;
begin
  Result := 0;
  if not HasProvisioning() then
    Exit;
  ExtractTemporaryFile('nrr-service.exe');
  if not Exec(ExpandConstant('{tmp}\nrr-service.exe'), 'provision-check' + ProvisionOptions(),
      '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := 14;
  Log(Format('nrr-service provision-check: exit %d', [Code]));
  Result := Code;
end;

function ActionLog(): String;
begin
  Result := ExpandConstant('{%TEMP}\NetRuleRouter-setup.log');
end;

{ Runs setup-actions.ps1 hidden; its exit code, or -1 when it could not start. }
function RunAction(const Script, Arguments: String): Integer;
var
  Code: Integer;
begin
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + Script + '" ' +
      Arguments + ' -LogPath "' + ActionLog() + '"',
      '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  Log(Format('setup-actions.ps1 %s: exit %d', [Arguments, Code]));
  Result := Code;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Refused: Integer;
begin
  Result := '';
  Refused := CheckProvisioning();
  if Refused <> 0 then
  begin
    Result := FmtMessage(CustomMessage('ProvisionRefused'), [IntToStr(Refused)]);
    Exit;
  end;
  ExtractTemporaryFile('setup-actions.ps1');
  ExtractTemporaryFile('service-paths.ps1');
  if RunAction(ExpandConstant('{tmp}\setup-actions.ps1'), '-Action Stop') <> 0 then
    Result := CustomMessage('ServiceStopFailed');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep <> ssPostInstall then
    Exit;
  { Staged before the service starts, so its first start applies them. }
  if HasProvisioning() then
  begin
    ProvisionExitCode := RunAction(ExpandConstant('{app}\scripts\setup-actions.ps1'),
      '-Action Provision -ProvisionSpec "' + ProvisionSpec() + '"');
    if ProvisionExitCode <> 0 then
      SuppressibleMsgBox(FmtMessage(CustomMessage('ProvisionNotStaged'),
        [IntToStr(ProvisionExitCode), ActionLog()]), mbError, MB_OK, IDOK);
  end;
  if RunAction(ExpandConstant('{app}\scripts\setup-actions.ps1'), '-Action Register') <> 0 then
    SuppressibleMsgBox(FmtMessage(CustomMessage('ServiceRegisterFailed'), [ActionLog()]),
      mbError, MB_OK, IDOK);
end;

{ A batch that installed the program but not its prepared files must not read
  that as success. }
function GetCustomSetupExitCode(): Integer;
begin
  Result := ProvisionExitCode;
end;

{ /NAME or /NAME=1 on the uninstaller's command line. }
function HasSwitch(const Name: String): Boolean;
var
  I: Integer;
  Arg: String;
begin
  Result := False;
  for I := 1 to ParamCount do
  begin
    Arg := Uppercase(ParamStr(I));
    if (Arg = '/' + Name) or (Arg = '/' + Name + '=1') then
      Result := True;
  end;
end;

{ A silent uninstall keeps the data unless /REMOVEALLDATA asks otherwise. }
function InitializeUninstall(): Boolean;
var
  Choice: Integer;
begin
  Result := True;
  if UninstallSilent then
  begin
    RemoveData := HasSwitch('REMOVEALLDATA');
    RemoveAudit := RemoveData and HasSwitch('REMOVEAUDIT');
    Exit;
  end;

  Choice := TaskDialogMsgBox(CustomMessage('UninstallModeTitle'),
    CustomMessage('UninstallModeText'), mbConfirmation, MB_YESNOCANCEL, [
    CustomMessage('UninstallModeProgram'), CustomMessage('UninstallModeComplete')], 0);
  if Choice = IDCANCEL then
  begin
    Result := False;
    Exit;
  end;
  RemoveData := Choice = IDNO;
  if RemoveData then
    RemoveAudit := TaskDialogMsgBox(CustomMessage('UninstallAuditTitle'),
      CustomMessage('UninstallAuditText'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2, [
      CustomMessage('UninstallAuditErase'), CustomMessage('UninstallAuditKeep')], 0) = IDYES;
end;

{ Before any file is deleted: the steps need the console and the scripts. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Arguments: String;
begin
  if CurUninstallStep <> usUninstall then
    Exit;
  Arguments := '-Action Unregister';
  if RemoveData then
    Arguments := Arguments + ' -RemoveData';
  if RemoveAudit then
    Arguments := Arguments + ' -RemoveAudit';
  case RunAction(ExpandConstant('{app}\scripts\setup-actions.ps1'), Arguments) of
    0: ;
    2: SuppressibleMsgBox(FmtMessage(CustomMessage('UninstallOthersLeft'), [ActionLog()]),
         mbInformation, MB_OK, IDOK);
  else
    SuppressibleMsgBox(FmtMessage(CustomMessage('UninstallIncomplete'), [ActionLog()]),
      mbInformation, MB_OK, IDOK);
  end;
end;
