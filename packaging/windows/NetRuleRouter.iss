; NetRuleRouter EXE installer (Inno Setup 6). Built by scripts\package-windows.ps1
; from the package folder it has just produced; see docs/en/packaging-windows.md.
;
; Defines (ISCC /D): PackageDir, AppVersion, VersionNumeric, OutputDir,
; OutputBaseFilename, AgreementEn and AgreementRu (the end-user agreement as
; RTF, made from docs/legal/eula.*.md), AgreementVersion (its revision),
; WizardImages and WizardSmallImages
; (comma-separated BMPs). Optional: Variant (full | headless), Arch (x64 | arm64).
;
; Service and data steps run through scripts\setup-actions.ps1, which reuses the
; console and the user scripts; nothing here registers or removes anything itself.
;
; Refuses to run over the MSI installation, which installs the same service, or
; over a newer version.
;
; /DIR=<folder> must lie inside Program Files: the service runs with system
; rights only from a folder that only administrators can change, and the
; uninstall steps run elevated from there. /COMPONENTS= lists what to install:
; main (with the console, always installed), tui (the terminal interface) and
; docs (the offline documentation); /COMPONENTS=main,tui leaves out the
; documentation, /COMPONENTS=main both.
; /TASKS= (or /MERGETASKS=) names desktopicon and addtopath; an upgrade keeps
; the earlier components and tasks unless they are given.
;
; Unattended install with prepared files (full paths):
;   Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /PROVISION=<rules for the main route>
;     /PROVISION_SECONDARY=<rules> /PROVISION_SETTINGS=<settings export>
;     /SECONDARY_UNSET=direct|block
; The files are checked before anything is installed: a refused one ends Setup
; with exit code 7, the service binary's own code (10-14) in the setup log. A
; file that fails when it is copied after the install ends with that code itself,
; and a service that could not be registered or started with 15.
;
; /INSTALL_FOR=all|me picks whose Start menu gets the shortcut (full package):
; every user's (the default for a new install) or only the account Setup runs
; as. Without it an upgrade keeps the earlier choice; another value ends Setup
; before anything is installed.

; The architecture identifiers used below arrived in 6.3.
#if VER < EncodeVer(6,3,0) || VER >= EncodeVer(7,0,0)
  #error Inno Setup 6.3 or newer within version 6 is required
#endif
#ifndef PackageDir
  #error PackageDir is not defined: build through scripts\package-windows.ps1
#endif
#ifndef AgreementEn
  #error AgreementEn is not defined: build through scripts\package-windows.ps1
#endif
#ifndef AgreementRu
  #error AgreementRu is not defined: build through scripts\package-windows.ps1
#endif
#ifndef AgreementVersion
  #error AgreementVersion is not defined: build through scripts\package-windows.ps1
#endif
#ifndef WizardImages
  #error WizardImages is not defined: build through scripts\package-windows.ps1
#endif
#ifndef WizardSmallImages
  #error WizardSmallImages is not defined: build through scripts\package-windows.ps1
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
; The folder is offered only inside Program Files (FolderAllowed); an upgrade
; keeps the earlier one.
DefaultDirName={autopf}\NetRuleRouter
DisableDirPage=auto
; The console tools on PATH (the addtopath task).
ChangesEnvironment=yes
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
WizardImageFile={#WizardImages}
WizardSmallImageFile={#WizardSmallImages}
Compression=lzma2/max
SolidCompression=yes
; PrepareToInstall closes the window, the tray and the console tools first
; (CloseApps): their launchers have no window for Restart Manager to ask, so it
; is the fallback only. Restarting them would run them elevated, as Setup.
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
; A removal that went wrong is diagnosed from its own log in %TEMP%.
UninstallLogging=yes
; {userprograms} is used only when Setup runs as the person who started it:
; see SetupRunsAsStarter.
UsedUserAreasWarning=no

; The licence page shows the end-user agreement in Setup's language. The app
; does not ask again the account Setup ran as when it accepted the page here;
; every other Windows account is asked on its own first launch.
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"; LicenseFile: "{#AgreementEn}"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"; LicenseFile: "{#AgreementRu}"

[Messages]
english.ConfirmUninstall=Remove %1 from this computer?
russian.ConfirmUninstall=Удалить %1 с этого компьютера?
; Inno's own last words claimed a complete removal after "Remove the program",
; which keeps the rules. The box cannot tell the two choices apart, so its
; text holds for both.
english.UninstalledAll=%1 is removed from this computer. Unless you chose to remove it completely, your rules and settings are kept and come back when you install it again.
russian.UninstalledAll=%1 удалена с этого компьютера. Если вы не выбрали полное удаление, ваши правила и настройки сохранены и вернутся при следующей установке.
english.UninstalledMost=%1 is removed, but some of its files could not be deleted; you can delete them yourself. Unless you chose to remove it completely, your rules and settings are kept.
russian.UninstalledMost=%1 удалена, но часть её файлов удалить не удалось; их можно удалить самостоятельно. Если вы не выбрали полное удаление, ваши правила и настройки сохранены.

[CustomMessages]
english.LaunchApp=Start NetRuleRouter
russian.LaunchApp=Запустить NetRuleRouter
english.MsiInstalled=NetRuleRouter is already installed from its MSI package. Remove that installation first (removing only the program keeps settings and rules), then run this Setup again.
russian.MsiInstalled=NetRuleRouter уже установлена из пакета MSI. Сначала удалите эту установку (при удалении только программы настройки и правила сохранятся), затем запустите эту установку снова.
english.FolderOutsideProgramFiles=NetRuleRouter installs only into a folder inside %1: its background service runs with system rights, so it may run only from a folder that only administrators can change. Choose a folder there.
russian.FolderOutsideProgramFiles=NetRuleRouter устанавливается только в папку внутри %1: её фоновая служба работает с правами системы, поэтому может запускаться только из папки, которую могут изменять лишь администраторы. Выберите папку там.
english.TypeDefault=Selected components
russian.TypeDefault=Выбранные компоненты
english.ComponentMainFull=NetRuleRouter: window, tray, background service and console (always installed: removing and repairing the program rely on the console)
russian.ComponentMainFull=NetRuleRouter: окно, значок в трее, фоновая служба и консоль (устанавливаются всегда: удаление и восстановление программы выполняются через консоль)
english.ComponentMainHeadless=NetRuleRouter: background service and console (always installed: removing and repairing the program rely on the console)
russian.ComponentMainHeadless=NetRuleRouter: фоновая служба и консоль (устанавливаются всегда: удаление и восстановление программы выполняются через консоль)
english.ComponentTui=Terminal interface (nrr-tui): rules, routes and settings in a terminal
russian.ComponentTui=Терминальный интерфейс (nrr-tui): правила, маршруты и настройки в терминале
english.ComponentDocs=Documentation (offline, HTML): opens from Help > Documentation without the internet
russian.ComponentDocs=Документация (офлайн, HTML): открывается из меню «Справка > Документация» без интернета
english.ConsoleTasks=Console tools:
russian.ConsoleTasks=Консольные инструменты:
english.AddToPath=Add the console tools to &PATH (nrr-cli, and nrr-tui when installed; not the program folder)
russian.AddToPath=Добавить консольные инструменты в &PATH (nrr-cli, а также nrr-tui, если он установлен; не папку программы)
english.NewerInstalled=A newer version of NetRuleRouter is already installed. To go back to this version, remove the installed one first (removing only the program keeps settings and rules).
russian.NewerInstalled=Уже установлена более новая версия NetRuleRouter. Чтобы вернуться к этой версии, сначала удалите установленную (при удалении только программы настройки и правила сохранятся).
english.ServiceStopFailed=The NetRuleRouter background service did not stop, so its files cannot be replaced. Restart Windows and run Setup again.
russian.ServiceStopFailed=Фоновая служба NetRuleRouter не остановилась, поэтому её файлы нельзя заменить. Перезагрузите Windows и запустите установку снова.
english.ServiceRegisterFailed=NetRuleRouter is installed, but its background service could not be registered or started. Open NetRuleRouter to see what is wrong, or run "nrr-cli diag doctor" in the installation folder. Details: %1
russian.ServiceRegisterFailed=NetRuleRouter установлена, но её фоновую службу не удалось зарегистрировать или запустить. Откройте NetRuleRouter, чтобы увидеть причину, или выполните "nrr-cli diag doctor" в папке установки. Подробности: %1
english.ProvisionRefused=A file given to Setup was refused (code %1), so nothing was installed. The reason is in the setup log.
russian.ProvisionRefused=Файл, переданный установке, отклонён (код %1), поэтому ничего не установлено. Причина указана в журнале установки.
english.ProvisionNotChecked=The files given to Setup could not be checked: the check did not start (code %1), so nothing was installed. Run Setup again; if it repeats, report the code.
russian.ProvisionNotChecked=Не удалось проверить файлы, переданные установке: проверка не запустилась (код %1), поэтому ничего не установлено. Запустите установку снова; если ошибка повторится, сообщите этот код.
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
english.InstallForTitle=Install for
russian.InstallForTitle=Для кого установить
english.InstallForDescription=Who should find NetRuleRouter in the Start menu?
russian.InstallForDescription=У кого NetRuleRouter появится в меню «Пуск»?
english.InstallForText=NetRuleRouter is installed once for the whole computer, and its background service routes traffic for every Windows account whichever you choose. This choice only decides whose Start menu and desktop get the NetRuleRouter shortcuts, and whose PATH gets the console tools if you add them.
russian.InstallForText=NetRuleRouter устанавливается один раз на весь компьютер, и её фоновая служба направляет трафик всех учётных записей Windows при любом выборе. Выбор определяет только, в чьём меню «Пуск» и на чьём рабочем столе появятся ярлыки NetRuleRouter и в чей PATH попадут консольные инструменты, если вы их добавите.
english.InstallForAllUsers=All users of this computer
russian.InstallForAllUsers=Все пользователи этого компьютера
english.InstallForOnlyMe=Only me (%1)
russian.InstallForOnlyMe=Только я (%1)
english.InstallForOnlyMeOff=Only me - not available, see above
russian.InstallForOnlyMeOff=Только я - недоступно, см. выше
english.InstallForOnlyMeUnavailable=Setup is running under the administrator account that approved it, not under yours, so the shortcut can only be added for all users.
russian.InstallForOnlyMeUnavailable=Установка выполняется от имени учётной записи администратора, который её подтвердил, а не от вашей, поэтому ярлык можно добавить только для всех пользователей.
english.InstallForInvalid=/INSTALL_FOR=%1 is not understood: use all or me. Nothing was installed.
russian.InstallForInvalid=Значение /INSTALL_FOR=%1 не распознано: укажите all или me. Ничего не установлено.
english.StatusCheckFiles=Checking the files given to Setup...
russian.StatusCheckFiles=Проверяем файлы, переданные установке...
english.StatusCloseApps=Closing the NetRuleRouter window and tray icon...
russian.StatusCloseApps=Закрываем окно и значок NetRuleRouter в трее...
english.StatusStopService=Stopping the background service...
russian.StatusStopService=Останавливаем фоновую службу...
english.StatusProvision=Handing the given rule files to the background service...
russian.StatusProvision=Передаём фоновой службе указанные файлы правил...
english.StatusRegister=Registering and starting the background service...
russian.StatusRegister=Регистрируем и запускаем фоновую службу...
english.StatusConsoleLinks=Adding the console tools...
russian.StatusConsoleLinks=Добавляем консольные инструменты...
english.UninstallStatusKeep=Removing the background service and restoring the network settings; your rules and settings stay...
russian.UninstallStatusKeep=Удаляем фоновую службу и возвращаем сетевые настройки; правила и настройки сохраняются...
english.UninstallStatusComplete=Removing the background service, restoring the network settings and erasing the data...
russian.UninstallStatusComplete=Удаляем фоновую службу, возвращаем сетевые настройки и стираем данные...
english.ShowSetupLog=Show the installation &log
russian.ShowSetupLog=Показать &журнал установки

; One type, so the page shows only the list.
[Types]
Name: "selected"; Description: "{cm:TypeDefault}"; Flags: iscustom

[Components]
#if Variant == "full"
Name: "main"; Description: "{cm:ComponentMainFull}"; Types: selected; Flags: fixed
#else
Name: "main"; Description: "{cm:ComponentMainHeadless}"; Types: selected; Flags: fixed
#endif
Name: "tui"; Description: "{cm:ComponentTui}"; Types: selected
Name: "docs"; Description: "{cm:ComponentDocs}"; Types: selected

[Tasks]
#if Variant == "full"
; Unticked: the Start menu shortcut is always there.
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
#endif
Name: "addtopath"; Description: "{cm:AddToPath}"; GroupDescription: "{cm:ConsoleTasks}"; Flags: unchecked

[InstallDelete]
; Symbols no longer ship; an upgrade would otherwise keep the earlier ones.
Type: files; Name: "{app}\*.pdb"
; A component left out on an upgrade takes its earlier file with it.
Type: files; Name: "{app}\nrr-tui.exe"; Components: not tui
; Always: a page the new version no longer has would stay linked from nowhere.
Type: filesandordirs; Name: "{app}\docs"

[Files]
Source: "{#PackageDir}\*"; DestDir: "{app}"; Excludes: "\.nrr-package,\nrr-tui.exe,\docs"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#PackageDir}\nrr-tui.exe"; DestDir: "{app}"; Components: tui; Flags: ignoreversion
Source: "{#PackageDir}\docs\*"; DestDir: "{app}\docs"; Components: docs; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "setup-actions.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
; Extracted to {tmp} to stop the service before any file is replaced.
Source: "setup-actions.ps1"; Flags: dontcopy
Source: "{#PackageDir}\scripts\lib\service-paths.ps1"; Flags: dontcopy
; Checks prepared files before anything is installed. It links the Visual C++
; runtime dynamically, and a clean Windows has none: the DLLs go beside it.
Source: "{#PackageDir}\nrr-service.exe"; Flags: dontcopy
Source: "{#PackageDir}\vcruntime140.dll"; Flags: dontcopy
#if FileExists(AddBackslash(PackageDir) + "vcruntime140_1.dll")
  #define HasVcRuntime1
Source: "{#PackageDir}\vcruntime140_1.dll"; Flags: dontcopy
#endif

[Registry]
; Read by the app at an account's first start: only after the wizard's licence
; page was accepted, and only for the account Setup ran as.
Root: HKLM64; Subkey: "SOFTWARE\NetRuleRouter\Agreement"; ValueType: dword; ValueName: "Version"; ValueData: "{#AgreementVersion}"; Flags: uninsdeletekey; Check: AgreementAcceptedInWizard
Root: HKLM64; Subkey: "SOFTWARE\NetRuleRouter\Agreement"; ValueType: string; ValueName: "AcceptedBy"; ValueData: "{code:SetupAccountSid}"; Check: AgreementAcceptedInWizard

#if Variant == "full"
[Icons]
Name: "{commonprograms}\NetRuleRouter"; Filename: "{app}\NetRuleRouter.exe"; WorkingDir: "{app}"; Check: ShortcutForAll
Name: "{userprograms}\NetRuleRouter"; Filename: "{app}\NetRuleRouter.exe"; WorkingDir: "{app}"; Check: ShortcutForMe
Name: "{commondesktop}\NetRuleRouter"; Filename: "{app}\NetRuleRouter.exe"; WorkingDir: "{app}"; Tasks: desktopicon; Check: ShortcutForAll
Name: "{userdesktop}\NetRuleRouter"; Filename: "{app}\NetRuleRouter.exe"; WorkingDir: "{app}"; Tasks: desktopicon; Check: ShortcutForMe

[Run]
Filename: "{app}\NetRuleRouter.exe"; Description: "{cm:LaunchApp}"; Flags: postinstall nowait skipifsilent runasoriginaluser
#endif

[Code]
var
  RemoveData, RemoveAudit: Boolean;
  { The service binary's code when staging the prepared files failed; 0 otherwise. }
  ProvisionExitCode: Integer;
  RegisterFailed: Boolean;
  { Setup stopped the service and Register has not taken it over yet. }
  ServiceStoppedBySetup: Boolean;
  { Left the licence page with "I accept" chosen. }
  LicenceAcceptedInWizard: Boolean;
  AccountSid: String;
  AccountSidRead: Boolean;

const
  { The MSI's UpgradeCode (NetRuleRouter.wxs), and this Setup's uninstall key:
    its AppId plus "_is1". }
  MsiUpgradeCode = '{32814437-D697-4AC1-B07C-BD46DE72F89C}';
  { Exit code of a Setup that installed the files but left no running service. }
  RegisterFailedExitCode = 15;
  OwnUninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{A7629E15-413C-4ACE-BD45-FE227D6CDEA1}_is1';

{ This Setup's numeric version a.b.c.d, split as a file version block holds it. }
procedure OwnVersionNumbers(var MS, LS: Cardinal);
var
  Rest: String;
  Parts: array[0..3] of Cardinal;
  I, Dot: Integer;
begin
  Rest := '{#VersionNumeric}';
  for I := 0 to 3 do
  begin
    Dot := Pos('.', Rest);
    if Dot = 0 then
      Dot := Length(Rest) + 1;
    Parts[I] := StrToIntDef(Copy(Rest, 1, Dot - 1), 0);
    Delete(Rest, 1, Dot);
  end;
  MS := (Parts[0] shl 16) or Parts[1];
  LS := (Parts[2] shl 16) or Parts[3];
end;

{ Whether the installed copy is newer, by its service binary's file version:
  the binaries carry the same numeric version this Setup does. }
function InstalledIsNewer(): Boolean;
var
  Location: String;
  InstalledMS, InstalledLS, OwnMS, OwnLS: Cardinal;
begin
  Result := False;
  if not RegQueryStringValue(HKLM64, OwnUninstallKey, 'InstallLocation', Location) then
    Exit;
  if not GetVersionNumbers(AddBackslash(Location) + 'nrr-service.exe', InstalledMS, InstalledLS) then
    Exit;
  OwnVersionNumbers(OwnMS, OwnLS);
  Result := (InstalledMS > OwnMS) or ((InstalledMS = OwnMS) and (InstalledLS > OwnLS));
end;

{ The MSI installs into the same folder, and an older build must not replace a
  newer one: both end Setup before anything changes. }
function MsiInstalled(): Boolean;
begin
  { Raises when Windows Installer cannot be asked: read as no MSI install. }
  try
    Result := IsMsiProductInstalled(MsiUpgradeCode, 0);
  except
    Log('Windows Installer query failed: ' + GetExceptionMessage());
    Result := False;
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if MsiInstalled() then
  begin
    SuppressibleMsgBox(CustomMessage('MsiInstalled'), mbError, MB_OK, IDOK);
    Result := False;
  end
  else if InstalledIsNewer() then
  begin
    SuppressibleMsgBox(CustomMessage('NewerInstalled'), mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

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

function ActionLog(): String;
begin
  Result := ExpandConstant('{%TEMP}\NetRuleRouter-setup.log');
end;

{ A line of ours in the steps' log: the uninstaller started as unins000.exe
  gets no /LOG and writes no log of its own. }
procedure NoteInActionLog(const Text: String);
begin
  Log(Text);
  SaveStringToFile(ActionLog(), GetDateTimeString('yyyy/mm/dd hh:nn:ss', '-', ':') + ' ' + Text + #13#10, True);
end;

{ What the next step does, where the person is looking: the preparing page
  before the files are copied, the progress page after them, the
  uninstaller's own form. A silent run shows none of them. }
procedure ShowStatus(const Name: String);
var
  Text: String;
begin
  Text := CustomMessage(Name);
  Log('Status: ' + Text);
  if IsUninstaller() then
  begin
    UninstallProgressForm.StatusLabel.Caption := Text;
    UninstallProgressForm.StatusLabel.Refresh;
  end
  else if WizardForm.CurPageID = wpPreparing then
  begin
    WizardForm.PreparingLabel.Caption := Text;
    WizardForm.PreparingLabel.Visible := True;
    WizardForm.PreparingLabel.Refresh;
  end
  else
  begin
    WizardForm.StatusLabel.Caption := Text;
    WizardForm.FilenameLabel.Caption := '';
    WizardForm.StatusLabel.Refresh;
    WizardForm.FilenameLabel.Refresh;
  end;
end;

{ Checked by the service binary itself, before a single file is replaced. }
function CheckProvisioning(): Integer;
var
  Code: Integer;
begin
  Result := 0;
  if not HasProvisioning() then
    Exit;
  ShowStatus('StatusCheckFiles');
  ExtractTemporaryFile('nrr-service.exe');
  ExtractTemporaryFile('vcruntime140.dll');
#ifdef HasVcRuntime1
  ExtractTemporaryFile('vcruntime140_1.dll');
#endif
  if not Exec(ExpandConstant('{tmp}\nrr-service.exe'), 'provision-check' + ProvisionOptions(),
      '', SW_HIDE, ewWaitUntilTerminated, Code) then
  begin
    { Code is a Windows error here and may fall inside 10-14. }
    Log('nrr-service provision-check did not start: ' + SysErrorMessage(Code));
    Code := -1;
  end;
  Log(Format('nrr-service provision-check: exit %d', [Code]));
  Result := Code;
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

{ Inside Program Files, below it: every folder above is one only
  administrators can change, as the service requires of the folder it runs
  from, and Register secures the folder itself. Never the folder a portable
  install copies the service to. }
function FolderAllowed(const Dir: String): Boolean;
var
  Full, Root: String;
  I: Integer;
begin
  Result := False;
  Full := Lowercase(AddBackslash(ExpandFileName(Dir)));
  for I := 0 to 1 do
  begin
    if I = 0 then
      Root := Lowercase(AddBackslash(ExpandConstant('{commonpf64}')))
    else
      Root := Lowercase(AddBackslash(ExpandConstant('{commonpf32}')));
    if (Length(Full) > Length(Root)) and (Copy(Full, 1, Length(Root)) = Root) then
      Result := True;
  end;
  if Full = Lowercase(AddBackslash(ExpandConstant('{commonpf64}\NetRuleRouter Service'))) then
    Result := False;
end;

function FolderRefusedText(): String;
begin
  Result := FmtMessage(CustomMessage('FolderOutsideProgramFiles'), [ExpandConstant('{commonpf64}')]);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = wpLicense then
    LicenceAcceptedInWizard := WizardForm.LicenseAcceptedRadio.Checked;
  if (CurPageID = wpSelectDir) and not FolderAllowed(WizardDirValue()) then
  begin
    MsgBox(FolderRefusedText(), mbError, MB_OK);
    Result := False;
  end;
end;

{ The security identifier of the account Setup runs as, from the system
  itself; '' when it cannot be read, and then nothing is recorded. }
function SetupAccountSid(Param: String): String;
var
  Output: TExecOutput;
  Code, I, Start, Stop: Integer;
  Line: String;
begin
  if not AccountSidRead then
  begin
    AccountSidRead := True;
    try
      if ExecAndCaptureOutput(ExpandConstant('{sys}\whoami.exe'), '/user /fo csv /nh', '',
          SW_HIDE, ewWaitUntilTerminated, Code, Output) and (Code = 0) then
        for I := 0 to GetArrayLength(Output.StdOut) - 1 do
        begin
          Line := Output.StdOut[I];
          Start := Pos('"S-1-', Line);
          if Start > 0 then
          begin
            Line := Copy(Line, Start + 1, Length(Line) - Start);
            Stop := Pos('"', Line);
            if Stop > 1 then
              AccountSid := Copy(Line, 1, Stop - 1);
          end;
        end;
    except
      Log('the account Setup runs as could not be read: ' + GetExceptionMessage());
    end;
  end;
  Result := AccountSid;
end;

{ A silent Setup shows no licence page, so it never records an acceptance. }
function AgreementAcceptedInWizard(): Boolean;
begin
  Result := LicenceAcceptedInWizard and not WizardSilent() and (SetupAccountSid('') <> '');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Refused: Integer;
begin
  { /DIR= of a silent Setup meets the same rule as the folder page. }
  if not FolderAllowed(ExpandConstant('{app}')) then
  begin
    Result := FolderRefusedText();
    Exit;
  end;
  Result := '';
  Refused := CheckProvisioning();
  { Outside 10-14 the binary did not run (a loader status such as 0xC0000135 is
    negative here), which says nothing about the files. }
  if (Refused >= 10) and (Refused <= 14) then
  begin
    Result := FmtMessage(CustomMessage('ProvisionRefused'), [IntToStr(Refused)]);
    Exit;
  end;
  if Refused <> 0 then
  begin
    Result := FmtMessage(CustomMessage('ProvisionNotChecked'), [Format('0x%.8x', [Refused])]);
    Exit;
  end;
  ExtractTemporaryFile('setup-actions.ps1');
  ExtractTemporaryFile('service-paths.ps1');
  { Before Restart Manager looks: it cannot close the windowless launchers. }
  if DirExists(ExpandConstant('{app}')) then
  begin
    ShowStatus('StatusCloseApps');
    RunAction(ExpandConstant('{tmp}\setup-actions.ps1'),
      '-Action CloseApps -Folder "' + ExpandConstant('{app}') + '"');
  end;
  ServiceStoppedBySetup := True;
  ShowStatus('StatusStopService');
  if RunAction(ExpandConstant('{tmp}\setup-actions.ps1'), '-Action Stop') <> 0 then
    Result := CustomMessage('ServiceStopFailed');
  { A refusal replaces the status with its own text; success leaves the page bare. }
  if Result = '' then
    WizardForm.PreparingLabel.Visible := False;
end;

{ A Setup that stopped the service and ends without installing (cancelled,
  refused, failed) starts it again: kept protection with no service behind it
  holds the network with nothing maintaining it. }
procedure DeinitializeSetup();
begin
  if ServiceStoppedBySetup then
    if RunAction(ExpandConstant('{tmp}\setup-actions.ps1'), '-Action Resume') <> 0 then
      Log('the service Setup stopped did not start again');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep <> ssPostInstall then
    Exit;
  { Staged before the service starts, so its first start applies them. }
  if HasProvisioning() then
  begin
    ShowStatus('StatusProvision');
    ProvisionExitCode := RunAction(ExpandConstant('{app}\scripts\setup-actions.ps1'),
      '-Action Provision -ProvisionSpec "' + ProvisionSpec() + '"');
    if ProvisionExitCode <> 0 then
      { A line may not start with a bracket: Inno reads it as a section. }
      SuppressibleMsgBox(FmtMessage(CustomMessage('ProvisionNotStaged'), [
        IntToStr(ProvisionExitCode), ActionLog()]), mbError, MB_OK, IDOK);
  end;
  ShowStatus('StatusRegister');
  RegisterFailed := RunAction(ExpandConstant('{app}\scripts\setup-actions.ps1'), '-Action Register') <> 0;
  ServiceStoppedBySetup := False;
  if RegisterFailed then
    SuppressibleMsgBox(FmtMessage(CustomMessage('ServiceRegisterFailed'), [ActionLog()]),
      mbError, MB_OK, IDOK);
end;

{ A batch that installed the program but not its prepared files, or without a
  service, must not read that as success; the MSI rolls back in both cases. }
function GetCustomSetupExitCode(): Integer;
begin
  Result := ProvisionExitCode;
  if (Result = 0) and RegisterFailed then
    Result := RegisterFailedExitCode;
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
  { A task dialog takes no MB_DEFBUTTON flag (it stops with "Invalid Buttons")
    and defaults to its first button: keeping the trail comes first. }
  if RemoveData then
    RemoveAudit := TaskDialogMsgBox(CustomMessage('UninstallAuditTitle'),
      CustomMessage('UninstallAuditText'), mbConfirmation, MB_YESNO, [
      CustomMessage('UninstallAuditKeep'), CustomMessage('UninstallAuditErase')], 0) = IDNO;
end;

const
  MachineEnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';
  UserEnvironmentKey = 'Environment';

{ Holds links to the console and the terminal interface only: the program
  folder carries Qt and runtime DLLs that every program searching PATH would
  load. }
function ConsoleBin(): String;
begin
  Result := ExpandConstant('{app}\bin');
end;

{ A PATH entry as the console's PATH action compares it: quotes, spaces, a
  trailing backslash and case do not count. }
function PathEntryKey(const Entry: String): String;
begin
  Result := Trim(Entry);
  StringChangeEx(Result, '"', '', True);
  Result := Lowercase(RemoveBackslashUnlessRoot(Trim(Result)));
end;

{ Adds Entry at the end of the PATH under RootKey once, or removes every copy
  of it; the rest of the value stays as written. }
procedure EditPath(RootKey: Integer; const SubKey, Entry: String; Add: Boolean);
var
  Old, Rest, Item, Kept: String;
  P: Integer;
  Found: Boolean;
begin
  if not RegQueryStringValue(RootKey, SubKey, 'Path', Old) then
    Old := '';
  Rest := Old;
  Kept := '';
  Found := False;
  while Rest <> '' do
  begin
    P := Pos(';', Rest);
    if P = 0 then
    begin
      Item := Rest;
      Rest := '';
    end
    else
    begin
      Item := Copy(Rest, 1, P - 1);
      Delete(Rest, 1, P);
    end;
    if (Trim(Item) <> '') and (PathEntryKey(Item) = PathEntryKey(Entry)) then
      Found := True
    else if Kept = '' then
      Kept := Item
    else
      Kept := Kept + ';' + Item;
  end;
  if Add = Found then
    Exit;
  if Add then
  begin
    if (Old = '') or (Copy(Old, Length(Old), 1) = ';') then
      Kept := Old + Entry
    else
      Kept := Old + ';' + Entry;
  end;
  if not RegWriteExpandStringValue(RootKey, SubKey, 'Path', Kept) then
    Log('PATH was not changed under ' + SubKey);
end;

{ Before any file is deleted: the steps need the console and the scripts. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Arguments, Status: String;
  Code: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    { Whichever scope the installation used; another one's entry is not ours. }
    EditPath(HKLM, MachineEnvironmentKey, ConsoleBin(), False);
    EditPath(HKCU, UserEnvironmentKey, ConsoleBin(), False);
    { Also when the installation that wrote it was not the last one. }
    RegDeleteKeyIncludingSubkeys(HKLM64, 'SOFTWARE\NetRuleRouter\Agreement');
    RegDeleteKeyIfEmpty(HKLM64, 'SOFTWARE\NetRuleRouter');
    NoteInActionLog('removal: program files, PATH entries and the agreement record removed; done');
    Exit;
  end;
  if CurUninstallStep <> usUninstall then
    Exit;
  { A line of [Code] must not start with "[": Inno reads it as a section tag. }
  NoteInActionLog(Format('removal started by %s (erase data: %d, erase audit trail: %d)', [
    ExpandConstant('{uninstallexe}'), Ord(RemoveData), Ord(RemoveAudit)]));
  { Inno's own text comes back once our steps are done. }
  Status := UninstallProgressForm.StatusLabel.Caption;
  { Every session's window, tray and console tools, before their files go. }
  ShowStatus('StatusCloseApps');
  RunAction(ExpandConstant('{app}\scripts\setup-actions.ps1'), '-Action CloseApps');
  Arguments := '-Action Unregister';
  if RemoveData then
    Arguments := Arguments + ' -RemoveData';
  if RemoveAudit then
    Arguments := Arguments + ' -RemoveAudit';
  if RemoveData then
    ShowStatus('UninstallStatusComplete')
  else
    ShowStatus('UninstallStatusKeep');
  Code := RunAction(ExpandConstant('{app}\scripts\setup-actions.ps1'), Arguments);
  NoteInActionLog(Format('removal: service and data steps ended with %d; removing the program files', [Code]));
  UninstallProgressForm.StatusLabel.Caption := Status;
  case Code of
    0: ;
    2: SuppressibleMsgBox(FmtMessage(CustomMessage('UninstallOthersLeft'), [ActionLog()]),
         mbInformation, MB_OK, IDOK);
  else
    SuppressibleMsgBox(FmtMessage(CustomMessage('UninstallIncomplete'), [ActionLog()]),
      mbInformation, MB_OK, IDOK);
  end;
end;

{ Whose Start menu gets the shortcut. The folder, the service and routing are
  per machine whichever is chosen; the tray's launch at sign-in stays the app's
  own per-user setting. }
function InstallForParam(): String;
begin
  Result := Lowercase(SetupParam('INSTALL_FOR'));
end;

<event('InitializeSetup')>
function InstallForInitializeSetup(): Boolean;
begin
  Result := (InstallForParam() = '') or (InstallForParam() = 'all') or (InstallForParam() = 'me');
  if not Result then
    SuppressibleMsgBox(FmtMessage(CustomMessage('InstallForInvalid'), [SetupParam('INSTALL_FOR')]),
      mbError, MB_OK, IDOK);
end;

const
  StarterProbeKey = 'Software\NetRuleRouter\SetupProbe';

var
  StarterAsked, StarterIsSetupAccount: Boolean;

{ Elevated with another account's credentials, Setup runs as that administrator
  and the per-user Programs folder is theirs. A value Setup writes to its own
  HKCU is seen by a process of the person who started Setup only when both share
  one hive. Asked once. }
function SetupRunsAsStarter(): Boolean;
var
  Probe: String;
  Code: Integer;
begin
  if StarterAsked then
  begin
    Result := StarterIsSetupAccount;
    Exit;
  end;
  StarterAsked := True;
  Result := False;
  Probe := 'Probe' + GetDateTimeString('hhnnsszzz', '-', ':') + IntToStr(Random(1000000));
  if not RegWriteStringValue(HKCU, StarterProbeKey, Probe, '') then
    Exit;
  try
    Result := ExecAsOriginalUser(ExpandConstant('{sys}\reg.exe'),
      'query "HKCU\' + StarterProbeKey + '" /v ' + Probe, '', SW_HIDE, ewWaitUntilTerminated, Code)
      and (Code = 0);
  except
    Log('the account that started Setup could not be asked: ' + GetExceptionMessage());
  end;
  RegDeleteKeyIncludingSubkeys(HKCU, StarterProbeKey);
  RegDeleteKeyIfEmpty(HKCU, 'Software\NetRuleRouter');
  StarterIsSetupAccount := Result;
  Log(Format('Setup runs as the account that started it: %d', [Ord(Result)]));
end;

var
  LogButton: TNewButton;

{ As the person who started Setup: an elevated editor's file dialogs would run
  anything with administrator rights. }
procedure OpenSetupLogs();
var
  Logs: array[0..1] of String;
  I, Code: Integer;
begin
  Logs[0] := ExpandConstant('{log}');
  Logs[1] := ActionLog();
  for I := 0 to 1 do
    if (Logs[I] <> '') and FileExists(Logs[I]) then
      try
        if not ShellExecAsOriginalUser('', ExpandConstant('{win}\notepad.exe'), AddQuotes(Logs[I]), '',
            SW_SHOWNORMAL, ewNoWait, Code) then
          Log('the log was not opened: ' + SysErrorMessage(Code));
      except
        Log('the log was not opened: ' + GetExceptionMessage());
      end;
end;

procedure OpenSetupLogsClick(Sender: TObject);
begin
  OpenSetupLogs();
end;

{ Under whatever the finished page shows. Only when Setup runs as the person
  who started it: the logs lie in that account's %TEMP%, which no other
  account's editor may read. }
procedure AddLogButton();
begin
  if (LogButton <> nil) or WizardSilent() or not SetupRunsAsStarter() then
    Exit;
  LogButton := TNewButton.Create(WizardForm);
  LogButton.Parent := WizardForm.FinishedPage;
  LogButton.Caption := CustomMessage('ShowSetupLog');
  LogButton.Width := WizardForm.CalculateButtonWidth([LogButton.Caption]);
  LogButton.Height := WizardForm.NextButton.Height;
  LogButton.Left := WizardForm.FinishedLabel.Left;
  LogButton.Top := WizardForm.FinishedPage.ClientHeight - LogButton.Height - ScaleY(12);
  LogButton.OnClick := @OpenSetupLogsClick;
  { The list of things to start runs down to the page's bottom edge. }
  if LogButton.Top - ScaleY(8) > WizardForm.RunList.Top then
    WizardForm.RunList.Height := LogButton.Top - ScaleY(8) - WizardForm.RunList.Top;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
    AddLogButton();
end;

#if Variant == "full"
const
  ShortcutFileName = 'NetRuleRouter.lnk';

var
  InstallForPage: TInputOptionWizardPage;
  { 'all' or 'me', settled when the installation starts. }
  InstallFor: String;
  { The per-user shortcuts this installation leaves in place, '' for none. }
  OwnShortcut, OwnDesktop: String;
  KeepEarlierShortcut: Boolean;

{ A silent Setup has no one else to ask about: "me" is the account it runs as. }
<event('InitializeWizard')>
procedure InstallForInitializeWizard();
var
  Starter: Boolean;
  Text, Initial: String;
begin
  if WizardSilent() then
    Exit;
  Starter := SetupRunsAsStarter();
  Text := CustomMessage('InstallForText');
  if not Starter then
    Text := Text + #13#10#13#10 + CustomMessage('InstallForOnlyMeUnavailable');
  InstallForPage := CreateInputOptionPage(wpWelcome, CustomMessage('InstallForTitle'),
    CustomMessage('InstallForDescription'), Text, True, False);
  InstallForPage.Add(CustomMessage('InstallForAllUsers'));
  if Starter then
    InstallForPage.Add(FmtMessage(CustomMessage('InstallForOnlyMe'), [GetUserNameString()]))
  else
  begin
    InstallForPage.Add(CustomMessage('InstallForOnlyMeOff'));
    InstallForPage.CheckListBox.ItemEnabled[1] := False;
  end;
  Initial := InstallForParam();
  if Initial = '' then
    Initial := GetPreviousData('InstallFor', 'all');
  if Starter and (Initial = 'me') then
    InstallForPage.SelectedValueIndex := 1
  else
    InstallForPage.SelectedValueIndex := 0;
end;

{ Only the shortcut file itself: the earlier path lies in a folder its owner controls. }
procedure DeleteShortcut(const Path: String);
begin
  if CompareText(ExtractFileName(Path), ShortcutFileName) <> 0 then
    Exit;
  if FileExists(Path) and not DeleteFile(Path) then
    Log('the earlier shortcut was not removed: ' + Path);
end;

<event('CurStepChanged')>
procedure InstallForStepChanged(CurStep: TSetupStep);
var
  Earlier, EarlierDesktop: String;
begin
  if CurStep <> ssInstall then
    Exit;
  Earlier := GetPreviousData('OwnShortcut', '');
  if InstallForPage <> nil then
  begin
    if InstallForPage.SelectedValueIndex = 1 then
      InstallFor := 'me'
    else
      InstallFor := 'all';
  end
  else
  begin
    InstallFor := InstallForParam();
    { A silent upgrade that does not say leaves the earlier person's shortcut be. }
    if InstallFor = '' then
    begin
      InstallFor := GetPreviousData('InstallFor', 'all');
      KeepEarlierShortcut := InstallFor = 'me';
    end;
  end;
  if KeepEarlierShortcut then
    OwnShortcut := Earlier
  else if InstallFor = 'me' then
    OwnShortcut := ExpandConstant('{userprograms}\' + ShortcutFileName)
  else
    OwnShortcut := '';
  { A changed choice takes away the shortcut the earlier one made. }
  if InstallFor = 'me' then
    DeleteShortcut(ExpandConstant('{commonprograms}\' + ShortcutFileName));
  if (Earlier <> '') and (CompareText(Earlier, OwnShortcut) <> 0) then
    DeleteShortcut(Earlier);
  Log(Format('Start menu shortcut for: %s %s', [InstallFor, OwnShortcut]));

  { The desktop shortcut follows the same choice, and goes when unticked. }
  EarlierDesktop := GetPreviousData('OwnDesktop', '');
  if KeepEarlierShortcut then
    OwnDesktop := EarlierDesktop
  else if WizardIsTaskSelected('desktopicon') and (InstallFor = 'me') then
    OwnDesktop := ExpandConstant('{userdesktop}\' + ShortcutFileName)
  else
    OwnDesktop := '';
  if (InstallFor = 'me') or not WizardIsTaskSelected('desktopicon') then
    DeleteShortcut(ExpandConstant('{commondesktop}\' + ShortcutFileName));
  if (EarlierDesktop <> '') and (CompareText(EarlierDesktop, OwnDesktop) <> 0) then
    DeleteShortcut(EarlierDesktop);
end;

function ShortcutForAll(): Boolean;
begin
  Result := InstallFor <> 'me';
end;

function ShortcutForMe(): Boolean;
begin
  Result := (InstallFor = 'me') and not KeepEarlierShortcut;
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(PreviousDataKey, 'InstallFor', InstallFor);
  SetPreviousData(PreviousDataKey, 'OwnShortcut', OwnShortcut);
  SetPreviousData(PreviousDataKey, 'OwnDesktop', OwnDesktop);
end;
#endif

{ The PATH of every user, or with "only me" of the account Setup runs as, gets
  bin; the other scope loses an entry an earlier choice left. }
function PathForMe(): Boolean;
begin
#if Variant == "full"
  Result := InstallFor = 'me';
#else
  Result := False;
#endif
end;

<event('CurStepChanged')>
procedure ConsoleStepChanged(CurStep: TSetupStep);
var
  Wanted: Boolean;
  Arguments: String;
begin
  if CurStep <> ssPostInstall then
    Exit;
  Wanted := WizardIsTaskSelected('addtopath');
  { Links always: the app's own "add to PATH" setting registers bin too. }
  Arguments := '-Action ConsoleLinks -Links';
  ShowStatus('StatusConsoleLinks');
  if RunAction(ExpandConstant('{app}\scripts\setup-actions.ps1'), Arguments) <> 0 then
    Log('the console links in ' + ConsoleBin() + ' are incomplete');
  EditPath(HKLM, MachineEnvironmentKey, ConsoleBin(), Wanted and not PathForMe());
  EditPath(HKCU, UserEnvironmentKey, ConsoleBin(), Wanted and PathForMe());
end;
