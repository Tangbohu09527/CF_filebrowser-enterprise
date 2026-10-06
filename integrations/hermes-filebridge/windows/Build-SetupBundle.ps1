# CI packaging only. No installation/profile access and no application changes.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$EvidenceDirectory,
      [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit,
      [string]$GoExecutable='go')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$evidence=[IO.Path]::GetFullPath($EvidenceDirectory)
$output=Join-Path $evidence 'windows-setup'
if(Test-Path -LiteralPath $output){throw 'CF_SETUP_BUILD_DESTINATION_EXISTS'}
[IO.Directory]::CreateDirectory($output)|Out-Null
$bundle=Join-Path $evidence 'inbound-bundle'
$inventoryPath=Join-Path $bundle 'inventory.json'
$inventory=[IO.File]::ReadAllText($inventoryPath)|ConvertFrom-Json
if($inventory.schema -cne 'cf-inbound-bundle/v1' -or $inventory.source_commit -cne $SourceCommit){throw 'CF_SETUP_BUILD_SOURCE_CONFLICT'}
$members=@('Setup-FileBridge.ps1','Setup-Lifecycle.ps1','Setup-Fresh.ps1','Upgrade-InboundClient.ps1',
    'ConfigFile.ps1','Manage-InboundClient.ps1','inbound_upgrade_config.py')
foreach($name in $members){[IO.File]::Copy((Join-Path $PSScriptRoot $name),(Join-Path $output $name),$false)}
$targetBundle=Join-Path $output 'inbound-bundle';[IO.Directory]::CreateDirectory($targetBundle)|Out-Null
[IO.Directory]::CreateDirectory((Join-Path $targetBundle 'plugin'))|Out-Null
foreach($property in $inventory.files.PSObject.Properties) {
    if($property.Name -notmatch '^(filebridge-inbound.exe|content-wheels.zip|requirements-inbound-content.txt|plugin/(__init__.py|plugin.yaml|inbound.py|inbound_control.py|inbound_directory.py|inbound_host.py|inbound_content.py))$'){throw 'CF_SETUP_BUILD_MEMBER_REFUSED'}
    $source=Join-Path $bundle $property.Name
    if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $property.Value){throw 'CF_SETUP_BUILD_MEMBER_HASH'}
    [IO.File]::Copy($source,(Join-Path $targetBundle $property.Name),$false)
}
[IO.File]::Copy($inventoryPath,(Join-Path $targetBundle 'inventory.json'),$false)
[IO.File]::Copy((Join-Path $evidence 'filebridge-source.tar.gz'),(Join-Path $output 'filebridge-source.tar.gz'),$false)
$files=[ordered]@{}
foreach($file in @(Get-ChildItem -LiteralPath $output -File -Recurse | Sort-Object FullName)) {
    if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'CF_SETUP_BUILD_REPARSE_REFUSED'}
    $files.Add($file.FullName.Substring($output.Length+1).Replace('\','/'),(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant())
}
$manifest=[ordered]@{schema='cf-filebridge-setup/v1';source_commit=$SourceCommit;
    inventory_sha256=(Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash.ToLowerInvariant();files=$files}
$utf8=[Text.UTF8Encoding]::new($false);$text=($manifest|ConvertTo-Json -Depth 4 -Compress)
[IO.File]::WriteAllText((Join-Path $output 'release-manifest.json'),$text,$utf8)
$encoded=[Convert]::ToBase64String($utf8.GetBytes($text))
$module=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../tools/filebrowser-agentctl'))
& $GoExecutable -C $module build -trimpath -mod=readonly -ldflags ('-H=windowsgui -X main.pinnedManifest='+$encoded) -o (Join-Path $output 'FileBridge-Setup.exe') ./cmd/filebridge-setup
if($LASTEXITCODE -ne 0){throw 'CF_SETUP_BUILD_FAILED'}
$process=Start-Process -FilePath (Join-Path $output 'FileBridge-Setup.exe') -ArgumentList '--verify-package' -WindowStyle Hidden -Wait -PassThru
if($process.ExitCode -ne 0){throw 'CF_SETUP_BUILT_PACKAGE_VERIFICATION_FAILED'}
@{source_commit=$SourceCommit;manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $output 'release-manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant();
  launcher_sha256=(Get-FileHash -LiteralPath (Join-Path $output 'FileBridge-Setup.exe') -Algorithm SHA256).Hash.ToLowerInvariant();payload_count=$files.Count}|ConvertTo-Json -Compress
