param([Parameter(Mandatory=$true)][string]$Binary, [ValidateRange(1024,65535)][int]$Port=18089)
$ErrorActionPreference='Stop'
$taskRepo=Split-Path -Parent $PSScriptRoot
$taskBinary=(Resolve-Path -LiteralPath $Binary).Path
$taskRoot=Join-Path $taskRepo '.local\recycle-preview'
$taskData=Join-Path $taskRoot 'data'
$taskMarker=Join-Path $taskRoot '.synthetic-preview'
if ((Test-Path -LiteralPath $taskRoot) -and !(Test-Path -LiteralPath $taskMarker)) { throw 'Refusing to adopt an existing non-fixture directory' }
if (!(Test-Path -LiteralPath $taskRoot)) {
  New-Item -ItemType Directory -Path $taskData -Force | Out-Null
  New-Item -ItemType File -Path $taskMarker | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $taskData 'normal-folder') | Out-Null
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'recycle-preview\synthetic-recycle.png') -Destination $taskData
  [IO.File]::WriteAllText((Join-Path $taskData 'synthetic-notes.txt'),'Synthetic recycle-bin acceptance fixture only.')
}
$taskDataYaml=$taskData.Replace('\','/').Replace("'","''")
$taskRootYaml=$taskRoot.Replace('\','/').Replace("'","''")
$taskConfig=@"
server:
  listen: '127.0.0.1'
  port: $Port
  baseURL: '/'
  database: '$taskRootYaml/fixture.db'
  cacheDir: '$taskRootYaml/cache'
  disableUpdateCheck: true
  logging:
    - levels: 'info|warning|error'
  sources:
    - name: 'synthetic-data'
      path: '$taskDataYaml'
      config:
        defaultEnabled: true
        defaultUserScope: '/'
auth:
  methods:
    noauth: true
userDefaults:
  listing:
    showHidden: true
    deleteWithoutConfirming: false
"@
$taskConfigFile=Join-Path $taskRoot 'config.yaml'
[IO.File]::WriteAllText($taskConfigFile,$taskConfig)
$taskStart=[Diagnostics.ProcessStartInfo]::new($taskBinary)
$taskStart.ArgumentList.Add('-c')
$taskStart.ArgumentList.Add($taskConfigFile)
$taskStart.WorkingDirectory=$taskRoot
$taskStart.UseShellExecute=$false
$taskStart.CreateNoWindow=$true
# Isolate the child from any existing FileBrowser deployment configuration or
# credentials without reading, modifying, printing, or deleting their values.
foreach ($taskName in @($taskStart.Environment.Keys)) {
  if ($taskName.StartsWith('FILEBROWSER_')) { [void]$taskStart.Environment.Remove($taskName) }
}
$taskProcess=[Diagnostics.Process]::Start($taskStart)
Write-Output "Synthetic preview PID: $($taskProcess.Id)"
Write-Output "Synthetic preview origin: http://127.0.0.1:$Port"
Write-Output 'This script does not open a browser or remove existing test files or journals.'
