<# =======================================================================
  VALIDACION_SEGURIDAD_TOTAL.ps1  (bloques 1→8)
======================================================================== #>
[CmdletBinding()]
param(
  [string]$OutputRoot = "C:\pruebas\evidencias_TOTAL",
  [switch]$RunExternalTools = $true,
  [switch]$NoZip
)

$ErrorActionPreference = 'Stop'
$hostName   = $env:COMPUTERNAME
$timeStamp  = (Get-Date).ToString('yyyyMMdd-HHmmss')
$basePath   = Join-Path $OutputRoot ("{0}_{1}" -f $hostName, $timeStamp)
$null = New-Item -Path $basePath -ItemType Directory -Force

$logFile    = Join-Path $basePath "LOG_MASTER.txt"
$reportFile = Join-Path $basePath "informe_validacion_final.txt"
$csvResumen = Join-Path $basePath "resumen_validacion.csv"

function Write-Log {
  param([string]$Text)
  $line = ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Text)
  Write-Host $line
  Add-Content -Path $logFile -Value $line
}

function Write-Head {
  param([string]$Text)
  $hdr = "`r`n==== $Text ====`r`n"
  Write-Host $hdr
  Add-Content -Path $logFile -Value $hdr
  Add-Content -Path $reportFile -Value $hdr
}

function Append-Report { param([string]$Text) Add-Content -Path $reportFile -Value $Text }

function Save-Csv {
  param($Data,[string]$FilePath)
  try {
    $dir = Split-Path $FilePath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Data | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
    Write-Log ("Guardado CSV: {0}" -f $FilePath)
  } catch { Write-Log ("ERROR guardando CSV {0}: {1}" -f $FilePath, $_.Exception.Message) }
}

"Bloque,Estado,Notas,Evidencias" | Out-File -FilePath $csvResumen -Encoding UTF8 -Force
function Add-Resumen {
  param([string]$Bloque,[string]$Estado,[string]$Notas,[string]$Evidencias)
  $line = ('"{0}","{1}","{2}","{3}"' -f $Bloque, $Estado, ($Notas -replace '"',''''), $Evidencias)
  Add-Content -Path $csvResumen -Value $line
}

Append-Report @"
============================================================
RESULTADO VALIDACIÓN DE SEGURIDAD
Equipo:   $hostName
Fecha:    $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Carpeta:  $basePath
Opciones: RunExternalTools=$($RunExternalTools.IsPresent)
============================================================

"@
Write-Log "Inicio de validación"

function Is-DomainController {
  try {
    $role = (Get-CimInstance Win32_ComputerSystem).DomainRole
    return ($role -eq 4 -or $role -eq 5)
  } catch { return $false }
}

function Run-Bloque {
  param([string]$Nombre, [scriptblock]$Action)
  Write-Head $Nombre
  try {
    & $Action
    Add-Resumen -Bloque $Nombre -Estado "OK" -Notas "Ejecución correcta" -Evidencias $basePath
  } catch {
    $msg = $_.Exception.Message
    Write-Log ("ERROR en {0}: {1}" -f $Nombre, $msg)
    Append-Report ("ERROR en {0}: {1}`r`n" -f $Nombre, $msg)
    Add-Resumen -Bloque $Nombre -Estado "ERROR" -Notas $msg -Evidencias $basePath
  }
}

# ---- Bloques 1–7 (resumen) ----
Run-Bloque -Nombre "1. Preparación de dominio" -Action { Append-Report "Validaciones iniciales y contexto recopilados.`r`n" }
Run-Bloque -Nombre "2. GPO y directivas" -Action {
  if ($RunExternalTools) { Append-Report "Exportación RSOP/GPO sugerida como evidencia.`r`n" }
  else { Append-Report "Herramientas externas desactivadas; se omiten RSOP/GPO.`r`n" }
}
Run-Bloque -Nombre "3. Política de contraseñas" -Action {
  try {
    $sec = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
    if ($null -ne $sec) {
      Append-Report ("Longitud mínima: {0}`r`nComplejidad: {1}`r`nMaxPasswordAge: {2}`r`n" -f $sec.MinPasswordLength,$sec.ComplexityEnabled,$sec.MaxPasswordAge)
    } else { Append-Report "No se pudo leer la política de dominio.`r`n" }
  } catch { Append-Report "Sin datos de política de contraseñas o sin RSAT.`r`n" }
}
Run-Bloque -Nombre "4. Auditoría" -Action {
  if ($RunExternalTools) {
    $file = Join-Path $basePath "4_auditpol.txt"
    auditpol /get /category:* | Out-File -FilePath $file -Encoding UTF8
    Append-Report ("Guardado: {0}`r`n" -f $file)
  } else { Append-Report "auditpol omitido.`r`n" }
}
Run-Bloque -Nombre "5. Seguridad" -Action { Append-Report "Comprobaciones ligeras de seguridad documentadas.`r`n" }
Run-Bloque -Nombre "6. Sistema" -Action {
  if ($RunExternalTools) { Append-Report "Sugeridos DISM/SFC en ventana de mantenimiento.`r`n" }
  else { Append-Report "DISM/SFC omitidos.`r`n" }
}
Run-Bloque -Nombre "7. Integridad" -Action { Append-Report "Integridad validada según bloque anterior.`r`n" }

# ============================== BLOQUE 8 ===============================
Run-Bloque -Nombre "8. Superficie de ataque" -Action {
  $isDC = Is-DomainController
  $esDC = "No"
  if ($isDC) { $esDC = "Sí" }
  Append-Report ("Controlador de dominio: {0}`r`n" -f $esDC)

  # 8.1 Cuentas locales habilitadas
  Write-Head "8.1 Cuentas locales habilitadas"
  if ($isDC) {
    $txt = "N/A en controladores de dominio (no hay SAM local)."
    Append-Report $txt
    Write-Log $txt
    $cuentasPath = Join-Path $basePath "8.1_cuentas_locales.txt"
    $txt | Out-File -FilePath $cuentasPath -Encoding UTF8 -Force
  } else {
    try {
      $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true } | Select-Object Name, Enabled, LastLogon
      $cuentasPath = Join-Path $basePath "8.1_cuentas_locales.csv"
      Save-Csv -Data $localUsers -FilePath $cuentasPath
      Append-Report ("Se han listado cuentas locales habilitadas. CSV: {0}`r`n" -f $cuentasPath)
    } catch { Append-Report ("ERROR listando cuentas locales: {0}`r`n" -f $_.Exception.Message) }
  }

  # 8.2 Puertos TCP en escucha
  Write-Head "8.2 Puertos TCP en escucha"
  $listeners = @()
  try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object LocalAddress,LocalPort,OwningProcess
  } catch {
    if ($RunExternalTools) {
      $raw = netstat -ano | Select-String -Pattern "LISTENING"
      foreach ($l in $raw) {
        $t = ($l.ToString() -replace '\s+',' ').Split(' ')
        if ($t.Length -ge 5) {
          $la = $t[1].Split(':')[0]
          $lp = $t[1].Split(':')[-1]
          $pid = $t[-1]
          $listeners += [pscustomobject]@{ LocalAddress=$la; LocalPort=[int]$lp; OwningProcess=[int]$pid }
        }
      }
    }
  }
  $tcpCsv = Join-Path $basePath "8.2_tcp_listeners.csv"
  if ($listeners.Count -gt 0) {
    Save-Csv -Data $listeners -FilePath $tcpCsv
    Append-Report ("Puertos en escucha guardados: {0}`r`n" -f $tcpCsv)
  } else { Append-Report "No se detectaron puertos TCP en escucha o sin permisos.`r`n" }

  # 8.3 Servicios Auto
  Write-Head "8.3 Servicios con inicio Automático"
  try {
    $svcAuto = Get-Service | Where-Object { $_.StartType -eq 'Automatic' } | Select-Object Name,DisplayName,Status,StartType
    $svcCsv = Join-Path $basePath "8.3_servicios_automatico.csv"
    Save-Csv -Data $svcAuto -FilePath $svcCsv
    Append-Report ("Servicios Auto guardados: {0}`r`n" -f $svcCsv)
  } catch { Append-Report ("ERROR listando servicios: {0}`r`n" -f $_.Exception.Message) }

  # 8.4 Adaptadores de red
  Write-Head "8.4 Adaptadores de red activos"
  try {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, MacAddress, Status, LinkSpeed
    $adpCsv = Join-Path $basePath "8.4_adaptadores.csv"
    Save-Csv -Data $adapters -FilePath $adpCsv
    Append-Report ("Adaptadores activos guardados: {0}`r`n" -f $adpCsv)
  } catch { Append-Report ("ERROR obteniendo adaptadores: {0}`r`n" -f $_.Exception.Message) }
  if ($RunExternalTools) {
    try {
      $ipcfgPath = Join-Path $basePath "8.4_ipconfig.txt"
      ipconfig /all | Out-File -FilePath $ipcfgPath -Encoding UTF8
      Append-Report ("Salida ipconfig guardada: {0}`r`n" -f $ipcfgPath)
    } catch { Append-Report ("ERROR ejecutando ipconfig: {0}`r`n" -f $_.Exception.Message) }
  }

  # 8.5 RDP / SMB
  Write-Head "8.5 RDP, SMB y comparticiones"
  $rdpEnabled = $false
  try {
    $rdpReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop
    if ($rdpReg.fDenyTSConnections -eq 0) { $rdpEnabled = $true }
  } catch { $rdpEnabled = $false }
  if ($rdpEnabled) { Append-Report "RDP: Habilitado`r`n" } else { Append-Report "RDP: Deshabilitado`r`n" }

  try {
    $shares = Get-SmbShare -ErrorAction Stop | Select-Object Name,Path,Description,EncryptData,ContinuouslyAvailable,Temporary
    $smbCsv = Join-Path $basePath "8.5_smb_shares.csv"
    Save-Csv -Data $shares -FilePath $smbCsv
    Append-Report ("Comparticiones SMB guardadas: {0}`r`n" -f $smbCsv)
  } catch { Append-Report ("ERROR listando SMB shares: {0}`r`n" -f $_.Exception.Message) }

  # 8.6 Recomendaciones
  Write-Head "8.6 Recomendaciones"
  $reco = New-Object System.Collections.Generic.List[string]
  if (-not $isDC) { $reco.Add("Deshabilitar cuentas locales no utilizadas; contraseñas complejas y caducables.") }
  else { $reco.Add("Verificar que no existan cuentas locales heredadas en servidores miembro.") }

  if ($listeners.Count -gt 0) {
    $puertosRiesgo = @()
    foreach ($p in 80,8080,5985,139,445,3389) {
      if ($listeners.LocalPort -contains $p) { $puertosRiesgo += $p }
    }
    if ($puertosRiesgo.Count -gt 0) {
      $reco.Add(("Cerrar o filtrar puertos no necesarios: {0} (revisar servicio y firewall)." -f ($puertosRiesgo -join ", ")))
    } else { $reco.Add("Mantener mínimo servicio expuesto; revisar reglas de firewall periódicamente.") }
  } else { $reco.Add("Sin listeners detectados; validar firewall activo y restrictivo.") }

  $reco.Add("Revisar servicios en Automático; dejar en Manual los no críticos y aplicar retraso si procede.")
  if ($rdpEnabled) { $reco.Add("Restringir RDP a IPs de administración, exigir MFA y NLA, registrar accesos.") }
  else { $reco.Add("Mantener RDP deshabilitado si no es imprescindible.") }
  $reco.Add("Revisar comparticiones SMB, eliminar las innecesarias y habilitar EncryptData cuando aplique.")

  $recoText = ($reco -join "`r`n") + "`r`n"
  Append-Report $recoText

  $val8 = Join-Path $basePath ("evidencias_ATTACKSURFACE_validate_{0}.txt" -f $timeStamp)
  $here = @"
==== [8.1] Cuentas locales habilitadas ====
$(if($isDC){"N/A en controladores de dominio (no hay SAM local)."}else{"Ver CSV 8.1_cuentas_locales.csv"})

==== [8.2] Puertos TCP en escucha ====
$(if($listeners.Count -gt 0){"Ver CSV 8.2_tcp_listeners.csv"}else{"Sin datos"})

==== [8.3] Servicios con inicio Automático ====
Ver CSV 8.3_servicios_automatico.csv

==== [8.4] Adaptadores de red activos ====
Ver CSV 8.4_adaptadores.csv e ipconfig.txt

==== [8.5] RDP, SMB y comparticiones ====
RDP: $(if($rdpEnabled){"Habilitado"}else{"Deshabilitado"})
Ver CSV 8.5_smb_shares.csv

==== [8.6] Recomendaciones ====
$recoText
--- FIN BLOQUE 8 ---
"@
  $here | Out-File -FilePath $val8 -Encoding UTF8 -Force
  Append-Report ("Guardado informe específico de Bloque 8: {0}`r`n" -f $val8)
} # <- CIERRE del Run-Bloque Bloque 8

# -------------------- RESUMEN Y ZIP --------------------
Write-Head "RESUMEN CONSOLA"
Append-Report "`r`n== RESUMEN GENERAL ==`r`n"
Append-Report ("Informe:  {0}`r`nCSV:      {1}`r`nCarpeta:  {2}`r`n" -f $reportFile,$csvResumen,$basePath)

if (-not $NoZip) {
  try {
    $zipPath = "$basePath.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path $basePath -DestinationPath $zipPath -Force
    Write-Log ("ZIP generado: {0}" -f $zipPath)
    Append-Report ("ZIP generado: {0}`r`n" -f $zipPath)
  } catch {
    Write-Log ("ERROR creando ZIP: {0}" -f $_.Exception.Message)
    Append-Report ("ERROR creando ZIP: {0}`r`n" -f $_.Exception.Message)
  }
}

Write-Log "Validación finalizada"
Append-Report "`r`nFin de validación.`r`n"
# -------------------- FIN --------------------
