#!/usr/bin/env bash
# =======================================================================
# VALIDACION_SEGURIDAD_DEBIAN.sh
# Adaptación para Debian del script VALIDACION_SEGURIDAD_TOTAL.ps1
# Objetivo: recopilar evidencias de configuración y superficie de ataque.
# No aplica cambios de hardening: valida, documenta y recomienda.
# =======================================================================

set -u
set -o pipefail

OUTPUT_ROOT="/var/tmp/evidencias_DEBIAN"
RUN_EXTERNAL_TOOLS=1
NO_ARCHIVE=0

usage() {
  cat <<USAGE
Uso:
  sudo bash $0 [opciones]

Opciones:
  --output-root RUTA       Carpeta raíz de evidencias. Por defecto: /var/tmp/evidencias_DEBIAN
  --no-external-tools      Omite herramientas externas opcionales cuando sea posible.
  --no-zip                 No genera archivo comprimido final.
  -h, --help               Muestra esta ayuda.

Ejemplos:
  sudo bash $0
  sudo bash $0 --output-root /root/evidencias --no-zip
  bash $0 --output-root ./evidencias --no-external-tools
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-root)
      OUTPUT_ROOT="${2:-}"
      shift 2
      ;;
    --no-external-tools)
      RUN_EXTERNAL_TOOLS=0
      shift
      ;;
    --no-zip|--no-archive)
      NO_ARCHIVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Opción no reconocida: $1" >&2
      usage
      exit 2
      ;;
  esac
done

HOST_NAME="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo debian-host)"
TIME_STAMP="$(date +%Y%m%d-%H%M%S)"
BASE_PATH="${OUTPUT_ROOT%/}/${HOST_NAME}_${TIME_STAMP}"
LOG_FILE="$BASE_PATH/LOG_MASTER.txt"
REPORT_FILE="$BASE_PATH/informe_validacion_final.txt"
CSV_RESUMEN="$BASE_PATH/resumen_validacion.csv"

mkdir -p "$BASE_PATH"

log() {
  local text="$*"
  local line
  line="[$(date '+%Y-%m-%d %H:%M:%S')] $text"
  echo "$line"
  printf '%s\n' "$line" >> "$LOG_FILE"
}

head_section() {
  local text="$*"
  local hdr
  hdr=$'\n==== '"$text"$' ====\n'
  echo "$hdr"
  printf '%s\n' "$hdr" >> "$LOG_FILE"
  printf '%s\n' "$hdr" >> "$REPORT_FILE"
}

append_report() {
  printf '%b' "$*" >> "$REPORT_FILE"
}

csv_escape() {
  local value="${1:-}"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

add_resumen() {
  local bloque="$1"
  local estado="$2"
  local notas="$3"
  local evidencias="$4"
  {
    csv_escape "$bloque"; printf ','
    csv_escape "$estado"; printf ','
    csv_escape "$notas"; printf ','
    csv_escape "$evidencias"; printf '\n'
  } >> "$CSV_RESUMEN"
}

run_cmd_to_file() {
  local out_file="$1"
  shift
  {
    echo "# Comando: $*"
    echo "# Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo
    "$@"
  } > "$out_file" 2>&1
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

is_root() {
  [[ "$(id -u)" -eq 0 ]]
}

is_debian() {
  [[ -r /etc/os-release ]] && grep -qiE '^ID=(debian|ubuntu)|^ID_LIKE=.*debian' /etc/os-release
}

is_samba_dc() {
  if command_exists systemctl && systemctl is-active --quiet samba-ad-dc 2>/dev/null; then
    return 0
  fi
  if command_exists samba && samba -b 2>/dev/null | grep -qi 'AD DC'; then
    return 0
  fi
  return 1
}

quote_csv_line() {
  local first=1
  for value in "$@"; do
    if [[ $first -eq 0 ]]; then printf ','; fi
    csv_escape "$value"
    first=0
  done
  printf '\n'
}

write_file_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -e "$src" ]]; then
    cp -a "$src" "$dst" 2>/dev/null || cat "$src" > "$dst" 2>&1 || true
  else
    printf 'No existe: %s\n' "$src" > "$dst"
  fi
}

run_block() {
  local nombre="$1"
  local function_name="$2"
  head_section "$nombre"
  set +e
  "$function_name"
  local rc=$?
  set -e 2>/dev/null || true
  if [[ $rc -eq 0 ]]; then
    add_resumen "$nombre" "OK" "Ejecución correcta" "$BASE_PATH"
  else
    log "ERROR en $nombre: código de salida $rc"
    append_report "ERROR en $nombre: código de salida $rc\n"
    add_resumen "$nombre" "ERROR" "Código de salida $rc" "$BASE_PATH"
  fi
}

# Cabeceras iniciales
quote_csv_line "Bloque" "Estado" "Notas" "Evidencias" > "$CSV_RESUMEN"

cat > "$REPORT_FILE" <<HEADER
============================================================
RESULTADO VALIDACIÓN DE SEGURIDAD - DEBIAN
Equipo:   $HOST_NAME
Fecha:    $(date '+%Y-%m-%d %H:%M:%S')
Carpeta:  $BASE_PATH
Opciones: RunExternalTools=$RUN_EXTERNAL_TOOLS
============================================================

HEADER

log "Inicio de validación Debian"

if ! is_debian; then
  log "AVISO: el sistema no parece Debian/derivado según /etc/os-release. El script continuará en modo best effort."
fi

if ! is_root; then
  log "AVISO: no se está ejecutando como root. Algunas evidencias de /etc/shadow, auditd, firewall o servicios pueden quedar incompletas."
  append_report "AVISO: ejecución sin privilegios root; evidencias potencialmente incompletas.\n\n"
fi

# -----------------------------------------------------------------------
# BLOQUE 1
# -----------------------------------------------------------------------
block_1_preparacion() {
  local ctx="$BASE_PATH/1_contexto_sistema.txt"
  {
    echo "==== Identidad del sistema ===="
    echo "Hostname corto: $HOST_NAME"
    hostnamectl 2>/dev/null || hostname 2>/dev/null || true
    echo
    echo "==== Sistema operativo ===="
    cat /etc/os-release 2>/dev/null || true
    echo
    echo "==== Kernel ===="
    uname -a
    echo
    echo "==== Uptime ===="
    uptime || true
    echo
    echo "==== Fecha/hora ===="
    date -Is
    timedatectl 2>/dev/null || true
    echo
    echo "==== Usuario de ejecución ===="
    id
    echo
    echo "==== Virtualización ===="
    systemd-detect-virt 2>/dev/null || true
  } > "$ctx" 2>&1

  append_report "Validaciones iniciales y contexto recopilados.\nGuardado: $ctx\n\n"
}

# -----------------------------------------------------------------------
# BLOQUE 2
# -----------------------------------------------------------------------
block_2_politicas() {
  local dir="$BASE_PATH/2_politicas_configuracion"
  mkdir -p "$dir"

  write_file_if_exists /etc/login.defs "$dir/login.defs"
  write_file_if_exists /etc/security/pwquality.conf "$dir/pwquality.conf"
  write_file_if_exists /etc/pam.d/common-password "$dir/pam_common-password"
  write_file_if_exists /etc/pam.d/common-auth "$dir/pam_common-auth"
  write_file_if_exists /etc/pam.d/common-account "$dir/pam_common-account"
  write_file_if_exists /etc/sudoers "$dir/sudoers"
  [[ -d /etc/sudoers.d ]] && tar -C /etc -cf "$dir/sudoers.d.tar" sudoers.d 2>/dev/null || true
  write_file_if_exists /etc/ssh/sshd_config "$dir/sshd_config"
  [[ -d /etc/ssh/sshd_config.d ]] && tar -C /etc/ssh -cf "$dir/sshd_config.d.tar" sshd_config.d 2>/dev/null || true

  if command_exists dpkg-query; then
    dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' > "$dir/paquetes_instalados.tsv" 2>&1
  fi

  append_report "Configuración base de seguridad recopilada: PAM, login.defs, sudoers, SSH y paquetes.\nGuardado en: $dir\n\n"
}

# -----------------------------------------------------------------------
# BLOQUE 3
# -----------------------------------------------------------------------
block_3_passwords() {
  local txt="$BASE_PATH/3_politica_contrasenas.txt"
  local csv="$BASE_PATH/3_usuarios_password_estado.csv"

  {
    echo "==== Parámetros /etc/login.defs ===="
    grep -E '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|PASS_MIN_LEN|ENCRYPT_METHOD|SHA_CRYPT_MIN_ROUNDS|SHA_CRYPT_MAX_ROUNDS)' /etc/login.defs 2>/dev/null || true
    echo
    echo "==== PAM common-password ===="
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/pam.d/common-password 2>/dev/null || true
    echo
    echo "==== pwquality.conf ===="
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/security/pwquality.conf 2>/dev/null || true
    echo
    echo "==== faillock / tally / pam_faillock detectado ===="
    grep -R "pam_faillock\|pam_tally" /etc/pam.d /etc/security 2>/dev/null || true
  } > "$txt" 2>&1

  quote_csv_line "Usuario" "UID" "Shell" "EstadoPassword" "UltimoCambio" "MinDias" "MaxDias" "AvisoDias" > "$csv"

  while IFS=: read -r user _ uid _ _ _ shell; do
    [[ -z "$user" ]] && continue
    local estado="N/D"
    local last="N/D"
    local min="N/D"
    local max="N/D"
    local warn="N/D"

    if is_root; then
      local shadow_line
      shadow_line="$(getent shadow "$user" 2>/dev/null || true)"
      local pass_field
      pass_field="$(printf '%s' "$shadow_line" | cut -d: -f2)"
      if [[ "$pass_field" == '!'* || "$pass_field" == '*'* ]]; then
        estado="Bloqueada/sin login por contraseña"
      elif [[ -z "$pass_field" ]]; then
        estado="Sin contraseña"
      else
        estado="Con hash de contraseña"
      fi
      last="$(printf '%s' "$shadow_line" | cut -d: -f3)"
      min="$(printf '%s' "$shadow_line" | cut -d: -f4)"
      max="$(printf '%s' "$shadow_line" | cut -d: -f5)"
      warn="$(printf '%s' "$shadow_line" | cut -d: -f6)"
    else
      if command_exists passwd; then
        estado="$(passwd -S "$user" 2>/dev/null | awk '{print $2}' || echo 'N/D')"
      fi
    fi

    quote_csv_line "$user" "$uid" "$shell" "$estado" "$last" "$min" "$max" "$warn" >> "$csv"
  done < <(getent passwd)

  append_report "Política de contraseñas y estado de usuarios recopilados.\nTXT: $txt\nCSV: $csv\n\n"
}

# -----------------------------------------------------------------------
# BLOQUE 4
# -----------------------------------------------------------------------
block_4_auditoria() {
  local dir="$BASE_PATH/4_auditoria"
  mkdir -p "$dir"

  if [[ "$RUN_EXTERNAL_TOOLS" -eq 1 ]]; then
    if command_exists systemctl; then
      run_cmd_to_file "$dir/auditd_status.txt" systemctl status auditd --no-pager
      run_cmd_to_file "$dir/systemd_journald_status.txt" systemctl status systemd-journald --no-pager
    fi
    if command_exists auditctl; then
      run_cmd_to_file "$dir/auditctl_status.txt" auditctl -s
      run_cmd_to_file "$dir/auditctl_rules.txt" auditctl -l
    else
      echo "auditctl no instalado o no disponible." > "$dir/auditctl_status.txt"
    fi
    if command_exists journalctl; then
      run_cmd_to_file "$dir/journalctl_boot_errors.txt" journalctl -p warning..alert -b --no-pager
    fi
    if command_exists last; then
      run_cmd_to_file "$dir/ultimos_logins.txt" last -a -n 50
    fi
    if command_exists lastb; then
      run_cmd_to_file "$dir/ultimos_logins_fallidos.txt" lastb -a -n 50
    fi
  else
    echo "Herramientas externas desactivadas; se omiten auditctl/journalctl/last." > "$dir/auditoria_omitida.txt"
  fi

  [[ -d /etc/audit ]] && tar -C /etc -cf "$dir/etc_audit.tar" audit 2>/dev/null || true
  write_file_if_exists /etc/systemd/journald.conf "$dir/journald.conf"

  append_report "Auditoría recopilada: auditd/auditctl, journald y últimos accesos cuando están disponibles.\nGuardado en: $dir\n\n"
}

# -----------------------------------------------------------------------
# BLOQUE 5
# -----------------------------------------------------------------------
block_5_seguridad() {
  local dir="$BASE_PATH/5_seguridad"
  mkdir -p "$dir"

  if command_exists systemctl; then
    run_cmd_to_file "$dir/ssh_status.txt" systemctl status ssh --no-pager
    run_cmd_to_file "$dir/apparmor_status_systemd.txt" systemctl status apparmor --no-pager
    run_cmd_to_file "$dir/ufw_status_systemd.txt" systemctl status ufw --no-pager
    run_cmd_to_file "$dir/fail2ban_status_systemd.txt" systemctl status fail2ban --no-pager
    run_cmd_to_file "$dir/unattended_upgrades_status.txt" systemctl status unattended-upgrades --no-pager
  fi

  if command_exists sshd; then
    sshd -T > "$dir/sshd_effective_config.txt" 2>&1 || true
  fi
  if command_exists ufw; then
    run_cmd_to_file "$dir/ufw_status_verbose.txt" ufw status verbose
  else
    echo "ufw no instalado." > "$dir/ufw_status_verbose.txt"
  fi
  if command_exists nft; then
    run_cmd_to_file "$dir/nft_ruleset.txt" nft list ruleset
  else
    echo "nft no instalado." > "$dir/nft_ruleset.txt"
  fi
  if command_exists iptables-save; then
    run_cmd_to_file "$dir/iptables_save.txt" iptables-save
  fi
  if command_exists aa-status; then
    run_cmd_to_file "$dir/apparmor_aa_status.txt" aa-status
  fi
  if command_exists fail2ban-client; then
    run_cmd_to_file "$dir/fail2ban_status.txt" fail2ban-client status
  fi

  write_file_if_exists /etc/apt/apt.conf.d/50unattended-upgrades "$dir/50unattended-upgrades"
  write_file_if_exists /etc/apt/apt.conf.d/20auto-upgrades "$dir/20auto-upgrades"

  append_report "Comprobaciones de seguridad documentadas: SSH, firewall, AppArmor, fail2ban y actualizaciones automáticas.\nGuardado en: $dir\n\n"
}

# -----------------------------------------------------------------------
# BLOQUE 6
# -----------------------------------------------------------------------
block_6_sistema() {
  local dir="$BASE_PATH/6_sistema"
  mkdir -p "$dir"

  if command_exists systemctl; then
    run_cmd_to_file "$dir/systemctl_failed.txt" systemctl --failed --no-pager
    run_cmd_to_file "$dir/systemctl_timers.txt" systemctl list-timers --all --no-pager
    run_cmd_to_file "$dir/systemctl_enabled_services.txt" systemctl list-unit-files --type=service --state=enabled --no-pager
  fi

  run_cmd_to_file "$dir/df_h.txt" df -hT
  run_cmd_to_file "$dir/free_h.txt" free -h
  run_cmd_to_file "$dir/lsblk.txt" lsblk -f
  run_cmd_to_file "$dir/mounts.txt" findmnt
  write_file_if_exists /etc/fstab "$dir/fstab"
  write_file_if_exists /proc/cmdline "$dir/kernel_cmdline.txt"

  if command_exists apt; then
    run_cmd_to_file "$dir/apt_upgradable.txt" apt list --upgradable
  fi
  if command_exists dpkg; then
    run_cmd_to_file "$dir/dpkg_audit.txt" dpkg --audit
  fi
  if command_exists timedatectl; then
    run_cmd_to_file "$dir/timedatectl.txt" timedatectl
  fi

  append_report "Estado del sistema recopilado: servicios fallidos, timers, disco, memoria, paquetes y hora.\nGuardado en: $dir\n\n"
}

# -----------------------------------------------------------------------
# BLOQUE 7
# -----------------------------------------------------------------------
block_7_integridad() {
  local dir="$BASE_PATH/7_integridad"
  mkdir -p "$dir"

  if command_exists debsums; then
    run_cmd_to_file "$dir/debsums_changed.txt" debsums -s
  else
    echo "debsums no instalado. Recomendación: apt install debsums para verificación de integridad de paquetes." > "$dir/debsums_changed.txt"
  fi

  if command_exists aide; then
    run_cmd_to_file "$dir/aide_check.txt" aide --check
  else
    echo "AIDE no instalado o no disponible." > "$dir/aide_check.txt"
  fi

  if command_exists tripwire; then
    run_cmd_to_file "$dir/tripwire_check.txt" tripwire --check
  else
    echo "Tripwire no instalado o no disponible." > "$dir/tripwire_check.txt"
  fi

  {
    echo "# Checksums de ficheros críticos"
    for f in /etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/login.defs; do
      if [[ -r "$f" ]]; then
        sha256sum "$f"
      else
        echo "No legible o no existe: $f"
      fi
    done
  } > "$dir/checksums_ficheros_criticos.txt" 2>&1

  {
    echo "# Directorios world-writable relevantes"
    find /etc /usr/local /opt -xdev -type d -perm -0002 -print 2>/dev/null || true
  } > "$dir/directorios_world_writable.txt" 2>&1

  append_report "Integridad validada en modo no intrusivo: debsums/AIDE/Tripwire si existen y checksums de ficheros críticos.\nGuardado en: $dir\n\n"
}

# -----------------------------------------------------------------------
# BLOQUE 8
# -----------------------------------------------------------------------
block_8_superficie_ataque() {
  local is_dc="No"
  if is_samba_dc; then is_dc="Sí - Samba AD DC detectado"; fi
  append_report "Controlador de dominio Samba/AD: $is_dc\n"

  # 8.1 Cuentas locales habilitadas
  head_section "8.1 Cuentas locales habilitadas"
  local cuentas_csv="$BASE_PATH/8.1_cuentas_locales.csv"
  quote_csv_line "Usuario" "UID" "GID" "Gecos" "Home" "Shell" "PasswordEstado" "Tipo" > "$cuentas_csv"

  while IFS=: read -r user _ uid gid gecos home shell; do
    [[ -z "$user" ]] && continue
    local tipo="Sistema"
    if [[ "$uid" -ge 1000 && "$user" != "nobody" ]]; then tipo="Humano/servicio local"; fi

    local estado="N/D"
    if is_root; then
      local shadow_line pass_field
      shadow_line="$(getent shadow "$user" 2>/dev/null || true)"
      pass_field="$(printf '%s' "$shadow_line" | cut -d: -f2)"
      if [[ "$pass_field" == '!'* || "$pass_field" == '*'* ]]; then
        estado="Bloqueada/sin contraseña usable"
      elif [[ -z "$pass_field" ]]; then
        estado="Sin contraseña"
      else
        estado="Con contraseña/hash"
      fi
    elif command_exists passwd; then
      estado="$(passwd -S "$user" 2>/dev/null | awk '{print $2}' || echo 'N/D')"
    fi
    quote_csv_line "$user" "$uid" "$gid" "$gecos" "$home" "$shell" "$estado" "$tipo" >> "$cuentas_csv"
  done < <(getent passwd)
  append_report "Se han listado cuentas locales. CSV: $cuentas_csv\n"

  # 8.2 Puertos TCP/UDP en escucha
  head_section "8.2 Puertos en escucha"
  local listeners_csv="$BASE_PATH/8.2_listeners.csv"
  quote_csv_line "Protocolo" "LocalAddress" "LocalPort" "Proceso" "PID" > "$listeners_csv"

  if command_exists ss; then
    ss -H -lntup 2>/dev/null | awk '
      BEGIN { OFS="," }
      {
        proto=$1;
        local=$5;
        proc="";
        pid="";
        for (i=6; i<=NF; i++) proc=proc" "$i;
        gsub(/^ /,"",proc);
        if (match(proc,/pid=[0-9]+/)) pid=substr(proc,RSTART+4,RLENGTH-4);
        addr=local;
        port="";
        if (local ~ /^\[/) {
          sub(/^\[/,"",addr);
          split(addr,a,"\\]:");
          addr=a[1]; port=a[2];
        } else {
          n=split(local,a,":"); port=a[n]; addr=local; sub(":"port"$","",addr);
        }
        gsub(/"/,"""",proto); gsub(/"/,"""",addr); gsub(/"/,"""",port); gsub(/"/,"""",proc); gsub(/"/,"""",pid);
        print "\""proto"\",\""addr"\",\""port"\",\""proc"\",\""pid"\""
      }' >> "$listeners_csv"
    ss -lntup > "$BASE_PATH/8.2_ss_listeners_raw.txt" 2>&1 || true
    append_report "Puertos en escucha guardados: $listeners_csv\n"
  elif command_exists netstat; then
    netstat -tulpen > "$BASE_PATH/8.2_netstat_listeners_raw.txt" 2>&1 || true
    append_report "ss no disponible; se guarda salida netstat raw: $BASE_PATH/8.2_netstat_listeners_raw.txt\n"
  else
    append_report "No se detectó ss ni netstat; no se pudieron listar listeners.\n"
  fi

  # 8.3 Servicios habilitados/activos
  head_section "8.3 Servicios habilitados y activos"
  local svc_csv="$BASE_PATH/8.3_servicios_enabled.csv"
  quote_csv_line "Unidad" "Estado" > "$svc_csv"
  if command_exists systemctl; then
    systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1","$2}' | while IFS=, read -r unit state; do
      quote_csv_line "$unit" "$state" >> "$svc_csv"
    done
    systemctl --type=service --state=running --no-legend --no-pager > "$BASE_PATH/8.3_servicios_running.txt" 2>&1 || true
    append_report "Servicios enabled guardados: $svc_csv\nServicios running guardados: $BASE_PATH/8.3_servicios_running.txt\n"
  else
    service --status-all > "$BASE_PATH/8.3_service_status_all.txt" 2>&1 || true
    append_report "systemctl no disponible; se guarda service --status-all.\n"
  fi

  # 8.4 Adaptadores de red activos
  head_section "8.4 Adaptadores de red activos"
  local adp_csv="$BASE_PATH/8.4_adaptadores.csv"
  quote_csv_line "Interfaz" "Estado" "MAC" "MTU" "Direcciones" > "$adp_csv"

  if command_exists ip; then
    while read -r iface state mac mtu; do
      [[ -z "$iface" ]] && continue
      local addrs
      addrs="$(ip -br addr show "$iface" 2>/dev/null | awk '{$1=""; $2=""; sub(/^  */,""); print}')"
      quote_csv_line "$iface" "$state" "$mac" "$mtu" "$addrs" >> "$adp_csv"
    done < <(ip -o link show up | awk -F': ' '{print $2}' | while read -r iface; do
      state="$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo N/D)"
      mac="$(cat "/sys/class/net/$iface/address" 2>/dev/null || echo N/D)"
      mtu="$(cat "/sys/class/net/$iface/mtu" 2>/dev/null || echo N/D)"
      printf '%s %s %s %s\n' "$iface" "$state" "$mac" "$mtu"
    done)
    ip addr show > "$BASE_PATH/8.4_ip_addr.txt" 2>&1 || true
    ip route show table all > "$BASE_PATH/8.4_ip_route.txt" 2>&1 || true
    append_report "Adaptadores activos guardados: $adp_csv\n"
  else
    append_report "Comando ip no disponible; no se pudieron listar adaptadores.\n"
  fi

  # 8.5 SSH, SMB, NFS y comparticiones
  head_section "8.5 SSH, SMB, NFS y comparticiones"
  local remote_txt="$BASE_PATH/8.5_ssh_smb_nfs.txt"
  {
    echo "==== SSH ===="
    if command_exists systemctl; then
      systemctl is-enabled ssh 2>/dev/null | sed 's/^/ssh enabled: /' || true
      systemctl is-active ssh 2>/dev/null | sed 's/^/ssh active: /' || true
    fi
    if command_exists sshd; then
      echo
      echo "==== sshd -T, parámetros relevantes ===="
      sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|challengeresponseauthentication|allowusers|allowgroups|x11forwarding|permitemptypasswords|maxauthtries|clientaliveinterval|loglevel) ' || true
    fi
    echo
    echo "==== Samba/SMB ===="
    if command_exists systemctl; then
      systemctl is-active smbd 2>/dev/null | sed 's/^/smbd active: /' || true
      systemctl is-active nmbd 2>/dev/null | sed 's/^/nmbd active: /' || true
      systemctl is-active samba-ad-dc 2>/dev/null | sed 's/^/samba-ad-dc active: /' || true
    fi
    if command_exists testparm; then
      testparm -s 2>/dev/null || true
    else
      echo "testparm no disponible."
    fi
    echo
    echo "==== NFS ===="
    if command_exists exportfs; then
      exportfs -v 2>/dev/null || true
    else
      echo "exportfs no disponible."
    fi
    echo
    echo "==== /etc/exports ===="
    cat /etc/exports 2>/dev/null || true
    echo
    echo "==== Docker published ports ===="
    if command_exists docker; then
      docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null || true
    else
      echo "docker no disponible."
    fi
  } > "$remote_txt" 2>&1
  append_report "SSH/SMB/NFS/puertos Docker documentados: $remote_txt\n"

  # 8.6 Recomendaciones
  head_section "8.6 Recomendaciones"
  local reco_file="$BASE_PATH/8.6_recomendaciones.txt"
  local reco=()

  local ssh_port_open=0
  local root_login="N/D"
  local pass_auth="N/D"
  local fw_detected=0

  if [[ -s "$listeners_csv" ]] && awk -F, 'NR>1 {gsub(/"/,"",$3); if ($3=="22") found=1} END{exit(found?0:1)}' "$listeners_csv"; then
    ssh_port_open=1
  fi

  if command_exists sshd; then
    root_login="$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin" {print $2; exit}')"
    pass_auth="$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication" {print $2; exit}')"
  fi

  if command_exists ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then fw_detected=1; fi
  if command_exists nft && nft list ruleset 2>/dev/null | grep -q 'table '; then fw_detected=1; fi
  if command_exists iptables-save && iptables-save 2>/dev/null | grep -qE '^-A '; then fw_detected=1; fi

  reco+=("Deshabilitar o bloquear cuentas locales no utilizadas; para usuarios humanos, exigir contraseñas robustas o autenticación por clave/MFA cuando aplique.")

  if [[ "$ssh_port_open" -eq 1 ]]; then
    reco+=("SSH está expuesto en escucha. Restringirlo por firewall a IPs de administración, deshabilitar login directo de root y preferir autenticación por clave pública.")
  else
    reco+=("SSH no aparece en escucha en el puerto 22; validar si la administración remota usa otro puerto o canal bastionado.")
  fi

  if [[ "$root_login" != "N/D" && "$root_login" != "no" ]]; then
    reco+=("Revisar PermitRootLogin: valor actual '$root_login'. Recomendado: no, salvo excepción justificada y controlada.")
  fi
  if [[ "$pass_auth" == "yes" ]]; then
    reco+=("Revisar PasswordAuthentication: valor actual 'yes'. Recomendado: usar claves públicas y, si es posible, deshabilitar contraseña para administración remota.")
  fi

  if [[ "$fw_detected" -eq 0 ]]; then
    reco+=("No se detecta firewall activo con reglas evidentes. Activar y documentar nftables/ufw/iptables con política restrictiva por defecto.")
  else
    reco+=("Firewall detectado. Revisar periódicamente reglas, origen permitido y exposición real frente a redes no confiables.")
  fi

  local risky_ports=""
  if [[ -s "$listeners_csv" ]]; then
    risky_ports="$(awk -F, 'NR>1 {gsub(/"/,"",$3); if ($3 ~ /^(21|23|25|53|80|111|139|389|445|3306|5432|5900|6379|8080|9200|9300)$/) print $3}' "$listeners_csv" | sort -n | uniq | paste -sd ', ' -)"
  fi
  if [[ -n "$risky_ports" ]]; then
    reco+=("Revisar servicios expuestos en puertos sensibles o habitualmente atacados: $risky_ports. Cerrar, segmentar o filtrar si no son imprescindibles.")
  else
    reco+=("No se han identificado puertos sensibles habituales en escucha; mantener revisión periódica de listeners y firewall.")
  fi

  reco+=("Revisar servicios systemd habilitados; dejar deshabilitados los no necesarios y documentar excepciones.")
  reco+=("Revisar comparticiones SMB/NFS; eliminar exports/shares no necesarios, limitar por origen y aplicar permisos mínimos.")
  reco+=("Activar auditoría persistente con auditd y journald persistente cuando el servidor sea crítico o esté sujeto a ENS/ISO 27001.")
  reco+=("Mantener actualizaciones de seguridad automáticas o un proceso de parcheo formal con ventana, evidencia y rollback.")
  reco+=("Implantar verificación de integridad con AIDE/debsums y centralizar logs en SIEM cuando aplique.")

  printf '%s\n' "${reco[@]}" | tee "$reco_file" >/dev/null
  append_report "$(printf '%s\n' "${reco[@]}")\n"

  local val8="$BASE_PATH/evidencias_ATTACKSURFACE_validate_${TIME_STAMP}.txt"
  cat > "$val8" <<VAL8
==== [8.1] Cuentas locales habilitadas ====
Ver CSV 8.1_cuentas_locales.csv

==== [8.2] Puertos en escucha ====
Ver CSV 8.2_listeners.csv y salida raw si existe.

==== [8.3] Servicios habilitados y activos ====
Ver CSV 8.3_servicios_enabled.csv y 8.3_servicios_running.txt.

==== [8.4] Adaptadores de red activos ====
Ver CSV 8.4_adaptadores.csv, 8.4_ip_addr.txt y 8.4_ip_route.txt.

==== [8.5] SSH, SMB, NFS y comparticiones ====
Ver 8.5_ssh_smb_nfs.txt.

==== [8.6] Recomendaciones ====
$(cat "$reco_file")

--- FIN BLOQUE 8 ---
VAL8

  append_report "Guardado informe específico de Bloque 8: $val8\n"
}

# -------------------- EJECUCIÓN --------------------
run_block "1. Preparación del sistema" block_1_preparacion
run_block "2. Políticas y configuración base" block_2_politicas
run_block "3. Política de contraseñas" block_3_passwords
run_block "4. Auditoría" block_4_auditoria
run_block "5. Seguridad" block_5_seguridad
run_block "6. Sistema" block_6_sistema
run_block "7. Integridad" block_7_integridad
run_block "8. Superficie de ataque" block_8_superficie_ataque

head_section "RESUMEN CONSOLA"
append_report "\n== RESUMEN GENERAL ==\n"
append_report "Informe:  $REPORT_FILE\nCSV:      $CSV_RESUMEN\nCarpeta:  $BASE_PATH\n"

if [[ "$NO_ARCHIVE" -eq 0 ]]; then
  if command_exists zip; then
    ZIP_PATH="${BASE_PATH}.zip"
    rm -f "$ZIP_PATH"
    (cd "$(dirname "$BASE_PATH")" && zip -qr "$ZIP_PATH" "$(basename "$BASE_PATH")")
    if [[ $? -eq 0 ]]; then
      log "ZIP generado: $ZIP_PATH"
      append_report "ZIP generado: $ZIP_PATH\n"
    else
      log "ERROR creando ZIP con zip"
      append_report "ERROR creando ZIP con zip\n"
    fi
  else
    TAR_PATH="${BASE_PATH}.tar.gz"
    tar -czf "$TAR_PATH" -C "$(dirname "$BASE_PATH")" "$(basename "$BASE_PATH")" 2>/dev/null
    if [[ $? -eq 0 ]]; then
      log "zip no instalado; TAR.GZ generado: $TAR_PATH"
      append_report "zip no instalado; TAR.GZ generado: $TAR_PATH\n"
    else
      log "ERROR creando TAR.GZ"
      append_report "ERROR creando TAR.GZ\n"
    fi
  fi
else
  log "Compresión omitida por --no-zip"
fi

log "Validación finalizada"
append_report "\nFin de validación.\n"
