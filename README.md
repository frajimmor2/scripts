# My Scripts

This repository contains some of the scripts I have developed.

# Index

* [Check Password Strength](#check-password-strength)
* [Top 5 CPU-Consuming Processes](#top-5-cpu-consuming-processes)
* [Windows Hardening](#windows-hardening)

---

## Check Password Strength

Script to check whether a password is secure enough. It not only evaluates the strength based on its length and character variety, but also checks the Have I Been Pwned API to determine whether the password has appeared in known data breaches and could be present in password dictionaries.

The script also calculates the password entropy to estimate how many attempts an attacker would need to crack it.

---

## Top 5 CPU consuming processes

This script retrieves the top 5 processes with the highest CPU utilization on the system. It was originally developed to support a custom Zabbix template item designed to help identify which processes were responsible for CPU usage spikes observed on monitored hosts. The output provides a quick overview of the most CPU-intensive processes at the time of execution, making it easier to correlate performance issues with specific applications or services.

## Windows Hardening

This PowerShell script performs a comprehensive security validation and system hardening audit for a Windows machine, generating structured evidence reports and CSV exports for each section. It checks domain context, group policies, password policies, auditing configuration, system integrity, and especially attack surface exposure such as local accounts, open TCP ports, automatically starting services, network adapters, RDP/SMB configuration, and shared resources. It also collects system and network diagnostics using native tools (e.g., Get-NetTCPConnection, auditpol, ipconfig, netstat fallback) and produces a consolidated report, logs, and optional ZIP archive of all evidence. Overall, the script is designed to support compliance and security assessment aligned with ENS “high” level (Esquema Nacional de Seguridad Alto), focusing on detailed traceability, auditability, and minimization of attack surface in enterprise Windows environments.
