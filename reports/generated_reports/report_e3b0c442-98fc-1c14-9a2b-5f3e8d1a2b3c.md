# Threat Intelligence Report

**Campaign:** Unclassified Activity
**Campaign ID:** e3b0c442-98fc-1c14-9a2b-5f3e8d1a2b3c
**Generated:** 2026-07-27T04:18:43.308068+00:00

---

# Threat Intelligence Report – Unclassified Activity  
**Date:** 2026‑07‑27  
**Prepared by:** Senior Threat Intelligence Analyst  

---

## Executive Summary  
On **20 June 2026** a Windows workstation (WORKSTATION‑07) exhibited two high‑confidence ATT&CK techniques:  
* **T1059.001 – PowerShell** (process execution)  
* **T1053.005 – Scheduled Task** (persistence)  

An outbound connection from internal IP **10.0.5.21** to external IP **185.44.12.7** was logged by Suricata. The destination IP is listed as *benign* in AbuseIPDB. No additional malicious indicators or actor attribution are present in the evidence.  

Immediate containment actions (host isolation and analyst notification) have been queued for approval.

---

## Timeline  

| Timestamp (UTC) | Event ID | Source | Description |
|-----------------|----------|--------|-------------|
| 2026‑06‑20T10:15:00Z | evt‑001 | sysmon | `powershell.exe` executed on WORKSTATION‑07 (no command line). |
| 2026‑06‑20T10:16:32Z | b0735a28‑573e‑4529‑bc6a‑33820c025f60 | suricata | Alert: possible C2 beacon – connection from 10.0.5.21 to 185.44.12.7. |
| 2026‑06‑20T10:17:10Z | 1b83ac9a‑59b5‑48b4‑b194‑576582b0b4e5 | wazuh | New scheduled task created on WORKSTATION‑07. |

---

## IOCs  

| Value | Type | Reputation | Confidence | Tags |
|-------|------|------------|------------|------|
| 185.44.12.7 | IP | benign | 0.0 | country:RU, data_center/web_hosting/transit, domain:atomdata.ru, isp:ATOMDATA JSC |

---

## ATT&CK Techniques  

| Technique ID | Name | Confidence | Evidence Event | Mapping Source | Known Groups | Known Software | Recommended Mitigations |
|--------------|------|------------|----------------|----------------|--------------|----------------|------------------------|
| T1059.001 | PowerShell | 1.0 | evt‑001 | deterministic_rule | WIRTE, APT42, APT5, Blue Mockingbird, APT39, Magic Hound, APT19, APT28, APT41, Sandworm Team, VOID MANTICORE, MoustachedBouncer, CopyKittens, Thrip, Storm‑0501, Storm‑1811, FIN13, Gorgon Group, Play, FIN7, RedCurl, TeamTNT, OilRig, Inception, Lazarus Group, APT32, Chimera, Volt Typhoon, Saint Bear, Earth Lusca, Threat Group‑3390, TA2541, Deep Panda, Indrik Spider, Cobalt Group, Leviathan, Wizard Spider, Akira, APT29, GALLIUM, Ember Bear, Daggerfly, FIN6, Medusa Group, HEXANE, LazyScripter, BlackByte, HAFNIUM, Sidewinder, FIN10, Gallmaker, Turla, Silence, Molerats, ToddyCat, UNC3886, APT3, DarkVishnya, TA459, Gamaredon Group, Kimsuky, TA505, FIN8, APT33, Scattered Spider, BRONZE BUTLER, Mustang Panda, Patchwork, Tonto Team, APT38, DarkHydrus, CURIUM, GOLD SOUTHFIELD, menuPass, Poseidon Group, Stealth Falcon, MuddyWater, Fox Kitten, Cinnamon Tempest, Dragonfly, Winter Vivern, Aquatic Panda, Confucius, Nomadic Octopus, APT‑C‑36 | RansomHub, BADHATCH, Empire, Zeus Panda, SystemBC, QakBot, AppleSeed, LunarWeb, LockBit 3.0, Spica, Covenant, REvil, Bazar, TRANSLATEXT, Woody RAT, Pupy, WellMess, WhisperGate, PowerStallion, JCry, TrickBot, LazyWiper, MoleNet, Akira, DarkWatchman, GLASSTOKEN, PowerShower, LitePower, Mafalda, Troll Stealer, NETWIRE, ShrinkLocker, PowerPunch, Havoc, Gootloader, POWERTON, StrelaStealer, Mosquito, Hancitor, Cuba, Helminth, PS1, Pysa, SharpStage, Koadic, njRAT, Sliver, FlawedAmmyy, CHIMNEYSWEEP, DarkGate, Cobalt Strike, KONNI, Socksbot, IPsec Helper, Emotet, Saint Bot, LP‑Notes, WarzoneRAT, RegDuke, CharmPower, Meteor, SILENTTRINITY, POWERSOURCE, ServHelper, Xbash, Ursnif, POSHSPY, PUNCHBUGGY, SHARPSTATS, ConnectWise, POWERSTATS, Black Basta, StrongPity, Netwalker, Lizar, ZeroCleare, Ferocious, HAMMERTOSS, BloodHound, PowGoop, Pillowmint, Prestige, Tsundere Botnet, Lumma Stealer, Denis, CreepyDrive, PureCrypter, Revenge RAT, PyDCrypt, Bandook, POWRUNER, KeyBoy, CreepySnail, ComRAT, Donut, HALFBAKED, PowerLess, KOCTOPUS, Medusa Ransomware, Lokibot, FatDuke, Shai‑Hulud, KGH_SPY, QUADAGENT, SMOKEDHAM, Bumblebee, MuddyViper, CrackMapExec, Clambling, Valak, LockBit