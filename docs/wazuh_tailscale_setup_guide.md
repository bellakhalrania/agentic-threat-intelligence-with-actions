# Guide Complet : Installation Tailscale + Connexion Wazuh Agent ↔ Manager

> **Architecture :**
> - **Machine 1 (Attacker)** : `ubuntu@ip-172-31-24-217`
> - **Machine 2 (Victim)** : `ubuntu@ip-172-31-42-38` → Wazuh Agent + Tailscale
> - **Machine 3 (Manager)** : `rania@Benlakhal` → Wazuh Manager (Docker) + Tailscale + Plateforme IA

---

## 📋 Prérequis

| Composant | Version utilisée |
|-----------|-----------------|
| Wazuh Manager | `4.14.6` (Docker) |
| Wazuh Agent | `4.14.6` |
| OS Machine 2 | Ubuntu 24.04 (Noble) |
| OS Machine 3 | Ubuntu (avec Docker) |

**Ports nécessaires (ouvrir via Tailscale ACL + firewall) :**
- `1514/TCP` — Événements agent → manager
- `1515/TCP` — Enregistrement agent
- `443/TCP` — Dashboard Wazuh
- `9200/TCP` — Wazuh Indexer (optionnel)

---

## 🖥️ Étape 1 — Machine 3 (Manager) : Installer Tailscale

### 1.1 Installer Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

### 1.2 Démarrer Tailscale et s'authentifier

```bash
sudo tailscale up
```

> Un lien d'authentification s'affiche. Ouvrez-le dans un navigateur et connectez-vous avec votre compte Tailscale.

### 1.3 Récupérer l'IP Tailscale

```bash
tailscale ip -4
```

**Sortie attendue :**
```
100.76.226.30
```

> **Notez cette IP** — elle sera utilisée comme `WAZUH_MANAGER` sur Machine 2.

### 1.4 Vérifier le statut Tailscale

```bash
sudo tailscale status
```

**Sortie attendue :**
```
100.76.226.30  benlakhal        bellakhalrania12@  linux  -
```

---

## 🖥️ Étape 2 — Machine 3 (Manager) : Vérifier Wazuh Manager (Docker)

### 2.1 Vérifier que les conteneurs tournent

```bash
sudo docker ps
```

**Sortie attendue :**
```
CONTAINER ID   IMAGE                          STATUS                    PORTS
5fefe11eafa1   wazuh/wazuh-dashboard:4.14.6   Up 11 minutes             0.0.0.0:443->5601/tcp
b27b803236f5   wazuh/wazuh-manager:4.14.6     Up 11 minutes             0.0.0.0:1514-1515->1514-1515/tcp
64459820d80f   wazuh/wazuh-indexer:4.14.6     Up 11 minutes             0.0.0.0:9200->9200/tcp
```

### 2.2 Vérifier que le Manager écoute sur les bons ports

```bash
sudo ss -tlnp | grep -E '1514|1515'
```

**Sortie attendue :**
```
tcp   LISTEN  0  4096  0.0.0.0:1514  0.0.0.0:*
tcp   LISTEN  0  4096  0.0.0.0:1515  0.0.0.0:*
```

> Si les ports n'écoutent que sur `127.0.0.1`, modifiez le `docker-compose.yml` pour binder sur `0.0.0.0`.

### 2.3 Vérifier les agents actuels

```bash
sudo docker exec -it single-node_wazuh.manager_1 /var/ossec/bin/agent_control -l
```

---

## 🖥️ Étape 3 — Machine 2 (Victim) : Installer Tailscale

### 3.1 Installer Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

### 3.2 Démarrer Tailscale et s'authentifier

```bash
sudo tailscale up
```

> Utilisez le **même compte Tailscale** que sur Machine 3 pour qu'elles soient sur le même réseau privé.

### 3.3 Vérifier le statut Tailscale

```bash
sudo tailscale status
```

**Sortie attendue :**
```
100.90.153.71  ip-172-31-42-38  bellakhalrania12@  linux  -
100.76.226.30  benlakhal        bellakhalrania12@  linux  -
```

### 3.4 Tester la connectivité vers Machine 3

```bash
nc -zv 100.76.226.30 1514
nc -zv 100.76.226.30 1515
```

**Sortie attendue :**
```
Connection to 100.76.226.30 1514 port [tcp/*] succeeded!
Connection to 100.76.226.30 1515 port [tcp/*] succeeded!
```

> Si `nc` n'est pas installé : `sudo apt-get install -y netcat-openbsd`

---

## 🖥️ Étape 4 — Machine 2 (Victim) : Installer l'Agent Wazuh

### 4.1 Mettre à jour le système et installer les dépendances

```bash
sudo apt-get update
sudo apt-get install -y gnupg apt-transport-https
```

### 4.2 Ajouter la clé GPG Wazuh

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
```

### 4.3 Ajouter le dépôt Wazuh

```bash
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
```

### 4.4 Installer l'Agent Wazuh (version compatible avec le Manager)

> **⚠️ Important** : La version de l'agent doit être **≤** à celle du Manager.
> Manager = `4.14.6` → Agent = `4.14.6`

```bash
WAZUH_MANAGER="100.76.226.30" \
WAZUH_AGENT_NAME="victim-machine" \
sudo -E apt-get install -y wazuh-agent=4.14.6-1
```

> Remplacez `100.76.226.30` par l'**IP Tailscale réelle** de votre Machine 3.

### 4.5 Vérifier la configuration

```bash
sudo cat /var/ossec/etc/ossec.conf | grep -A 5 "<server>"
```

**Sortie attendue :**
```xml
    <server>
      <address>100.76.226.30</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
```

### 4.6 Démarrer et activer l'Agent

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### 4.7 Vérifier le statut de l'Agent

```bash
sudo systemctl status wazuh-agent
```

**Sortie attendue :**
```
● wazuh-agent.service - Wazuh agent
     Loaded: loaded (...; enabled; ...)
     Active: active (running) since ...
```

### 4.8 Vérifier la version de l'Agent

```bash
sudo /var/ossec/bin/wazuh-control info
```

**Sortie attendue :**
```
WAZUH_VERSION="v4.14.6"
WAZUH_REVISION="rc2"
WAZUH_TYPE="agent"
```

---

## ✅ Étape 5 — Vérifications

### 5.1 Sur Machine 3 — Vérifier que l'agent est enregistré

```bash
sudo docker exec -it single-node_wazuh.manager_1 /var/ossec/bin/agent_control -l
```

**Sortie attendue :**
```
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh.manager (server), IP: 127.0.0.1, Active/Local
   ID: 004, Name: victim-machine, IP: any, Active
```

> Le statut doit être **`Active`** (pas `Never connected` ni `Disconnected`).

### 5.2 Sur Machine 2 — Vérifier les logs de l'Agent

```bash
sudo tail -n 30 /var/ossec/logs/ossec.log
```

**Sortie attendue (lignes positives) :**
```
wazuh-agentd: INFO: Trying to connect to server 100.76.226.30:1514/tcp
wazuh-agentd: INFO: Connected to the server
```

### 5.3 Via le Dashboard Wazuh

1. Ouvrez le navigateur : `https://<IP-Machine-3>`
2. Connectez-vous avec vos identifiants
3. Allez dans **Agents management** → **Summary**
4. Vous devez voir `victim-machine` avec le statut **Active** 🟢

---

## 🔒 Étape 6 — Sécuriser (Optionnel mais recommandé)

### 6.1 Bloquer les mises à jour automatiques de l'Agent

Pour éviter une incompatibilité de version future :

```bash
echo "wazuh-agent hold" | sudo dpkg --set-selections
```

Ou commenter le dépôt :

```bash
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
```

---

## 🔧 Dépannage

### Problème : "Duplicate agent name"

**Symptôme dans les logs :**
```
wazuh-agentd: ERROR: Duplicate agent name: victim-machine. Unable to add agent (from manager)
```

**Solution sur Machine 3 :**
```bash
# Lister les agents
sudo docker exec -it single-node_wazuh.manager_1 /var/ossec/bin/agent_control -l

# Supprimer l'ancien agent (remplacez 003 par l'ID correct)
sudo docker exec -it single-node_wazuh.manager_1 /var/ossec/bin/manage_agents -r 003
# Confirmer : y

# Redémarrer l'agent sur Machine 2
sudo systemctl restart wazuh-agent
```

---

### Problème : "Never connected" ou "Disconnected"

**Vérifications :**

```bash
# 1. Vérifier Tailscale sur les deux machines
sudo tailscale status

# 2. Tester la connectivité réseau (Machine 2)
nc -zv 100.76.226.30 1514
nc -zv 100.76.226.30 1515

# 3. Vérifier les logs (Machine 2)
sudo tail -n 50 /var/ossec/logs/ossec.log

# 4. Vérifier la compatibilité des versions
sudo /var/ossec/bin/wazuh-control info        # Machine 2
sudo docker exec single-node_wazuh.manager_1 /var/ossec/bin/wazuh-control info  # Machine 3
```

**Si la version de l'agent est supérieure au Manager :**

```bash
# Sur Machine 2
sudo systemctl stop wazuh-agent
sudo apt-get remove --purge -y wazuh-agent
sudo rm -rf /var/ossec/
WAZUH_MANAGER="100.76.226.30" WAZUH_AGENT_NAME="victim-machine" \
  sudo -E apt-get install -y wazuh-agent=4.14.6-1
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

### Problème : Ports non accessibles via Tailscale

**Vérifier que le Manager écoute sur 0.0.0.0 (Machine 3) :**

```bash
sudo ss -tlnp | grep -E '1514|1515'
```

Si vous voyez `127.0.0.1:1514` au lieu de `0.0.0.0:1514`, modifiez le `docker-compose.yml` :

```yaml
ports:
  - "0.0.0.0:1514:1514"
  - "0.0.0.0:1515:1515"
```

Puis redémarrez :

```bash
cd /chemin/vers/docker-compose/
sudo docker-compose down
sudo docker-compose up -d
```

---

## 📎 Récapitulatif des IPs utilisées

| Machine | IP Tailscale | Rôle |
|---------|-------------|------|
| Machine 3 (Manager) | `100.76.226.30` | Wazuh Manager + Dashboard + Neo4j |
| Machine 2 (Victim) | `100.90.153.71` | Wazuh Agent + Tailscale |

---

*Guide généré le 2026-08-06*
