# Metavoria — Hardening Lab

Projet de stage : durcissement d'infrastructure Linux, automatisation Ansible, supervision Wazuh et extension Kubernetes (k3s).

## Contexte

Stage d'application en sécurité informatique — volet Infrastructure, réalisé chez Metavoria. Durcissement d'une VM Ubuntu 22.04 LTS selon les référentiels CIS Benchmark, automatisation via Ansible, mise en place d'une supervision de sécurité (Wazuh) et extension à un cluster Kubernetes léger (k3s).

## Structure du dépôt

## Mesures de durcissement automatisées

- **SSH** : authentification par clé, port non standard, désactivation root/mot de passe
- **fail2ban** : protection anti brute-force
- **UFW** : pare-feu Deny by Default
- **Mises à jour automatiques** : unattended-upgrades
- **Services inutiles** : désactivation (cups, avahi-daemon, ModemManager, colord)
- **auditd** : traçabilité (fichiers sensibles, commandes sudo)
- **AIDE** : contrôle d'intégrité des fichiers

## Utilisation

```bash
# Test en simulation (dry-run)
ansible-playbook -i inventory/hosts.ini site.yml --check --ask-become-pass

# Exécution réelle
ansible-playbook -i inventory/hosts.ini site.yml --ask-become-pass
```

## Qualité

Rôle validé avec `ansible-lint`, profil **production**, 0 échec.

## Stack

Ansible, Wazuh, k3s, Lynis, Nmap, auditd, AIDE, UFW, fail2ban.
