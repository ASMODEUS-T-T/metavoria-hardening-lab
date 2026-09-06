# Déploiement — Wazuh Stats & ML Dashboard

## 1. Copier le projet sur `stage` (ou une VM avec accès à VM-SOC)

Transfère le dossier `wazuh-dashboard-ml/` entier sur `stage`, par exemple avec `scp`
depuis ton PC hôte, ou en le recréant directement avec les fichiers fournis.

## 2. Tester en local d'abord (recommandé avant de conteneuriser)

```bash
cd wazuh-dashboard-ml/app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export WAZUH_INDEXER_URL="https://192.168.56.105:9200"
export WAZUH_INDEXER_USER="admin"
export WAZUH_INDEXER_PASSWORD="<ton_mot_de_passe_indexer>"

uvicorn main:app --host 0.0.0.0 --port 8000
```

Ouvre `http://<IP_de_stage>:8000` dans ton navigateur — tu dois voir le dashboard
se remplir avec tes vraies données Wazuh.

## 3. Construire l'image Docker

Sur `stage` (ou n'importe quelle machine avec Docker) :

```bash
cd wazuh-dashboard-ml/app
docker build -t wazuh-ml-dashboard:latest .
```

Si Docker n'est pas installé :
```bash
sudo apt install docker.io -y
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# se reconnecter pour que le groupe prenne effet
```

## 4. Importer l'image dans le cluster k3s

k3s utilise containerd, pas Docker directement — il faut donc exporter l'image
Docker et l'importer dans containerd de chaque nœud qui pourrait exécuter le pod
(le plus simple : le faire sur VM-K3, le control-plane).

```bash
docker save wazuh-ml-dashboard:latest -o wazuh-ml-dashboard.tar
# copier ce fichier .tar sur VM-K3 si construit ailleurs (scp)
sudo k3s ctr images import wazuh-ml-dashboard.tar
```

Vérifie que l'image est bien présente :
```bash
sudo k3s ctr images list | grep wazuh-ml
```

## 5. Renseigner le vrai mot de passe dans le Secret

Édite `k8s/deployment.yaml` avant de l'appliquer :
```yaml
WAZUH_INDEXER_PASSWORD: "<ton_mot_de_passe_indexer_reel>"
```

## 6. Déployer sur le cluster

```bash
k3s kubectl apply -f k8s/deployment.yaml
```

## 7. Vérifier le déploiement

```bash
k3s kubectl get pods -n wazuh-ml
k3s kubectl logs -n wazuh-ml -l app=wazuh-ml-dashboard
k3s kubectl get certificate -n wazuh-ml
```

## 8. Ajouter l'entrée DNS locale (sur ton PC hôte)

```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "192.168.56.107 wazuh-ml.lab.local"
```

## 9. Accéder au dashboard

```
https://wazuh-ml.lab.local
```
(avertissement de certificat auto-signé attendu — accepte le risque)

---

## Notes importantes

- Le cluster k3s n'a **pas accès à Internet** pour tirer des images depuis un
  registre — d'où l'étape d'import manuel via `ctr images import`.
- Si tu veux déployer sur plusieurs nœuds (control-plane + worker), il faut
  importer l'image sur **chaque nœud** susceptible d'exécuter le pod, ou monter
  un registre Docker privé local (`registry:2`) accessible depuis le réseau
  host-only — étape possible pour une version plus avancée du pipeline CI/CD.
- Les mots de passe sont stockés en `Secret` Kubernetes — en base64, pas chiffré
  par défaut avec k3s (à documenter comme limitation connue, ou activer
  `secrets-encryption: true` comme identifié dans le rapport kube-bench).
