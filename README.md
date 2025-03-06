# Honeypot SSH 

Un honeypot SSH interactif et réaliste permettant de capturer et d’analyser les tentatives d’intrusion, tout en fournissant un tableau de bord web (via Flask) pour la visualisation des logs.

## Sommaire

1. [Aperçu du Projet](#aperçu-du-projet)  
2. [Architecture du Répertoire](#architecture-du-répertoire)  
3. [Fonctionnalités Clés](#fonctionnalités-clés)  
4. [Prérequis](#prérequis)  
5. [Installation et Configuration](#installation-et-configuration)  
6. [Redirection du Port 22 vers le Port 2222](#redirection-du-port-22-vers-le-port-2222)  
7. [Lancement du Projet](#lancement-du-projet)  
8. [Exemple d’Utilisation](#exemple-dutilisation)  
9. [Dashboard Web](#dashboard-web)  
10. [Sécurisation et Isolation](#sécurisation-et-isolation)  
11. [Contribuer](#contribuer)  
12. [Licence](#licence)

---

## Aperçu du Projet

Ce honeypot SSH vise à simuler un environnement Linux complet :  
- Un système de fichiers virtuel riche, contenant des fichiers sensibles 
- Un shell interactif prenant en charge des commandes internes (cd, ls, cat, cp, mv, mkdir, rm, rmdir, touch, echo, etc.), la complétion automatique (Tab) et la gestion de pipelines.  
- Un serveur SSH écoutant sur un port non privilégié (par défaut 2222).  
- Un dashboard web (Flask) pour suivre en temps réel les tentatives d’intrusion et les commandes exécutées.

---

## Architecture du Répertoire

```plaintext
project-root/
├── src/
│   ├── honeypot.py          # Script principal (exemple)
│   ├── alert.log            # Logs d’alertes (exploits, force brute, etc.)
│   ├── auth.log             # Logs d’authentification (tentatives de connexion)
│   ├── commands.log         # Logs des commandes exécutées par les attaquants
│   ├── server.key           # Clé SSH persistante (générée si absente)
│   ├── Makefile             # Fichier Make (optionnel)
│   └── requirements.txt     # Liste des dépendances Python
├── venv/                    # Environnement virtuel (optionnel)
├── LICENSE
└── README.md                # Ce fichier
```

*Note : Les noms de fichiers peuvent varier selon votre organisation. L’essentiel est de disposer des logs (auth.log, commands.log, alert.log), du script honeypot et de la clé SSH (server.key). que vous pouvez aussi générer via la commande ssh keygen*

*Note : le dossier logs contient l'ensemble des fichiers de journalisation lorsque le honeypot a été ouvert sur le tunnel SSH* 

---

## Fonctionnalités Clés

1. **Environnement Linux Virtuel**  
   - Arborescence réaliste, avec `/etc`, `/home`, `/root`, `/var`, etc.  
   - Fichiers « sensibles » (mots de passe, dumps SQL, clés privées, etc.).

2. **Shell Interactif**  
   - Commandes internes : `ls`, `cd`, `cat`, `cp`, `mv`, `mkdir`, `rm`, `rmdir`, `touch`, `echo`, etc.  
   - Gestion de pipelines (`|`) et auto-complétion (touche Tab).

3. **Serveur SSH**  
   - Basé sur Paramiko.  
   - Écoute par défaut sur le port **2222** (configurable).

4. **Dashboard Web**  
   - Flask pour l’affichage des logs en temps réel.  
   - Interface améliorée avec Bootstrap.

5. **Détection d’Intrusions**  
   - Journalisation avancée dans `auth.log`, `commands.log` et `alert.log`.  
   - Détection de brute force (IntrusionDetector).  
   - Détection d’exploits courants (injections SQL, XSS, RCE).

---

## Prérequis

- **Python 3.8+**  
- **pip** (ou pip3)  
- **iptables** (pour la redirection de port, sous Linux)  

---

## Installation et Configuration

1. **Cloner ou Copier le Dépôt**  
   ```bash
   git clone https://github.com/Amayes985-stack/Honeypot-SSH
   cd Honeypot-SSH/src
   ```

2. **Créer un Environnement Virtuel (optionnel mais recommandé)**  
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Sous Windows : venv\Scripts\activate
   ```

3. **Installer les Dépendances**  
   ```bash
   pip install -r requirements.txt
   ```

4. **Vérifier la Clé SSH**  
   Le script vérifie automatiquement la présence de `server.key`. S’il n’existe pas, il en génère un.  
   Assurez-vous que les permissions sont correctes :  
   ```bash
   chmod 600 server.key
   ```


---

## Redirection du Port 22 vers le Port 2222

Par défaut, le honeypot écoute sur le port **2222**. Pour l’exposer sur le port **22**, procédez comme suit :

1. **Activer le Transfert IP**  
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   ```
   Et pour rendre permanent :  
   ```bash
   echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
   ```

2. **Ajouter la Règle de Redirection (iptables)**  
   ```bash
   sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
   ```

3. **Sauvegarder les Règles**  
   ```bash
   sudo apt install iptables-persistent -y
   sudo netfilter-persistent save
   ```

---

## Lancement du Projet

1. **Lancer le Honeypot**  
   ```bash
   python3 honeypot.py 
   ```
   ou 
   
   ```bash
   make honeypot
   ```

   Vous verrez le message :
   ```
   Honeypot SSH actif sur le port 2222
   ```

2. **Lancer le Dashboard Web (Flask)**  
   Le script `honeypot.py` inclut le démarrage du dashboard (via `start_dashboard`) en tant que thread daemon, par défaut sur le port 5000.  
   Accédez-y via :  
   ```
   http://<votre-ip>:5000
   ```

---

## Exemple d’Utilisation

- **Connexion SSH** depuis une machine externe :  
  ```bash
  ssh user@<IP-de-votre-serveur> -p 22
  ```
  (Le trafic sera redirigé du port 22 vers le port 2222.)

- **Exécution de Commandes** :  
  L’attaquant pourra exécuter des commandes comme `ls`, `cd /root`, `cat secrets.txt`, etc. Le honeypot enregistrera toutes ces commandes dans `commands.log`.

- **Vérification des Logs** :  
  - `auth.log` : Tentatives de connexion (adresses IP, mots de passe testés).  
  - `commands.log` : Commandes exécutées.  
  - `alert.log` : Activités suspectes détectées (ex. brute force, exploits).

---

## Dashboard Web

Le dashboard Flask, accessible via `http://<votre-ip>:5000`, affiche les 10 dernières commandes enregistrées dans `commands.log` :

- **Time** : Horodatage de la commande.  
- **IP** : Adresse IP de l’attaquant.  
- **Command** : La commande exacte tapée.  
- **Country** : Pays d’origine (selon l’API IP-API).

---

## Sécurisation et Isolation

- **Isolation du Honeypot** : Utilisez une **machine virtuelle** ou un **container** Docker dédié.  
- **Pare-feu** : Bloquez tous les ports inutiles et surveillez le trafic vers le port 22.  
- **Surveillance Active** : Consultez régulièrement les logs (`auth.log`, `commands.log`, `alert.log`) et le dashboard pour détecter des activités suspectes.  
- **Mises à Jour** : Mettez à jour Kali Linux (ou votre distribution) et vérifiez régulièrement les dépendances Python.

---

## Contribuer

1. **Forkez** le dépôt.  
2. **Créez** une nouvelle branche pour vos modifications.  
3. **Envoyez** une Pull Request avec vos changements.  

Les suggestions de nouvelles commandes internes, d’améliorations de l’auto-complétion ou de modules de détection d’exploits sont particulièrement bienvenues !

---

## Licence

Ce projet est distribué sous licence [MIT](../LICENSE). Consultez le fichier `LICENSE` pour plus d’informations.

---

**Contact :**  
- Auteur : *Amayes DJERMOUNE*  
- Email : *[amayes.djermoune2002@gmail.com]*  
- GitHub : [https://github.com/Amayes985-stack/Honeypot-SSH]

---

