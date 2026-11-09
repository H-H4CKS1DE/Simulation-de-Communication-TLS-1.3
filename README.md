# Simulation-de-Communication-TLS-1.3
Communication en local en canal sécurisé via TLS 1.3, à partir de OpenSSL. Observables via wireshark.


# Mini-lab TLS 1.3 — Client et serveur

Ce kit reproduit un handshake TLS 1.3 local avec Python + OpenSSL. Il est conçu pour deux machines sur un réseau de laboratoire.

**Accès rapide :** [Création des certificats, commande par commande](#3-création-des-certificats-commande-par-commande) · [Mise en réseau des deux ordinateurs](#4-mise-en-réseau-des-deux-ordinateurs) · [Observer le handshake dans Wireshark](#7-observer-le-handshake-dans-wireshark) · [Tests d'échec et diagnostic](#8-tests-déchec-et-diagnostic)

## 1. Vue d'ensemble

Le scénario comporte quatre rôles :

| Élément | Rôle |
|---|---|
| Client | Initie la connexion TLS |
| Serveur | Attend une connexion TLS |
| CA | Autorité qui signe le certificat du serveur |
| Wireshark | Outil qui observe les paquets réseau |

Le port choisi est `4433`. En local, le client et le serveur utilisent `127.0.0.1` et l'interface `lo`. Sur deux machines, le client utilise l'adresse IP LAN du serveur et Wireshark capture sur `wlo1` ou `eth0`.

### Répartition des fichiers

Sur le serveur :

```text
bob_server.py
bob.crt
bob.key
```

Sur le client :

```text
alice_client.py
ca.crt
```

Ne jamais copier `ca.key` ou `bob.key` sur le client.

## 2. Prérequis
- Linux, deux machines sur le même LAN.
- OpenSSL >= 1.1.1.
- Python >= 3.8, lié à un OpenSSL qui supporte TLS 1.3.
- TCP/4433 autorisé entre le client et le serveur uniquement.

Vérifier :
```bash
openssl version
python3 --version
python3 -c "import ssl; print(ssl.OPENSSL_VERSION); print(ssl.HAS_TLSv1_3)"
```

## 3. Création des certificats, commande par commande

### 3.1 Créer la clé privée de la CA

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
```

- `ecparam` choisit les paramètres de cryptographie elliptique ;
- `prime256v1` est la courbe utilisée ;
- `-genkey` génère une clé privée ;
- `-noout` évite d'afficher les paramètres ;
- `-out ca.key` écrit la clé privée de l'autorité.

`ca.key` est le fichier le plus sensible du TP. Il ne doit jamais être envoyé au client ni publié sur GitHub.

### 3.2 Créer le certificat racine de la CA

```bash
openssl req -x509 -new -key ca.key -sha256 -days 365 \
  -subj "/C=CM/O=ENSPY TLS Lab/CN=ENSPY Lab Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
```

- `-x509` crée directement un certificat auto-signé ;
- `-key ca.key` utilise la clé de la CA ;
- `-sha256` choisit la fonction de hachage ;
- `-days 365` donne une validité d'un an ;
- `-subj` définit le nom de la CA ;
- `CA:TRUE` indique que le certificat peut signer d'autres certificats ;
- `keyCertSign` autorise la signature de certificats ;
- `ca.crt` est la partie publique distribuée au client.

Le client ne fait pas confiance au serveur directement. Il fait confiance à `ca.crt`, qui permet de valider la signature du certificat du serveur.

### 3.3 Créer la clé et la demande du serveur

```bash
openssl ecparam -name prime256v1 -genkey -noout -out bob.key
openssl req -new -key bob.key \
  -subj "/C=CM/O=ENSPY TLS Lab/CN=bob.lab" -out bob.csr
```

La première commande crée la clé privée du serveur. La seconde crée `bob.csr`, une demande contenant l'identité du serveur et sa clé publique.

### 3.4 Définir les usages du certificat

Le fichier `bob.ext` contient :

```text
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:bob.lab
```

- `CA:FALSE` interdit au serveur de signer d'autres certificats ;
- `digitalSignature` autorise le serveur à prouver la possession de sa clé ;
- `serverAuth` indique un certificat de serveur ;
- `subjectAltName=DNS:bob.lab` indique le nom exact vérifié par le client.

Le nom `bob.lab` est important. Utiliser `client.lab` doit provoquer une erreur `Hostname mismatch`.

### 3.5 Faire signer le certificat du serveur

```bash
openssl x509 -req -in bob.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -days 90 -sha256 -extfile bob.ext -out bob.crt
```

- `-in bob.csr` lit la demande du serveur ;
- `-CA ca.crt` indique la CA ;
- `-CAkey ca.key` utilise la clé privée de la CA pour signer ;
- `-CAcreateserial` crée un numéro de série ;
- `-days 90` rend le certificat du serveur valide 90 jours ;
- `-extfile bob.ext` ajoute les usages et le nom `bob.lab` ;
- `bob.crt` est le certificat public du serveur.

Vérification :

```bash
openssl verify -CAfile ca.crt -purpose sslserver \
  -verify_hostname bob.lab bob.crt
chmod 600 ca.key bob.key
```

Le résultat attendu est `bob.crt: OK`.

## 4. Mise en réseau des deux ordinateurs

Pour un test sur une seule machine, sauter cette section : l'adresse est `127.0.0.1` et Wireshark capture sur `lo`.

### 4.1 Trouver l'adresse IP du serveur

Sur le serveur, trouver l'adresse IP LAN :

```bash
ip -br addr
```

Exemple :

```text
wlo1    UP    192.168.1.170/24
```

Dans cet exemple, l'adresse du serveur est `192.168.1.170`. Elle doit être remplacée par l'adresse réellement affichée sur votre machine.

### 4.2 Autoriser le client dans le pare-feu du serveur

Si le pare-feu `ufw` est actif, autoriser uniquement l'adresse du client :

```bash
sudo ufw allow from IP_CLIENT to any port 4433 proto tcp
```

Remplacer `IP_CLIENT` par l'adresse IP de l'ordinateur du client. Cette règle autorise le client à joindre le serveur sur le port du TP sans ouvrir inutilement le service à tout le réseau.

### 4.3 Préparer l'ordinateur du client

Le client ne reçoit que `alice_client.py` et `ca.crt` (voir section 1).

Depuis le client, `ca.crt` peut être copié avec `scp` :

```bash
scp utilisateur@IP_SERVEUR:/chemin/vers/ca.crt .
```

Ajouter le nom utilisé dans le certificat dans `/etc/hosts` sur le client :

```bash
sudo nano /etc/hosts
```

Ajouter une ligne de la forme :

```text
IP_SERVEUR bob.lab
```

Par exemple :

```text
192.168.1.170 bob.lab
```

Cette ligne indique que `bob.lab` correspond à l'adresse IP du serveur. Le nom est important car le client doit vérifier le `subjectAltName` du certificat, qui contient `bob.lab`.

### 4.4 Tester le réseau avant TLS

Depuis le client :

```bash
ping -c 4 IP_SERVEUR
nc -vz IP_SERVEUR 4433
```

`ping` vérifie que la machine est joignable. `nc` vérifie que le port TCP `4433` est accessible. Si `nc` échoue, il faut corriger l'adresse IP, la route ou le pare-feu avant de chercher un problème TLS.

## 5. Test de référence avec OpenSSL

Sur le serveur :

```bash
openssl s_server -accept 4433 -cert bob.crt -key bob.key \
  -tls1_3 -www -msg -state
```

- `s_server` démarre un serveur TLS ;
- `-accept 4433` écoute sur le port 4433 ;
- `-cert` charge le certificat ;
- `-key` charge la clé privée ;
- `-tls1_3` force TLS 1.3 ;
- `-www` renvoie une réponse HTTP de démonstration ;
- `-msg` et `-state` affichent les étapes du handshake.

Sur le client :

```bash
openssl s_client -connect bob.lab:4433 -servername bob.lab \
  -CAfile ca.crt -verify_hostname bob.lab -verify_return_error \
  -tls1_3 -groups X25519 -msg -state -brief
```

Le client se connecte, annonce `bob.lab`, vérifie la chaîne de certificats et exige TLS 1.3.

Pour comparer avec TLS 1.2, relancer le serveur avec `-tls1_2` puis le client avec `-tls1_2`, et comparer l'ordre des messages et le moment où le chiffrement commence.

## 6. Scripts Python

### 6.1 `bob_server.py`

Code : [`bob_server.py`](bob_server.py)

```python
import socket
import ssl
```

Importe les modules réseau et TLS.

```python
HOST = "0.0.0.0"
PORT = 4433
```

Le serveur écoute sur toutes les interfaces réseau, sur le port 4433.

```python
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
```

Crée une configuration TLS destinée à un serveur.

```python
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
```

Force TLS 1.3 et refuse les versions précédentes.

```python
context.load_cert_chain(certfile="bob.crt", keyfile="bob.key")
```

Charge le certificat public et la clé privée du serveur.

```python
context.keylog_filename = "bob.keys"
```

Écrit les secrets de session utilisables par Wireshark. Cette option est réservée au TP.

```python
with socket.create_server((HOST, PORT)) as server:
```

Crée le socket TCP d'écoute.

```python
print(f"Bob écoute sur {HOST}:{PORT}", flush=True)
```

Affiche que le serveur est prêt.

```python
while True:
    raw_socket, address = server.accept()
```

Attend un client et récupère sa connexion TCP.

```python
with context.wrap_socket(raw_socket, server_side=True) as tls_socket:
```

Transforme la connexion TCP en connexion TLS et réalise le handshake.

```python
print(
    f"Client {address[0]} | {tls_socket.version()} | {tls_socket.cipher()}",
    flush=True,
)
```

Affiche le client, la version TLS et la suite cryptographique négociée.

```python
payload = tls_socket.recv(4096)
tls_socket.sendall(b"Bob a recu : " + payload)
```

Reçoit le message déchiffré par Python, puis renvoie une réponse dans la session TLS.

```python
except ssl.SSLError as exc:
    print(f"Échec TLS avec {address}: {exc}", flush=True)
```

Affiche les erreurs de handshake, de certificat ou de protocole.

### 6.2 `alice_client.py`

Code : [`alice_client.py`](alice_client.py)

```python
import os
import socket
import ssl
```

Importe les variables d'environnement, les sockets et TLS.

```python
SERVER_IP = os.environ.get("TLS_SERVER_IP", "IP_SERVEUR")
TLS_SERVER_NAME = os.environ.get("TLS_SERVER_NAME", "bob.lab")
CA_FILE = os.environ.get("TLS_CA_FILE", "ca.crt")
PORT = 4433
```

Permet de changer la destination sans modifier le code : l'IP indique où se connecter, tandis que `TLS_SERVER_NAME` indique le nom à vérifier dans le certificat.

```python
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
```

Crée un contexte client qui vérifie le certificat du serveur avec `ca.crt`.

```python
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
```

Force TLS 1.3.

```python
context.keylog_filename = "alice.keys"
```

Enregistre les secrets permettant à Wireshark de déchiffrer cette session de TP.

```python
with socket.create_connection((SERVER_IP, PORT), timeout=5) as raw_socket:
    with context.wrap_socket(raw_socket, server_hostname=TLS_SERVER_NAME) as tls_socket:
```

Ouvre d'abord une connexion TCP, puis lance le handshake TLS et vérifie que le certificat correspond à `bob.lab`.

```python
print("Version :", tls_socket.version())
print("Suite   :", tls_socket.cipher())
tls_socket.sendall(b"Bonjour Alice")
```

Affiche les paramètres négociés et envoie le message applicatif dans la session chiffrée.

```python
print("Réponse :", tls_socket.recv(4096).decode("utf-8", errors="replace"))
```

Reçoit et affiche la réponse du serveur.

Les deux blocs `except` distinguent une erreur de vérification de certificat d'une erreur réseau ou TLS générale.

### 6.3 Exécution
Terminal 1, sur le serveur :
```bash
python3 bob_server.py
```
Résultat attendu : `Bob écoute sur 0.0.0.0:4433`. Une seule instance suffit (voir la section 8.2 si le port est déjà pris).

Terminal 2, sur le client, depuis le dossier contenant `alice_client.py` et `ca.crt` :
```bash
TLS_SERVER_IP=IP_SERVEUR TLS_SERVER_NAME=bob.lab TLS_CA_FILE=ca.crt python3 alice_client.py
```
`IP_SERVEUR` vaut `127.0.0.1` pour un test sur une seule machine, sinon l'adresse LAN du serveur (par exemple `192.168.1.170`).

Résultat attendu :
```text
Version : TLSv1.3
Suite   : ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
Réponse : Bob a recu : Bonjour Alice
```

## 7. Observer le handshake dans Wireshark

### 7.1 Principe
En TLS 1.3, tout ce qui suit le `ServerHello` est chiffré. Le fichier `alice.keys` (écrit par `keylog_filename`) contient les *secrets de trafic* de la session : Wireshark s'en sert pour déchiffrer la capture après coup. Sans ce fichier, un observateur (Oscar) ne voit que du chiffré, c'est précisément la garantie attendue.

### 7.2 Installation et droits (une seule fois)
```bash
sudo apt install wireshark tshark tcpdump
sudo dpkg-reconfigure wireshark-common   # répondre « Oui » : capture sans root
sudo usermod -aG wireshark $USER         # puis se déconnecter / reconnecter, et vérifier avec `id` (le groupe `wireshark` doit apparaître)
```

### 7.3 Procédure en 6 étapes
1. **Dossier propre sur le client** : `cd ~/tls13-lab && umask 077 && : > alice.keys` (fichier vide, créé en mode privé : une seule session dedans).
2. **Interface** : `lo` si le client utilise `127.0.0.1`, sinon l'interface du LAN (`wlo1` ou `eth0`, voir `ip -br link`).
3. **Filtre de capture** (champ au-dessus de la liste d'interfaces) : `tcp port 4433`, puis démarrer la capture.
4. **Lancer le client depuis le même dossier** (le chemin `alice.keys` est relatif) :
   ```bash
   TLS_SERVER_IP=IP_SERVEUR TLS_SERVER_NAME=bob.lab TLS_CA_FILE=ca.crt python3 alice_client.py
   ```
5. **Arrêter** la capture et l'enregistrer : `lab_tls13.pcapng`.
6. **Charger les clés** : `Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename` → chemin **absolu** de `alice.keys`. Cela peut se faire après la capture : Wireshark redécode tout. Variante en une ligne :
   ```bash
   wireshark -o tls.keylog_file:$HOME/tls13-lab/alice.keys lab_tls13.pcapng
   ```

### 7.4 Ce qui est visible, sans puis avec `alice.keys`
| Paquet | Sans `alice.keys` | Avec `alice.keys` | Lien avec le cours |
|---|---|---|---|
| ClientHello | Lisible : SNI `bob.lab`, `supported_versions`, `key_share` x25519, suites | Idem | Négociation, part ECDHE du client (A) |
| ServerHello | Lisible : suite `TLS_AES_256_GCM_SHA384`, `key_share` du serveur (B) | Idem | Dernier message en clair |
| Change Cipher Spec | Visible, factice | Idem | Compatibilité avec les équipements intermédiaires |
| EncryptedExtensions, Certificate, CertificateVerify, Finished (serveur) | Affichés comme `Application Data` | Affichés comme messages de handshake déchiffrés | **Exercice 24, question 3** : chiffrement dès après le ServerHello |
| Finished (client) | `Application Data` | Handshake déchiffré | Confirmation de l'intégrité du handshake |
| NewSessionTicket (souvent 1 ou 2) | `Application Data` | Handshake déchiffré | Reprise de session par PSK |
| « Bonjour Alice » et réponse du serveur | `Application Data` | Texte lisible (panneau « Decrypted TLS », ou `Follow > TLS Stream`) | Couche Record, AEAD |
| Alerte `close_notify` | `Application Data` | Alerte lisible | Fermeture propre |

### 7.5 Filtres d'affichage utiles
| Objectif | Filtre |
|---|---|
| Tout le TP | `tcp.port == 4433` |
| Tous les messages de handshake | `tls.handshake` |
| ClientHello / ServerHello | `tls.handshake.type == 1` / `tls.handshake.type == 2` |
| Messages déchiffrés | `tls.handshake.type == 8` (EncryptedExtensions), `== 11` (Certificate), `== 15` (CertificateVerify), `== 20` (Finished), `== 4` (NewSessionTicket) |
| Type visible des enregistrements | `tls.record.content_type == 22` (handshake), `== 23` (application), `== 20` (CCS), `== 21` (alerte) |
| SNI, version, groupe, suite | `tls.handshake.extensions_server_name`, `tls.handshake.extensions_supported_version`, `tls.handshake.extensions_key_share_group`, `tls.handshake.ciphersuite` |
| Données applicatives déchiffrées | `tls.app_data` |

Les noms de champs sont ceux de Wireshark 4.x. Si l'un est refusé, sélectionner le champ dans le panneau de détails puis `Clic droit > Apply as Filter`.

### 7.6 Quoi relever dans le détail des paquets
- **ClientHello** : `legacy_version = 0x0303` mais `supported_versions` contient `0x0304` (TLS 1.3) ; `key_share` de groupe `x25519` et de **32 octets** (la clé publique A) ; `server_name = bob.lab`.
- **ServerHello** : suite choisie, `key_share` de 32 octets (la clé publique B).
- **Certificate** : la chaîne de `bob.crt`, avec `subjectAltName = bob.lab`.
- **CertificateVerify** : algorithme de signature (`ecdsa_secp256r1_sha256` pour une clé P-256).
- **Finished** : `verify_data` de 48 octets avec SHA-384.
- **En-tête d'enregistrement chiffré** : `17 03 03 <longueur>` ; le type réel est caché dans le chiffré.

### 7.7 Lire `alice.keys`
Chaque ligne a la forme `ÉTIQUETTE client_random secret`. Le `client_random` relie la ligne à la session visible dans le ClientHello (`tls.handshake.random`).

| Étiquette dans `alice.keys` | Secret du cours (RFC 8446, §7.1) |
|---|---|
| `CLIENT_HANDSHAKE_TRAFFIC_SECRET` | `client_handshake_traffic_secret` (`c hs traffic`) |
| `SERVER_HANDSHAKE_TRAFFIC_SECRET` | `server_handshake_traffic_secret` (`s hs traffic`) |
| `CLIENT_TRAFFIC_SECRET_0` | `client_application_traffic_secret_0` (`c ap traffic`) |
| `SERVER_TRAFFIC_SECRET_0` | `server_application_traffic_secret_0` (`s ap traffic`) |
| `EXPORTER_SECRET` | `exporter_master_secret` |

Ce sont les cinq étiquettes produites par `alice_client.py` lors de l'essai de validation.

### 7.8 Sans interface graphique (tcpdump et tshark)
```bash
sudo tcpdump -i wlo1 -w lab_tls13.pcap 'tcp port 4433'       # Ctrl+C après la connexion du client
tshark -r lab_tls13.pcap -o tls.keylog_file:alice.keys -Y tls.handshake \
  -T fields -e frame.number -e ip.src -e ip.dst -e tls.handshake.type
tshark -r lab_tls13.pcap -o tls.keylog_file:alice.keys -Y tls -V | less
tshark -r lab_tls13.pcap -d tcp.port==4433,tls -Y tls.handshake   # forcer le décodage TLS
```
Le message applicatif se lit avec `-Y tls.app_data -T fields -e tls.app_data`, puis `xxd -r -p` pour passer de l'hexadécimal au texte.

### 7.9 Dépannage Wireshark
| Symptôme | Cause probable | Solution |
|---|---|---|
| Uniquement des paquets `TCP` | Port 4433 non reconnu comme TLS, ou capture lancée en cours de connexion | `Clic droit > Decode As… > TCP port 4433 > TLS`, puis relancer capture et client |
| Handshake visible, tout le reste en `Application Data` | Clés non chargées, mauvais fichier, fichier vide ou autre session | Chemin absolu, `wc -l alice.keys`, refaire une capture avec `: > alice.keys` avant le test |
| `alice.keys` vide | La connexion a échoué avant le handshake, ou Python < 3.8 | Régler d'abord la connexion (section 8.2) |
| Aucun paquet | Mauvaise interface (`lo` pour 127.0.0.1, `wlo1`/`eth0` pour le LAN) ou filtre de capture erroné | Revérifier `ip -br addr` et le filtre `tcp port 4433` |
| `Permission denied` à la capture | Utilisateur hors du groupe `wireshark` | Section 7.2, puis se reconnecter |
| Capture vide depuis une 3ᵉ machine | Un réseau commuté n'envoie pas le trafic d'autrui ; Wi-Fi avec isolation des clients | Capturer sur le client ou sur le serveur (les extrémités) |
| Texte de « Bonjour Alice » introuvable | Données dans un enregistrement chiffré non décodé | `Clic droit > Follow > TLS Stream` après chargement des clés |

### 7.10 Mini-exercice (lien avec les exercices 24 et 25)
1. Relever la version négociée et la suite (ServerHello). 
2. Repérer le premier paquet affiché en `Application Data` : quels messages contient-il avant déchiffrement ?
3. Relever le groupe et la taille des deux `key_share`.
4. Comparer le `content_type` de l'enregistrement externe (23) et le type réel du message après déchiffrement.
5. Relancer avec `TLS_CA_FILE=other_ca.crt` : l'alerte envoyée par le client est elle-même chiffrée, et ne devient lisible qu'avec `alice.keys`.

## 8. Tests d'échec et diagnostic

### 8.1 Tests d'échec voulus
Ces deux essais doivent échouer : ils prouvent que la vérification fonctionne. Ne jamais désactiver la validation pour contourner l'erreur.

**Mauvais nom** : la CA est correcte, mais le certificat est destiné à `bob.lab`.
```bash
TLS_SERVER_IP=IP_SERVEUR TLS_SERVER_NAME=client.lab TLS_CA_FILE=ca.crt python3 alice_client.py
```
Avec OpenSSL, remplacer `-verify_hostname bob.lab` par `-verify_hostname client.lab`. Résultat attendu : `Hostname mismatch`.

**Mauvaise CA** : créer une autorité indépendante sur le client.
```bash
openssl ecparam -name prime256v1 -genkey -noout -out other_ca.key
openssl req -x509 -new -key other_ca.key -sha256 -days 30 \
  -subj "/CN=Other Lab CA" -out other_ca.crt
TLS_SERVER_IP=IP_SERVEUR TLS_SERVER_NAME=bob.lab TLS_CA_FILE=other_ca.crt python3 alice_client.py
```
Avec OpenSSL, remplacer `-CAfile ca.crt` par `-CAfile other_ca.crt`. Résultat attendu : erreur d'émetteur inconnu (chaîne de certification).

### 8.2 Diagnostic de connexion en 5 minutes

Faire les tests **dans cet ordre** ; s'arrêter au premier qui échoue.

| # | Où | Commande | Réussite attendue |
|---|---|---|---|
| 1 | Serveur | `ip -br addr` | Une adresse LAN (ex. `192.168.1.170`) |
| 2 | Serveur | `ss -ltnp \| grep 4433` | Ligne `LISTEN` sur `0.0.0.0:4433` |
| 3 | Serveur | `sudo ufw status` | Règle autorisant `IP_CLIENT` sur `4433/tcp`, ou pare-feu inactif |
| 4 | Client | `ping -c 2 IP_SERVEUR` | Réponses reçues (certains réseaux bloquent ICMP : passer au test 5) |
| 5 | Client | `nc -vz IP_SERVEUR 4433` | `succeeded` |
| 6 | Client | `getent hosts bob.lab` | `IP_SERVEUR bob.lab` (nécessaire pour `openssl s_client -connect bob.lab:4433` ; Python utilise `TLS_SERVER_IP`) |
| 7 | Client | `date` sur les deux machines | Heures voisines |
| 8 | Client | `openssl s_client -connect IP_SERVEUR:4433 -servername bob.lab -CAfile ca.crt -verify_hostname bob.lab -verify_return_error -brief </dev/null` | `Verification: OK` |

#### Messages d'erreur courants
| Message | Signification | Solution |
|---|---|---|
| `Connection refused` (111) | Aucun serveur sur ce port | Lancer `bob_server.py`, vérifier le test 2 |
| `timed out` | Paquets perdus : pare-feu, mauvaise IP, isolation Wi-Fi | Tests 3 à 5 |
| `No route to host` (113) | Pas de route vers le serveur | Test 1, même réseau, bonne interface |
| `Address already in use` | Le port 4433 est déjà pris | `ss -ltnp \| grep 4433`, arrêter l'ancien processus |
| `unable to get local issuer certificate` (code 20) | Mauvais `ca.crt` | Copier le `ca.crt` de la CA qui a signé `bob.crt` |
| `Hostname mismatch` (code 62) | Nom demandé absent du SAN | `TLS_SERVER_NAME=bob.lab` |
| `certificate is not yet valid` (code 9) ou `has expired` (code 10) | Horloges désynchronisées ou certificat échu | `timedatectl`, activer NTP, régénérer le certificat |
| `wrong version number` | L'autre extrémité ne parle pas TLS (ou pas TLS 1.3) | Vérifier le port et `ssl.HAS_TLSv1_3` |
| Côté serveur : `tlsv1 alert unknown ca` | Le client a rejeté le certificat du serveur | Voir les deux lignes ci-dessus |

## 9. Explication du handshake à présenter

1. Le client ouvre une connexion TCP vers le serveur.
2. Le client envoie `Client Hello` avec TLS 1.3, `bob.lab` et ses options cryptographiques.
3. Le serveur répond par `Server Hello` et choisit les paramètres communs.
4. Le serveur envoie son certificat signé par la CA.
5. Le client vérifie la signature, la validité, l'usage serveur et le nom `bob.lab`.
6. Le client et le serveur effectuent un échange de clés éphémères.
7. Ils calculent le même secret de session sans envoyer ce secret sur le réseau.
8. Les messages suivants sont chiffrés et authentifiés.
9. Le client envoie `Bonjour Alice`.
10. Le serveur le déchiffre et répond `Bob a recu : Bonjour Alice`.

La CA sert à authentifier le serveur. Les clés temporaires de la session servent à chiffrer les données.

## 10. Résultat attendu, sécurité et nettoyage

### Le TP est réussi si
- Le serveur écoute sur `4433` ; le client négocie `TLSv1.3` et reçoit « Bob a recu : Bonjour Alice » ;
- le certificat `bob.lab` est accepté ; le mauvais nom (`hostname mismatch`) et la mauvaise CA (émetteur inconnu) échouent ;
- Wireshark montre `Client Hello`, `Server Hello`, puis `Application Data` (et les messages de handshake déchiffrés avec `alice.keys`).

### Règles de sécurité
- Réseau local fermé, aucun service sensible, aucune clé privée partagée entre machines.
- Les fichiers `.keys` créés par Python sont lisibles par tous par défaut : travailler avec `umask 077` ou `chmod 600 alice.keys bob.keys`.
- Après le TP : `shred -u alice.keys bob.keys`, puis supprimer les `.pcap`/`.pcapng`, les certificats temporaires et les clés de test.
- Ne jamais publier `ca.key`, `bob.key`, `other_ca.key`, `alice.keys`, `bob.keys` ni une capture. Avant un push : `git status` puis `git diff --cached --name-only`. Le dépôt contient le code, ce README et les certificats publics, jamais de clé privée.
