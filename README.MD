# Émission d’un PID avec ID360 et OpenID4VC Hub

Ce service Flask vérifie l’identité d’un utilisateur avec ID360, transforme le rapport obtenu en attributs PID, puis demande à OpenID4VC Hub de préparer l’émission du PID. Le navigateur affiche ensuite l’offre sous forme de QR code et suit son état sans exposer la clé API du Hub.

Le projet ne fournit plus l’ancienne API générique d’émission de justificatifs Altme. Seul le parcours ID360 vers OpenID4VC Hub est maintenu.

## Déroulement

1. Le navigateur ouvre `GET /id360`.
2. Le service crée une session ID360 et redirige l’utilisateur vers l’interface de vérification d’identité.
3. ID360 redirige le navigateur vers la page d’attente et appelle le callback serveur.
4. Lorsque le callback annonce un succès, le service récupère le rapport ID360 et contrôle les attributs PID obligatoires.
5. Le service crée l’émission auprès de `https://openid4vc-hub.com/api/v1/issuances` avec la clé transmise dans l’en-tête `X-API-Key`.
6. Le navigateur affiche le QR code de l’offre et interroge le service pour connaître l’état de l’émission.

La clé API OpenID4VC Hub reste côté serveur.

## Prérequis

- Python 3.10 ou plus récent ;
- Redis sur `127.0.0.1:6379`, base `0` ;
- un compte, un parcours et une clé de callback ID360 ;
- une clé API OpenID4VC Hub autorisée à utiliser l’émetteur `core-pid-issuer` ;
- une URL publique HTTPS permettant à ID360 de joindre le callback.

## Configuration

Créer `keys.json` à la racine du projet. Ce fichier est ignoré par Git et ne doit jamais être publié.

```json
{
  "appSecretKey": "replace-with-a-random-flask-secret",
  "id360ApiKey": "replace-with-the-id360-callback-key",
  "openid4vc-hub": "replace-with-the-hub-api-key",
  "username": "replace-with-the-id360-preproduction-login",
  "password": "replace-with-the-id360-preproduction-password",
  "username_prod": "replace-with-the-id360-production-login",
  "password_prod": "replace-with-the-id360-production-password"
}
```

Les URLs ID360, les identifiants de parcours et l’URL publique du service sont définis dans `environment.py` :

- `MYENV=local` utilise la préproduction ID360 et l’URL `ngrok` configurée dans ce fichier ;
- `MYENV=aws` utilise la production ID360 et `https://talao.co` ;
- sans variable `MYENV`, le mode `local` est sélectionné.

Avant un essai local, remplacer la valeur `ngrok` par l’URL publique HTTPS correspondant au tunnel actif.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Redis doit être démarré avant l’application.

## Lancement

En local :

```bash
MYENV=local python main.py
```

Avec Gunicorn, par exemple :

```bash
MYENV=aws gunicorn --bind 127.0.0.1:3000 main:app
```

## Routes actives

| Méthode | Route | Rôle |
| --- | --- | --- |
| `GET` | `/id360` | Démarre l’identification ID360. |
| `GET`, `POST` | `/id360/callback/<code>` | Reçoit le résultat ID360. L’en-tête `api-key` est obligatoire. |
| `GET` | `/id360/wait/<code>` | Affiche la page d’attente après le parcours ID360. |
| `GET` | `/id360/kyc_status/<code>` | Indique au navigateur l’état du traitement ID360. |
| `GET` | `/id360/offer/<code>` | Affiche le QR code de l’offre PID. |
| `GET` | `/id360/status/<code>` | Transmet au navigateur l’état renvoyé par le Hub. |

Les routes de callback, d’attente et d’offre sont générées par l’application. Un client normal démarre uniquement sur `/id360`.

## États et durées de vie

Les états de traitement enregistrés dans Redis sont :

- `PENDING` : ID360 n’a pas encore terminé ;
- `CREATING` : le rapport est reçu et l’émission Hub est en cours de création ;
- `OK` : l’offre PID est disponible ;
- `KO` : ID360 a échoué ou l’émission n’a pas pu être créée.

Durées configurées dans `routes/oidc_openid4vc_hub.py` :

- token ID360 : 14 minutes ;
- session ID360 en attente : 24 heures ;
- émission et offre Hub : 10 minutes ;
- verrou anti-double-callback : 60 secondes.

Les callbacks ID360 répétés sont ignorés après le premier traitement valide.

## Données PID

Les attributs obligatoires sont `family_name`, `given_name`, `birthdate` et `sex`. La date de naissance doit être au format `YYYY-MM-DD` et ne peut pas être future. Une émission n’est pas créée lorsqu’un attribut obligatoire manque ou que la valeur du sexe n’est pas reconnue.

La configuration Hub actuellement demandée est :

- émetteur : `core-pid-issuer` ;
- configuration : `eu.europa.ec.eudi.pid_jwt_vc` ;
- grant : `urn:ietf:params:oauth:grant-type:pre-authorized_code`.

## Compatibilité ID360

Le code utilise les champs `callback_url`, `browser_callback_url` et `callback_headers`, qui fonctionnent avec le déploiement ID360 actuellement utilisé. Une documentation ID360 plus récente peut présenter `callback_endpoints` ; toute migration vers ce format doit être testée séparément avant de remplacer le format fonctionnel.

Références de travail :

- `Guide du développeur ID360.pdf`, copie locale potentiellement ancienne ;
- `../openid4vc-hub/API.md`, documentation API du Hub dans le dépôt voisin ;
- [documentation développeur ID360](https://wiki.id360.dis-docaposte.com/doku.php?id=guide_du_developpeur_capture).

## Vérification rapide

Les tests utilisent uniquement des clés, un Redis et des réponses HTTP fictifs :

```bash
python -m unittest discover -s tests -v
```

La commande suivante vérifie que l’application peut être importée et affiche sa carte de routes sans démarrer le serveur :

```bash
MYENV=aws python -c "from main import app; print(app.url_map)"
```

## Conservation de `doca.py`

`doca.py` est un utilitaire ID360 historique conservé volontairement, notamment pour permettre de retrouver ou tester l’ancien accès ID360 si les identifiants ne peuvent pas être remplacés.

Ce fichier est autonome, contient des informations sensibles et effectue des appels réseau lorsqu’il est exécuté. Il ne doit pas être importé par l’application, exécuté automatiquement ou ajouté à un dépôt public. Il ne doit pas être supprimé lors des futurs nettoyages.
