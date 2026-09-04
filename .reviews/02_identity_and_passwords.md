# Audit de Sécurité : Sous-systèmes Identity, Passwords et Rate Limiting

**Projet :** `github.com/JLugagne/libauth`  
**Périmètre :** `identity/`, `passwords/`, `ratelimit/`, `adapters/pgx/identity`  
**Date :** 4 septembre 2026  
**Auditeur :** Expert en Sécurité Logicielle & Gestion des Identités Go  

---

## Synthèse Exécutive

Cet audit de sécurité approfondi a porté sur le cœur d'authentification, le cycle de vie des identités, le hachage et les politiques de mots de passe, ainsi que les mécanismes de rate limiting et l'adaptateur de persistance PostgreSQL (`adapters/pgx/identity`).

L'architecture globale présente des choix cryptographiques solides (utilisation de CSPRNG, hashage Argon2id avec planchers minimaux, tokens à schéma sélecteur/vérificateur avec comparaisons en temps constant). Néanmoins, plusieurs vulnérabilités critiques et majeures ont été identifiées, notamment :
1. **Des failles d'usurpation de compte (ATO)** via la modification d'adresse email sans ré-authentification ni notification du compte d'origine, ainsi qu'un contournement du MFA lors de la connexion par Magic Link.
2. **Des dénis de service (DoS) pré-authentification** déclenchés par le calcul coûteux d'Argon2id sur des tokens inexistants ou des emails déjà enregistrés avant toute validation en base.
3. **Une énumération d'utilisateurs couplée à un verrouillage de compte (Lockout DoS)** due à la distinction HTTP 429 (`account_locked`) vs 401 (`invalid_credentials`) qui permet à un attaquant non authentifié de tester des listes d'emails et de verrouiller les comptes valides.
4. **Des contournements de rate limiting** causés par l'éviction de buckets épuisés lors de saturation du cache en mémoire.

Plusieurs vulnérabilités dépassent le seuil critique de **CVSS > 7.5**.

---

## Vulnérabilités Identifiées

### SEC-ID-01 : Déni de Service Pré-Authentification par Hachage Argon2id Inconditionnel dans `ResetPassword` et `Register`

- **Score CVSS v3.1 :** **7.5** (High)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Fichiers et lignes :**
  - `identity/service.go:440-447` (méthode `Register`)
  - `identity/service.go:704-712` (méthode `ResetPassword`)
- **Description détaillée du mécanisme :**
  - Dans `ResetPassword`, l'appel `s.hasher.Hash(ctx, newPassword)` est exécuté **avant** de vérifier la validité, l'existence ou l'expiration du token de réinitialisation (`s.consumeForLiveUser`). Un attaquant distant peut envoyer des requêtes avec des tokens aléatoires/forgés : le serveur alloue 64 MiB de mémoire et mobilise 4 threads CPU pour dériver la clé Argon2id avant de constater que le token n'existe pas.
  - Dans `Register`, `s.hasher.Hash(ctx, password)` est exécuté **avant** de vérifier si l'adresse email existe déjà en base (`s.store.CreateUser`). L'attaquant peut envoyer des requêtes de création avec des emails déjà existants pour forcer un hachage lourd systématique sans aucun coût côté attaquant.
- **Scénario d'exploitation théorique et impact :**
  Un attaquant non authentifié envoie un flux continu de requêtes HTTP `POST /password-reset/confirm` (ou `/register`) avec un mot de passe valide selon la politique et un token fictif. Le serveur alloue 64 MiB par requête concurrente. Avec quelques dizaines de requêtes concurrentes, le CPU est saturé à 100% et la mémoire vive est épuisée, déclenchant l'intervention du OOM Killer Linux et rendant le service indisponible pour tous les utilisateurs.
- **Recommandation de correction :**
  - Dans `ResetPassword` : valider et vérifier l'existence/l'expiration du token (ou le consommer de manière transactionnelle) **avant** d'invoquer le KDF `s.hasher.Hash`.
  - Dans `Register` : vérifier l'unicité de l'email (ou insérer une réservation) **avant** de lancer le hachage coûteux du mot de passe.

---

### SEC-ID-02 : Prise de Contrôle de Compte (ATO) via Modification d'Email sans Ré-authentification ni Alerte

- **Score CVSS v3.1 :** **8.8** (High)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Fichiers et lignes :**
  - `identity/handlers.go:889-943` (`RequestEmailChangeHandler`)
  - `identity/service.go:807-833` (`RequestEmailChange`)
  - `identity/service.go:836-864` (`ConfirmEmailChange`)
- **Description détaillée du mécanisme :**
  - Contrairement à `ChangePasswordHandler` qui exige le `current_password`, `RequestEmailChangeHandler` exige uniquement le nouveau champ `new_email`. Aucune preuve de possession du mot de passe actuel ou challenge MFA n'est demandé.
  - De plus, le token de confirmation est expédié **uniquement** à l'adresse `new_email` (`deliverTo := newEmail`). Aucune notification, confirmation ni lien d'annulation n'est transmis à l'adresse email initiale (`user.Email`).
  - Lors de la confirmation (`ConfirmEmailChange`), la méthode `UpdateUserEmail` re-lie automatiquement l'identité `password` vers `newEmail`.
- **Scénario d'exploitation théorique et impact :**
  Un attaquant obtenant un accès temporaire à une session utilisateur (via XSS, vol de token, poste de travail non verrouillé ou session préliminaire) soumet une requête `POST /email-change/request` avec une adresse qu'il contrôle. La victime ne reçoit aucun avertissement sur sa boîte de réception habituelle. L'attaquant confirme le changement depuis sa propre boîte mail, puis exécute un `RequestPasswordReset` pour écraser le mot de passe et expulser définitivement la victime de son compte.
- **Recommandation de correction :**
  1. Exiger la saisie du mot de passe actuel (`current_password`) ou une ré-authentification forte (step-up MFA) avant d'accepter une demande de changement d'email.
  2. Expédier obligatoirement un email d'avertissement avec possibilité de blocage/révocation sur l'adresse email d'origine de l'utilisateur.

---

### SEC-ID-03 : Contournement Complet du MFA via la Connexion par Magic Link (`MagicLinkLoginHandler`)

- **Score CVSS v3.1 :** **8.1** (High)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
- **Fichiers et lignes :**
  - `identity/handlers.go:718-759` (`MagicLinkLoginHandler`)
  - `identity/handlers.go:345-360` (comparaison avec `LoginHandler`)
- **Description détaillée du mécanisme :**
  - Dans `LoginHandler`, lorsque l'option `WithMFAGate` est activée, l'enrôlement MFA de l'utilisateur est contrôlé via `cfg.mfaGate.IsEnrolled`. Si l'utilisateur possède un second facteur configuré, il reçoit un token d'accès temporaire intermédiaire (`AMR=[pwd]`, sans cookie de rafraîchissement) forçant le passage par le second facteur.
  - Dans `MagicLinkLoginHandler`, la vérification `cfg.mfaGate` est **totalement absente**. Dès que le token de magic link est validé, le handler appelle directement `issuePairAndSetCookies(w, r, cfg, issuer, claimsOf, user, remember, mustChange)`, qui émet une paire complète de tokens d'accès et de rafraîchissement pérennes, sans exiger le second facteur.
- **Scénario d'exploitation théorique et impact :**
  Un utilisateur a activé une authentification à deux facteurs stricte (TOTP ou WebAuthn/FIDO2) pour protéger son compte. Si un attaquant compromet sa messagerie ou intercepte un lien magique, il utilise l'endpoint `MagicLinkLoginHandler`. Le serveur l'authentifie immédiatement avec une session complète et durable sans jamais exiger le second facteur. Le MFA est rendu inopérant.
- **Recommandation de correction :**
  Intégrer le contrôle `cfg.mfaGate` dans `MagicLinkLoginHandler` : si l'utilisateur possède un second facteur enrôlé, émettre un token intermédiaire et exiger la validation du second facteur avant de délivrer le cookie de rafraîchissement et la session complète.

---

### SEC-ID-04 : Énumération d'Utilisateurs et Déni de Service par Verrouillage Forcé (`mapAuthError`)

- **Score CVSS v3.1 :** **8.2** (High)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H`
- **Fichiers et lignes :**
  - `identity/handlers.go:520-536` (`mapAuthError`)
  - `identity/service.go:549-553` (`Authenticate`)
- **Description détaillée du mécanisme :**
  - La fonction `mapAuthError` traduit `ErrAccountLocked` et `ErrAccountDisabled` en HTTP 429 Too Many Requests (`"account_locked"`), tandis que les mauvais identifiants ou comptes inexistants renvoient HTTP 401 Unauthorized (`"invalid_credentials"`).
  - Bien que `Authenticate` utilise `decoyHash` pour lisser le temps de calcul, le statut HTTP renvoyé divulgue l'état réel du compte.
  - Un attaquant peut soumettre 5 tentatives erronées (seuil par défaut `DefaultLockThreshold`) pour une adresse cible :
    * Si le compte **n'existe pas** : chaque tentative renvoie `401 invalid_credentials`.
    * Si le compte **existe** : la 6ème tentative renvoie `429 account_locked`.
- **Scénario d'exploitation théorique et impact :**
  Un attaquant distant peut scanner une liste d'adresses email. Dès qu'une cible répond avec le code HTTP 429 au bout de 5 essais, l'attaquant a la confirmation formelle que le compte existe dans le système. Simultanément, cette attaque verrouille le compte de la victime pendant `DefaultLockDuration` (15 minutes), interdisant tout accès légitime à l'utilisateur.
- **Recommandation de correction :**
  Renvoyer un statut uniforme (HTTP 401 avec message générique) en cas d'échec d'authentification, qu'il s'agisse d'un mauvais mot de passe ou d'un compte verrouillé, ou appliquer un rate-limiting global par IP/cible empêchant d'atteindre le seuil de verrouillage de manière anonyme.

---

### SEC-ID-05 : Contournement du Rate Limiting par Empoisonnement et Éviction dans `TokenBucket`

- **Score CVSS v3.1 :** **5.3** (Medium)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
- **Fichiers et lignes :**
  - `ratelimit/tokenbucket.go:86-90` (`Allow`)
  - `ratelimit/tokenbucket.go:160-185` (`evictOne`)
- **Description détaillée du mécanisme :**
  - Lorsque `TokenBucket` est configuré avec `WithMaxKeys(N)`, la méthode `evictOne` est appelée dès que le nombre de clés atteint le plafond.
  - `evictOne` échantillonne 5 clés au hasard et recherche celle dont le nombre de tokens recalculé `toks` est supérieur à `evictToks` (initialisé à `-1`).
  - Si les 5 clés échantillonnées sont sous forte pression (par exemple `tokens == 0`), `0 > -1` est vrai : `evictOne` sélectionne et **supprime** un bucket complètement épuisé.
  - Lorsqu'une clé supprimée effectue sa requête suivante, `tb.buckets[key]` n'existe plus : un nouveau bucket est instancié avec le quota maximal de tokens (`tokens = tb.burst`).
- **Scénario d'exploitation théorique et impact :**
  Un attaquant dont l'adresse IP est bloquée par le limiteur de débit génère `N` requêtes avec des clés factices (par exemple des adresses IP forgées si le middleware lit un header non assaini, ou des emails aléatoires). L'éviction supprime son propre bucket bloqué. L'attaquant retrouve instantanément son quota de burst maximal et peut reprendre ses attaques par force brute sans jamais attendre la période de rechargement.
- **Recommandation de correction :**
  Refuser formellement l'éviction de buckets qui ne sont pas entièrement rechargés (`toks < tb.burst`), ou implémenter une politique LRU/LFU stricte qui conserve la trace des clés bannies ou épuisées.

---

### SEC-ID-06 : Épuisement Mémoire (DoS) par Absence de Plafond par Défaut dans `TokenBucket`

- **Score CVSS v3.1 :** **7.5** (High)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Fichiers et lignes :**
  - `ratelimit/tokenbucket.go:33, 57-74` (`NewTokenBucket`)
  - `ratelimit/tokenbucket.go:84-93` (`Allow`)
- **Description détaillée du mécanisme :**
  - Par défaut, `NewTokenBucket` initialise `maxKeys` à `0` (ce qui signifie illimité).
  - Aucune tâche d'éviction ou de nettoyage automatique en arrière-plan n'est démarrée par défaut dans l'instance de `TokenBucket`.
  - Chaque clé unique reçue (adresse IP source, identifiant, etc.) alloue une structure `bucketState` stockée indéfiniment dans la map `tb.buckets`.
- **Scénario d'exploitation théorique et impact :**
  Un attaquant distribuant ses requêtes depuis un botnet ou forgeant des clés uniques remplit la map mémoire du limiteur de débit. Sans appel externe à `Cleanup()`, la mémoire du processus croît de manière non bornée jusqu'au crash de l'application.
- **Recommandation de correction :**
  Fixer un plafond `maxKeys` par défaut (ex: 100 000 clés) dans `NewTokenBucket` et/ou intégrer un worker de nettoyage automatique périodique des buckets expirés.

---

### SEC-ID-07 : Déni de Service Distribué des Livraisons de Sécurité (Email/SMS) par Saturation du Sémaphore

- **Score CVSS v3.1 :** **7.5** (High)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Fichiers et lignes :**
  - `identity/handlers.go:35, 40` (`DefaultDeliveryConcurrency`, `DefaultDeliveryTimeout`)
  - `identity/handlers.go:456-491` (`dispatchDelivery`)
- **Description détaillée du mécanisme :**
  - Les requêtes de réinitialisation de mot de passe, de magic links et de vérifications utilisent `dispatchDelivery` pour expédier les emails/SMS hors du chemin critique de la requête HTTP.
  - Le parallélisme est limité par un sémaphore channel `deliverySem` de capacité fixe (64 par défaut) avec un timeout de 30 secondes.
  - Lorsque le sémaphore est plein, la clause `select ... default:` **abandonne immédiatement** la livraison (`ErrDeliveryDropped`) sans mise en file d'attente.
  - Le handler HTTP renvoie cependant une réponse positive `204 No Content` au client.
- **Scénario d'exploitation théorique et impact :**
  Un attaquant bombarde l'endpoint public non authentifié `RequestPasswordResetHandler` de 64 requêtes vers des comptes existants. Si le serveur SMTP externe met quelques secondes à répondre, les 64 créneaux sont monopolisés. Toute demande légitime de réinitialisation de mot de passe ou de magic link survenant pendant cette période est silencieusement détruite alors que l'utilisateur reçoit un message indiquant que l'email a été envoyé. L'utilisateur est dans l'impossibilité de se connecter ou de récupérer son compte.
- **Recommandation de correction :**
  Remplacer le rejet immédiat (`drop`) par une file d'attente tamponnée (buffered queue) persistante avec mécanisme de retry, ou appliquer un rate limiting strict en amont du sémaphore.

---

### SEC-ID-08 : Usurpation de Compte par Confusion Sociale sur le Token SMS de Réinitialisation

- **Score CVSS v3.1 :** **8.8** (High)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **Fichiers et lignes :**
  - `identity/handlers.go:1320-1325` (`RequestPasswordResetViaRecoveryHandler`)
  - `identity/delivery.go:83-90, 100-103` (`PhoneVerificationSMS`, `SMSSender`)
- **Description détaillée du mécanisme :**
  - Lors d'une réinitialisation de mot de passe via le canal de récupération téléphonique (`RequestPasswordResetViaRecoveryHandler`), le token généré est de type `KindPasswordReset`.
  - Cependant, le handler transmet ce token via le callback `sender.PhoneVerification` en l'encapsulant dans la structure `PhoneVerificationSMS{User: user, Phone: phone, Token: token}`.
  - L'application intégratrice, s'appuyant sur le nom de la structure et du callback, transmet au destinataire un SMS standard du type : *"Votre code de vérification de numéro de téléphone est : [token]"*.
- **Scénario d'exploitation théorique et impact :**
  Un attaquant déclenche une réinitialisation de mot de passe vers le numéro de téléphone de secours de la victime. La victime reçoit un SMS indiquant qu'il s'agit d'une simple validation de numéro de téléphone. L'attaquant contacte la victime (ingénierie sociale / vishing) sous un prétexte bénin pour récupérer ce code. Dès que la victime transmet le code, l'attaquant l'injecte dans `ResetPassword` et réinitialise le mot de passe, prenant le contrôle total du compte.
- **Recommandation de correction :**
  Créer une interface et une structure distinctes dédiées aux SMS de réinitialisation de mot de passe (`PasswordResetSMS`), affichant clairement un avertissement de sécurité explicite dans le message.

---

### SEC-ID-09 : Modification et Réactivation de Comptes Suspendus ou Supprimés dans `ChangePassword` et `UpdateIdentityPassword`

- **Score CVSS v3.1 :** **7.1** (High)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`
- **Fichiers et lignes :**
  - `identity/service.go:743-804` (`ChangePassword`)
  - `identity/service.go:1369-1402` (`SetTemporaryPassword`)
  - `adapters/pgx/identity/store.go:346-361` (`UpdateIdentityPassword`)
  - `identity/memory/store.go:270-288` (`UpdateIdentityPassword`)
- **Description détaillée du mécanisme :**
  - La méthode `ChangePassword` charge les identités via `FindIdentitiesByUserID`, sans vérifier si l'utilisateur possède `deleted_at IS NOT NULL` ou `disabled_at IS NOT NULL`.
  - La requête SQL dans `adapters/pgx/identity/store.go` met à jour `identities` sans joindre sur `users` pour vérifier si le compte est actif.
  - `UpdateIdentityPassword` remet à zéro `failed_attempts` et `locked_until`.
  - Dans `ChangePasswordWithReissueHandler` (`identity/handlers.go:873`), une fois le mot de passe modifié, le handler réémet immédiatement une paire de tokens d'authentification valides (`issuePairAndSetCookies`).
- **Scénario d'exploitation théorique et impact :**
  Un compte utilisateur suspendu administrativement (`DisabledAt != nil`) dont la session résiduelle n'a pas été invalidée peut invoquer `ChangePasswordWithReissueHandler`. Le mot de passe est mis à jour, les verrouillages sont réinitialisés et le serveur lui délivre une nouvelle session JWT active, annulant de fait la suspension administrative.
- **Recommandation de correction :**
  Dans `ChangePassword`, `SetTemporaryPassword` et `UpdateIdentityPassword`, valider systématiquement que le compte utilisateur existe et qu'il n'est ni supprimé (`DeletedAt == nil`) ni suspendu (`DisabledAt == nil`).

---

### SEC-ID-10 : Piégeage de Compte et Verrouillage Indéfini par Absence d'Expiration des Tentatives Échouées

- **Score CVSS v3.1 :** **5.3** (Medium)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **Fichiers et lignes :**
  - `adapters/pgx/identity/store.go:473-488` (`IncrementFailedAttempts`)
  - `identity/memory/store.go:376-401` (`IncrementFailedAttempts`)
- **Description détaillée du mécanisme :**
  - Le compteur `failed_attempts` n'est réinitialisé que lors d'un login réussi ou d'un changement de mot de passe.
  - Tant que le seuil de verrouillage n'est pas atteint (`locked_until IS NULL`), les tentatives échouées ne subissent aucun décrément ni fenêtre temporelle glissante (pas de TTL).
- **Scénario d'exploitation théorique et impact :**
  Un attaquant envoie 4 tentatives infructueuses contre un compte (seuil = 5). Le compteur reste à 4 pendant plusieurs semaines. Dès que l'utilisateur légitime commet une seule faute de frappe, son compte est instantanément verrouillé pour 15 minutes.
- **Recommandation de correction :**
  Associer une fenêtre d'expiration (ex: 15 minutes d'inactivité) au compteur `failed_attempts` afin qu'il se réinitialise automatiquement en l'absence de tentatives répétées rapprochées (conformément au NIST SP 800-63B).

---

### SEC-ID-11 : Fuite d'Informations et Énumération d'Utilisateurs par Oracle Temporel sur les Requêtes de Réinitialisation et Magic Links

- **Score CVSS v3.1 :** **5.3** (Medium)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Fichiers et lignes :**
  - `identity/service.go:617-649` (`RequestPasswordReset`)
  - `identity/service.go:1030-1049` (`RequestMagicLink`)
  - `identity/service.go:1258-1295` (`RequestPasswordResetViaRecovery`)
- **Description détaillée du mécanisme :**
  - Dans `Authenticate`, une opération `decoyHash` équilibre le temps de réponse.
  - En revanche, dans `RequestPasswordReset`, `RequestMagicLink` et `RequestPasswordResetViaRecovery`, lorsqu'un email n'existe pas, la fonction s'interrompt immédiatement après une simple lecture SQL (`FindUserByEmail`).
  - Si l'email existe, le serveur effectue des lectures supplémentaires, génère de l'entropie cryptographique et exécute un `INSERT` synchrone dans la table `verification_tokens` (écriture sur disque/WAL).
- **Scénario d'exploitation théorique et impact :**
  En mesurant la latence des réponses HTTP sur un grand nombre d'échantillons, un attaquant distant peut distinguer les adresses valides (nécessitant des écritures DB) des adresses inexistantes, contournant l'objectif d'anti-énumération de la bibliothèque.
- **Recommandation de correction :**
  Introduire une charge fictive (calcul ou lecture) sur le chemin d'échec ou différer la création du token hors du chemin critique synchrone.

---

### SEC-ID-12 : Jeton d'Accès Intermédiaire MFA Valide sur les Routes Non Gated par AMR

- **Score CVSS v3.1 :** **8.2** (High)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Fichiers et lignes :**
  - `identity/handlers.go:1370-1392` (`issueInterimAndSetCookie`)
- **Description détaillée du mécanisme :**
  - Lors de la phase 1 du login MFA, `issueInterimAndSetCookie` génère un véritable JWT d'accès avec `claims.Subject = user.ID`, `AMR=["pwd"]` et le dépose dans le cookie standard `auth_access`.
  - Le middleware `tokens.RequireAuth` ne vérifie pas les claims `AMR` par défaut à moins que le développeur n'ajoute explicitement `tokens.WithRequiredAMR(tokens.AMRMFA)`.
- **Scénario d'exploitation théorique et impact :**
  Un attaquant ne disposant que du mot de passe de la victime reçoit ce jeton intermédiaire valable 5 minutes. Il peut alors requêter n'importe quel endpoint de l'API protégé par `RequireAuth` standard qui n'a pas été configuré manuellement avec le filtre `WithRequiredAMR`.
- **Recommandation de correction :**
  Utiliser un cookie ou un type de jeton dédié distinct (ex: `auth_mfa_pending`) ou marquer le token avec un scope restreint empêchant son acceptation par `RequireAuth`.

---

### SEC-ID-13 : Absence d'Anonymisation des Numéros de Téléphone et Emails de Secours lors de la Suppression de Compte

- **Score CVSS v3.1 :** **5.3** (Medium)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Fichiers et lignes :**
  - `adapters/pgx/identity/store.go:201-218` (`DeleteUser`)
  - `identity/memory/store.go:174-191` (`DeleteUser`)
- **Description détaillée du mécanisme :**
  - Lorsque `DeleteUser` est appelé pour effectuer un soft-delete avec anonymisation, seules les colonnes `email` et `identities.provider_id` (pour le provider `password`) sont anonymisées avec un UUID.
  - Les champs `phone`, `phone_verified_at`, `recovery_email` et `recovery_email_verified_at` restent intacts dans la base de données.
- **Scénario d'exploitation théorique et impact :**
  Non-conformité RGPD / violation de la vie privée : les données personnelles sensibles (numéro de téléphone et email secondaire) sont conservées en clair indéfiniment après la suppression du compte.
- **Recommandation de correction :**
  Ajouter la réinitialisation à `NULL` de `phone`, `phone_verified_at`, `recovery_email` et `recovery_email_verified_at` dans la clause `UPDATE users` de `DeleteUser`.

---

### SEC-ID-14 : Politique de Mot de Passe par Défaut Non Conforme aux Recommandations Modernes (NIST SP 800-63B)

- **Score CVSS v3.1 :** **6.5** (Medium)
- **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
- **Fichiers et lignes :**
  - `passwords/policy/default.go:23-32, 35-76`
- **Description détaillée du mécanisme :**
  - `DefaultPolicy` impose des règles de composition traditionnelles (majuscule, minuscule, chiffre, caractère spécial) et limite arbitrairement la longueur à 72 caractères.
  - Elle n'effectue aucune vérification contre les listes de mots de passe compromis (denylist ou HIBP).
- **Scénario d'exploitation théorique et impact :**
  Des mots de passe très faibles mais respectant les classes de caractères (ex: `Password123!`, `Admin2024!`) sont acceptés, facilitant les attaques par pulvérisation de mots de passe (password spraying) et credential stuffing.
- **Recommandation de correction :**
  Faire de `PassphrasePolicy` avec `BreachChecker` la politique recommandée par défaut, augmenter la longueur minimale à 12 caractères et bannir les mots de passe compromis.

---

## Récapitulatif des Vulnérabilités

| ID | Titre | Sévérité | Score CVSS v3.1 | Vecteur CVSS v3.1 |
|---|---|---|---|---|
| **SEC-ID-01** | DoS Pré-Auth par Hachage Argon2id Inconditionnel | High | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-ID-02** | Account Takeover (ATO) via Changement d'Email sans Re-Auth | High | **8.8** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **SEC-ID-03** | Contournement du MFA via Magic Link Login | High | **8.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` |
| **SEC-ID-04** | Énumération d'Utilisateurs & Lockout DoS via HTTP 429 | High | **8.2** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H` |
| **SEC-ID-05** | Contournement du Rate Limiting par Éviction de Buckets | Medium | **5.3** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **SEC-ID-06** | Fuite Mémoire et DoS par Défaut dans `TokenBucket` | High | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-ID-07** | Rejet et Perte Silencieuse des Livraisons de Sécurité | High | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-ID-08** | Social Engineering ATO via Mislabeled Reset SMS | High | **8.8** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| **SEC-ID-09** | Mutation & Réactivation de Comptes Suspendus / Supprimés | High | **7.1** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` |
| **SEC-ID-10** | Piégeage de Compte par Persistance des Échecs sans TTL | Medium | **5.3** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **SEC-ID-11** | Énumération d'Utilisateurs par Oracle Temporel | Medium | **5.3** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **SEC-ID-12** | Jeton Intermédiaire MFA Utilisable sur Routes Non Gated | High | **8.2** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| **SEC-ID-13** | Conservation de PII (Phone/Recovery) lors de Suppression | Medium | **5.3** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **SEC-ID-14** | Faiblesse de la Politique de Mot de Passe par Défaut | Medium | **6.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |

---

## Alerte Sévérité : Vulnérabilités avec Score CVSS > 7.5

> [!CAUTION]
> **OUI**, il existe **5 vulnérabilités critiques/hautes avec un score CVSS > 7.5** (et 3 vulnérabilités supplémentaires atteignant exactement 7.5) :
>
> 1. **SEC-ID-02 (CVSS 8.8)** : Prise de Contrôle de Compte (ATO) via Changement d'Email sans Ré-authentification
> 2. **SEC-ID-08 (CVSS 8.8)** : Usurpation de Compte par Confusion Sociale sur le Token SMS de Réinitialisation
> 3. **SEC-ID-04 (CVSS 8.2)** : Énumération d'Utilisateurs et Lockout DoS via Distinction HTTP 429
> 4. **SEC-ID-12 (CVSS 8.2)** : Jeton d'Accès Intermédiaire MFA Valide sur les Routes Standard
> 5. **SEC-ID-03 (CVSS 8.1)** : Contournement Total du MFA via Connexion Magic Link
>
> Ces failles doivent être corrigées en priorité absolue avant tout déploiement en production.
