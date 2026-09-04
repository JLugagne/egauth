# Rapport Exhaustif des Vulnérabilités par Criticité (CVSS v3.1)

**Projet :** `github.com/JLugagne/libauth` (`egauth`)  
**Type d'audit :** Audit de sécurité approfondi multi-agents (Statique, Cryptographique, Dynamique & Workflows)  
**Date :** 4 septembre 2026  
**Total de vulnérabilités identifiées :** **77 vulnérabilités**  

---

## 1. Distribution par Niveau de Criticité (CVSS v3.1)

| Criticité | Intervalle CVSS | Nombre de Failles | Pourcentage | Statut |
| :--- | :---: | :---: | :---: | :--- |
| 🔴 **Critique** | 9.0 - 10.0 | **1** | 1.3 % | Patch en cours |
| 🟠 **Élevée** | 7.0 - 8.9 | **26** | 33.8 % | 18 failles > 7.5, 8 failles = 7.5 |
| 🟡 **Moyenne** | 4.0 - 6.9 | **41** | 53.2 % | Advisory / Hardening |
| 🟢 **Faible** | 0.1 - 3.9 | **9** | 11.7 % | Qualité & Robustesse |

---

## 2. Vulnérabilités Critiques (CVSS 9.0 - 10.0)

### [SEC-OAU-01] Collision d'identifiants OAuth/OIDC et usurpation de compte via perte de précision flottante (`float64`) dans `stringifyID`
* **Score CVSS v3.1 :** **9.8** (Critique) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **Composant :** `oauth/providers/gitlab.go:70-79`, `oauth/providers/okta.go:76`
* **Description :** `oauth.GetJSON` décode les payloads JSON dans un champ `any` sans `json.Decoder.UseNumber()`. Les identifiants numériques (notamment Snowflake / 64 bits dépassant $2^{53}$) sont convertis en `float64`, perdant leur précision (ex: `9007199254740992` et `9007199254740993` s'arrondissent à la même valeur). Deux utilisateurs distincts obtiennent le même `ProviderID`, permettant l'usurpation totale de compte (Account Takeover).
* **Remédiation :** Utiliser `json.Decoder.UseNumber()` dans `GetJSON` et traiter `json.Number` dans `stringifyID`.

---

## 3. Vulnérabilités Élevées (CVSS 7.0 - 8.9)

### [SEC-ID-02] Prise de Contrôle de Compte (ATO) via Changement d'Email sans Ré-authentification ni Alerte
* **Score CVSS v3.1 :** **8.8** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
* **Composant :** `identity/service.go:811`, `identity/handlers.go:585`
* **Description :** L'initiation d'un changement d'email n'exige pas le mot de passe actuel et n'envoie aucune notification préventive sur l'adresse email d'origine. Un attaquant disposant d'un accès temporaire à une session peut modifier l'email sans que la victime ne soit alertée.
* **Remédiation :** Exiger le mot de passe actuel ou une confirmation sur l'email d'origine avant validation.

### [SEC-ID-08] Usurpation de Compte par Confusion Sociale sur le Token SMS de Réinitialisation
* **Score CVSS v3.1 :** **8.8** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
* **Composant :** `identity/handlers.go:1323`, `identity/service.go:1264`
* **Description :** `RequestPasswordResetViaRecoveryHandler` réutilise le callback `PhoneVerification` pour transmettre un code de réinitialisation de mot de passe. Le SMS reçu par l'utilisateur indique "code de vérification", facilitant le phishing et l'ingénierie sociale pour réinitialiser le mot de passe.
* **Remédiation :** Introduire un callback dédié et explicite `PasswordResetSMS`.

### [SEC-MFA-02] Révocation non autorisée du 2FA et destruction des facteurs via un jeton intermédiaire
* **Score CVSS v3.1 :** **8.8** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
* **Composant :** `mfa/handlers.go:275-296`
* **Description :** Le endpoint `DisableHandler` autorise les requêtes authentifiées avec un simple jeton intermédiaire (pré-MFA), permettant à un attaquant connaissant le mot de passe de désactiver le second facteur sans le posséder.
* **Remédiation :** Exiger formellement un jeton pleinement authentifié avec claim `amr` (Step-Up / MFA complété).

### [SEC-TOK-01] Absence de données associées (AAD) dans le chiffrement d'enveloppe KEK
* **Score CVSS v3.1 :** **8.3** (Élevé) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N`
* **Composant :** `keystore/kek.go:60,71`, `keystore/resolve.go:73-80`
* **Description :** `KEK.Seal` et `Open` chiffrent avec AES-GCM avec un AAD nul (`nil`). Le secret stocké en base n'est pas lié au `tenantID`. Un attaquant avec accès DB peut copier le ciphertext du Tenant A vers le Tenant B et forger des jetons pour le Tenant A.
* **Remédiation :** Lier systématiquement `tenantID` comme AAD lors du scellement et de l'ouverture KEK.

### [SEC-MFA-03] Absence d'AAD dans le chiffrement d'enveloppe KEK des secrets TOTP
* **Score CVSS v3.1 :** **8.3** (Élevé) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N`
* **Composant :** `adapters/pgx/mfa/store.go:62`
* **Description :** Similaire à SEC-TOK-01, les secrets TOTP scellés en base de données ne comportent pas de liaison AAD avec `userID` ou `tenantID`, autorisant la permutation malveillante de facteurs.
* **Remédiation :** Inclure `tenantID` et `userID` dans l'AAD du chiffrement du secret TOTP.

### [SEC-ID-04] Énumération d'Utilisateurs & Lockout DoS via Distinction HTTP 429 (`mapAuthError`)
* **Score CVSS v3.1 :** **8.2** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H`
* **Composant :** `identity/handlers.go:210, 520`
* **Description :** Lorsqu'un compte est verrouillé, `/login` renvoie HTTP `429 Too Many Requests` avec `"account_locked"`, alors qu'un identifiant inexistant renvoie HTTP `401 Unauthorized` avec `"invalid_credentials"`, permettant l'énumération exacte d'utilisateurs.
* **Remédiation :** Renvoyer une réponse uniforme HTTP 401 `"invalid_credentials"` en mode anti-énumération.

### [SEC-ID-12] Jeton d'Accès Intermédiaire MFA Valide sur les Routes Non Gated par AMR
* **Score CVSS v3.1 :** **8.2** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
* **Composant :** `tokens/middleware.go:221`, `tokens/service.go:53`
* **Description :** Le jeton émis après le mot de passe mais avant la validation du 2FA est un JWT structurellement valide. Les routes protégées par `RequireAuth` sans clause `WithRequiredAMR("mfa")` acceptent ce jeton, contournant le 2FA sur une partie de l'API.
* **Remédiation :** Émettre un jeton typé explicitement comme `pre-mfa` rejeté par défaut sur les routes applicatives standard.

### [SEC-OTP-01] Absence de Cooldown et Réinitialisation du Budget d'Attaques sur OTP
* **Score CVSS v3.1 :** **8.2** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`
* **Composant :** `otp/service.go:94`, `otp/handlers.go:190`
* **Description :** Aucune temporisation minimale (cooldown) n'est imposée entre deux demandes de code OTP. De plus, chaque réémission réinitialise le compteur d'essais à zéro, facilitant les attaques par force brute et la fraude financière sur SMS.
* **Remédiation :** Conserver le budget d'essais par fenêtre temporelle et imposer un cooldown strict (ex: 60s).

### [SEC-OAU-02] Chiffrement KEK sans AAD pour `client_secret` OAuth
* **Score CVSS v3.1 :** **8.2** (Élevé) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N`
* **Composant :** `adapters/pgx/oauth/store.go:102`
* **Description :** Le secret client OAuth stocké est chiffré sans AAD, rendant possible la transposition de configuration d'un tenant vers un autre.
* **Remédiation :** Lier le `tenantID` et le `providerName` dans l'AAD du chiffrement KEK.

### [SEC-ID-03] Contournement Complet du MFA via Connexion Magic Link
* **Score CVSS v3.1 :** **8.1** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
* **Composant :** `identity/handlers.go:961`, `identity/service.go:1052`
* **Description :** `MagicLinkLoginHandler` délivre directement une session ou des jetons complets sans vérifier si l'utilisateur possède un second facteur actif (TOTP ou Passkey).
* **Remédiation :** Vérifier l'enrôlement MFA après validation du Magic Link et rediriger vers le sas 2FA.

### [SEC-SES-04] Absence Totale de Vérification CSRF / Origine dans `sessions.RequireSession`
* **Score CVSS v3.1 :** **8.1** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
* **Composant :** `sessions/middleware.go:29`
* **Description :** Le middleware de session authentifie les cookies ambiants sans vérifier l'en-tête `Origin` / `Referer` ni exiger de token anti-CSRF, exposant les endpoints aux attaques CSRF cross-site.
* **Remédiation :** Intégrer une vérification stricte de l'origine sur les méthodes d'écriture (POST, PUT, DELETE, PATCH).

### [SEC-SES-11] Désactivation Silencieuse du CSRF par Conflit dans `webapp.NewWebApp`
* **Score CVSS v3.1 :** **8.1** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
* **Composant :** `webapp/webapp.go:173-178`
* **Description :** Configurer `TrustedOrigins` tout en ayant `InsecureNoOriginCheck = true` désactive silencieusement la vérification CSRF sur toutes les routes webapp.
* **Remédiation :** Rejeter la configuration à la construction si les deux options sont spécifiées simultanément.

### [SEC-MFA-01] Contournement Complet du 2FA via `ChangePasswordWithReissueHandler`
* **Score CVSS v3.1 :** **8.1** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
* **Composant :** `identity/handlers.go:742-780`
* **Description :** L'endpoint de changement de mot de passe réémet immédiatement de nouveaux jetons complets valides sans revalider le second facteur.
* **Remédiation :** Exiger la validation MFA avant réémission ou préserver les contraintes AMR.

### [SEC-OAU-03] Cookie d'État OAuth (`oauth_state`) Non Signé et Non Lié à la Session
* **Score CVSS v3.1 :** **8.1** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
* **Composant :** `oauth/state.go:50`, `oauth/handlers.go:169`
* **Description :** Le cookie d'état OAuth transportant le state CSRF et le code verifier PKCE n'est pas signé cryptographiquement. Un attaquant peut injecter un cookie d'état forgé pour forcer une connexion sur son compte (Login CSRF).
* **Remédiation :** Signer le cookie d'état avec une clé secrète via HMAC-SHA256 ou le chiffrer.

### [SEC-GLO-01] Rupture de Chaîne de Révocation lors de la Réinitialisation de Mot de Passe
* **Score CVSS v3.1 :** **8.1** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
* **Composant :** `identity/service.go:718`, `examples/fullstack/main.go:98`
* **Description :** `ResetPassword` appelle par erreur `erasers` (destiné à détruire le compte et le MFA) au lieu de révoquer les sessions actives, tout en laissant les JWT déjà émis valides pendant leur TTL.
* **Remédiation :** Remplacer l'appel aux `erasers` par les révocateurs de sessions et tokens (`disableRevokers`).

### [SEC-GLO-02] Contournement Complet du MFA/2FA via Connexion OAuth/OIDC
* **Score CVSS v3.1 :** **8.1** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
* **Composant :** `oauth/handlers.go:248-265`, `identity/service.go:944`
* **Description :** `CallbackHandler` émet directement les jetons d'accès applicatifs sans vérifier si le compte lié requiert une authentification à deux facteurs.
* **Remédiation :** Intercepter le flux post-OAuth et rediriger vers le challenge MFA si un facteur est actif.

### [SEC-GLO-03] Absence d'Implémentation de Cascade de Suppression de Tenant
* **Score CVSS v3.1 :** **7.9** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N`
* **Composant :** `keystore/manager.go:235`, `adapters/pgx/`
* **Description :** `DeleteTenant` ne nettoie que le Keystore. Les tables de comptes, identités, sessions et refresh tokens conservent les données orphelines.
* **Remédiation :** Implémenter l'interface `TenantEraser` dans tous les adaptateurs de persistance.

### [SEC-SES-02] Éviction Inter-Tenants Non Cloisonnée dans `sessions/memory.BoundedStore`
* **Score CVSS v3.1 :** **7.7** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H`
* **Composant :** `sessions/memory/store.go:249-266`
* **Description :** `evictOne()` balaie l'ensemble des sessions sans tenir compte du `tenantID`. Un locataire peut saturer la mémoire pour forcer l'éviction des sessions d'autres locataires.
* **Remédiation :** Évincer prioritairement au sein du même tenant ou cloisonner les compteurs par tenant.

### [SEC-OAU-04] SSRF et Contournement DNS Rebinding dans `providers.OIDC`
* **Score CVSS v3.1 :** **7.7** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
* **Composant :** `oauth/providers/oidc.go:78-88`
* **Description :** Le client HTTP par défaut n'utilise pas de `safeDialControl`. Un émetteur malveillant exploitant le DNS rebinding peut cibler l'IP locale `169.254.169.254` ou des sous-réseaux privés.
* **Remédiation :** Appliquer systématiquement le transport sécurisé avec résolution IP stricte au moment de la connexion TCP.

### [SEC-TOK-02] Épuisement Mémoire Non Borné dans `CachingKeyStore`
* **Score CVSS v3.1 :** **7.5** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Composant :** `tokens/jwt/keycache.go:58, 128`
* **Description :** La map des clés mises en cache ne dispose d'aucun plafond maximal (LRU / max size), causant une fuite mémoire continue lors de résolutions de tenants churnants.
* **Remédiation :** Implémenter une taille maximale ou un nettoyage périodique automatique.

### [SEC-ID-01] DoS Pré-Auth par Hachage Argon2id Inconditionnel dans `ResetPassword`
* **Score CVSS v3.1 :** **7.5** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Composant :** `identity/service.go:704`
* **Description :** Le coût CPU et mémoire d'Argon2id est consommé avant même de vérifier la validité du token de réinitialisation en base de données.
* **Remédiation :** Valider l'existence et l'expiration du token de réinitialisation avant d'exécuter le hachage coûteux.

### [SEC-ID-06] Fuite Mémoire et DoS par Défaut dans `TokenBucket` (`maxKeys=0`)
* **Score CVSS v3.1 :** **7.5** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Composant :** `ratelimit/tokenbucket.go:33`
* **Description :** En l'absence de configuration explicite, `maxKeys` vaut 0 (illimité), permettant à un attaquant spoofant des adresses IP d'épuiser la mémoire de l'application.
* **Remédiation :** Définir une limite par défaut stricte (ex: 100 000 clés) avec éviction LRU.

### [SEC-ID-07] Rejet Silencieux des Livraisons de Sécurité par Saturation de Sémaphore
* **Score CVSS v3.1 :** **7.5** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Composant :** `identity/handlers.go:449`
* **Description :** Lorsque le pool de goroutines de livraison de mail est saturé, les emails de réinitialisation de mot de passe sont silencieusement abandonnés sans alerte.
* **Remédiation :** Bloquer temporairement avec timeout ou alerter immédiatement via `event.Sink`.

### [SEC-SES-01] Éviction de Sessions Actives Légitimes dans `BoundedStore`
* **Score CVSS v3.1 :** **7.5** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Composant :** `sessions/memory/store.go:249-266`
* **Description :** Dès que la capacité est atteinte, le store détruit des sessions actives légitimes pour insérer les nouvelles, provoquant des déconnexions intempestives.
* **Remédiation :** Rejeter l'insertion ou augmenter dynamiquement la capacité plutôt que d'expulser des sessions valides.

### [SEC-SES-07] Paniques Silencieusement Avalées dans le Janitor
* **Score CVSS v3.1 :** **7.5** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Composant :** `janitor/janitor.go:104`
* **Description :** Un `recover()` sans journalisation avale les paniques des fonctions de nettoyage périodique, arrêtant le délestage de mémoire sans aucune visibilité opérationnelle.
* **Remédiation :** Journaliser l'erreur et l'émettre sur le bus d'événements `event.Sink`.

### [SEC-OAU-05] DoS et Amplification par Absence de Cache Négatif sur JWKS
* **Score CVSS v3.1 :** **7.5** (Élevé) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Composant :** `oauth/oidc.go:290-310`
* **Description :** Chaque `kid` inconnu déclenche immédiatement une requête HTTP vers le serveur JWKS distant, ouvrant la voie à des attaques d'amplification DoS.
* **Remédiation :** Appliquer du rate limiting et un cache négatif sur les `kid` inconnus.

---

## 4. Vulnérabilités Moyennes (CVSS 4.0 - 6.9) — 41 Vulnérabilités

| ID | Module | Score CVSS | Description Synthétique |
| :--- | :--- | :---: | :--- |
| **SEC-TOK-04** | Tokens | **7.4** | Détournement de session sans détection de vol lors de l'avance de l'attaquant dans la fenêtre de grâce |
| **SEC-GLO-04** | Passkey | **7.4** | Perte de contexte multi-tenant dans le callback Passkey `LoginSuccessFunc` |
| **SEC-TOK-03** | Tokens | **7.1** | Non-atomicité de la rotation des Refresh Tokens menant au DoS et à l'invalidation de session |
| **SEC-ID-09** | Identity | **7.1** | Modification et réactivation de comptes suspendus ou supprimés dans `ChangePassword` |
| **SEC-OAU-06** | OAuth | **6.9** | Dérivation non sécurisée de `redirect_uri` via `Host`/`X-Forwarded-Proto` |
| **SEC-SES-10** | HttpUtil | **6.8** | Faiblesses de validation d'origine dans `internal/httputil` (Cross-Scheme / Host Spoofing) |
| **SEC-TOK-05** | Keystore | **6.5** | Suppression destructrice des clés actives par `RetireExpiredKeys` sur PostgreSQL |
| **SEC-ID-14** | Passwords | **6.5** | Politique de mot de passe par défaut non conforme aux recommandations NIST SP 800-63B |
| **SEC-SES-05** | Sessions | **6.5** | Absence de primitive d'écriture de cookie et omission de `HttpOnly` dans `sessions` |
| **SEC-GLO-08** | Actor | **6.5** | Évanouissement des rôles/groupes et classification humaine abusive de l'acteur anonyme |
| **SEC-GLO-07** | Tokens/OTP | **6.3** | Désynchronisation de tenant entre `tokens.ContextMiddleware` et `otp.SubjectResolver` |
| **SEC-TOK-10** | Tokens | **5.8** | Absence d'expiration absolue des familles de Refresh Tokens (Prolongation indéfinie) |
| **SEC-GLO-06** | Tokens | **5.8** | Collision et écrasement inter-tenant dans le store de jetons en mémoire |
| **SEC-TOK-07** | Keystore | **5.5** | Rétention des clés et secrets déchiffrés en mémoire tas sans zéroisation |
| **SEC-TOK-09** | Tokens | **5.4** | Écrasement et contournement du contrôle `MustChangePassword` lors du rafraîchissement |
| **SEC-TOK-11** | Tokens | **5.4** | Absence de révocation de famille lors de l'appel à `VerifyRefreshToken` sur jeton rejoué |
| **SEC-SES-06** | Sessions | **5.4** | Contournement du plafond `maxLifetime` par `CreateSession` dans le stockage et le Janitor |
| **SEC-TOK-06** | Tokens | **5.3** | Décalage d'horloge provoquant la révocation immédiate de sessions légitimes |
| **SEC-TOK-12** | Tokens | **5.3** | Destruction des preuves d'audit et suppression définitive lors de `RevokeFamily` |
| **SEC-ID-05** | RateLimit | **5.3** | Contournement du Rate Limiting par empoisonnement d'éviction dans `TokenBucket` |
| **SEC-ID-10** | Identity | **5.3** | Piégeage de compte par persistance indéfinie des tentatives échouées sans TTL |
| **SEC-ID-11** | Identity | **5.3** | Énumération d'utilisateurs par oracle temporel sur Password Reset & Magic Link |
| **SEC-ID-13** | Identity | **5.3** | Incomplétude de l'anonymisation PII (Téléphone / Recovery Email) lors de la suppression |
| **SEC-OAU-07** | OAuth | **5.3** | Suivi automatique non sécurisé des redirections HTTP (307/308) avec fuite de `client_secret` |
| **SEC-OAU-08** | OAuth | **5.3** | Absence de validation du paramètre `iss` (RFC 9207) facilitant les attaques Mix-Up |
| **SEC-GLO-09** | Event | **5.3** | Cécité totale de l'Audit Trail (`event.Sink`) sur les rejets du Middleware HTTP |
| **SEC-GLO-10** | Janitor | **5.3** | Blocage indéfini et déni de service lors de l'arrêt du Janitor (`janitor.Stop`) |
| **SEC-TOK-08** | Keystore | **4.9** | Rupture de la procédure de reprise `RenewSigningKey` après révocation d'urgence |
| **SEC-OAU-09** | OAuth | **4.8** | Défaut de filtrage des algorithmes symétriques (`none`, HMAC) dans `AllowedAlgs` |
| **SEC-PSK-01** | Passkey | **4.8** | Absence d'implémentation PostgreSQL de `ChallengeStore` |
| **SEC-PSK-03** | Passkey | **4.7** | Absence de révocation des identifiants clonés sous concurrence |
| **SEC-MFA-04** | MFA | **4.4** | Défaut d'architecture Step-Up : Impossibilité d'utiliser les codes de secours |
| **SEC-SES-08** | Sessions | **4.3** | Non-idempotence de `RevokeSession` et évasion des logs d'audit sur sessions expirées |
| **SEC-OAU-10** | OAuth | **4.3** | Mise en cache en mémoire non bornée `providerCache` dans `pgx/oauth` |
| **SEC-TOK-13** | Tokens | **4.2** | Désynchronisation de type de principal pour les clés API sans type explicite (`""`) |
| **SEC-SES-14** | Sessions | **4.2** | Réassignation arbitraire d'identité utilisateur dans `sessions.Service.BindUser` |
| **SEC-MFA-05** | MFA | **4.2** | Déni de service sur les codes de récupération par verrouillage partagé avec TOTP |
| **SEC-SES-09** | Janitor | **4.0** | Boucle CPU intensive (Busy Loop) dans `janitor.Start` sur intervalle non positif |
| **SEC-PSK-04** | Passkey | **4.0** | Absence d'isolation tenant dans les cookies de cérémonie Passkey |
| **SEC-MFA-06** | MFA | **4.0** | Non-atomicité de la confirmation TOTP (`ConfirmTOTP`) |
| **SEC-OTP-02** | OTP | **4.0** | Condition de course lors de l'émission asynchrone d'OTP |

---

## 5. Vulnérabilités Faibles (CVSS 0.1 - 3.9) — 9 Vulnérabilités

| ID | Module | Score CVSS | Description Synthétique |
| :--- | :--- | :---: | :--- |
| **SEC-PSK-05** | Passkey | **3.8** | Omission des métadonnées d'authentificateur dans `LoginSuccessFunc` |
| **SEC-MFA-07** | MFA | **3.7** | Ordre d'évaluation de la dérive TOTP priorisant l'intervalle passé |
| **SEC-TOK-14** | Tokens | **3.1** | Violation contractuelle de conservation d'état en échec de `ClaimsProvider` |
| **SEC-PSK-06** | Passkey | **3.1** | Absence de vérification Origin / CSRF sur les endpoints Passkey |
| **SEC-SES-12** | Sessions | **2.6** | Déni de service par concurrence stricte lors de la rotation de session |
| **SEC-DOC-01** | Doc | **2.2** | Incohérences mineures dans la documentation d'API |
| **SEC-INT-01** | Internal | **2.0** | Dead code de validation d'origine permissive dans `internal/httputil` |
| **SEC-LOG-01** | Logs | **1.8** | Troncature insuffisante des préfixes de hash dans les journaux de debug |
| **SEC-TST-01** | Test | **1.5** | Mocks de test ignorant les contextes de requête variadiques |

