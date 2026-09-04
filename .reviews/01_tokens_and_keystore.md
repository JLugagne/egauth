# Rapport d'Audit de Sécurité : Sous-système Tokens, JWT et Keystore

**Cible :** `github.com/JLugagne/libauth`  
**Périmètre audité :**
- `tokens/` (jwt, basic, cookies, middleware, handlers, context, redact, service, store)
- `keystore/` (manager, resolve, memory, key lifecycle, tenant keys, rotation, revocation)
- `adapters/pgx/tokens`
- `adapters/pgx/keystore`

**Date :** 4 septembre 2026  
**Auditeur :** Antigravity Security Research  
**Statut :** Terminé

---

## Sommaire Exécutif

Cet audit a analysé en profondeur l'architecture cryptographique, les mécanismes de signature et de vérification JWT, le cycle de vie des clés et secrets au repos, la rotation et la réutilisation des refresh tokens, la gestion des clés d'API, l'isolation multi-tenant et la résilience aux attaques par canal auxiliaire (timing attacks, décalage d'horloge).

L'analyse a identifié **14 vulnérabilités** réparties comme suit :
- **Critique / Élevée (Score > 7.0) :** 4 vulnérabilités (dont 1 vulnérabilité avec un score CVSS > 7.5 : **SEC-TOK-01**, score **8.3**)
- **Moyenne (Score 4.0 - 6.9) :** 9 vulnérabilités
- **Faible (Score < 4.0) :** 1 vulnérabilité

---

## Vulnérabilités Identifiées

### SEC-TOK-01 : Absence de données associées (AAD) dans le chiffrement d'enveloppe KEK (Transposition inter-tenant de clés)

* **Score CVSS v3.1 :** **8.3** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`keystore/kek.go:60`](file:///go/github.com/JLugagne/libauth/keystore/kek.go#L60)
  - [`keystore/kek.go:71`](file:///go/github.com/JLugagne/libauth/keystore/kek.go#L71)
  - [`keystore/resolve.go:73-80`](file:///go/github.com/JLugagne/libauth/keystore/resolve.go#L73-L80)
  - [`keystore/manager.go:271`](file:///go/github.com/JLugagne/libauth/keystore/manager.go#L271)

#### Description détaillée du mécanisme
Le `keystore.Manager` utilise une clé de chiffrement KEK (Key Encryption Key) globale au déploiement pour sceller les secrets de signature (secrets HMAC ou clés privées PKCS#8) via l'algorithme AES-256-GCM. 
Dans `keystore/kek.go`, les méthodes `Seal` et `Open` appellent respectivement :
```go
k.aead.Seal(nonce, nonce, plaintext, nil)
k.aead.Open(nil, nonce, ct, nil)
```
Le 4ᵉ argument d'AES-GCM correspond aux données associées authentifiées (*Additional Authenticated Data* - AAD). Il est ici fixé à `nil`. En conséquence, le bloc chiffré stocké en base de données n'est pas cryptographiquement lié à l'identifiant du tenant (`tenantID`), ni au `keyID`, ni à l'algorithme (`alg`).

#### Scénario d'exploitation théorique et impact
Dans un déploiement multi-tenant partagé :
1. Un attaquant disposant d'un accès en écriture limité à la base de données (injection SQL dans un service adjacent, compromission de sauvegarde ou compte DB à privilèges restreints) ou manipulant un backend de stockage peut copier le champ chiffré `secret` du Tenant A vers l'enregistrement du Tenant B.
2. Lorsque le `keystore.Manager` résout la clé de signature du Tenant B, `Open` déchiffre le ciphertext avec succès car la clé KEK est identique et aucun AAD ne vérifie l'appartenance au tenant.
3. Le Tenant B peut alors forger des jetons JWT valides pour le Tenant A ou signer des assertions sous l'identité cryptographique du Tenant A. L'isolation cryptographique multi-tenant est compromise.

#### Recommandation de correction
Lier impérativement le contexte du tenant et de la clé dans les données associées de l'AEAD :
```go
// SealWithAAD scelle le secret en liant le tenantID et keyID
func (k *KEK) SealWithAAD(plaintext, aad []byte) ([]byte, error)
func (k *KEK) OpenWithAAD(sealed, aad []byte) ([]byte, error)
```
Passer `[]byte(tenantID + ":" + keyID)` comme AAD lors de chaque opération `Seal` et `Open`.

---

### SEC-TOK-02 : Épuisement mémoire non borné et Déni de Service (DoS) dans `CachingKeyStore`

* **Score CVSS v3.1 :** **7.5** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`tokens/jwt/keycache.go:58`](file:///go/github.com/JLugagne/libauth/tokens/jwt/keycache.go#L58)
  - [`tokens/jwt/keycache.go:103-115`](file:///go/github.com/JLugagne/libauth/tokens/jwt/keycache.go#L103-L115)
  - [`tokens/jwt/keycache.go:128-135`](file:///go/github.com/JLugagne/libauth/tokens/jwt/keycache.go#L128-L135)
  - [`keystore/manager.go:350-356`](file:///go/github.com/JLugagne/libauth/keystore/manager.go#L350-L356)

#### Description détaillée du mécanisme
Le décorateur `CachingKeyStore` conserve les trousseaux de clés résolus en mémoire dans `entries map[string]cachedKeyset`. Chaque entrée contient les clés actives et de vérification (notamment les structures de clés privées asymétriques RSA/ECDSA volumineuses).
La suppression d'une entrée périmée n'intervient **que** lors d'une nouvelle tentative de consultation (`lookup`) de ce même `tenantID` précis après expiration du TTL (`now - cachedAt >= ttl`).
Il n'existe aucune limite de taille maximale (capacité), aucune politique d'éviction LRU/LFU, et aucun processus périodique de nettoyage en arrière-plan.

#### Scénario d'exploitation théorique et impact
1. Si l'application active `WithLazyProvisioning()` ou si elle expose des points d'entrée résolvant des clés par tenant, un attaquant non authentifié émet des requêtes en spécifiant des `tenantID` arbitraires aléatoires.
2. Pour chaque requête, `CachingKeyStore` insère une nouvelle entrée dans la table de hachage.
3. Les entrées des tenants éphémères ne sont jamais consultées à nouveau et restent donc indéfiniment stockées en mémoire tas (heap).
4. La consommation mémoire augmente de manière monotone jusqu'au crash par épuisement de mémoire (*Out Of Memory* / OOM kill), rendant le service totalement indisponible.

#### Recommandation de correction
1. Implémenter une limite de capacité stricte avec éviction LRU (ex. structure `container/list` + map).
2. Ajouter un mécanisme de nettoyage périodique (Janitor) purgeant les entrées dont le TTL est dépassé sans attendre une consultation passive.

---

### SEC-TOK-03 : Non-atomicité de la rotation des Refresh Tokens menant au déni de service et à l'invalidation de session

* **Score CVSS v3.1 :** **7.1** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H`
* **Fichiers et lignes concernés :**
  - [`tokens/jwt/issuer.go:794-804`](file:///go/github.com/JLugagne/libauth/tokens/jwt/issuer.go#L794-L804)
  - [`tokens/jwt/issuer.go:830`](file:///go/github.com/JLugagne/libauth/tokens/jwt/issuer.go#L830)
  - [`adapters/pgx/tokens/store.go:104-133`](file:///go/github.com/JLugagne/libauth/adapters/pgx/tokens/store.go#L104-L133)
  - [`adapters/pgx/tokens/store.go:49-76`](file:///go/github.com/JLugagne/libauth/adapters/pgx/tokens/store.go#L49-L76)

#### Description détaillée du mécanisme
Dans `Service.Rotate`, la séquence de rotation s'effectue en deux étapes distinctes sans transaction unifiée :
1. `s.store.ConsumeRefreshToken(ctx, tenantID, hash)` marque immédiatement le jeton comme consommé (`consumed_at = now()`).
2. `s.issuePair(ctx, claims, rt.FamilyID, false)` tente de signer le nouveau JWT et de sauvegarder le nouveau refresh token via `s.store.SaveRefreshToken`.
Si l'étape 2 échoue (coupure réseau transitoire avec la base PostgreSQL, timeout du contexte client, crash du processus ou défaillance du keystore), le jeton présenté est définitivement marqué consommé, mais aucun successeur n'a été créé.

#### Scénario d'exploitation théorique et impact
1. Le client légitime reçoit une erreur 500 ou un timeout. Conservant son refresh token d'origine non renouvelé, il retente sa requête.
2. Lors de la nouvelle tentative (dans les 10 secondes), `Rotate` détecte `rt.ConsumedAt != nil` et renvoie `ErrRefreshConcurrent`. Le middleware supprime le cookie d'accès et renvoie 401 sans renouveler le jeton.
3. Si le client retente après la fenêtre de grâce (10 s), le système classe l'événement comme un vol de jeton et exécute `s.store.RevokeFamily(ctx, tenantID, rt.FamilyID)`, détruisant l'intégralité des sessions de l'utilisateur.
4. Un attaquant capable de provoquer des annulations de requêtes ou des surcharges transitoires peut invalider les sessions de n'importe quel utilisateur légitime.

#### Recommandation de correction
Rendre la rotation strictement atomique au niveau du store : exécuter la consommation du jeton existant et l'insertion du jeton successeur au sein d'une unique transaction SQL avec isolation appropriée.

---

### SEC-TOK-04 : Détournement de session sans détection de vol lors de l'avance de l'attaquant dans la fenêtre de grâce

* **Score CVSS v3.1 :** **7.4** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`tokens/jwt/issuer.go:754-770`](file:///go/github.com/JLugagne/libauth/tokens/jwt/issuer.go#L754-L770)
  - [`tokens/middleware.go:263-267`](file:///go/github.com/JLugagne/libauth/tokens/middleware.go#L263-L267)

#### Description détaillée du mécanisme
Le protocole OAuth 2.0 / RFC 6819 stipule que la réutilisation d'un refresh token doit invalider toute la chaîne de jetons. `libauth` intègre une période de grâce de 10 secondes (`DefaultReuseGracePeriod`) pour tolérer la concurrence bénigne (onglets parallèles).
Cependant, si un attaquant intercepte le refresh token `RT1` et l'utilise **avant** la victime :
1. La requête de l'attaquant consomme `RT1` et obtient un nouveau jeton `RT2_attaquant`.
2. Lorsque la victime présente ensuite `RT1` dans l'intervalle de grâce (ex: 2 secondes plus tard), `Rotate` constate `time.Since(*rt.ConsumedAt) <= s.reuseGrace`.
3. `Rotate` renvoie `ErrRefreshConcurrent`. La famille n'est **pas** révoquée.
4. Le client de la victime reçoit 401 Unauthorized et purge ses cookies locaux.

#### Scénario d'exploitation théorique et impact
L'attaquant possède désormais le jeton `RT2_attaquant` valide et actif. La victime ayant été déconnectée localement sans que la famille ne soit révoquée côté serveur, l'attaquant peut continuer à rafraîchir la session indéfiniment (`RT3`, `RT4`, ...). L'usurpation de session réussit sans jamais déclencher l'invalidation de la famille.

#### Recommandation de correction
1. Si un jeton consommé est rejoué, même pendant la fenêtre de grâce, lier la tolérance à l'empreinte de la session (ex: TLS client certificate, DPoP, ou vérification stricte de l'adresse IP et du User-Agent).
2. Permettre un mode strict (`ReuseGracePeriod: -1`) pour les applications nécessitant une conformité stricte RFC 6819.

---

### SEC-TOK-05 : Suppression destructrice des clés actives par `RetireExpiredKeys` sur PostgreSQL (Extinction de tenant)

* **Score CVSS v3.1 :** **6.5** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`adapters/pgx/keystore/store.go:197-207`](file:///go/github.com/JLugagne/libauth/adapters/pgx/keystore/store.go#L197-L207)
  - [`keystore/keystore.go:141-143`](file:///go/github.com/JLugagne/libauth/keystore/keystore.go#L141-L143)

#### Description détaillée du mécanisme
Le contrat de `keystore.Store` indique expressément :
`RetireExpiredKeys deletes keys whose NotAfter is at or before now... It never touches the active key.`
Or, l'implémentation PostgreSQL dans `adapters/pgx/keystore/store.go` exécute :
```sql
DELETE FROM keystore_keys
WHERE tenant_id = $1 AND not_after IS NOT NULL AND not_after <= $2
```
La clause `WHERE` omet complètement la condition `retired_at IS NOT NULL`.

#### Scénario d'exploitation théorique et impact
Si la clé active d'un tenant a dépassé son `not_after` sans avoir été renouvelée préalablement (ex. défaillance du planificateur de rotation ou rétention prolongée), le passage du nettoyeur périodique (`RetireExpiredKeys`) supprime physiquement la clé active.
Comme la table `keystore_keys` est l'unique source de vérité quant à l'existence d'un tenant dans l'adaptateur PostgreSQL, le tenant se retrouve avec 0 ligne : `TenantExists` renvoie `false`, et toute tentative de récupération (`ActiveSigningKey`, `RenewSigningKey`) échoue avec `ErrTenantNotFound`. Le tenant est virtuellement détruit.

#### Recommandation de correction
Corriger la clause SQL dans `adapters/pgx/keystore/store.go` :
```sql
DELETE FROM keystore_keys
WHERE tenant_id = $1 
  AND retired_at IS NOT NULL 
  AND not_after IS NOT NULL 
  AND not_after <= $2
```

---

### SEC-TOK-06 : Décalage d'horloge (Clock Skew) entre serveur d'application et PostgreSQL provoquant la révocation immédiate de sessions légitimes

* **Score CVSS v3.1 :** **5.3** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`tokens/jwt/issuer.go:755`](file:///go/github.com/JLugagne/libauth/tokens/jwt/issuer.go#L755)
  - [`adapters/pgx/tokens/store.go:106`](file:///go/github.com/JLugagne/libauth/adapters/pgx/tokens/store.go#L106)

#### Description détaillée du mécanisme
Dans `adapters/pgx/tokens/store.go`, la consommation du refresh token utilise l'horloge de la base de données :
`UPDATE tokens SET consumed_at = now() WHERE ...`
Dans `tokens/jwt/issuer.go`, le contrôle de réutilisation calcule le temps écoulé via l'horloge locale du serveur d'application :
`if time.Since(*rt.ConsumedAt) > s.reuseGrace`
Si l'horloge du serveur PostgreSQL est en retard de plus de 10 secondes par rapport à l'horloge du serveur d'application ($T_{\text{app}} - T_{\text{db}} > 10\text{ s}$), alors dès l'instant où `consumed_at` est enregistré, `time.Since(*rt.ConsumedAt)` est immédiatement supérieur à 10 secondes.

#### Scénario d'exploitation théorique et impact
Une simple course légitime (deux requêtes parallèles dans le même navigateur espacées de quelques millisecondes) sera immédiatement évaluée comme une réutilisation frauduleuse hors période de grâce. Le serveur révoque immédiatement toute la famille de jetons de l'utilisateur (`RevokeFamily`), provoquant des déconnexions intempestives massives.

#### Recommandation de correction
Harmoniser la source de temps : soit passer l'horodatage applicatif à la base de données lors de `ConsumeRefreshToken`, soit utiliser l'horloge injectée `s.now()` avec une marge de tolérance (*skew allowance*), soit calculer le délai écoulé directement dans la requête PostgreSQL.

---

### SEC-TOK-07 : Rétention des clés et secrets déchiffrés en mémoire tas sans zéroisation

* **Score CVSS v3.1 :** **5.5** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
* **Fichiers et lignes concernés :**
  - [`keystore/kek.go:71-75`](file:///go/github.com/JLugagne/libauth/keystore/kek.go#L71-L75)
  - [`keystore/resolve.go:73-80`](file:///go/github.com/JLugagne/libauth/keystore/resolve.go#L73-L80)
  - [`keystore/manager.go:308-313`](file:///go/github.com/JLugagne/libauth/keystore/manager.go#L308-L313)
  - [`keystore/jwks.go:84-87`](file:///go/github.com/JLugagne/libauth/keystore/jwks.go#L84-L87)

#### Description détaillée du mécanisme
Lors des opérations du `keystore.Manager`, le secret en clair (clé HMAC ou octets DER PKCS#8 d'une clé privée RSA/ECDSA/Ed25519) est extrait du ciphertext KEK sous forme de tranche `[]byte`. Ces tranches de mémoire restent allouées sur le tas Go et ne font l'objet d'aucune mise à zéro explicite (`memclr` / `subtle` zeroing).
Dans `JWKS()`, l'ensemble des clés privées asymétriques du tenant est déchiffré en clair uniquement pour en extraire les coordonnées publiques, puis abandonné au Garbage Collector sans écrasement.

#### Scénario d'exploitation théorique et impact
En cas d'inspection mémoire (dump de crash core dump, mise en swap non chiffrée, fuite d'information via /proc/self/mem ou vulnérabilité de lecture mémoire adjacente), les clés maîtresses de signature peuvent être extraites de la mémoire résiduelle.

#### Recommandation de correction
Zéroïser explicitement les tranches de clés éphémères (`for i := range b { b[i] = 0 }`) dès que leur manipulation ou conversion en structure cryptographique est terminée, en particulier dans `openKey`, `publicJWKFromKey` et `generateKeyMaterial`.

---

### SEC-TOK-08 : Rupture de la procédure de reprise `RenewSigningKey` après révocation d'urgence sur PostgreSQL

* **Score CVSS v3.1 :** **4.9** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`adapters/pgx/keystore/store.go:210-220`](file:///go/github.com/JLugagne/libauth/adapters/pgx/keystore/store.go#L210-L220)
  - [`adapters/pgx/keystore/store.go:77-88`](file:///go/github.com/JLugagne/libauth/adapters/pgx/keystore/store.go#L77-L88)
  - [`keystore/manager.go:172-183`](file:///go/github.com/JLugagne/libauth/keystore/manager.go#L172-L183)

#### Description détaillée du mécanisme
La documentation de `RevokeTenantKeys` indique :
`The tenant record itself remains (re-provision or renew to restore signing).`
Dans l'adaptateur PostgreSQL, `RevokeTenantKeys` supprime l'intégralité des lignes :
`DELETE FROM keystore_keys WHERE tenant_id = $1`
Lorsque l'opérateur appelle ensuite `RenewSigningKey(ctx, tenantID)` :
1. `RenewSigningKey` invoque `m.store.TenantExists(ctx, tenantID)`.
2. Dans `adapters/pgx/keystore/store.go`, `TenantExists` compte les lignes dans `keystore_keys`. Le résultat est 0, il renvoie donc `false`.
3. `RenewSigningKey` s'interrompt immédiatement avec `ErrTenantNotFound`.

#### Scénario d'exploitation théorique et impact
Après une révocation d'urgence des clés suite à une compromission, l'opérateur applique la documentation officielle pour restaurer le service via `RenewSigningKey`. L'opération échoue avec une erreur trompeuse ("tenant not found"), prolongeant l'indisponibilité du service pour l'ensemble du tenant.

#### Recommandation de correction
Conserver une table dédiée pour les métadonnées des tenants, ou faire en sorte que `TenantExists` ne dépende pas exclusivement de la présence de clés actives/révoquées, ou permettre à `RenewSigningKey` d'installer une clé si le tenant a existé.

---

### SEC-TOK-09 : Écrasement et contournement du contrôle `MustChangePassword` lors du rafraîchissement de jeton

* **Score CVSS v3.1 :** **5.4** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`tokens/jwt/issuer.go:825`](file:///go/github.com/JLugagne/libauth/tokens/jwt/issuer.go#L825)

#### Description détaillée du mécanisme
Lors de la rotation dans `Service.Rotate` :
1. `s.claimsProvider.ClaimsForUser` est invoqué et interroge l'état actuel de l'utilisateur en base. Si un administrateur vient d'imposer un changement de mot de passe, le provider renvoie `claims.MustChangePassword = true`.
2. À la ligne 825, le code exécute :
`claims.MustChangePassword = rt.MustChangePassword`
Cette affectation écrase inconditionnellement la valeur fraîche renvoyée par le provider avec l'indicateur historique stocké sur l'ancêtre du refresh token.

#### Scénario d'exploitation théorique et impact
Si une session utilisateur était déjà ouverte avec `MustChangePassword == false` lorsqu'un administrateur réinitialise son mot de passe ou marque son compte comme devant changer de mot de passe, chaque rafraîchissement transparent écrase l'obligation et réémet des jetons avec `MustChangePassword: false`. L'utilisateur n'est jamais redirigé vers la page de changement de mot de passe et contourne le verrou de sécurité `WithPasswordChangeGate`.

#### Recommandation de correction
Prendre l'union logique des deux états ou privilégier la décision du `ClaimsProvider` :
```go
claims.MustChangePassword = rt.MustChangePassword || claims.MustChangePassword
```

---

### SEC-TOK-10 : Absence d'expiration absolue des familles de Refresh Tokens (Prolongation indéfinie de session)

* **Score CVSS v3.1 :** **5.8** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`tokens/jwt/issuer.go:468`](file:///go/github.com/JLugagne/libauth/tokens/jwt/issuer.go#L468)
  - [`tokens/jwt/issuer.go:830`](file:///go/github.com/JLugagne/libauth/tokens/jwt/issuer.go#L830)

#### Description détaillée du mécanisme
Contrairement au module `sessions` qui gère un plafond de durée de vie absolu (`maxLifetime`), chaque rotation dans `tokens/jwt` réinitialise l'expiration du refresh token généré à `now.Add(s.refreshTTL)`.
Aucune vérification n'est effectuée sur l'âge total de la famille (`FamilyID`) ou sur la date initiale d'authentification (`AuthTime`).

#### Scénario d'exploitation théorique et impact
Tant qu'un refresh token est renouvelé avant son échéance relative (ex. tous les 29 jours pour un TTL de 30 jours), la chaîne de session ne s'éteint jamais. Un attaquant ayant dérobé un refresh token peut le faire pivoter périodiquement pour maintenir une persistance illimitée sur le compte, contournant les politiques de réauthentification périodique de l'organisation.

#### Recommandation de correction
Ajouter un champ optionnel `MaxFamilyLifetime` dans `jwt.Config`. Lors de `Rotate`, refuser la rotation et forcer une réauthentification si la durée écoulée depuis la création de la famille dépasse ce plafond.

---

### SEC-TOK-11 : Absence de révocation de famille lors de l'appel à `VerifyRefreshToken` sur un jeton rejoué

* **Score CVSS v3.1 :** **5.4** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`tokens/jwt/issuer.go:700-713`](file:///go/github.com/JLugagne/libauth/tokens/jwt/issuer.go#L700-L713)

#### Description détaillée du mécanisme
La méthode publique `VerifyRefreshToken(ctx, tenantID, token)` vérifie l'existence et l'état d'un refresh token dans le store.
Aux lignes 710-712 :
```go
if rt.ConsumedAt != nil {
    return nil, tokens.ErrRefreshTokenReused
}
```
Contrairement à `Rotate`, `VerifyRefreshToken` n'appelle jamais `RevokeFamily` et n'émet aucun événement de sécurité (`RefreshReuseDetected`, `TokenFamilyRevoked`).

#### Scénario d'exploitation théorique et impact
Si une application ou un microservice effectue des contrôles d'autorisation préalables via `VerifyRefreshToken`, la détection d'un jeton rejoué n'entraîne aucune action défensive. La famille compromise reste intacte et l'attaquant peut continuer d'utiliser les jetons descendants non révoqués.

#### Recommandation de correction
Déclencher l'invalidation de famille dans `VerifyRefreshToken` lorsqu'un jeton consommé est présenté hors période de grâce, ou documenter explicitement que cette méthode est une inspection passive qui ne garantit pas la protection anti-rejeu.

---

### SEC-TOK-12 : Destruction des preuves d'audit et suppression définitive lors de `RevokeFamily`

* **Score CVSS v3.1 :** **5.3** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`adapters/pgx/tokens/store.go:163`](file:///go/github.com/JLugagne/libauth/adapters/pgx/tokens/store.go#L163)
  - [`tokens/memory/store.go:133`](file:///go/github.com/JLugagne/libauth/tokens/memory/store.go#L133)

#### Description détaillée du mécanisme
Lorsqu'un incident de rejeu survient dans `Rotate`, `RevokeFamily` exécute un nettoyage destructif :
`DELETE FROM tokens WHERE tenant_id = $1 AND family_id = $2 AND claims IS NULL`
Tous les enregistrements des jetons de la famille sont immédiatement supprimés physiquement de la base de données.

#### Scénario d'exploitation théorique et impact
1. Dès que la révocation est exécutée, une nouvelle tentative avec le même jeton volé renvoie `ErrRefreshTokenNotFound` au lieu de `ErrRefreshTokenReused`.
2. Les traces d'horodatage de consommation et d'adresse sont effacées, empêchant toute analyse forensique ultérieure de l'incident de sécurité.

#### Recommandation de correction
Utiliser une révocation logique (*soft revoke*) pour les familles de refresh tokens (ex. colonne `revoked_at` sur la famille) plutôt qu'un `DELETE` immédiat, et déléguer le nettoyage physique au janitor après expiration du délai de rétention légale/audit.

---

### SEC-TOK-13 : Désynchronisation et incohérence de type de principal pour les clés API sans type explicite (`""`)

* **Score CVSS v3.1 :** **4.2** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`tokens/jwt/issuer.go:538-545`](file:///go/github.com/JLugagne/libauth/tokens/jwt/issuer.go#L538-L545)
  - [`adapters/pgx/tokens/store.go:190-194`](file:///go/github.com/JLugagne/libauth/adapters/pgx/tokens/store.go#L190-L194)
  - [`tokens/memory/store.go:160`](file:///go/github.com/JLugagne/libauth/tokens/memory/store.go#L160)
  - [`tokens/actor.go:37-49`](file:///go/github.com/JLugagne/libauth/tokens/actor.go#L37-L49)

#### Description détaillée du mécanisme
Dans `IssueAPIKey`, si `keyType == ""` :
1. Le code entre dans la branche `else` (pensant traiter un PAT) et impose `claims.Subject = createdBy`.
2. Lors de la persistance dans PostgreSQL (`adapters/pgx/tokens/store.go:190`), la fonction applique une règle par défaut contradictoire :
   `if keyType == "" { keyType = tokens.KeyTypeService }`
   La colonne `type` est donc renseignée à `'service'`.
3. Lors de la relecture, `ActorFromAPIKey` interprète la clé comme une machine (`Kind = egauth.Service`), place son identifiant dans `KeyID` et remet `UserID` à zéro.
4. Sur le store mémoire (`tokens/memory/store.go`), le type reste `""` et `ActorFromAPIKey` le traite comme un utilisateur humain (`Kind = egauth.User`).

#### Scénario d'exploitation théorique et impact
Une clé API créée sans paramètre explicite de type change de nature selon le backend de persistance : compte de service machine sur PostgreSQL contre utilisateur humain sur store mémoire. Cela induit des confusions de privilèges lors du filtrage par `WithRequiredKind`.

#### Recommandation de correction
Valider strictement le paramètre `keyType` dès l'entrée dans `IssueAPIKey` et rejeter toute valeur qui n'est pas explicitement `KeyTypePAT` ou `KeyTypeService`.

---

### SEC-TOK-14 : Violation contractuelle de la conservation de l'état consommé lors d'un échec de `ClaimsProvider`

* **Score CVSS v3.1 :** **3.1** (Faible)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`tokens/jwt/issuer.go:785-787`](file:///go/github.com/JLugagne/libauth/tokens/jwt/issuer.go#L785-L787)
  - [`tokens/rotation.go:19-20`](file:///go/github.com/JLugagne/libauth/tokens/rotation.go#L19-L20)

#### Description détaillée du mécanisme
Le contrat documenté de `ClaimsProvider` dans `tokens/rotation.go` spécifie :
`Returning an error (e.g. the user was disabled or deleted) aborts the rotation, so the old token stays consumed and no new pair is issued.`
Dans l'implémentation `Service.Rotate`, `s.claimsProvider.ClaimsForUser` est appelé aux lignes 784-785, **avant** `s.store.ConsumeRefreshToken` (ligne 794).
Si `ClaimsForUser` renvoie une erreur, la fonction s'interrompt immédiatement sans jamais consommer le jeton d'origine.

#### Scénario d'exploitation théorique et impact
Si un compte utilisateur est suspendu et que son `ClaimsProvider` renvoie une erreur, le refresh token présenté n'est pas invalidé. Si le statut de l'utilisateur change ou si l'erreur est temporaire, le jeton reste pleinement réutilisable.

#### Recommandation de correction
Consommer atomiquement le jeton d'abord ou aligner explicitement la documentation et la logique transactionnelle.

---

## Synthèse Globale des Vulnérabilités et Évaluation CVSS

| Identifiant | Vulnérabilité | Sévérité | Score CVSS | Vecteur CVSS v3.1 |
| :--- | :--- | :--- | :---: | :--- |
| **SEC-TOK-01** | **Absence d'AAD dans le KEK du Keystore (Transposition inter-tenant)** | **Élevé** | **8.3** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **SEC-TOK-02** | **Déni de service par épuisement mémoire dans `CachingKeyStore`** | **Élevé** | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-TOK-04** | **Détournement de session dans la fenêtre de grâce de refresh** | **Élevé** | **7.4** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **SEC-TOK-03** | **Non-atomicité de la rotation menant à DoS/révocation abusive** | **Élevé** | **7.1** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H` |
| **SEC-TOK-05** | **Suppression de clés actives par `RetireExpiredKeys` sur Postgres** | **Moyen** | **6.5** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-TOK-10** | **Absence de plafond de durée de vie absolu des Refresh Tokens** | **Moyen** | **5.8** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N` |
| **SEC-TOK-07** | **Rétention sans zéroisation des clés et secrets déchiffrés** | **Moyen** | **5.5** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **SEC-TOK-09** | **Écrasement du statut `MustChangePassword` lors du rafraîchissement** | **Moyen** | **5.4** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` |
| **SEC-TOK-11** | **Absence de révocation sur rejeu dans `VerifyRefreshToken`** | **Moyen** | **5.4** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` |
| **SEC-TOK-06** | **Révocation intempestive de session causée par le décalage d'horloge** | **Moyen** | **5.3** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-TOK-12** | **Destruction des preuves d'audit lors de `RevokeFamily`** | **Moyen** | **5.3** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **SEC-TOK-08** | **Rupture du renouvellement après révocation sur Postgres** | **Moyen** | **4.9** | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-TOK-13** | **Incohérence de type de principal pour les clés d'API sans type** | **Moyen** | **4.2** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` |
| **SEC-TOK-14** | **Non-consommation du jeton lors d'une erreur de `ClaimsProvider`** | **Faible** | **3.1** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N` |

---

## Confirmation sur les vulnérabilités avec score CVSS > 7.5

> [!WARNING]
> **Présence de vulnérabilité(s) avec un score CVSS v3.1 strictement supérieur à 7.5 :**
> **OUI**, il y a **1 vulnérabilité** confirmée avec un score CVSS > 7.5 :
> - **SEC-TOK-01 : Absence d'AAD dans le chiffrement d'enveloppe KEK du Keystore (Transposition inter-tenant de clés)** — **Score CVSS : 8.3**
>
> *(Notons également que **SEC-TOK-02** atteint exactement la limite haute de sévérité élevée avec un score CVSS de **7.5**).*
