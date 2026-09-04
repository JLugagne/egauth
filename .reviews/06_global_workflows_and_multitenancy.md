# Rapport d'Audit de Sécurité : Workflows Globaux, Architecture Multi-Tenant et Isolation

**Cible :** `github.com/JLugagne/libauth`  
**Périmètre audité :**
- `actor.go` (modèle PrincipalKind, Actor, attributs, helpers)
- `event/` (Sink, journalisation, RequestContext, types d'événements)
- `examples/fullstack/` (intégration globale, câblage des services, gestion des rôles et routes)
- Interactions inter-modules : `identity`, `sessions`, `tokens`, `mfa`, `oauth`, `passkey`
- Modèle Multi-tenant & Cloisonnement (pgx adapters & memory stores)
- Janitor & Background Workers (`janitor/`, `ratelimit/`)

**Date :** 4 septembre 2026  
**Auditeur :** Antigravity Security Research  
**Statut :** Terminé

---

## Sommaire Exécutif

Cet audit a analysé l'architecture de sécurité transverse de `libauth`, en se concentrant sur les chaînes de responsabilité, les transitions d'état du cycle de vie des utilisateurs, l'étanchéité multi-tenant, l'intégrité du modèle d'autorisation basé sur l'Acteur (`Actor`), la couverture de l'audit trail (`event.Sink`) et la résilience face aux dénis de service (DoS).

L'analyse transversale a mis en lumière plusieurs failles architecturales critiques :
1. **Rupture systémique de révocation lors de la réinitialisation/changement de mot de passe :** L'interface `identity.Service` invoque le hook destructif `s.erasers` (destiné à `DeleteAccount`) au lieu de `s.disableRevokers`. Il en résulte que le câblage standard documenté soit détruit définitivement les secrets MFA/Passkey lors d'un simple changement de mot de passe, soit ne révoque aucun jeton actif. De plus, les jetons d'accès JWT demeurent valides de manière statique pendant 15 minutes sans aucune vérification d'invalidation.
2. **Contournement total du MFA/2FA via OAuth/OIDC :** Le point de terminaison de rappel OAuth (`CallbackHandler`) émet directement une paire complète et renouvelable de jetons (`AccessToken` + `RefreshToken`) sans consulter `mfaGate`, contournant tout enrôlement 2FA existant sur le compte local.
3. **Absence d'implémentation de cascade de suppression de tenant (`TenantEraser`) :** Bien que l'interface `TenantEraser` soit documentée, aucun module (`identity`, `sessions`, `tokens`, `mfa`, `passkey`) n'implémente cette purge. La suppression d'un tenant dans le keystore laisse l'intégralité des données utilisateurs et sessions orphelines en base, exposées à une réattribution ultérieure du même ID de tenant.
4. **Perte de contexte multi-tenant dans Passkey :** Le callback `LoginSuccessFunc` ne reçoit aucun identifiant de tenant, contraignant les intégrateurs (comme dans l'exemple de référence `fullstack`) à forcer un `TenantID: ""` statique, brisant l'isolation inter-tenant.
5. **Déni de service par saturation mémoire dans `ratelimit` :** `TokenBucket` n'impose aucune limite de cardinalité par défaut (`maxKeys = 0`), permettant à un attaquant non authentifié d'épuiser la mémoire tas en spoofant les adresses IP.

Au total, **10 vulnérabilités** ont été identifiées :
- **Critique / Élevée (Score CVSS > 7.0) :** 4 vulnérabilités (dont **3 vulnérabilités avec un score CVSS strictement supérieur à 7.5**)
- **Moyenne (Score 4.0 - 6.9) :** 6 vulnérabilités
- **Faible (Score < 4.0) :** 0 vulnérabilité

---

## Vulnérabilités Identifiées

### SEC-GLO-01 : Rupture de chaîne de révocation lors de la réinitialisation de mot de passe (MFA écrasé ou sessions orphelines)

* **Score CVSS v3.1 :** **8.1** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
* **Fichiers et lignes concernés :**
  - [`identity/service.go:718-736`](file:///go/github.com/JLugagne/libauth/identity/service.go#L718-L736) (`ResetPassword`)
  - [`identity/service.go:786-800`](file:///go/github.com/JLugagne/libauth/identity/service.go#L786-L800) (`ChangePassword`)
  - [`identity/service.go:1367-1383`](file:///go/github.com/JLugagne/libauth/identity/service.go#L1367-L1383) (`SetTemporaryPassword`)
  - [`identity/service.go:240-256`](file:///go/github.com/JLugagne/libauth/identity/service.go#L240-L256)
  - [`tokens/revoke.go:10-34`](file:///go/github.com/JLugagne/libauth/tokens/revoke.go#L10-L34) (`NewAccountRevoker`)
  - [`examples/fullstack/main.go:98-106`](file:///go/github.com/JLugagne/libauth/examples/fullstack/main.go#L98-L106)

#### Description détaillée du mécanisme
Dans l'architecture de `libauth`, l'invalidation des artefacts cross-modules (sessions, refresh tokens, enrôlements MFA) repose sur des hooks injectés lors de la construction d'identité :
- `WithAccountErasers` : explicitement documenté pour `DeleteAccount` afin de **détruire définitivement** toutes les données d'enrôlement (MFA, Passkey, sessions).
- `WithDisableRevokers` : explicitement documenté pour invalider uniquement les **identifiants ré-établissables** (refresh tokens, sessions) tout en conservant les facteurs MFA et clés WebAuthn.

Cependant, dans `ResetPassword`, `ChangePassword` et `SetTemporaryPassword`, le code exécute `s.erasers` (les hooks destructifs de suppression) au lieu de `s.disableRevokers` :
```go
for _, erase := range s.erasers {
    if erase == nil { continue }
    if err := erase(ctx, tenantID, user.ID); err != nil { ... }
}
```
Cette incohérence architecturale engendre deux défaillances majeures :
1. Si le développeur configure `WithAccountErasers` pour supprimer les clés MFA et passkeys lors de la suppression de compte (conformité RGPD), alors **chaque changement ou réinitialisation de mot de passe supprime également tous les facteurs MFA et Passkeys de la victime**.
2. Si le développeur enregistre la révocation de sessions via `WithDisableRevokers` (comme prescrit pour les identifiants actifs), `ResetPassword` et `ChangePassword` n'appellent **pas** ces hooks. Par conséquent, aucune session ni refresh token n'est révoqué.
3. Dans l'exemple de référence `examples/fullstack/main.go`, aucun hook (`WithAccountErasers` ou `WithDisableRevokers`) n'est passé à `identity.NewService`.
4. Enfin, les jetons d'accès JWT (`tokens.Claims`) sont strictement sans état (*stateless*). Le middleware `RequireAuth` et le validateur `VerifyAccessToken` ne vérifient ni le timestamp de modification du mot de passe (`password_changed_at`), ni une version de jeton (*token version* / *security stamp*). Les jetons d'accès existants restent valides pendant toute leur durée de vie (15 minutes par défaut).

#### Scénario d'exploitation théorique et impact
1. Le compte d'un utilisateur est compromis par un attaquant qui a dérobé un refresh token et un JWT d'accès.
2. L'utilisateur légitime constate une activité suspecte et réinitialise son mot de passe via `/auth/reset-password`.
3. En raison de l'absence ou du mauvais ciblage des hooks, les familles de refresh tokens et les sessions HTTP actives ne sont pas révoquées.
4. L'attaquant continue d'utiliser son jeton d'accès et renouvelle ses jetons via `/auth/refresh`, maintenant sa persistance sur le compte compromis malgré le changement de mot de passe.
5. Inversement, si les erasers de suppression sont branchés, la victime perd son second facteur 2FA (TOTP/WebAuthn) dès qu'elle met à jour son mot de passe.

#### Recommandation de correction
1. Créer un hook distinct `CredentialRevoker` (ou réutiliser `disableRevokers`) dédié au changement/réinitialisation de mot de passe, n'invoquant **que** la révocation des sessions actives, refresh tokens et clés API temporaires, sans toucher aux enrôlements MFA/Passkey.
2. Intégrer dans les claims JWT un horodatage d'invalidation (ou comparer `claims.IssuedAt` / `claims.AuthTime` avec la date de dernière mise à jour du mot de passe de l'utilisateur ou une version de session).
3. Mettre à jour `examples/fullstack/main.go` pour câbler impérativement les révocations cross-modules au démarrage.

---

### SEC-GLO-02 : Contournement complet du MFA/2FA via le flux de connexion OAuth / OIDC

* **Score CVSS v3.1 :** **8.1** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`oauth/handlers.go:248-265`](file:///go/github.com/JLugagne/libauth/oauth/handlers.go#L248-L265) (`CallbackHandler`)
  - [`identity/service.go:944-980`](file:///go/github.com/JLugagne/libauth/identity/service.go#L944-L980) (`LinkOrCreateIdentity`)
  - [`identity/handlers.go:340-360`](file:///go/github.com/JLugagne/libauth/identity/handlers.go#L340-L360) (contraste avec `LoginHandler`)

#### Description détaillée du mécanisme
Dans `identity.LoginHandler`, lorsqu'un utilisateur possède un facteur MFA configuré (`cfg.mfaGate.IsEnrolled` renvoie `true`), le gestionnaire bloque l'émission d'une session complète et émet un jeton d'accès intérimaire (`AMR=[pwd]`, sans cookie de rafraîchissement). L'utilisateur doit impérativement franchir `mfa.StepUpHandler` pour obtenir ses jetons définitifs.

En revanche, dans le module `oauth`, `CallbackHandler` ne dispose d'aucune intégration de `mfaGate` :
```go
user, err := linker.LinkOrCreateIdentity(r.Context(), cfg.tenant(r), p.Name(), info.ProviderID, info.Email, info.EmailVerified)
if err != nil { ... }

pair, err := issuer.IssueTokenPair(r.Context(), claimsOf(user))
if err != nil { ... }
cfg.cookies.SetAccess(w, pair.AccessToken)
cfg.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, cfg.persistRefresh)
```
Dès que l'authentification OAuth/OIDC réussit auprès du fournisseur externe, `CallbackHandler` émet directement une paire complète `AccessToken` + `RefreshToken` pour le compte local lié. Aucune vérification n'est opérée pour savoir si le compte local requiert ou possède un second facteur TOTP ou Passkey.

#### Scénario d'exploitation théorique et impact
1. Une organisation impose l'utilisation du 2FA TOTP pour tous ses comptes sensibles.
2. Un utilisateur a lié son compte Google ou GitHub à son compte local.
3. Un attaquant qui parvient à compromettre la boîte email ou la session OAuth de la victime (ou via une attaque d'ingénierie sociale / vol de session OAuth) effectue une connexion via "Se connecter avec Google".
4. Le rappel OAuth connecte directement l'attaquant et lui délivre une session complète avec refresh token, sans jamais lui demander le second facteur TOTP de l'organisation. La politique 2FA est entièrement court-circuitée.

#### Recommandation de correction
1. Étendre `oauth.CallbackHandler` pour accepter une option `WithMFAGate(gate identity.MFAGate)`.
2. Si `gate.IsEnrolled` retourne `true`, ne pas émettre la paire définitive de jetons ; émettre un jeton intérimaire restreint (`AMR=[oauth]`) et rediriger vers le challenge MFA de step-up (`mfa.StepUpHandler`).

---

### SEC-GLO-03 : Absence d'implémentation de purge en cascade de tenant (`TenantEraser`) et persistance orpheline

* **Score CVSS v3.1 :** **7.9** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`keystore/manager.go:235-248`](file:///go/github.com/JLugagne/libauth/keystore/manager.go#L235-L248) (`DeleteTenant`)
  - [`keystore/keystore.go:159-169`](file:///go/github.com/JLugagne/libauth/keystore/keystore.go#L159-L169) (`TenantEraser` interface)
  - [`adapters/pgx/`](file:///go/github.com/JLugagne/libauth/adapters/pgx/) (absence totale de méthode `EraseTenant` dans tous les adaptateurs pgx)

#### Description détaillée du mécanisme
Le package `keystore` propose la méthode `Manager.DeleteTenant(ctx, tenantID)` comme point d'entrée unique pour la destruction d'un tenant. Sa documentation stipule :
*"DeleteTenant purges a tenant in one auditable, idempotent, resumable operation: it fans out across the registered TenantErasers (sessions, tokens, …) and then removes the tenant's crypto material."*

Cependant, dans l'ensemble de la bibliothèque :
- Aucun des adaptateurs PostgreSQL dans `adapters/pgx/` (`identity`, `sessions`, `tokens`, `mfa`, `otp`, `passkey`, `oauth`) n'implémente l'interface `keystore.TenantEraser`.
- Aucune requête `DELETE FROM ... WHERE tenant_id = $1` n'existe pour nettoyer les tables `users`, `identities`, `sessions`, `tokens`, `mfa_totp`, `passkey_credentials`.
- Lorsque `DeleteTenant` est exécuté, seul le trousseau de clés cryptographiques du keystore est purgé.

#### Scénario d'exploitation théorique et impact
1. Dans un système multi-tenant SaaS, un client quitte le service. L'administrateur système appelle `keystore.DeleteTenant(ctx, "client-xyz")` pour satisfaire aux obligations légales de purge des données (RGPD).
2. Toutes les données personnelles, mots de passe hashés, clés API et sessions du client demeurent intactes dans la base de données.
3. Si un nouveau client s'inscrit ultérieurement avec le même slug ou identifiant `"client-xyz"` (ou si l'identifiant est réaffecté), le nouvel arrivant accède directement aux comptes, profils et données de l'ancien client sans aucune séparation cryptographique ni logique.

#### Recommandation de correction
1. Implémenter formellement la méthode `EraseTenant(ctx context.Context, tenantID string) error` sur tous les stores de `adapters/pgx/` et de `memory/`.
2. Fournir une fonction d'enregistrement globale ou un orchestrateur garantissant que la suppression d'un tenant purge de manière atomique ou transactionnelle toutes les tables associées à ce `tenant_id`.

---

### SEC-GLO-04 : Perte de contexte multi-tenant dans le callback Passkey `LoginSuccessFunc`

* **Score CVSS v3.1 :** **7.4** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`passkey/handlers.go:37-40`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L37-L40) (`LoginSuccessFunc`)
  - [`passkey/handlers.go:235-238`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L235-L238) (`FinishLoginHandler`)
  - [`passkey/handlers.go:514-517`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L514-L517) (`FinishDiscoverableLoginHandler`)
  - [`examples/fullstack/main.go:240-254`](file:///go/github.com/JLugagne/libauth/examples/fullstack/main.go#L240-L254)

#### Description détaillée du mécanisme
Le module `passkey` supporte l'authentification avec clé d'accès (identifiants découvrables ou avec nom d'utilisateur) et résout le tenant de la requête.
Cependant, la signature de `LoginSuccessFunc` est la suivante :
```go
type LoginSuccessFunc func(w http.ResponseWriter, r *http.Request, userID uuid.UUID)
```
Le paramètre `tenantID` est **absent** de cette signature.
Lorsque `FinishLoginHandler` ou `FinishDiscoverableLoginHandler` valide l'assertion WebAuthn pour un tenant donné, il invoque `cfg.onLoginSuccess(w, r, uid)` en omettant totalement le tenant sous lequel la vérification a eu lieu.
Dans l'application de référence (`examples/fullstack/main.go:242-246`), le callback doit émettre les jetons mais n'a pas accès au tenant :
```go
passkeyLoginSuccess := passkey.LoginSuccessFunc(func(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
    pair, err := issuer.IssueTokenPair(r.Context(), tokens.Claims[AppClaims]{
        Subject:  userID,
        TenantID: "", // Hardcodé à vide !
        Custom:   AppClaims{Role: "user"},
    })
    ...
})
```

#### Scénario d'exploitation théorique et impact
Dans un déploiement multi-tenant :
1. Un utilisateur s'authentifie avec une Passkey sur le sous-domaine du Tenant A (`tenant-a.app.com`).
2. L'assertion Passkey est validée avec succès pour le Tenant A.
3. Le callback ne recevant aucun tenant, l'implémentation émet un JWT sans tenant (`TenantID: ""`) ou doit dériver à nouveau le tenant via une méthode potentiellement divergente.
4. Si le jeton est émis avec `TenantID: ""`, il est valide pour la partition globale/par défaut, permettant d'accéder à des ressources administratives ou transverses en contournant l'isolation du Tenant A.

#### Recommandation de correction
Modifier la signature de `LoginSuccessFunc` pour transmettre explicitement le `tenantID` résolu :
```go
type LoginSuccessFunc func(w http.ResponseWriter, r *http.Request, tenantID string, userID uuid.UUID)
```

---

### SEC-GLO-05 : Déni de service par épuisement mémoire illimité par défaut dans `ratelimit.TokenBucket`

* **Score CVSS v3.1 :** **7.5** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`ratelimit/tokenbucket.go:33-35`](file:///go/github.com/JLugagne/libauth/ratelimit/tokenbucket.go#L33-L35)
  - [`ratelimit/tokenbucket.go:57-74`](file:///go/github.com/JLugagne/libauth/ratelimit/tokenbucket.go#L57-L74) (`NewTokenBucket`)
  - [`ratelimit/tokenbucket.go:79-99`](file:///go/github.com/JLugagne/libauth/ratelimit/tokenbucket.go#L79-L99) (`Allow`)

#### Description détaillée du mécanisme
Le limiteur de débit en mémoire `ratelimit.TokenBucket` maintient une table de hachage `buckets map[string]*bucketState`.
Dans le constructeur `NewTokenBucket(burst int, refillInterval time.Duration, opts ...Option)` :
- Le champ `maxKeys` vaut `0` par défaut (ce qui correspond à un mode non borné).
- L'option `WithMaxKeys(n)` est optionnelle.
- Lorsque de nouvelles requêtes arrivent pour des clés inconnues, la méthode `Allow` insère directement une nouvelle entrée dans la map :
```go
b, ok := tb.buckets[key]
if !ok {
    if tb.maxKeys > 0 && len(tb.buckets) >= tb.maxKeys {
        tb.evictOne(now)
    }
    b = &bucketState{tokens: tb.burst, last: now}
    tb.buckets[key] = b
}
```
Sans configuration explicite de `WithMaxKeys` ou sans déclenchement d'un `janitor` externe appelant périodiquement `Cleanup()`, la mémoire allouée croît indéfiniment de manière monotone.

#### Scénario d'exploitation théorique et impact
1. Un attaquant envoie un flux massif de requêtes HTTP vers un point d'entrée protégé par le middleware de rate-limiting (ex. `/auth/login` ou `/otp/issue`).
2. L'attaquant fait varier l'en-tête `X-Forwarded-For` ou utilise un botnet générant des millions d'adresses IP sources distinctes.
3. Le limiteur crée une entrée pour chaque IP dans la map en mémoire tas (*heap*).
4. La consommation mémoire s'envole jusqu'à provoquer l'intervention de l'OOM killer Linux, provoquant le crash complet du service.

#### Recommandation de correction
1. Fixer une valeur par défaut raisonnable et sécurisée pour `maxKeys` (par exemple 100 000 clés) dans `NewTokenBucket`.
2. Forcer une éviction automatique (LRU ou plus forte réplétion) dès que cette capacité est atteinte.

---

### SEC-GLO-06 : Collision et écrasement inter-tenant dans le store de jetons en mémoire (`tokens/memory/store.go`)

* **Score CVSS v3.1 :** **5.8** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H`
* **Fichiers et lignes concernés :**
  - [`tokens/memory/store.go:17-18`](file:///go/github.com/JLugagne/libauth/tokens/memory/store.go#L17-L18)
  - [`tokens/memory/store.go:73`](file:///go/github.com/JLugagne/libauth/tokens/memory/store.go#L73) (`SaveRefreshToken`)
  - [`tokens/memory/store.go:173`](file:///go/github.com/JLugagne/libauth/tokens/memory/store.go#L173) (`SaveAPIKey`)
  - [`tokens/memory/store.go:83-86`](file:///go/github.com/JLugagne/libauth/tokens/memory/store.go#L83-L86) (`FindRefreshToken`)

#### Description détaillée du mécanisme
Contrairement aux modules `sessions/memory` (qui utilise `tenantID + "\x00" + tokenHash`) et `otp/memory` (qui utilise `tenantID + "\x00" + subjectID + "\x00" + purpose`), l'implémentation en mémoire des jetons (`tokens/memory/store.go`) utilise des tables de hachage indexées **uniquement par le hash du jeton** :
```go
type Store[C any] struct {
    refreshTokens map[string]*tokens.RefreshToken // indexé par hash seul
    apiKeys       map[string]*tokens.APIKey[C]    // indexé par hash seul
}
```
Lors de l'enregistrement d'un refresh token ou d'une clé d'API :
```go
s.refreshTokens[rtCopy.Hash] = &rtCopy
s.apiKeys[kCopy.Hash] = &kCopy
```
La clé du dictionnaire n'est pas partitionnée par tenant. Si deux tenants utilisent des jetons dont les hashs entrent en collision (ou si un attaquant disposant d'un accès à un tenant parvient à injecter un hash identique à celui d'un autre tenant), l'enregistrement du Tenant B écrase purement et simplement celui du Tenant A.

Lors de la recherche ultérieure par le Tenant A :
```go
entry, exists := s.refreshTokens[tokenHash]
if !exists || entry.TenantID != tenantID {
    return nil, tokens.ErrRefreshTokenNotFound
}
```
`entry.TenantID` appartenant désormais au Tenant B, le Tenant A reçoit une erreur `ErrRefreshTokenNotFound`, révoquant de facto sa session.

#### Scénario d'exploitation théorique et impact
Un utilisateur ou test multi-tenant manipulant des clés d'API ou refresh tokens dans un environnement en mémoire voit ses jetons invalidés de manière intempestive dès lors qu'une opération concurrente sur un autre tenant référence la même clé de stockage.

#### Recommandation de correction
Préfixer systématiquement la clé du dictionnaire avec l'identifiant du tenant :
```go
func tokenKey(tenantID, hash string) string {
    return tenantID + "\x00" + hash
}
```

---

### SEC-GLO-07 : Désynchronisation de tenant entre `tokens.ContextMiddleware` et `otp.SubjectResolverFromContext`

* **Score CVSS v3.1 :** **6.3** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L`
* **Fichiers et lignes concernés :**
  - [`tokens/context.go:124-130`](file:///go/github.com/JLugagne/libauth/tokens/context.go#L124-L130) (`SubjectResolverFromContext`)
  - [`otp/handlers.go:194-198`](file:///go/github.com/JLugagne/libauth/otp/handlers.go#L194-L198) (`IssueHandler`)
  - [`otp/handlers.go:307-313`](file:///go/github.com/JLugagne/libauth/otp/handlers.go#L307-L313) (`tenant`)

#### Description détaillée du mécanisme
Le package `tokens` propose `SubjectResolverFromContext` comme adaptateur officiel pour relier `ContextMiddleware` aux gestionnaires `otp` :
```go
func SubjectResolverFromContext(r *http.Request) (uuid.UUID, bool) {
    a, ok := ActorFromContext(r.Context())
    if !ok {
        return uuid.Nil, false
    }
    return a.UserID, true
}
```
Cet adaptateur renvoie uniquement `(uuid.UUID, bool)` et ignore totalement `a.TenantID`.
Dans `otp.IssueHandler` et `otp.VerifyHandler`, le tenant est extrait indépendamment :
```go
func (cfg handlerConfig) tenant(r *http.Request) string {
    if cfg.tenantResolver == nil {
        return ""
    }
    return cfg.tenantResolver(r)
}
```
Si le développeur monte `otp.IssueHandler` derrière `tokens.ContextMiddleware` sans spécifier `otp.WithTenantResolver`, `cfg.tenant(r)` renvoie `""`.
Le code OTP est alors créé et vérifié sous le tenant `""` (la partition par défaut), alors même que l'utilisateur a été authentifié dans `tenant-123`.

#### Scénario d'exploitation théorique et impact
1. Un utilisateur est authentifié sur le Tenant A.
2. Il demande l'émission d'un code OTP pour une validation d'action sensible.
3. Le code OTP est enregistré sous le tenant vide `""`.
4. Un utilisateur ou attaquant opérant sur le tenant par défaut `""` ayant connaissance de ce `subjectID` peut intercepter, valider ou brûler ce challenge OTP, brisant l'isolation inter-tenant.

#### Recommandation de correction
Fournir un résolveur contextualisé `TenantAndSubjectResolverFromContext` ou permettre aux handlers `otp` d'extraire automatiquement le tenant de l'`Actor` présent dans le contexte HTTP si aucun `tenantResolver` n'est configuré.

---

### SEC-GLO-08 : Évanouissement des rôles/groupes et classification humaine abusive de l'acteur anonyme (`Actor.IsHuman`)

* **Score CVSS v3.1 :** **6.5** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`actor.go:34-48`](file:///go/github.com/JLugagne/libauth/actor.go#L34-L48)
  - [`actor.go:53-61`](file:///go/github.com/JLugagne/libauth/actor.go#L53-L61) (`IsHuman`, `IsMachine`)
  - [`tokens/middleware.go:332-344`](file:///go/github.com/JLugagne/libauth/tokens/middleware.go#L332-L344) (`actorFromClaims`)
  - [`tokens/token.go:55-56`](file:///go/github.com/JLugagne/libauth/tokens/token.go#L55-L56) (`Claims.Roles`, `Claims.Groups`)

#### Description détaillée du mécanisme
1. **Perte silencieuse des rôles et groupes** : La structure `tokens.Claims` contient des champs `Roles []string` et `Groups []string`. En revanche, la structure de domaine `egauth.Actor` ne comporte aucun champ pour les rôles ou groupes. Lorsque `RequireAuth` authentifie un utilisateur, `actorFromClaims` copie uniquement `claims.Scopes`. Les autorisations RBAC basées sur `Roles` sont totalement invisibles pour les handlers recevant `egauth.Actor`.
2. **Classification humaine erronée de l'acteur vide / anonyme** : `actor.go` ne définit aucun rôle `Anonymous`. Sa valeur zéro `Actor{}` possède `Kind: ""` et `UserID: uuid.Nil`. Selon la logique de `Actor.IsHuman()` :
```go
func (a Actor) IsHuman() bool {
    return a.Kind == User || a.Kind == PAT || a.Kind == ""
}
```
Un acteur vide, non authentifié, est classifié comme **humain**.
Si un handler applicatif utilise `if actor.IsHuman()` pour autoriser l'accès aux fonctionnalités réservées aux utilisateurs réels, un acteur non initialisé est autorisé.
De plus, son `actor.UserID` valant `uuid.Nil` (`00000000-0000-0000-0000-000000000000`), toute requête en base de données filtrant sur `user_id = $1` peut matcher des enregistrements non assignés ou créés par le système.

#### Scénario d'exploitation théorique et impact
Un composant applicatif évalue les droits d'accès en vérifiant `actor.IsHuman()`. Un contexte non authentifié ou partiellement initialisé franchit le filtre et accède aux ressources utilisateurs en se faisant passer pour un utilisateur légitime avec l'ID `uuid.Nil`.

#### Recommandation de correction
1. Ajouter explicitement `Roles []string` et `Groups []string` dans la structure `egauth.Actor`.
2. Introduire une constante explicite `Anonymous PrincipalKind = "anonymous"`, et faire en sorte que `Actor.IsHuman()` ne retourne `true` que pour `User` et `PAT`, en rejetant la chaîne vide `""` ou en la qualifiant d'anonyme / non authentifiée.

---

### SEC-GLO-09 : Cécité totale de l'Audit Trail (`event.Sink`) sur les rejets du Middleware HTTP et les révocations en masse

* **Score CVSS v3.1 :** **5.3** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`tokens/middleware.go:1-490`](file:///go/github.com/JLugagne/libauth/tokens/middleware.go#L1-L490) (absence d'`event.Sink`)
  - [`tokens/revoke.go:23-34`](file:///go/github.com/JLugagne/libauth/tokens/revoke.go#L23-L34) (`NewAccountRevoker`)
  - [`otp/handlers.go:280-283`](file:///go/github.com/JLugagne/libauth/otp/handlers.go#L280-L283) (`dispatchDelivery`)

#### Description détaillée du mécanisme
Le système d'audit trail repose sur `event.Sink`. Cependant, des pans entiers de la sécurité du système s'exécutent de manière totalement silencieuse :
1. `tokens/middleware.go` (`RequireAuth` et `ContextMiddleware`) n'accepte aucun `event.Sink`. Lorsqu'une requête est rejetée en 401 (signature invalide, jeton malformé, tentative d'usurpation inter-tenant) ou en 403 (manque de scope, mauvais `PrincipalKind`, facteur AMR absent), aucun événement de sécurité n'est émis. Un attaquant scannant ou testant des jetons forgés ne laisse aucune trace dans les journaux de sécurité.
2. `tokens.NewAccountRevoker` appelle directement les méthodes de store `RevokeAllRefreshTokensForUser` et `RevokeAllAPIKeysForUser`. Ces méthodes n'ont pas accès au sink et n'émettent aucun événement `api_key.revoked` ou `token.family_revoked`. Les révocations administratives massives s'effectuent sans aucune piste d'audit.
3. Dans `otp.IssueHandler`, lorsque la sémaphore de livraison concurrente est saturée, la requête est abandonnée sans émettre `event.DeliveryFailed`.

#### Scénario d'exploitation théorique et impact
Un attaquant mène une campagne de force brute ou rejoue des jetons volés expirés / inter-tenants contre l'API. Le SIEM de l'entreprise ne reçoit aucune alerte, car le middleware absorbe et rejette silencieusement les requêtes sans notifier le récepteur d'événements.

#### Recommandation de correction
1. Intégrer `WithEventSink(sink event.Sink)` dans `tokens.AuthOption` pour tracer les échecs d'authentification et refus d'accès.
2. Modifier `NewAccountRevoker` pour accepter un `event.Sink` et émettre les événements de révocation correspondants.

---

### SEC-GLO-10 : Blocage indéfini et déni de service lors de l'arrêt du Janitor (`janitor.Stop`)

* **Score CVSS v3.1 :** **5.3** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
* **Fichiers et lignes concernés :**
  - [`janitor/janitor.go:82-121`](file:///go/github.com/JLugagne/libauth/janitor/janitor.go#L82-L121) (`Start`, `Stop`)

#### Description détaillée du mécanisme
Le composant `janitor.Start` lance une goroutine de purge périodique :
```go
go func() {
    defer close(j.done)
    t := time.NewTicker(interval)
    defer t.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-t.C:
            func() {
                defer func() { _ = recover() }()
                fn()
            }()
        }
    }
}()
```
La fonction `fn` ne prend aucun paramètre (`fn func()`). Elle n'a aucun moyen d'observer `ctx.Done()`.
Si `fn()` exécute une boucle longue sur des milliers de tenants (pattern explicitement documenté dans le fichier même : `for _, tid := range tenantIDs() { ... }`) ou si une requête SQL subit un verrouillage (*lock contention*) :
Lorsque `Janitor.Stop()` est appelé lors de l'extinction du serveur :
```go
func (j *Janitor) Stop() {
    j.once.Do(func() {
        j.cancel()
        <-j.done
    })
}
```
`Stop()` reste bloqué indéfiniment sur `<-j.done` tant que l'itération de `fn()` en cours n'est pas terminée.

#### Scénario d'exploitation théorique et impact
Lors d'une opération de déploiement continu ou de redémarrage de conteneurs (Kubernetes), l'arrêt gracieux du processus se fige sur l'arrêt du janitor. Le conteneur ne répond plus et finit par être tué sauvagement par SIGKILL après le délai de grâce, causant des interruptions de service et d'éventuelles corruptions de transactions.

#### Recommandation de correction
1. Modifier la signature de la fonction de nettoyage pour accepter un contexte : `fn func(ctx context.Context)`.
2. Dans `Stop()`, appliquer un timeout ou un mécanisme d'abandon pour ne pas bloquer indéfiniment la chaîne d'extinction du service.

---

## Récapitulatif des Vulnérabilités

| Identifiant | Titre | Score CVSS v3.1 | Sévérité | Statut (> 7.5) |
|---|---|:---:|:---:|:---:|
| **SEC-GLO-01** | Rupture de révocation lors de la réinitialisation de mot de passe (MFA écrasé ou sessions orphelines) | **8.1** | Élevée | **OUI** |
| **SEC-GLO-02** | Contournement complet du MFA/2FA via le flux de connexion OAuth/OIDC | **8.1** | Élevée | **OUI** |
| **SEC-GLO-03** | Absence d'implémentation de cascade de suppression de tenant (`TenantEraser`) | **7.9** | Élevée | **OUI** |
| **SEC-GLO-04** | Perte de contexte multi-tenant dans le callback Passkey `LoginSuccessFunc` | **7.4** | Élevée | Non |
| **SEC-GLO-05** | Déni de service par épuisement mémoire illimité par défaut dans `ratelimit.TokenBucket` | **7.5** | Élevée | Non (seuil = 7.5) |
| **SEC-GLO-06** | Collision et écrasement inter-tenant dans le store de jetons en mémoire | **5.8** | Moyenne | Non |
| **SEC-GLO-07** | Désynchronisation de tenant entre `tokens.ContextMiddleware` et `otp.SubjectResolverFromContext` | **6.3** | Moyenne | Non |
| **SEC-GLO-08** | Évanouissement des rôles/groupes et classification humaine abusive de l'acteur anonyme | **6.5** | Moyenne | Non |
| **SEC-GLO-09** | Cécité totale de l'Audit Trail (`event.Sink`) sur les rejets de middleware et révocations | **5.3** | Moyenne | Non |
| **SEC-GLO-10** | Blocage indéfini et déni de service lors de l'arrêt du Janitor (`janitor.Stop`) | **5.3** | Moyenne | Non |

### Conclusion relative au seuil CVSS > 7.5

Il y a très clairement **trois (3) vulnérabilités** dont le score CVSS v3.1 est **strictement supérieur à 7.5** :
1. **SEC-GLO-01 (Score 8.1)** : La désynchronisation entre les hooks de suppression et de révocation permet soit la persistance non autorisée d'un attaquant après un changement de mot de passe, soit la destruction abusive du second facteur (MFA) d'un utilisateur légitime.
2. **SEC-GLO-02 (Score 8.1)** : L'absence totale de contrôle MFA dans le rappel OAuth permet à toute personne s'authentifiant via un fournisseur social ou fédéré d'outrepasser l'exigence d'un second facteur 2FA.
3. **SEC-GLO-03 (Score 7.9)** : L'absence de purge effective des données de tenant dans les modules métiers expose à des fuites de données et à une réassignation de données orphelines en environnement mutualisé.

De plus, **SEC-GLO-05** atteint exactement le score élevé de **7.5** en raison de l'épuisement mémoire non borné du composant de limitation de débit.
