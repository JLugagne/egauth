# Rapport d'Audit de Sécurité : Sous-systèmes Sessions, Webapp, Cookies et CSRF

**Cible :** `github.com/JLugagne/libauth`  
**Périmètre audité :**
- `sessions/` (service, middleware, session, singletenant, memory store, storetest)
- `webapp/` (routes, preset NewWebApp, configuration CSRF et cookies)
- `janitor/` (boucle d'éviction, gestion des tickers et paniques)
- `internal/httputil` (validation de l'origine, extraction Host/Origin/Referer, formulaires)
- `adapters/pgx/sessions` (adaptateur de persistance PostgreSQL, migrations SQL, requêtes de sweep)

**Date :** 4 septembre 2026  
**Auditeur :** Expert en Sécurité Logicielle & Sécurité Web Go  
**Statut :** Terminé  

---

## Sommaire Exécutif

Cet audit de sécurité a passé au crible le sous-système de gestion des sessions avec état (stateful), le preset web composite `webapp`, le démon de nettoyage en arrière-plan `janitor`, les utilitaires HTTP de protection CSRF `internal/httputil`, ainsi que l'adaptateur de persistance relationnel PostgreSQL `adapters/pgx/sessions`.

### Constats d'Architecture et d'Implémentation
1. **Primitives Cryptographiques et Hachage :** Les identifiants de session et jetons sont générés via `crypto/rand` (256 bits d'entropie), et stockés sous forme de condensats SHA-256 (`TokenHash`), ce qui empêche la fuite de jetons en clair en cas de compromission en lecture seule de la base de données.
2. **Absence de Rendu et de Messages Flash :** Le module `webapp` ne contient actuellement aucun mécanisme de templates HTML ni de messages flash. Il se limite à un câblage prédéfini des handlers `identity` et `tokens`. La présente analyse a donc évalué la sécurité de ce câblage, des routes et de la délégation des formulaires.
3. **Vulnérabilités Majeures Découvertes :**
   - **Protection CSRF Défaillante ou Inexistante :** Le middleware principal de session `sessions.RequireSession` n'intègre **aucune** vérification d'origine ni protection CSRF, exposant directement les endpoints applicatifs aux requêtes forgées inter-sites. De plus, `webapp.NewWebApp` désactive silencieusement le contrôle d'origine lorsque des origines de confiance sont déclarées conjointement avec le flag d'opt-out.
   - **Rupture d'Isolation Multi-Tenant et Déni de Service en Mémoire :** Le magasin borné `sessions/memory.BoundedStore` expulse des sessions actives légitimes lors de la saturation de la capacité, et réalise cette éviction de manière indifférenciée à travers tous les tenants, permettant à un tenant d'annihiler les sessions d'un autre tenant.
   - **Panique à l'Exécution (Crash DoS) dans `webapp` :** La configuration de `CookieDomain` dans `webapp.NewWebApp` provoque un `panic` systématique à l'exécution lors de la première tentative de connexion ou d'inscription, en raison d'une incohérence avec les préfixes `__Host-`.
   - **Défaut d'Observabilité et Fuite Mémoire dans `janitor` :** Le composant `janitor` étouffe silencieusement toute panique levée par les routines de nettoyage, masquant la rupture du processus d'éviction et provoquant une accumulation infinie d'enregistrements en mémoire ou en base de données jusqu'au crash par OOM.

L'analyse a identifié **14 vulnérabilités** :
- **Critique / Élevée (Score ≥ 7.0) :** 7 vulnérabilités (dont **3 vulnérabilités critiques/élevées avec un score CVSS > 7.5 : SEC-SES-02, SEC-SES-04, SEC-SES-11**)
- **Moyenne (Score 4.0 - 6.9) :** 5 vulnérabilités
- **Faible (Score < 4.0) :** 2 vulnérabilités

---

## Vulnérabilités Identifiées

### SEC-SES-01 : Éviction de sessions actives légitimes dans `sessions/memory.BoundedStore` (Déni de Service & Déconnexion Forcée)

* **Score CVSS v3.1 :** **7.5** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`sessions/memory/store.go:104-106`](file:///go/github.com/JLugagne/libauth/sessions/memory/store.go#L104-L106)
  - [`sessions/memory/store.go:249-266`](file:///go/github.com/JLugagne/libauth/sessions/memory/store.go#L249-L266)

#### Description détaillée du mécanisme
Lorsqu'un magasin en mémoire est instancié avec `NewBoundedStore(maxSize)`, la méthode `CreateSession` vérifie si le nombre d'entrées atteint la limite (`len(s.sessions) >= s.maxSize`). Si tel est le cas, elle appelle la méthode interne `evictOne()`.  
Dans `evictOne()` :
```go
// Pass 1: evict any expired session.
for id, sess := range s.sessions {
    if sess.ExpiresAt.Before(now) {
        delete(s.sessions, id)
        delete(s.byHash, hashKey(sess.TenantID, sess.TokenHash))
        return
    }
}

// Pass 2: no expired session found — evict the soonest-expiring live one.
var (
    evictID   uuid.UUID
    evictTime time.Time
    evictSet  bool
)
for id, sess := range s.sessions {
    if !evictSet || sess.ExpiresAt.Before(evictTime) {
        evictID = id
        evictTime = sess.ExpiresAt
        evictSet = true
    }
}
if evictSet {
    sess := s.sessions[evictID]
    delete(s.sessions, evictID)
    delete(s.byHash, hashKey(sess.TenantID, sess.TokenHash))
}
```
Si aucune session n'est encore expirée, le code supprime purement et simplement la session **active et valide** dont l'échéance est la plus proche (`soonest-expiring live one`).

#### Scénario d'exploitation théorique et impact
1. Une application utilise `NewBoundedStore(1000)` pour gérer les sessions de ses utilisateurs.
2. Un attaquant non authentifié émet une rafale continue de requêtes de création de session (par exemple via des sessions anonymes ou des tentatives d'authentification/inscription).
3. Dès que le cap de 1000 sessions est atteint, chaque nouvelle session créée par l'attaquant provoque l'éviction immédiate et arbitraire de la session active d'un utilisateur légitime.
4. À sa prochaine requête HTTP, l'utilisateur légitime reçoit une erreur `401 Unauthorized` (`ErrSessionNotFound`) et se trouve brutalement déconnecté. L'attaquant peut ainsi déconnecter l'ensemble des utilisateurs légitimes du service en quelques secondes.

#### Recommandation de correction
1. Ne jamais expulser silencieusement une session active pour satisfaire une nouvelle insertion.
2. Si le magasin est saturé et qu'aucune session n'est expirée, `CreateSession` doit renvoyer une erreur explicite (ex. `ErrStoreCapacityReached` ou code HTTP 503/429) afin de préserver l'intégrité et la disponibilité des sessions existantes.
3. À défaut, réserver un quota strict par utilisateur/IP ou imposer une politique LRU sur le dernier accès plutôt que d'interrompre des sessions valides.

---

### SEC-SES-02 : Éviction inter-tenants non cloisonnée dans `sessions/memory.BoundedStore` (Rupture d'Isolation Multi-Tenant et DoS Croisé)

* **Score CVSS v3.1 :** **7.7** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`sessions/memory/store.go:237-267`](file:///go/github.com/JLugagne/libauth/sessions/memory/store.go#L237-L267)
  - [`sessions/memory/store.go:86-112`](file:///go/github.com/JLugagne/libauth/sessions/memory/store.go#L86-L112)

#### Description détaillée du mécanisme
La méthode `evictOne()` itère sur l'intégralité de la table `s.sessions map[uuid.UUID]*sessions.Session`. Cette table regroupe indifféremment les sessions de **tous les tenants** hébergés sur l'instance.  
Le filtre dans `evictOne()` ne prend en compte ni le `tenantID` de la session candidate à l'insertion, ni le `tenantID` des sessions enregistrées :
```go
for id, sess := range s.sessions {
    if !evictSet || sess.ExpiresAt.Before(evictTime) {
        evictID = id
        evictTime = sess.ExpiresAt
        evictSet = true
    }
}
```
Par conséquent, lorsqu'une insertion est déclenchée pour le Tenant A et que le magasin atteint `maxSize`, la session évincée peut appartenir au Tenant B.

#### Scénario d'exploitation théorique et impact
1. Dans une architecture multi-tenant SaaS où plusieurs organisations partagent une même instance ou un pool en mémoire, un utilisateur malveillant dispose d'un compte sur l'organisation A (Tenant A).
2. L'attaquant génère en masse des sessions au sein du Tenant A.
3. Le magasin atteint `maxSize`. L'algorithme `evictOne()` parcourt les sessions globales et sélectionne des sessions du Tenant B (dont la durée de vie résiduelle est plus courte).
4. Les sessions actives des utilisateurs et administrateurs du Tenant B sont détruites. L'attaquant du Tenant A parvient à provoquer un déni de service ciblé ou généralisé contre les clients du Tenant B sans disposer d'aucun droit chez ces derniers. L'isolation multi-tenant est rompue.

#### Recommandation de correction
1. Cloisonner strictement les capacités par tenant : `BoundedStore` doit maintenir un compteur et une politique de capacité dédiés par `tenantID` (ex. `map[string]*tenantPartition` ou `maxSizePerTenant`).
2. Limiter la portée de `evictOne(tenantID string)` aux seules sessions du tenant concerné par la nouvelle insertion.

---

### SEC-SES-03 : Panique à l'exécution dans `webapp.NewWebApp` en cas de configuration de `CookieDomain` (Déni de Service sur l'Authentification)

* **Score CVSS v3.1 :** **7.5** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`webapp/webapp.go:66-67`](file:///go/github.com/JLugagne/libauth/webapp/webapp.go#L66-L67)
  - [`webapp/webapp.go:165-168`](file:///go/github.com/JLugagne/libauth/webapp/webapp.go#L165-L168)
  - [`tokens/cookies.go:80-95`](file:///go/github.com/JLugagne/libauth/tokens/cookies.go#L80-L95)
  - [`tokens/cookies.go:136-138`](file:///go/github.com/JLugagne/libauth/tokens/cookies.go#L136-L138)
  - [`identity/handlers.go:135-138`](file:///go/github.com/JLugagne/libauth/identity/handlers.go#L135-L138)
  - [`identity/handlers.go:426-427`](file:///go/github.com/JLugagne/libauth/identity/handlers.go#L426-L427)

#### Description détaillée du mécanisme
Le composant `webapp.NewWebApp` expose un champ de configuration public `CookieDomain` :
```go
// CookieDomain optionally scopes the auth cookies to a domain (empty = host-only).
CookieDomain string
```
Lors de l'initialisation, si `CookieDomain` est non vide, `NewWebApp` ajoute les options :
```go
if cfg.CookieDomain != "" {
    idOpts = append(idOpts, identity.WithCookieDomain(cfg.CookieDomain))
    tkOpts = append(tkOpts, tokens.WithCookieDomain(cfg.CookieDomain))
}
```
Or, par défaut, les noms de cookies utilisés par `identity` et `tokens` sont configurés sur `DefaultAccessCookieName = "__Host-access_token"` et `DefaultRefreshCookieName = "__Host-refresh_token"`.  
Dans `tokens/cookies.go`, la méthode `Validate()` vérifie la conformité RFC 6265bis :
```go
if strings.HasPrefix(c.AccessName, hostPrefix) {
    if c.Domain != "" {
        errs = append(errs, fmt.Errorf("cookie %q: __Host- prefix requires Domain to be empty, got %q", c.AccessName, c.Domain))
    }
...
```
Et lors de l'écriture du cookie (`SetAccess`), `withDefaults()` invoque :
```go
if err := c.Validate(); err != nil {
    panic("tokens.Cookies: invalid __Host- cookie configuration: " + err.Error())
}
```
`NewWebApp` ne valide pas la cohérence lors de la construction et ne modifie pas les noms des cookies pour retirer le préfixe `__Host-`. Le constructeur `NewWebApp` renvoie `(handler, nil)` avec succès, masquant l'anomalie au démarrage.

#### Scénario d'exploitation théorique et impact
1. L'administrateur configure `webapp.NewWebApp` en renseignant `CookieDomain: "example.com"` pour partager l'authentification sur ses sous-domaines.
2. Le serveur démarre sans aucune erreur.
3. Dès qu'un utilisateur soumet un formulaire sur `POST /auth/login` ou `POST /auth/register`, le handler traite les identifiants puis appelle `cfg.cookies.SetAccess(...)`.
4. `withDefaults()` déclenche un `panic` Go non intercepté au sein de la goroutine HTTP :
   `panic: tokens.Cookies: invalid __Host- cookie configuration: cookie "__Host-access_token": __Host- prefix requires Domain to be empty, got "example.com"`
5. La requête échoue en erreur 500 (ou crashe le processus si aucun recover middleware n'est installé). Toute authentification et inscription devient totalement impossible sur l'ensemble de la plateforme.

#### Recommandation de correction
1. Dans `webapp.NewWebApp`, valider immédiatement la configuration des cookies et refuser le build (`return nil, fmt.Errorf(...)`) si `CookieDomain != ""` sans ajustement des noms de cookies.
2. Lorsque `CookieDomain` est renseigné, remplacer automatiquement les noms de cookies par défaut par des noms sans préfixe `__Host-` (ex. `access_token` et `refresh_token`), tout en consignant un avertissement de sécurité.

---

### SEC-SES-04 : Absence totale de vérification CSRF / Origine dans le middleware `sessions.RequireSession` (Cross-Site Request Forgery)

* **Score CVSS v3.1 :** **8.1** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`sessions/middleware.go:21-97`](file:///go/github.com/JLugagne/libauth/sessions/middleware.go#L21-L97)

#### Description détaillée du mécanisme
Le package `sessions` propose `RequireSession` comme middleware standard pour sécuriser les routes nécessitant une session active.  
L'extraction du jeton s'effectue en lisant en premier lieu le cookie HTTP :
```go
// 1. Try Cookie
cookie, err := r.Cookie(cfg.cookieName)
if err == nil {
    token = cookie.Value
}
```
Puis, la session est validée via `svc.ValidateSession(r.Context(), tenantID, token)` et le handler aval est invoqué.  
Contrairement aux packages `tokens` (`RefreshHandler`, `LogoutHandler`), `identity` et `mfa` qui appliquent une vérification systématique de l'origine (`originAllowed` basée sur `Origin` et `Referer`), le middleware `sessions.RequireSession` n'exécute **strictement aucun contrôle d'origine ou de méthode HTTP**.  
Aucune option `WithTrustedOrigins` n'existe pour `RequireSession`.

#### Scénario d'exploitation théorique et impact
1. Une application web utilise `sessions.RequireSession` pour protéger des actions sensibles avec état (ex. `POST /api/user/email`, `POST /account/transfer`, `POST /settings/delete`).
2. Les cookies de session sont transmis automatiquement par le navigateur de la victime. Si les cookies utilisent `SameSite=Lax` (ou si l'action est déclenchée par un chemin autorisé ou un cookie sans SameSite strict), une requête forgée inter-site (CSRF) initiée depuis `https://evil.com` soumet un formulaire POST vers l'application cible.
3. `RequireSession` lit le cookie valide, valide la session et transmet la requête au handler cible sans vérifier si l'en-tête `Origin` ou `Referer` provient d'une source de confiance.
4. L'action sensible est exécutée avec l'identité de la victime à son insu (modification de profil, transactions non autorisées).

#### Recommandation de correction
1. Intégrer un contrôle strict de l'origine dans `RequireSession` pour toutes les requêtes modifiant l'état (`POST`, `PUT`, `DELETE`, `PATCH`), en utilisant la fonction `originAllowed` et une option `WithTrustedOrigins(...)`.
2. Rejeter toute requête dont l'en-tête `Origin`/`Referer` ne correspond ni au Host de la requête, ni à la liste blanche d'origines autorisées.
3. Fournir ou recommander un intergiciel de jetons anti-CSRF (Synchronizer Token Pattern ou Double Submit Cookie) pour les formulaires HTML traditionnels.

---

### SEC-SES-05 : Absence de primitive d'écriture de cookie et non-application de `HttpOnly` dans `sessions` (Risque d'Exfiltration de Session via XSS)

* **Score CVSS v3.1 :** **6.5** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`
* **Fichiers et lignes concernés :**
  - [`sessions/middleware.go:10-16`](file:///go/github.com/JLugagne/libauth/sessions/middleware.go#L10-L16)
  - [`sessions/middleware.go:28-34`](file:///go/github.com/JLugagne/libauth/sessions/middleware.go#L28-L34)
  - [`sessions/middleware.go:46-52`](file:///go/github.com/JLugagne/libauth/sessions/middleware.go#L46-L52)

#### Description détaillée du mécanisme
La documentation de `sessions` met en avant le préfixe `DefaultSessionCookieName = "__Host-session_token"` en affirmant :
> "The __Host- prefix is browser-enforced: the cookie must be Secure, must carry no Domain attribute, and must have Path=/, which host-locks it and defeats subdomain/sibling-host cookie-tossing session fixation. This is the secure default — consumers no longer have to opt in."

Cependant :
1. Le package `sessions` ne fournit **aucun helper ni fonction d'écriture de cookie** (aucun `SetSessionCookie`, `WriteCookie`, etc.). Le développeur consommateur doit écrire manuellement l'appel `http.SetCookie(w, ...)`.
2. La spécification RFC 6265bis impose au navigateur d'exiger les attributs `Secure`, `Path=/` et l'absence de `Domain` pour un cookie préfixé par `__Host-`, mais **n'impose absolument pas le drapeau `HttpOnly`**.
3. En incitant les développeurs à croire que le préfixe `__Host-` garantit à lui seul la sécurité totale du cookie, la bibliothèque crée un faux sentiment de sécurité. Si le consommateur omet `HttpOnly: true`, le jeton est directement accessible au JavaScript client via `document.cookie`.

#### Scénario d'exploitation théorique et impact
1. Un développeur intègre le package `sessions` et lit dans la documentation que le nom `__Host-session_token` applique automatiquement les durcissements de sécurité.
2. Il émet le cookie de session lors du login sans positionner explicitement `HttpOnly: true`.
3. Le navigateur accepte le cookie car `__Host-` requiert uniquement `Secure` et `Path=/`.
4. Une vulnérabilité XSS mineure (ou l'injection d'un script tiers de métrique/publicité compromis) s'exécute dans le contexte de l'application. Le script accède à `document.cookie`, lit la valeur de `__Host-session_token` et l'exfiltre vers un serveur distant, permettant le détournement immédiat de la session utilisateur (*Session Hijacking*).

#### Recommandation de correction
1. Fournir dans `sessions` une structure et des fonctions officielles de manipulation de cookies (ex. `sessions.CookieConfig`, `SetSession(w, token, expiresAt)` et `ClearSession(w)`), analogues à celles de `tokens.Cookies`.
2. Forcer impérativement `HttpOnly: true` et `SameSite: http.SameSiteLaxMode` lors de l'émission des cookies de session.
3. Corriger la documentation pour préciser que le préfixe `__Host-` ne protège en aucun cas contre la lecture JavaScript et qu'un flag `HttpOnly` explicite demeure indispensable.

---

### SEC-SES-06 : Contournement du plafond `maxLifetime` par `CreateSession` dans le stockage et le Janitor (Sessions Zombie et Rétention Indue)

* **Score CVSS v3.1 :** **5.4** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L`
* **Fichiers et lignes concernés :**
  - [`sessions/service.go:114-116`](file:///go/github.com/JLugagne/libauth/sessions/service.go#L114-L116)
  - [`sessions/service.go:284-289`](file:///go/github.com/JLugagne/libauth/sessions/service.go#L284-L289)
  - [`adapters/pgx/sessions/store.go:149-156`](file:///go/github.com/JLugagne/libauth/adapters/pgx/sessions/store.go#L149-L156)
  - [`sessions/memory/store.go:200-212`](file:///go/github.com/JLugagne/libauth/sessions/memory/store.go#L200-L212)

#### Description détaillée du mécanisme
Le service applique par défaut un plafond absolu de 30 jours (`maxLifetime = 30 * 24 * time.Hour`, SEC-08).  
Les méthodes `Touch`, `Rotate` et `BindUser` appellent systématiquement `s.clampExpiry(session, s.now().Add(duration))` pour empêcher que l'échéance `ExpiresAt` ne dépasse `CreatedAt + maxLifetime`.  
En revanche, dans `CreateSession` :
```go
session := &Session{
    ID:        uuid.Must(uuid.NewV7()),
    TenantID:  tenantID,
    UserID:    userID,
    TokenHash: hash,
    UserAgent: userAgent,
    IP:        ip,
    ExpiresAt: now.Add(duration), // NON PLAFONNÉ
    CreatedAt: now,
}
```
L'expiration initiale `ExpiresAt` est fixée directement à `now.Add(duration)` sans passer par `s.clampExpiry`.  
Si un appelant initialise une session avec une durée longue (par exemple 90 jours ou 1 an pour une option "se souvenir de moi") :
- La base PostgreSQL ou la mémoire enregistre `expires_at = now + 90 jours`.
- Après 30 jours, `ValidateSession` rejette la session car `now.After(deadline)`.
- Cependant, la routine d'éviction du Janitor (`DeleteExpired`) exécute :
  `DELETE FROM sessions WHERE expires_at < now() AND tenant_id = $1`
  La session n'est donc **pas** supprimée avant l'échéance des 90 jours.

#### Scénario d'exploitation théorique et impact
1. Une application émet des sessions avec `duration = 90 jours`.
2. Après 30 jours, le jeton est refusé par la logique applicative, mais l'enregistrement de session continue d'exister en base de données et dans les tables d'index pendant 60 jours supplémentaires.
3. Des millions de sessions périmées dites "zombies" s'accumulent sans pouvoir être purgées par le `Janitor`.
4. De surcroît, tout composant externe, microservice ou requête analytique consultant directement la table `sessions` (ou utilisant un store tiers vérifiant `expires_at >= NOW()`) considérera la session comme toujours active pendant 90 jours, contournant la politique de sécurité absolue.

#### Recommandation de correction
Dans `sessions/service.go`, plafonner systématiquement `ExpiresAt` dès la création :
```go
session := &Session{
    ID:        uuid.Must(uuid.NewV7()),
    TenantID:  tenantID,
    UserID:    userID,
    TokenHash: hash,
    UserAgent: userAgent,
    IP:        ip,
    ExpiresAt: s.clampExpiry(&Session{CreatedAt: now}, now.Add(duration)),
    CreatedAt: now,
}
```

---

### SEC-SES-07 : Paniques silencieusement avalées dans la boucle du Janitor (Échec d'Observabilité et Fuite Mémoire/Base menant au DoS)

* **Score CVSS v3.1 :** **7.5** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`janitor/janitor.go:102-108`](file:///go/github.com/JLugagne/libauth/janitor/janitor.go#L102-L108)

#### Description détaillée du mécanisme
Dans `janitor/janitor.go`, la goroutine périodique encapsule l'exécution de la fonction de nettoyage dans un `recover()` anonyme :
```go
case <-t.C:
    func() {
        defer func() {
            _ = recover()
        }()
        fn()
    }()
```
La valeur récupérée par `recover()` est purement ignorée (`_ = recover()`). Aucun log (ni `slog`, ni `logrus`), aucun compteur d'erreur, aucun événement d'audit et aucun canal d'alerte ne sont notifiés.  
Si la fonction `fn()` panique (par exemple en cas de rupture de connexion avec PostgreSQL, pointeur nul dans un store personnalisé, ou corruption mémoire), la panique est étouffée à chaque tick.

#### Scénario d'exploitation théorique et impact
1. Le package `janitor` a pour rôle documenté d'éviter que les magasins mémoire ou bases de données ne croissent indéfiniment (qualifié dans la doc de `trivial denial-of-service vector`).
2. À la suite d'un incident transitoire ou d'un bug de pilote (ex. fermeture inattendue du pool `pgx` ou déréférencement nul dans `DeleteExpired`), `fn()` panique à chaque exécution.
3. Le Janitor avale silencieusement chaque panique sans émettre le moindre avertissement.
4. L'administrateur système et les outils de supervision croient le service de nettoyage opérationnel.
5. La mémoire ou l'espace disque de la base de données sature de manière continue sous la charge jusqu'à l'intervention du OOM Killer Linux ou le crash du système de fichiers, provoquant une interruption totale de service.

#### Recommandation de correction
1. Ne pas masquer les paniques : consigner l'erreur récupérée avec sa trace de pile (`debug.Stack()`) via le logger par défaut ou `slog`.
2. Fournir une option de configuration pour remonter les erreurs ou notifier un gestionnaire d'incidents (ex. `WithErrorHandler(func(err any))`).
3. Incrémenter une métrique d'échec ou basculer une sonde de santé (`health.Pinger`) en état critique.

---

### SEC-SES-08 : Non-idempotence de `RevokeSession` et évasion des logs d'audit sur les sessions expirées

* **Score CVSS v3.1 :** **4.3** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`sessions/service.go:214-233`](file:///go/github.com/JLugagne/libauth/sessions/service.go#L214-L233)

#### Description détaillée du mécanisme
Dans `sessions/service.go` :
```go
func (s *service) RevokeSession(ctx context.Context, tenantID string, token string, rc ...event.RequestContext) error {
    hash := s.hashToken(token)

    session, err := s.store.FindSessionByHash(ctx, tenantID, hash)
    if err != nil {
        return err
    }

    if err := s.store.DeleteSession(ctx, tenantID, session.ID); err != nil {
        return err
    }
    reqCtx := event.RequestContextFrom(rc...)
    s.emit(ctx, event.Event{
        Type:     event.Logout,
        UserID:   session.UserID.String(),
        TenantID: tenantID,
        Attrs:    reqCtx.ApplyTo(nil),
    })
    return nil
}
```
Si la session a déjà dépassé sa durée de validité (ne serait-ce que de quelques millisecondes) ou si elle a déjà été révoquée par une requête concurrente, `FindSessionByHash` renvoie `ErrSessionNotFound`.  
`RevokeSession` s'interrompt immédiatement et retourne cette erreur.  
Conséquences :
1. La méthode n'est pas idempotente, contrairement à `RevokeAllForUser`.
2. L'événement d'audit `event.Logout` n'est **jamais émis** sur ce chemin.

#### Scénario d'exploitation théorique et impact
1. Un utilisateur clique sur "Se déconnecter" alors que sa session vient d'expirer ou clique deux fois rapidement sur le bouton de déconnexion.
2. Le handler HTTP reçoit `ErrSessionNotFound` et retourne une erreur 401 ou 500 au lieu de confirmer le succès de la déconnexion et de nettoyer les cookies.
3. Aucun événement de sécurité `event.Logout` n'est envoyé vers le SIEM ou le journal d'audit pour consigner la volonté explicite de déconnexion. Les journaux d'audit de sécurité deviennent incomplets et non conformes aux exigences de traçabilité.

#### Recommandation de correction
1. Rendre `RevokeSession` idempotent : si `FindSessionByHash` renvoie `ErrSessionNotFound`, la fonction doit considérer la session comme déjà révoquée, retourner `nil` et éventuellement émettre un événement de déconnexion générique sans `UserID`.

---

### SEC-SES-09 : Boucle CPU intensive (Busy Loop) dans `janitor.Start` sur intervalle non strictement positif

* **Score CVSS v3.1 :** **4.0** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
* **Fichiers et lignes concernés :**
  - [`janitor/janitor.go:83-85`](file:///go/github.com/JLugagne/libauth/janitor/janitor.go#L83-L85)
  - [`janitor/janitor.go:95-96`](file:///go/github.com/JLugagne/libauth/janitor/janitor.go#L95-L96)

#### Description détaillée du mécanisme
Dans `janitor.Start` :
```go
if interval <= 0 {
    interval = time.Nanosecond
}
...
t := time.NewTicker(interval)
```
Si un appelant fournit par erreur un intervalle nul ou négatif (par exemple issu d'une variable d'environnement mal renseignée ou d'une valeur zéro non initialisée dans une structure de configuration Go), le code force l'intervalle à **1 nanoseconde**.  
Un `time.NewTicker(time.Nanosecond)` génère des déclenchements continus à la vitesse maximale permise par le scheduler Go.

#### Scénario d'exploitation théorique et impact
1. Lors du déploiement ou du redémarrage d'un service, une erreur de typage dans le fichier de configuration laisse la variable d'intervalle à 0.
2. Le Janitor démarre avec un ticker de 1 ns.
3. La goroutine tourne en boucle fermée à 100 % de charge CPU sur un cœur, mobilisant les verrous mémoire ou les connexions à la base de données de façon ininterrompue.
4. L'ensemble des performances de l'application s'effondre sans qu'aucun message d'erreur clair n'indique l'origine de la saturation CPU.

#### Recommandation de correction
1. Rejeter toute valeur non positive en levant une panique immédiate au démarrage ou en renvoyant une erreur (`if interval <= 0 { panic("janitor: interval must be positive") }`).
2. À défaut, imposer un plancher de sécurité raisonnable (par exemple 1 seconde ou 1 minute).

---

### SEC-SES-10 : Faiblesses de validation d'origine dans `internal/httputil` (Contournement Cross-Scheme et Host Header Spoofing)

* **Score CVSS v3.1 :** **6.8** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`internal/httputil/httputil.go:35-55`](file:///go/github.com/JLugagne/libauth/internal/httputil/httputil.go#L35-L55)
  - [`internal/httputil/httputil.go:57-69`](file:///go/github.com/JLugagne/libauth/internal/httputil/httputil.go#L57-L69)

#### Description détaillée du mécanisme
La fonction `RequestOriginHost` extrait uniquement l'hôte via `u.Host` sans vérifier le protocole (`scheme`) :
```go
if u, err := url.Parse(o); err == nil {
    return u.Host
}
```
Puis, `OriginAllowed` valide l'origine selon :
```go
return host == r.Host || trustedOrigins[host]
```
Deux faiblesses majeures apparaissent :
1. **Suppression du Schéma (Cross-Scheme CSRF) :** Si l'application légitime est servie sur `https://example.com`, une requête provenant de `http://example.com` (HTTP non chiffré) produira `host = "example.com"`. Elle sera jugée équivalente à `r.Host == "example.com"`. Un attaquant en position d'homme du milieu (sur un réseau Wi-Fi public ou via SSL stripping) ou exploitant une faille sur un sous-domaine/port HTTP peut déclencher des requêtes CSRF valides vers les endpoints HTTPS sécurisés.
2. **Dépendance à `r.Host` sans contrôle de proxy :** `r.Host` provient directement de l'en-tête HTTP `Host` envoyé par le client. Si le serveur web écoute sur une adresse générique (`0.0.0.0`) ou si le reverse proxy transmet l'en-tête `Host` sans validation stricte, un attaquant utilisant le DNS Rebinding ou manipulant le Host header peut faire correspondre `host == r.Host`.
3. **Défaut laxiste de `OriginAllowed` :** Si `trustedOrigins` est vide ou non initialisé, `OriginAllowed` renvoie `true` inconditionnellement (`if len(trustedOrigins) == 0 { return true }`), adoptant un modèle permissif par défaut (fail-open) plutôt que restrictif (fail-closed).

#### Scénario d'exploitation théorique et impact
Un attaquant sur un réseau local non sécurisé injecte une ressource HTML sur une page HTTP visitée par la victime. Cette page soumet une requête POST forgée vers l'application d'authentification HTTPS de la victime. La fonction `OriginAllowed` compare `example.com` (HTTP) avec `r.Host` (`example.com`), valide la requête et autorise la transaction sensible.

#### Recommandation de correction
1. Valider l'origine complète (schéma + hôte + port optionnel) : rejeter toute origine en `http://` lorsque la requête est reçue en HTTPS.
2. Basculer `httputil.OriginAllowed` vers un modèle fail-closed par défaut : si `trustedOrigins` est vide, exiger impérativement une correspondance exacte avec l'hôte sécurisé configuré.
3. Permettre la configuration d'une liste blanche stricte de serveurs mandataires de confiance (`TrustedProxies`) pour la résolution des en-têtes `X-Forwarded-*`.

---

### SEC-SES-11 : Désactivation silencieuse de la protection CSRF par conflit de configuration dans `webapp.NewWebApp`

* **Score CVSS v3.1 :** **8.1** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`webapp/webapp.go:71-77`](file:///go/github.com/JLugagne/libauth/webapp/webapp.go#L71-L77)
  - [`webapp/webapp.go:122-124`](file:///go/github.com/JLugagne/libauth/webapp/webapp.go#L122-L124)
  - [`webapp/webapp.go:169-178`](file:///go/github.com/JLugagne/libauth/webapp/webapp.go#L169-L178)

#### Description détaillée du mécanisme
Dans `webapp/webapp.go`, le garde de construction vérifie :
```go
if len(cfg.TrustedOrigins) == 0 && !cfg.InsecureNoOriginCheck {
    return nil, errors.New("webapp: Config.TrustedOrigins must be set for CSRF-by-default...")
}
```
Plus bas, lors de l'application des options des handlers :
```go
if len(cfg.TrustedOrigins) > 0 {
    idOpts = append(idOpts, identity.WithTrustedOrigins(cfg.TrustedOrigins...))
    tkOpts = append(tkOpts, tokens.WithTrustedOrigins(cfg.TrustedOrigins...))
}
if cfg.InsecureNoOriginCheck {
    idOpts = append(idOpts, identity.WithInsecureNoOriginCheck())
    tkOpts = append(tkOpts, tokens.WithInsecureNoOriginCheck())
}
```
Si un développeur renseigne `TrustedOrigins: []string{"https://app.example.com"}` tout en ayant laissé `InsecureNoOriginCheck: true` (par exemple hérité d'un environnement de dev/test ou par erreur de configuration) :
1. Le constructeur `NewWebApp` ne signale aucune erreur et n'émet aucun avertissement.
2. L'option `WithInsecureNoOriginCheck()` est ajoutée **après** `WithTrustedOrigins()`.
3. Dans la configuration interne des handlers, `insecureNoOriginCheck` passe à `true`, ce qui désactive complètement le contrôle d'origine lors de l'exécution de `originAllowed(r)`.
4. La liste blanche d'origines renseignée par le développeur est silencieusement ignorée.

#### Scénario d'exploitation théorique et impact
L'équipe de développement déploie l'application en production en croyant être protégée contre les attaques CSRF car `TrustedOrigins` a été explicitement défini. Cependant, en raison du flag `InsecureNoOriginCheck` laissé actif, aucune protection CSRF n'est en vigueur. Un attaquant peut monter des attaques CSRF contre `/auth/refresh`, `/auth/logout`, `/auth/login` et `/auth/register` en toute impunité.

#### Recommandation de correction
Interdire strictement cette combinaison contradictoire dans `NewWebApp` :
```go
if len(cfg.TrustedOrigins) > 0 && cfg.InsecureNoOriginCheck {
    return nil, errors.New("webapp: cannot specify both TrustedOrigins and InsecureNoOriginCheck")
}
```

---

### SEC-SES-12 : Déni de service par concurrence stricte lors de la rotation de session dans `sessions.Service.Rotate`

* **Score CVSS v3.1 :** **2.6** (Faible)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L`
* **Fichiers et lignes concernés :**
  - [`sessions/service.go:164-186`](file:///go/github.com/JLugagne/libauth/sessions/service.go#L164-L186)
  - [`adapters/pgx/sessions/store.go:95-109`](file:///go/github.com/JLugagne/libauth/adapters/pgx/sessions/store.go#L95-L109)
  - [`sessions/memory/store.go:119-148`](file:///go/github.com/JLugagne/libauth/sessions/memory/store.go#L119-L148)

#### Description détaillée du mécanisme
La méthode `sessions.Service.Rotate` procède à une rotation immédiate du jeton en mémoire ou en base via un compare-and-set sur l'ancien condensat :
```go
oldHash := session.TokenHash
session.TokenHash = s.hashToken(newToken)
session.ExpiresAt = s.clampExpiry(session, s.now().Add(duration))
if err := s.store.UpdateSession(ctx, tenantID, session, oldHash); err != nil {
    return nil, "", err
}
```
Si deux requêtes concurrentes émises par le navigateur de l'utilisateur (ex. chargement initial d'une SPA déclenchant plusieurs appels d'API parallèles avec le même cookie de session) sollicitent la rotation en même temps :
- La première requête réussit et remplace le condensat.
- La seconde requête échoue sur la clause `token_hash = oldHash` et reçoit immédiatement `ErrSessionNotFound`.
Contrairement au sous-système de jetons (`tokens/jwt`) qui intègre une fenêtre de grâce (`ReuseGracePeriod` de 10 secondes) pour absorber la concurrence bénigne, `sessions` n'offre aucune tolérance de grâce temporelle.

#### Scénario d'exploitation théorique et impact
Un utilisateur naviguant normalement sur l'application subit des déconnexions intempestives ou des erreurs 401 lors de l'ouverture d'onglets multiples ou du chargement de composants web parallèles.

#### Recommandation de correction
Introduire une période de grâce configurable lors de la rotation de session, permettant à l'ancien condensat de continuer à valider pendant quelques secondes (5 à 10 secondes) pour les requêtes concurrentes en vol.

---

### SEC-SES-13 : Fuite mémoire non bornée par défaut dans `sessions/memory.NewStore` en l'absence de Janitor

* **Score CVSS v3.1 :** **7.5** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`sessions/memory/store.go:51-56`](file:///go/github.com/JLugagne/libauth/sessions/memory/store.go#L51-L56)
  - [`sessions/memory/store.go:59`](file:///go/github.com/JLugagne/libauth/sessions/memory/store.go#L59)
  - [`sessions/memory/store.go:67-73`](file:///go/github.com/JLugagne/libauth/sessions/memory/store.go#L67-L73)

#### Description détaillée du mécanisme
Le constructeur `memory.NewStore()` initialise un magasin dont la capacité est infinie (`maxSize = 0`).  
L'éviction opportuniste des sessions expirées n'intervient **que** lorsqu'une requête tente spécifiquement de consulter le hash d'une session périmée (`FindSessionByHash`).  
Si une session expire sans que son propriétaire ne revienne sur le site, ou si un robot émet des milliers de sessions anonymes éphémères, ces entrées ne sont jamais consultées et restent allouées dans la heap Go pour une durée indéterminée.

#### Scénario d'exploitation théorique et impact
1. Un service déployé en production utilise `memory.NewStore()` sans avoir instancié de `janitor.Start`.
2. Un attaquant émet des requêtes en continu générant de nouvelles sessions.
3. Les maps `sessions` et `byHash` croissent sans aucune limite.
4. Le processus Go consomme l'intégralité de la RAM disponible, déclenchant l'intervention du OOM Killer et provoquant un déni de service complet.

#### Recommandation de correction
1. Faire de `BoundedStore` le comportement par défaut ou imposer une taille maximale par défaut dans `NewStore`.
2. Documenter avec force l'obligation d'activer un reaper en arrière-plan (`janitor`) et émettre un log d'avertissement au démarrage si aucun nettoyeur n'est détecté.

---

### SEC-SES-14 : Réassignation arbitraire d'identité utilisateur sans contrôle d'état dans `sessions.Service.BindUser`

* **Score CVSS v3.1 :** **4.2** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`sessions/service.go:190-212`](file:///go/github.com/JLugagne/libauth/sessions/service.go#L190-L212)

#### Description détaillée du mécanisme
La méthode `BindUser` a pour vocation de promouvoir une session anonyme préliminaire en session authentifiée (ex. transfert d'un panier d'achat après login).  
Cependant, l'implémentation de `BindUser` ne contrôle à aucun moment si la session initiale était réellement anonyme (`session.UserID == uuid.Nil`) :
```go
oldHash := session.TokenHash
session.UserID = userID // Écriture inconditionnelle
session.TokenHash = s.hashToken(newToken)
```
Si une session appartenant déjà à l'utilisateur A est passée en argument à `BindUser` avec l'identifiant de l'utilisateur B, la session est réassignée silencieusement à l'utilisateur B en conservant son `ID` d'origine et son horodatage de création `CreatedAt`.

#### Scénario d'exploitation théorique et impact
Dans une application gérant des changements de profil, des délégations ou des sessions partagées, une logique métier imparfaite peut réassigner une session active existante sans réinitialiser complètement le contexte de session, créant un mélange d'identités ou une confusion d'état de privilèges.

#### Recommandation de correction
Exiger que la session soit strictement anonyme avant de permettre le re-binding :
```go
if session.UserID != uuid.Nil {
    return nil, "", errors.New("sessions: cannot bind an already authenticated session")
}
```

---

## Synthèse Globale des Vulnérabilités

| ID | Titre | Sévérité | Score CVSS v3.1 | Vecteur CVSS v3.1 |
|---|---|---|---|---|
| **SEC-SES-01** | Éviction de sessions actives légitimes dans `sessions/memory.BoundedStore` | **Élevé** | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-SES-02** | Éviction inter-tenants non cloisonnée dans `sessions/memory.BoundedStore` | **Élevé** | **7.7** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H` |
| **SEC-SES-03** | Panique à l'exécution dans `webapp.NewWebApp` en cas de configuration de `CookieDomain` | **Élevé** | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-SES-04** | Absence totale de vérification CSRF / Origine dans `sessions.RequireSession` | **Élevé** | **8.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` |
| **SEC-SES-05** | Absence de primitive d'écriture de cookie et omission de `HttpOnly` dans `sessions` | **Moyen** | **6.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` |
| **SEC-SES-06** | Contournement du plafond `maxLifetime` par `CreateSession` dans le stockage et le Janitor | **Moyen** | **5.4** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L` |
| **SEC-SES-07** | Paniques silencieusement avalées dans la boucle du Janitor | **Élevé** | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-SES-08** | Non-idempotence de `RevokeSession` et évasion des logs d'audit sur sessions expirées | **Moyen** | **4.3** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` |
| **SEC-SES-09** | Boucle CPU intensive (Busy Loop) dans `janitor.Start` sur intervalle non positif | **Moyen** | **4.0** | `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **SEC-SES-10** | Faiblesses de validation d'origine dans `internal/httputil` (Cross-Scheme & Host Spoofing) | **Moyen** | **6.8** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` |
| **SEC-SES-11** | Désactivation silencieuse du CSRF par conflit de configuration dans `webapp.NewWebApp` | **Élevé** | **8.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` |
| **SEC-SES-12** | Déni de service par concurrence stricte lors de la rotation dans `sessions.Service.Rotate` | **Faible** | **2.6** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L` |
| **SEC-SES-13** | Fuite mémoire non bornée par défaut dans `sessions/memory.NewStore` | **Élevé** | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-SES-14** | Réassignation arbitraire d'identité utilisateur dans `sessions.Service.BindUser` | **Moyen** | **4.2** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` |

---

## Focus sur les Vulnérabilités Critiques (Score CVSS v3.1 > 7.5)

Conformément aux exigences de l'audit, **trois (3) vulnérabilités distinctes présentent un score strictement supérieur à 7.5 (CVSS > 7.5)** :

1. **SEC-SES-04 (Score 8.1 - `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`) :**  
   *Absence totale de vérification CSRF / Origine dans `sessions.RequireSession`.*  
   Le middleware principal de session authentifie aveuglément les requêtes modifiant l'état sur la base du seul cookie transmis par le navigateur, sans valider l'en-tête `Origin` ou `Referer`, exposant les applications consommatrices au Cross-Site Request Forgery avec impact complet sur l'intégrité et la confidentialité des comptes.

2. **SEC-SES-11 (Score 8.1 - `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`) :**  
   *Désactivation silencieuse de la protection CSRF par conflit de configuration dans `webapp.NewWebApp`.*  
   La présence simultanée de `TrustedOrigins` et de `InsecureNoOriginCheck` désactive sans avertissement le contrôle d'origine sur l'ensemble des routes (`/auth/login`, `/auth/register`, `/auth/refresh`, `/auth/logout`), rendant caduque la liste blanche déclarée par le développeur et laissant l'application totalement vulnérable au CSRF.

3. **SEC-SES-02 (Score 7.7 - `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H`) :**  
   *Éviction inter-tenants non cloisonnée dans `sessions/memory.BoundedStore`.*  
   L'algorithme de libération d'espace mémoire itère indifféremment sur toutes les sessions de l'instance sans isolation par tenant. Un attaquant authentifié dans le Tenant A peut saturer le store et provoquer la déconnexion massive forcée des utilisateurs du Tenant B (changement de périmètre de sécurité `S:C`).

*(Note : Quatre vulnérabilités additionnelles atteignent le seuil élevé de **CVSS = 7.5** : SEC-SES-01, SEC-SES-03, SEC-SES-07 et SEC-SES-13).*
