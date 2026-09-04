# Rapport d'Audit de Sécurité : Sous-système OAuth 2.0 et OpenID Connect (OIDC)

**Cible :** `github.com/JLugagne/libauth`  
**Périmètre audité :**
- `oauth/` (handlers, provider, state, pkce, cookie, oidc verifier, jwks cache, oidc discovery, ssrf)
- `oauth/providers/` (Google, GitHub, GitLab, Okta, Microsoft, Apple, Discord, Facebook, LinkedIn, Auth0, Cognito, Keycloak, OIDC générique, helpers)
- `adapters/pgx/oauth` (store, migrations, cache, KEK)

**Date :** 4 septembre 2026  
**Auditeur :** Antigravity Security Research  
**Statut :** Terminé

---

## Sommaire Exécutif

Un audit de sécurité approfondi et impitoyable a été conduit sur l'ensemble du sous-système OAuth 2.0 et OpenID Connect (OIDC) de la bibliothèque `libauth`, ainsi que sur son adaptateur de persistance dynamique multi-tenant PostgreSQL (`jackc/pgx`).

L'analyse de code source a mis en évidence des défaillances critiques touchant l'intégrité de l'authentification, la robustesse cryptographique, l'isolation inter-tenant et la résistance aux attaques réseau :

1. **Usurpation totale de compte par perte de précision numérique (`float64`) :** Le normalisateur d'identifiants `stringifyID` décode les identifiants numériques JSON sous forme de flottants IEEE 754 à 53 bits de mantisse. Pour les identifiants entiers supérieurs à $2^{53}$ (courants chez GitLab, les identifiants snowflake et les bases de données d'entreprise), les identifiants adjacents subissent une collision silencieuse, permettant à un attaquant de s'authentifier directement sur le compte de la victime via `LinkOrCreateIdentity`.
2. **Faiblesse du cookie d'état OAuth (CSRF / Session Fixation) :** Le cookie `oauth_state` regroupant l'état CSRF, le vérificateur PKCE et le nonce OIDC n'est ni signé cryptographiquement (absence d'HMAC), ni chiffré, ni préfixé par `__Host-`, ni validé temporellement par le serveur (`exp` non vérifié côté serveur). Une injection de cookie (via sous-domaine compromis ou HTTP en clair) permet de forcer une authentification sur le compte de l'attaquant (Login CSRF / Session Fixation).
3. **Absence de données associées (AAD) dans le chiffrement KEK des secrets clients OAuth :** L'interface `KEK` chiffre les `client_secret` sans associer cryptographiquement le `tenant_id` ou le `provider_name`, autorisant la transposition et le vol de configurations entre locataires dans un modèle SaaS multi-tenant.
4. **SSRF et contournement DNS Rebinding dans `providers.OIDC` :** Le constructeur générique OIDC utilise par défaut un client HTTP standard non durci contre le rebouclage DNS lors de la découverte et de la récupération des clés, autorisant des requêtes arbitraires vers les métadonnées cloud (ex. `169.254.169.254`) et les réseaux internes RFC 1918.
5. **Déni de service et amplification sur le cache JWKS :** Le gestionnaire de clés `jwksCache` ne pratique aucune mise en cache négative, aucune limitation de débit (*rate limiting*) et aucune déduplication concurrente (*singleflight*) lors des échecs de résolution d'un `kid`. Des requêtes successives ou concurrentes avec des `kid` aléatoires saturent le serveur et provoquent le bannissement de l'application par les fournisseurs d'identité.

Au total, **10 vulnérabilités** ont été formellement identifiées :
- **Critique (Score CVSS 9.0 - 10.0) :** 1 vulnérabilité
- **Élevée (Score CVSS 7.0 - 8.9) :** 4 vulnérabilités (dont **4 vulnérabilités avec un score CVSS strictement supérieur à 7.5**)
- **Moyenne (Score CVSS 4.0 - 6.9) :** 5 vulnérabilités

---

## Vulnérabilités Identifiées

### SEC-OAU-01 : Collision d'identifiants OAuth/OIDC et usurpation de compte via perte de précision flottante (`float64`) dans `stringifyID`

* **Score CVSS v3.1 :** **9.8** (Critique)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **Fichiers et lignes concernés :**
  - [`oauth/providers/gitlab.go:70-79`](file:///go/github.com/JLugagne/libauth/oauth/providers/gitlab.go#L70-L79)
  - [`oauth/providers/gitlab.go:46-66`](file:///go/github.com/JLugagne/libauth/oauth/providers/gitlab.go#L46-L66)
  - [`oauth/providers/okta.go:66-87`](file:///go/github.com/JLugagne/libauth/oauth/providers/okta.go#L66-L87)
  - [`oauth/providers/internal_test.go:24-43`](file:///go/github.com/JLugagne/libauth/oauth/providers/internal_test.go#L24-L43)

#### Description détaillée du mécanisme
Dans `oauth/providers/gitlab.go` et `oauth/providers/okta.go` (dont l'implémentation `oidcUserInfoFetcher` est partagée par Okta, Auth0, Cognito, Keycloak et le constructeur générique OIDC), les données du profil utilisateur sont récupérées via la fonction `oauth.GetJSON` :
```go
var u struct {
    Sub           any    `json:"sub"`
    Email         string `json:"email"`
    EmailVerified bool   `json:"email_verified"`
    Name          string `json:"name"`
}
if err := oauth.GetJSON(ctx, c, userInfoURL, accessToken, &u); err != nil { ... }
providerID := stringifyID(u.Sub)
```
La fonction utilitaire `stringifyID` normalise ensuite le champ `Sub` :
```go
func stringifyID(v any) string {
    switch id := v.(type) {
    case string:
        return id
    case float64:
        return strconv.FormatInt(int64(id), 10)
    default:
        return ""
    }
}
```
En Go, lorsque `json.Unmarshal` désérialise un nombre JSON dans un champ de type `any` sans utiliser `json.Decoder.UseNumber()`, le moteur standard le convertit obligatoirement en `float64`. Or, selon le standard IEEE 754, un flottant 64 bits dispose de 53 bits de mantisse. La valeur entière maximale représentable sans ambiguïté est $2^{53} - 1 = 9\,007\,199\,254\,740\,991$.

Dès qu'un identifiant entier atteint ou dépasse $2^{53}$ (ce qui est le cas pour les identifiants générés sous format *snowflake*, les clés primaires entières 64 bits `BIGINT` dans les annuaires d'entreprise ou les instances auto-hébergées GitLab / Keycloak) :
- `9007199254740992` est représenté fidèlement.
- `9007199254740993` est automatiquement arrondi à `9007199254740992` lors du parsing JSON.
- Les deux identifiants distincts produisent exactement le même `providerID` sous forme de chaîne de caractères (`"9007199254740992"`).

#### Scénario d'exploitation théorique et impact
1. La victime s'enregistre via GitLab ou un fournisseur OIDC avec un compte d'identifiant numérique `9007199254740992`. `LinkOrCreateIdentity` associe l'identité `("gitlab", "9007199254740992")` à son compte utilisateur local.
2. L'attaquant dispose ou crée un compte sur le même fournisseur dont l'identifiant numérique est `9007199254740993`.
3. L'attaquant initie un flux de connexion OAuth vers l'application cible.
4. Lors du rappel (`CallbackHandler`), `oauth.GetJSON` décode `{"sub": 9007199254740993}` en `float64(9007199254740992)`.
5. `stringifyID` convertit ce flottant en `"9007199254740992"`.
6. Le service d'identité exécute l'étape 1 de `LinkOrCreateIdentity` ([`identity/service.go:957`](file:///go/github.com/JLugagne/libauth/identity/service.go#L957)) :
   ```go
   ident, err := s.store.FindIdentityByProvider(ctx, tenantID, provider, providerID)
   ```
   L'identité existante de la victime est trouvée. Le système délivre à l'attaquant une session authentifiée complète (`AccessToken` + `RefreshToken`) au nom de la victime.
7. L'attaquant prend le contrôle total du compte de la victime, sans aucune interaction de sa part.

#### Recommandation de correction
1. Dans `oauth.GetJSON`, configurer le décodeur JSON pour utiliser `UseNumber()` afin de préserver la représentation textuelle exacte des entiers :
   ```go
   dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
   dec.UseNumber()
   if err := dec.Decode(dst); err != nil { ... }
   ```
2. Mettre à jour `stringifyID` pour accepter le type `json.Number` :
   ```go
   func stringifyID(v any) string {
       switch id := v.(type) {
       case string:
           return id
       case json.Number:
           return id.String()
       case int64:
           return strconv.FormatInt(id, 10)
       default:
           return ""
       }
   }
   ```

---

### SEC-OAU-02 : Chiffrement d'enveloppe KEK sans données associées (AAD) pour `client_secret` (Transposition multi-tenant et substitution de secrets)

* **Score CVSS v3.1 :** **8.2** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`adapters/pgx/oauth/store.go:102-106`](file:///go/github.com/JLugagne/libauth/adapters/pgx/oauth/store.go#L102-L106)
  - [`adapters/pgx/oauth/store.go:175-185`](file:///go/github.com/JLugagne/libauth/adapters/pgx/oauth/store.go#L175-L185)
  - [`adapters/pgx/oauth/store.go:261-268`](file:///go/github.com/JLugagne/libauth/adapters/pgx/oauth/store.go#L261-L268)

#### Description détaillée du mécanisme
Dans `adapters/pgx/oauth/store.go`, le chiffrement au repos des secrets clients OIDC repose sur l'interface :
```go
type KEK interface {
    Seal(ctx context.Context, plaintext []byte) ([]byte, error)
    Open(ctx context.Context, ciphertext []byte) ([]byte, error)
}
```
Lors des opérations `UpsertProvider` et `GetProvider`, les appels `Seal` et `Open` sont effectués sans aucune donnée associée authentifiée (*Additional Authenticated Data* - AAD) :
```go
// UpsertProvider:
enc, err := s.kek.Seal(ctx, []byte(config.ClientSecret))
// GetProvider:
dec, decErr := s.kek.Open(ctx, sealed)
```
Le cryptogramme résultant stocké dans la colonne `client_secret` de la table `oauth_oidc_providers` n'est cryptographiquement lié ni au `tenant_id`, ni au `provider_name`, ni à l'URL de l'émetteur OIDC.

#### Scénario d'exploitation théorique et impact
1. Dans un déploiement mutualisé (multi-tenant BYO-SSO), l'attaquant contrôle le Tenant B. Il configure son propre fournisseur OIDC et enregistre un secret client connu.
2. L'attaquant exploite une vulnérabilité d'écriture SQL, une sauvegarde non cloisonnée ou un accès restreint à la base de données pour copier la valeur chiffrée `client_secret` du Tenant A (victime) vers sa propre ligne dans le Tenant B.
3. Alternativement, l'attaquant injecte le `client_secret` chiffré du Tenant B dans la configuration du Tenant A pour un IdP qu'il contrôle.
4. Lors de l'appel à `GetProvider`, la clé KEK globale déchiffre le ciphertext sans vérifier l'intégrité contextuelle du tenant propriétaire.
5. L'attaquant peut provoquer l'exfiltration du secret ou détourner les échanges de jetons OAuth entre différents tenants.

#### Recommandation de correction
Faire évoluer l'interface `KEK` du paquet `adapters/pgx/oauth` pour intégrer un paramètre AAD obligatoire :
```go
type KEK interface {
    Seal(ctx context.Context, plaintext, aad []byte) ([]byte, error)
    Open(ctx context.Context, ciphertext, aad []byte) ([]byte, error)
}
```
Lier systématiquement le contexte lors du chiffrement et du déchiffrement :
```go
aad := []byte(tenantID + ":" + providerName)
```

---

### SEC-OAU-03 : Cookie d'état OAuth (`oauth_state`) non signé et non lié à la session (Injection de cookie, Login CSRF et fixation de session)

* **Score CVSS v3.1 :** **8.1** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`oauth/state.go:50-86`](file:///go/github.com/JLugagne/libauth/oauth/state.go#L50-L86)
  - [`oauth/handlers.go:169`](file:///go/github.com/JLugagne/libauth/oauth/handlers.go#L169)
  - [`oauth/handlers.go:181-213`](file:///go/github.com/JLugagne/libauth/oauth/handlers.go#L181-L213)
  - [`oauth/handlers.go:269-280`](file:///go/github.com/JLugagne/libauth/oauth/handlers.go#L269-L280)

#### Description détaillée du mécanisme
Le sous-système OAuth encode les paramètres de sécurité temporaires dans un cookie HTTP nommé `oauth_state` :
```go
func packState(state, verifier, nonce, provider, tenant string) string {
    return state + stateSeparator + verifier + stateSeparator + nonce +
        stateSeparator + base64.RawURLEncoding.EncodeToString([]byte(provider)) +
        stateSeparator + base64.RawURLEncoding.EncodeToString([]byte(tenant))
}
```
Ce cookie présente plusieurs défaillances de sécurité majeures :
1. **Absence de signature cryptographique (HMAC) :** Le contenu du cookie est intégralement en clair. Aucune signature d'intégrité n'est calculée par le serveur. N'importe quel client ou attaquant en mesure d'écrire un cookie HTTP peut en forger un parfaitement valide.
2. **Absence de préfixe de sécurité (`__Host-`) :** Le cookie utilise par défaut le nom `oauth_state` sans préfixe `__Host-`. Il est donc vulnérable aux attaques de *cookie tossing* depuis des sous-domaines frères (ex. `vulnerable.example.com` écrivant un cookie sur `.example.com` ou `app.example.com`).
3. **Absence de vérification de l'expiration côté serveur :** La structure `packState` n'inclut aucun horodatage de création (`iat`) ou d'expiration (`exp`). Le serveur délègue l'expiration uniquement au paramètre `MaxAge` du cookie HTTP géré par le navigateur.
4. **Absence de liaison avec la session de l'utilisateur :** Le flux ne lie pas le cookie d'état à un identifiant de session ou à un jeton CSRF existant.

#### Scénario d'exploitation théorique et impact
1. L'attaquant initialise un flux OAuth légitime depuis son propre navigateur ou script et obtient un triplet valide : `state_att`, `verifier_att`, `nonce_att` ainsi qu'un code d'autorisation `code_att` auprès du fournisseur d'identité.
2. L'attaquant injecte dans le navigateur de la victime le cookie d'état forgé :
   `Set-Cookie: oauth_state=state_att.verifier_att.nonce_att.b64(provider).b64(tenant); Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax`
   (Cette injection peut être réalisée via une faille XSS sur un sous-domaine connexe, un réseau non sécurisé avant HSTS, ou une injection d'en-tête CRLF).
3. L'attaquant force la victime à exécuter la requête de rappel :
   `GET /oauth/callback?state=state_att&code=code_att`
4. Le serveur lit le cookie injecté, vérifie que `q.Get("state") == cookieState`, valide le provider et le tenant, puis échange le code `code_att` en fournissant le `verifier_att` extrait du cookie injecté.
5. Le serveur émet une paire de jetons d'accès et de rafraîchissement correspondant au compte de l'attaquant et les dépose dans le navigateur de la victime.
6. La victime est connectée sur le compte de l'attaquant sans s'en rendre compte. Toute action sensible, saisie d'informations bancaires ou téléversement de documents confidentiels est rattachée au compte contrôlé par l'attaquant (Login CSRF / Session Fixation).

#### Recommandation de correction
1. Signer systématiquement le cookie d'état avec un HMAC SHA-256 à l'aide d'une clé secrète serveur, ou utiliser un chiffrement authentifié (AEAD).
2. Adopter le préfixe de cookie durci `__Host-oauth_state` (`Path=/`, `Secure=true`, sans attribut `Domain`) pour neutraliser définitivement le *cookie tossing* inter-sous-domaines.
3. Intégrer un horodatage d'expiration Unix (`ExpiresAt`) dans la charge utile du cookie et vérifier formellement lors de `unpackState` que `time.Now().Unix() < expiresAt`.
4. Si l'utilisateur possède déjà une session authentifiée, lier cryptographiquement son identifiant de session (`session_id`) ou `user_id` dans la signature de l'état.

---

### SEC-OAU-04 : Server-Side Request Forgery (SSRF) et contournement DNS Rebinding par l'utilisation d'un client HTTP non sécurisé par défaut dans `providers.OIDC`

* **Score CVSS v3.1 :** **7.7** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
* **Fichiers et lignes concernés :**
  - [`oauth/providers/oidc.go:78-88`](file:///go/github.com/JLugagne/libauth/oauth/providers/oidc.go#L78-L88)
  - [`oauth/providers/oidc.go:116-130`](file:///go/github.com/JLugagne/libauth/oauth/providers/oidc.go#L116-L130)
  - [`oauth/oidc.go:146-152`](file:///go/github.com/JLugagne/libauth/oauth/oidc.go#L146-L152)
  - [`oauth/provider.go:114`](file:///go/github.com/JLugagne/libauth/oauth/provider.go#L114)
  - [`oauth/ssrf.go:47-69`](file:///go/github.com/JLugagne/libauth/oauth/ssrf.go#L47-L69)

#### Description détaillée du mécanisme
Le constructeur générique `providers.OIDC` permet de configurer un fournisseur OpenID Connect dynamique à partir de l'URL de son émetteur (`issuer`).
Pour initialiser le fournisseur, il appelle la fonction `fetchOIDCDiscovery` :
```go
func OIDC(ctx context.Context, issuer, clientID, clientSecret string, providerOpts []oauth.ProviderOption, opts ...OIDCOption) *oauth.Provider {
    settings := oidcSettings{
        httpClient: &http.Client{Timeout: 10 * time.Second},
        scopes:     []string{"openid", "email", "profile"},
        name:       "oidc",
    }
    for _, o := range opts { o(&settings) }

    meta, err := fetchOIDCDiscovery(ctx, settings.httpClient, issuer, settings.allowInsecureURLs)
    ...
```
Dans `fetchOIDCDiscovery` :
```go
if err := oauth.ValidateOIDCEndpointURL(issuer, allowInsecure); err != nil { ... }
configURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
resp, err := c.Do(req)
```
La fonction `ValidateOIDCEndpointURL` (qui délègue à `ValidateExternalURL`) effectue une vérification syntaxique préalable : elle impose le schéma `https://` et vérifie si le nom d'hôte est une adresse IP littérale privée (`net.ParseIP(host)`).

Cependant :
1. Si l'attaquant fournit un nom de domaine valide (ex. `rebind.attacker.com`), `ValidateExternalURL` autorise l'URL car le nom d'hôte n'est pas une IP littérale.
2. Le client HTTP utilisé par défaut dans `providers.OIDC` est un `&http.Client{Timeout: 10 * time.Second}` ordinaire, dépourvu du hook de contrôle au niveau du dialer réseau (`safeDialControl`).
3. Lors de la résolution DNS dynamique effectuée par le système d'exploitation au moment du `c.Do(req)`, le domaine `rebind.attacker.com` se résout vers une IP interne sensible (ex. `169.254.169.254` pour AWS/GCP Metadata, ou `127.0.0.1` / `10.0.0.1`).
4. Le serveur envoie une requête GET vers l'adresse interne ciblée.

Le même problème affecte `oauth.WithOIDC` lorsque `OIDCConfig.HTTPClient` n'est pas renseigné : il bascule sur un client HTTP standard sans protection dial-time contre le rebouclage DNS.

#### Scénario d'exploitation théorique et impact
1. Dans une architecture SaaS permettant aux administrateurs de locataires de configurer leur propre fournisseur SSO OpenID Connect (BYO-SSO), un attaquant enregistre un domaine DNS configuré avec un TTL court (0 seconde) :
   - Requête 1 (pour passer d'éventuels tests) : renvoie une IP publique.
   - Requête 2 (au moment de l'appel système `c.Do`) : renvoie `169.254.169.254` (point d'accès aux métadonnées d'instance cloud).
2. L'application émet une requête HTTP GET vers le service de métadonnées de l'infrastructure cloud.
3. Bien que le document soit rejeté ensuite s'il n'est pas au format JSON attendu, des requêtes GET non authentifiées peuvent déclencher des effets de bord sur des API internes ou exposer des réponses lors de l'analyse des erreurs.

#### Recommandation de correction
1. Dans `providers.OIDC` et `newOIDCVerifier`, configurer `oauth.SafeHTTPClient()` comme client par défaut absolu (sauf en environnement de test avec `allowInsecureURLs`) :
   ```go
   settings := oidcSettings{
       httpClient: oauth.SafeHTTPClient(),
       scopes:     []string{"openid", "email", "profile"},
       name:       "oidc",
   }
   ```
2. Interdire l'utilisation d'un client HTTP standard non pourvu de `safeDialControl` sur tous les chemins traitant des entrées potentiellement non fiables.

---

### SEC-OAU-05 : Déni de service (DoS) et amplification par absence de limitation de débit et de mise en cache négative sur les clés JWKS inconnues (`jwksCache.publicKey`)

* **Score CVSS v3.1 :** **7.5** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`oauth/oidc.go:292-302`](file:///go/github.com/JLugagne/libauth/oauth/oidc.go#L292-L302)
  - [`oauth/oidc.go:304-315`](file:///go/github.com/JLugagne/libauth/oauth/oidc.go#L304-L315)
  - [`oauth/oidc.go:317-348`](file:///go/github.com/JLugagne/libauth/oauth/oidc.go#L317-L348)

#### Description détaillée du mécanisme
Dans `oauth/oidc.go`, la résolution d'une clé publique de vérification d'un jeton `id_token` s'effectue via `jwksCache.publicKey` :
```go
func (c *jwksCache) publicKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
    if k, ok := c.cached(kid); ok {
        return k, nil
    }
    if err := c.refresh(ctx); err != nil {
        return nil, err
    }
    c.mu.RLock()
    defer c.mu.RUnlock()
    return lookupKey(c.keys, kid)
}
```
L'analyse de cette implémentation révèle une faille de déni de service algorithmique :
1. Lorsqu'un `kid` inconnu est soumis, `c.cached(kid)` renvoie `false`.
2. Le cache déclenche immédiatement `c.refresh(ctx)`, qui effectue une requête HTTP GET synchrone vers le point d'accès JWKS distant du fournisseur d'identité.
3. Si le `kid` n'existe toujours pas dans le document téléchargé, `c.keys` ne le contient pas.
4. **Absence de cache négatif :** Aucun enregistrement n'est conservé pour mémoriser que le `kid` est inexistant.
5. **Absence de temporisation / Cooldown :** Aucun délai minimal n'est imposé entre deux rafraîchissements réseau.
6. **Absence de fusion des requêtes (*Singleflight*) :** Si 100 requêtes concurrentes arrivent avec un `kid` invalide ou différent, 100 requêtes HTTP GET distinctes sont émises en parallèle vers l'IdP.

#### Scénario d'exploitation théorique et impact
1. Un attaquant génère des flux d'authentification ou des rappels avec un faux `id_token` dont l'en-tête déclare un `kid` aléatoire différent à chaque requête (`kid: "attack-1"`, `kid: "attack-2"`, etc.).
2. Chaque requête entrante force le serveur `libauth` à émettre immédiatement une requête HTTP GET sortante vers le serveur JWKS distant.
3. Cela entraîne :
   - L'épuisement des descripteurs de fichiers, du pool de connexions HTTP sortantes et des threads applicatifs du serveur `libauth`.
   - Le bannissement par limitation de débit (*rate-limiting* / 429 Too Many Requests) de l'adresse IP de l'application par les fournisseurs majeurs (Google, Microsoft, Okta, etc.), empêchant ainsi tous les utilisateurs légitimes de se connecter (Déni de service global).
   - L'utilisation du serveur `libauth` comme amplificateur et réflecteur d'attaques HTTP contre les serveurs JWKS tiers.

#### Recommandation de correction
1. Utiliser le pattern `golang.org/x/sync/singleflight` pour fusionner les requêtes de rafraîchissement concurrentes sur un même cache JWKS.
2. Instaurer un délai minimal de temporisation (cooldown, ex. 30 secondes à 1 minute) entre deux actualisations réseau de `jwksCache`.
3. Implémenter une mise en cache négative temporaire pour les identifiants `kid` absents afin de bloquer immédiatement les requêtes répétitives sans sollicitation réseau.

---

### SEC-OAU-06 : Dérivation non sécurisée de `redirect_uri` via les en-têtes non fiables `Host` et `X-Forwarded-Proto` sans liaison cryptographique dans le state

* **Score CVSS v3.1 :** **6.9** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`oauth/handlers.go:306-321`](file:///go/github.com/JLugagne/libauth/oauth/handlers.go#L306-L321)
  - [`oauth/handlers.go:170`](file:///go/github.com/JLugagne/libauth/oauth/handlers.go#L170)
  - [`oauth/handlers.go:224`](file:///go/github.com/JLugagne/libauth/oauth/handlers.go#L224)

#### Description détaillée du mécanisme
Lorsque l'option `WithRedirectURL` n'est pas explicitement définie à la construction du gestionnaire (comportement par défaut), l'URI de redirection est calculée dynamiquement à partir de la requête HTTP entrante :
```go
func (cfg handlerConfig) resolveRedirectURL(r *http.Request) string {
    if cfg.redirectURL != "" {
        return cfg.redirectURL
    }
    return requestScheme(r) + "://" + r.Host + r.URL.Path
}

func requestScheme(r *http.Request) string {
    if r.TLS != nil {
        return "https"
    }
    if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
        return proto
    }
    return "http"
}
```
Ce mécanisme pose deux problèmes de sécurité :
1. **Empoisonnement d'en-tête `Host` et `X-Forwarded-Proto` :** La valeur `r.Host` provient directement de l'en-tête HTTP `Host` envoyé par le client. De même, l'en-tête `X-Forwarded-Proto` est lu aveuglément sans vérifier si la requête provient d'un reverse-proxy de confiance configuré.
2. **Absence de liaison de `redirect_uri` dans l'état :** `packState` n'inclut pas le `redirect_uri` utilisé lors de `BeginHandler`. Dans `CallbackHandler`, `resolveRedirectURL` est réévalué indépendamment. Si les en-têtes ou le chemin diffèrent, la valeur transmise lors du `p.Exchange` ne correspond plus à celle de l'autorisation initiale.
3. **Incohérence du chemin de repli dans `BeginHandler` :** Si `WithRedirectURL` n'est pas fourni, `BeginHandler` transmet son propre chemin (`/oauth/begin`) comme `redirect_uri` au lieu de celui du callback, provoquant un rejet par l'IdP ou une boucle infinie de redirection.

#### Scénario d'exploitation théorique et impact
1. Une application est déployée derrière un répartiteur de charge qui ne filtre pas rigoureusement l'en-tête `Host` ou `X-Forwarded-Host`.
2. L'attaquant envoie une requête `GET /oauth/login` avec un en-tête `Host: attacker-domain.com`.
3. Si le fournisseur d'identité OAuth tolère les correspondances partielles ou de sous-domaines (ou si le domaine appartient à la même organisation), le navigateur de la victime est redirigé vers l'IdP avec `redirect_uri=https://attacker-domain.com/oauth/login`.
4. À l'issue de l'authentification de la victime, le code d'autorisation OAuth est envoyé directement sur le serveur de l'attaquant, permettant la compromission du compte.

#### Recommandation de correction
1. Rendre obligatoire la configuration explicite de `WithRedirectURL` en environnement de production, ou valider `r.Host` contre une liste stricte de noms de domaines autorisés (*allowlist*).
2. Ne faire confiance à l'en-tête `X-Forwarded-Proto` que lorsque l'adresse IP distante (`RemoteAddr`) correspond à un reverse-proxy explicitement approuvé.
3. Stocker le `redirect_uri` calculé au démarrage dans le cookie d'état signé, et réutiliser cette valeur immuable lors du rappel dans `CallbackHandler`.

---

### SEC-OAU-07 : Suivi automatique non sécurisé des redirections HTTP (307/308) lors de l'échange de jetons avec transmission du `client_secret`

* **Score CVSS v3.1 :** **5.3** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`
* **Fichiers et lignes concernés :**
  - [`oauth/provider.go:232-243`](file:///go/github.com/JLugagne/libauth/oauth/provider.go#L232-L243)
  - [`oauth/ssrf.go:87-108`](file:///go/github.com/JLugagne/libauth/oauth/ssrf.go#L87-L108)

#### Description détaillée du mécanisme
Dans `oauth.Provider.Exchange`, la requête POST transmettant le secret client s'exécute via le client HTTP configuré :
```go
form := url.Values{}
form.Set("grant_type", "authorization_code")
form.Set("code", code)
form.Set("redirect_uri", redirectURI)
form.Set("client_id", p.clientID)
form.Set("client_secret", p.clientSecret)
...
req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
...
resp, err := p.httpClient.Do(req)
```
Dans `SafeHTTPClient()` ainsi que dans le client par défaut de `oauth.New`, aucun gestionnaire `CheckRedirect` n'est défini. En Go standard, `http.Client` suit automatiquement jusqu'à 10 redirections HTTP consécutives.
Conformément aux spécifications HTTP (RFC 7231 et RFC 7538), lorsqu'un serveur renvoie un code de redirection `307 Temporary Redirect` ou `308 Permanent Redirect`, le client HTTP réémet la requête en conservant la méthode `POST` et le corps de la requête intact (contenant `client_secret`, `code` et `code_verifier`).

#### Scénario d'exploitation théorique et impact
1. Dans un contexte multi-tenant dynamique, un administrateur malveillant de tenant enregistre une configuration OIDC avec une URL de jeton pointant vers son propre serveur HTTPS : `token_url = https://idp.attacker.com/token`.
2. Lors de la phase de connexion, le serveur `libauth` émet la requête POST d'échange de jeton avec le secret client configuré.
3. Le serveur de l'attaquant répond par un code `307 Temporary Redirect` vers un serveur tiers de capture.
4. Le client HTTP de `libauth` retransmet automatiquement l'intégralité du corps POST, provoquant la fuite des identifiants confidentiels.

#### Recommandation de correction
Désactiver formellement le suivi des redirections HTTP sur le client HTTP dédié à l'échange de jetons dans `oauth.Provider` :
```go
p.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
    return http.ErrUseLastResponse
}
```

---

### SEC-OAU-08 : Absence de validation du paramètre de réponse `iss` (RFC 9207) facilitant les attaques par confusion de fournisseur d'identité (Mix-Up Attack)

* **Score CVSS v3.1 :** **5.3** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N`
* **Fichiers et lignes concernés :**
  - [`oauth/handlers.go:193-219`](file:///go/github.com/JLugagne/libauth/oauth/handlers.go#L193-L219)

#### Description détaillée du mécanisme
La RFC 9207 (*OAuth 2.0 Authorization Server Issuer Identification*) stipule que les serveurs d'autorisation conformes retournent un paramètre `iss` dans la chaîne de requête de la redirection d'autorisation afin de neutraliser définitivement les attaques par confusion de fournisseur d'identité (*IdP Mix-Up attacks*).
Selon la RFC 9207 Section 2.2 :
> "If the authorization response contains an `iss` response parameter, the client MUST validate that its value equals the issuer identifier of the authorization server that sent the response."

Dans `oauth/handlers.go` (`CallbackHandler`), les paramètres de requête sont analysés comme suit :
```go
q := r.URL.Query()
if q.Get("error") != "" { ... }
if !stateMatches(q.Get("state"), cookieState) { ... }
if !stateMatches(cookieProvider, p.Name()) { ... }
if !stateMatches(cookieTenant, cfg.tenant(r)) { ... }
code := q.Get("code")
```
Le gestionnaire ignore complètement le paramètre `iss`. Bien que `cookieProvider` soit comparé à `p.Name()`, le fait que le cookie d'état ne soit pas signé (voir SEC-OAU-03) combiné à l'absence de vérification de `q.Get("iss")` expose les architectures multi-fournisseurs à des substitutions de codes d'autorisation entre IdP légitimes et malveillants.

#### Scénario d'exploitation théorique et impact
Un attaquant parvenant à intercepter ou injecter une réponse d'autorisation peut faire consommer un code délivré par un IdP A à l'endpoint de rappel d'un IdP B, provoquant la divulgation de codes d'autorisation ou des erreurs d'attribution de profil.

#### Recommandation de correction
Dans `CallbackHandler`, si le fournisseur est OIDC ou possède un émetteur connu (`p.oidc != nil`), vérifier systématiquement la présence et la conformité du paramètre `iss` :
```go
if iss := q.Get("iss"); iss != "" && p.oidc != nil {
    if subtle.ConstantTimeCompare([]byte(iss), []byte(p.oidc.issuer)) != 1 {
        cfg.fail(w, r, http.StatusForbidden, "issuer_mismatch")
        return
    }
}
```

---

### SEC-OAU-09 : Défaut de filtrage programmatique des algorithmes symétriques (`none`, HMAC) dans `OIDCConfig.AllowedAlgs`

* **Score CVSS v3.1 :** **4.8** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`oauth/oidc.go:75-76`](file:///go/github.com/JLugagne/libauth/oauth/oidc.go#L75-L76)
  - [`oauth/oidc.go:134-137`](file:///go/github.com/JLugagne/libauth/oauth/oidc.go#L134-L137)

#### Description détaillée du mécanisme
La documentation de `OIDCConfig` indique formellement :
```go
// AllowedAlgs restricts the accepted id_token signing algorithms. Defaults to RS256/384/512
// and ES256/384/512. "none" and HMAC algorithms are always rejected regardless of this list.
```
Cependant, dans la fonction `newOIDCVerifier` :
```go
algs := cfg.AllowedAlgs
if len(algs) == 0 {
    algs = defaultAllowedAlgs
}
```
Aucun filtre programmatique ne purge ni ne rejette `"none"` ou les algorithmes de la famille HMAC (`HS256`, `HS384`, `HS512`) si un développeur ou une configuration dynamique fournit une tranche contenant ces valeurs. Bien que `golang-jwt/jwt/v5` refuse d'utiliser une clé publique RSA/ECDSA pour vérifier une signature HMAC (évitant ainsi l'attaque de confusion classique grâce aux vérifications de type du paquet externe), le constructeur viole sa propre promesse documentaire de sécurité en acceptant ces algorithmes sans validation.

#### Scénario d'exploitation théorique et impact
Si une configuration personnalisée ou dynamique active par inadvertance `"none"` ou un algorithme non asymétrique, le composant ne garantit pas en amont l'interdiction de ces méthodes, affaiblissant la politique de défense en profondeur.

#### Recommandation de correction
Valider explicitement `cfg.AllowedAlgs` dans `newOIDCVerifier` et rejeter toute configuration contenant `"none"` ou un algorithme commençant par `"HS"` :
```go
for _, alg := range algs {
    upper := strings.ToUpper(strings.TrimSpace(alg))
    if upper == "NONE" || strings.HasPrefix(upper, "HS") {
        return nil, fmt.Errorf("oauth: algorithm %q is not allowed for OIDC id_tokens", alg)
    }
}
```

---

### SEC-OAU-10 : Mise en cache en mémoire non bornée `providerCache` dans l'adaptateur `pgx/oauth` (Fuite mémoire et déni de service)

* **Score CVSS v3.1 :** **4.3** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L`
* **Fichiers et lignes concernés :**
  - [`adapters/pgx/oauth/store.go:66`](file:///go/github.com/JLugagne/libauth/adapters/pgx/oauth/store.go#L66)
  - [`adapters/pgx/oauth/store.go:223-231`](file:///go/github.com/JLugagne/libauth/adapters/pgx/oauth/store.go#L223-L231)

#### Description détaillée du mécanisme
Dans `adapters/pgx/oauth/store.go`, les instances `*oauth.Provider` construites dynamiquement sont stockées dans une table de hachage interne :
```go
type Store struct {
    ...
    providerCache map[string]*cachedProvider
}
```
Cette table `providerCache` est initialisée via `make(map[string]*cachedProvider)` et ne dispose d'aucune politique d'éviction (LRU/LFU), d'aucune limite de capacité maximale (*capacity cap*) et d'aucun délai d'expiration (TTL).
Chaque couple `(tenant_id, provider_name)` enregistré et consulté insère une entrée qui demeure indéfiniment en mémoire vive avec l'ensemble des structures sous-jacentes (clés JWKS, métadonnées de découverte, client HTTP).

#### Scénario d'exploitation théorique et impact
Dans un déploiement SaaS mutualisé ouvert où de multiples locataires créent et suppriment régulièrement des configurations SSO, la mémoire consommée par le processus croît de manière monotone jusqu'à saturation de la RAM de l'hôte et déclenchement du mécanisme OOM Killer du système d'exploitation.

#### Recommandation de correction
Remplacer la table brute par un cache LRU borné en capacité (ex. 1 000 entrées maximum) avec expiration temporelle des entrées inactives.

---

## Tableau Récapitulatif des Vulnérabilités

| Identifiant | Titre | Sévérité | Score CVSS v3.1 | Vecteur CVSS v3.1 |
| :--- | :--- | :---: | :---: | :--- |
| **SEC-OAU-01** | Collision d'identifiants et usurpation de compte via perte de précision flottante (`float64`) dans `stringifyID` | **Critique** | **9.8** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **SEC-OAU-02** | Chiffrement KEK sans données associées (AAD) pour `client_secret` (Transposition multi-tenant) | **Élevée** | **8.2** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **SEC-OAU-03** | Cookie d'état OAuth non signé et non lié à la session (Injection de cookie et Login CSRF) | **Élevée** | **8.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` |
| **SEC-OAU-04** | SSRF et contournement DNS Rebinding par client HTTP non sécurisé par défaut dans `providers.OIDC` | **Élevée** | **7.7** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **SEC-OAU-05** | DoS et amplification par absence de limitation de débit et de cache négatif sur `jwksCache` | **Élevée** | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-OAU-06** | Dérivation non sécurisée de `redirect_uri` via `Host`/`X-Forwarded-Proto` sans liaison dans le state | **Moyenne** | **6.9** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N` |
| **SEC-OAU-07** | Suivi automatique non sécurisé des redirections HTTP (307/308) avec fuite de `client_secret` | **Moyenne** | **5.3** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **SEC-OAU-08** | Absence de validation du paramètre `iss` (RFC 9207) facilitant les attaques Mix-Up | **Moyenne** | **5.3** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` |
| **SEC-OAU-09** | Défaut de filtrage des algorithmes symétriques (`none`, HMAC) dans `AllowedAlgs` | **Moyenne** | **4.8** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| **SEC-OAU-10** | Mise en cache en mémoire non bornée `providerCache` dans l'adaptateur `pgx/oauth` | **Moyenne** | **4.3** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` |

---

## Conclusion et Notification des Vulnérabilités Majeures (CVSS > 7.5)

> [!CAUTION]
> **ALERTE DE SÉCURITÉ MAJEURE :**
> L'audit confirme la présence de **4 vulnérabilités critiques et hautement sévères présentant un score CVSS v3.1 strictement supérieur à 7.5** :
> 1. **SEC-OAU-01 (Score CVSS : 9.8) :** Collision d'identifiants et usurpation directe de compte utilisateur par arrondi flottant `float64` dans `stringifyID`.
> 2. **SEC-OAU-02 (Score CVSS : 8.2) :** Substitution et transposition de secrets clients entre locataires via KEK sans AAD.
> 3. **SEC-OAU-03 (Score CVSS : 8.1) :** Absence totale de signature cryptographique sur le cookie d'état ouvrant la porte au Login CSRF et à la fixation de session.
> 4. **SEC-OAU-04 (Score CVSS : 7.7) :** Server-Side Request Forgery (SSRF) et rebouclage DNS vers les métadonnées internes dans `providers.OIDC`.
>
> *(Une cinquième vulnérabilité, **SEC-OAU-05**, atteint exactement le seuil critique de **7.5** pour un déni de service externe et interne sur les résolutions de clés JWKS).*
>
> La correction prioritaire et immédiate de **SEC-OAU-01**, **SEC-OAU-02**, **SEC-OAU-03** et **SEC-OAU-04** est indispensable avant tout déploiement en environnement de production.
