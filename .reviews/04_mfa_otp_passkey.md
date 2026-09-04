# Rapport d'Audit de Sécurité : Sous-système MFA, OTP et Passkey

**Cible :** `github.com/JLugagne/libauth`  
**Périmètre audité :**
- `mfa/` (service, handlers, TOTP enrollment/validation, backup recovery codes)
- `otp/` (service, handlers, codes courts email/sms)
- `passkey/` (webauthn service, handlers, ceremony, challenges, attestation)
- `adapters/pgx/mfa`, `adapters/pgx/otp`, `adapters/pgx/passkey`
- Points de contact et passerelles d'authentification (`identity/handlers.go`, `tokens/middleware.go`)

**Date :** 4 septembre 2026  
**Auditeur :** Antigravity Security Research  
**Statut :** Terminé

---

## Sommaire Exécutif

Un audit de sécurité impitoyable et approfondi a été mené sur les mécanismes d'authentification multi-facteurs (MFA/2FA TOTP), les codes à usage unique (OTP par email/SMS) et les identifiants FIDO2 / WebAuthn (Passkeys), ainsi que sur leurs adaptateurs PostgreSQL (`jackc/pgx`).

L'analyse a révélé de graves défaillances architecturales et cryptographiques :
1. **Contournement total du MFA (2FA Bypass) :** Le gestionnaire de changement forcé de mot de passe (`ChangePasswordWithReissueHandler`) réémet une paire de jetons complète et renouvelable sans jamais vérifier l'enrôlement ou la validation du second facteur. De plus, un jeton intermédiaire non élevé (`AMR=[pwd]`) peut appeler directement `DisableHandler` et purger les facteurs MFA d'un compte.
2. **Vulnérabilité KEK multi-tenant / multi-utilisateurs :** Les secrets TOTP sont chiffrés au repos sans données associées (AAD), permettant la transposition de secrets entre tenants ou comptes.
3. **Déni de service et absence d'implémentation persistante de `ChallengeStore` pour Passkey :** L'adaptateur PostgreSQL ne fournit aucune implémentation de `ChallengeStore`, rendant les déploiements multi-nœuds soit vulnérables aux rejeux d'assertions Passkey à compteur nul (`SignCount = 0`), soit dépendants d'un store mémoire sujet à un déni de service algorithmique $O(N)$ sous verrou global.
4. **Blocage abusif des codes de secours :** Le budget de tentatives partagé entre TOTP et codes de secours permet à un attaquant connaissant uniquement le premier facteur de verrouiller le mécanisme de secours légitime.
5. **Abus et saturation sur OTP :** Absence de temporisation (cooldown) et réinitialisation du budget d'attaques lors de la réémission, ouvrant la porte à des attaques par déni de service et *toll fraud*.

Au total, **15 vulnérabilités** ont été identifiées :
- **Critique / Élevée (Score CVSS > 7.0) :** 8 vulnérabilités (dont **4 vulnérabilités avec un score CVSS strictement supérieur à 7.5**)
- **Moyenne (Score 4.0 - 6.9) :** 5 vulnérabilités
- **Faible (Score < 4.0) :** 2 vulnérabilités

---

## Vulnérabilités Identifiées

### SEC-MFA-01 : Contournement complet du 2FA via `ChangePasswordWithReissueHandler`

* **Score CVSS v3.1 :** **8.1** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`identity/handlers.go:829-878`](file:///go/github.com/JLugagne/libauth/identity/handlers.go#L829-L878)
  - [`identity/handlers.go:340-359`](file:///go/github.com/JLugagne/libauth/identity/handlers.go#L340-L359)
  - [`identity/handlers.go:419-428`](file:///go/github.com/JLugagne/libauth/identity/handlers.go#L419-L428)

#### Description détaillée du mécanisme
Dans `identity.LoginHandler`, lorsqu'un utilisateur enrôlé au 2FA (`cfg.mfaGate.IsEnrolled` renvoie `true`) s'authentifie avec son mot de passe, l'application bloque l'émission de la session complète et émet un jeton d'accès temporaire intermédiaire (`AMR=[pwd]`, sans cookie de rafraîchissement) via `issueInterimAndSetCookie`.
Si le compte possède l'attribut `MustChangePassword=true` (ex. mot de passe temporaire défini par un administrateur), le jeton intermédiaire propage ce drapeau et l'utilisateur est intercepté par le middleware `WithPasswordChangeGate`, qui le redirige vers le point d'entrée de changement de mot de passe géré par `ChangePasswordWithReissueHandler`.

Cependant, dans `ChangePasswordWithReissueHandler` (lignes 869-877) :
```go
if err := svc.ChangePassword(r.Context(), cfg.tenant(r), user.ID, current, newPassword); err != nil { ... }

if err := issuePairAndSetCookies(w, r, cfg, issuer, claimsOf, user, false, false); err != nil {
    cfg.fail(w, r, http.StatusInternalServerError, "token_issuance_failed")
    return
}
```
`ChangePasswordWithReissueHandler` n'intègre **aucun contrôle sur `cfg.mfaGate`**. Il invoque aveuglément `issuePairAndSetCookies`, qui génère et dépose dans les cookies du navigateur une paire de jetons **complète, définitive et renouvelable** (`AccessToken` + `RefreshToken`).

#### Scénario d'exploitation théorique et impact
1. Un attaquant intercepte ou achète un mot de passe temporaire (ou compromis) d'un utilisateur cible soumis à une obligation de changement de mot de passe et disposant d'un second facteur TOTP actif.
2. L'attaquant soumet le mot de passe sur `/login`. `LoginHandler` lui délivre un jeton intermédiaire restreint `AMR=[pwd]`.
3. L'attaquant se rend sur `/change-password` et soumet le mot de passe actuel ainsi qu'un nouveau mot de passe.
4. `ChangePasswordWithReissueHandler` valide le changement et lui délivre instantanément une session complète avec jeton de rafraîchissement persistant.
5. L'attaquant accède à l'ensemble du compte sans jamais avoir eu à renseigner le code TOTP du second facteur. Le facteur MFA a été totalement contourné.

#### Recommandation de correction
Dans `ChangePasswordWithReissueHandler`, vérifier systématiquement si l'utilisateur possède un facteur MFA actif (`cfg.mfaGate.IsEnrolled`). Si c'est le cas, réémettre uniquement un jeton intermédiaire avec `MustChangePassword=false` et forcer l'utilisateur à franchir `mfa.StepUpHandler` avant de lui octroyer la paire de jetons complète.

---

### SEC-MFA-02 : Révocation non autorisée du 2FA et destruction des facteurs via un jeton intermédiaire (`DisableHandler`)

* **Score CVSS v3.1 :** **8.8** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
* **Fichiers et lignes concernés :**
  - [`mfa/handlers.go:206-215`](file:///go/github.com/JLugagne/libauth/mfa/handlers.go#L206-L215)
  - [`mfa/handlers.go:193-203`](file:///go/github.com/JLugagne/libauth/mfa/handlers.go#L193-L203)
  - [`mfa/handlers.go:220-245`](file:///go/github.com/JLugagne/libauth/mfa/handlers.go#L220-L245)
  - [`mfa/service.go:38-42`](file:///go/github.com/JLugagne/libauth/mfa/service.go#L38-L42)

#### Description détaillée du mécanisme
Le point d'entrée `DisableHandler` supprime sans condition l'enrôlement TOTP et l'ensemble des codes de secours d'un utilisateur via `svc.DisableTOTP(ctx, tenant, uid)`.
Pour s'exécuter, le préambule `guarded` requiert uniquement que `cfg.resolve(r)` retourne un `userID` valide.
La documentation de `mfa.Service.DisableTOTP` préconise :
```go
// callers SHOULD gate its route behind step-up re-authentication by
// wrapping DisableHandler with tokens.RequireAuth(..., tokens.WithMaxAuthAge(d))
```
Or, un jeton intermédiaire délivré par `LoginHandler` pour un utilisateur soumis au MFA possède :
- Un `UserID` et un `TenantID` valides ;
- Un horodatage `AuthTime` tout juste créé (`time.Now().Unix()`), satisfaisant n'importe quelle contrainte `tokens.WithMaxAuthAge(d)`.

`DisableHandler` n'exige ni le code TOTP actuel, ni le mot de passe de l'utilisateur, ni l'assurance `AMRMFA`. Par conséquent, un jeton d'authentification intermédiaire (obtenu au stade 1 du login) est pleinement qualifié pour désactiver le MFA du compte. Le même problème affecte `RegenerateRecoveryCodesHandler`, qui permet à un jeton intermédiaire de générer et d'afficher un nouveau jeu de codes de secours.

#### Scénario d'exploitation théorique et impact
1. L'attaquant dispose du mot de passe de la victime (obtenu via credential stuffing ou hameçonnage).
2. L'attaquant POSTe le mot de passe sur `/login`. Le serveur répond avec le cookie d'accès intermédiaire (valide 5 minutes, `AMR=[pwd]`).
3. Au lieu de se présenter sur `/mfa/step-up`, l'attaquant envoie immédiatement une requête POST vers `/mfa/disable` avec le cookie reçu.
4. `DisableHandler` s'exécute avec succès, supprimant la clé secrète TOTP et tous les codes de récupération de la victime.
5. L'attaquant renvoie une requête sur `/login` avec le mot de passe. `LoginHandler` constate que `enrolled == false`, et accorde immédiatement une session complète avec refresh token.
6. L'attaquant a neutralisé le second facteur et pris le contrôle exclusif du compte.

#### Recommandation de correction
1. Exiger dans `DisableHandler` la fourniture et la validation d'un code TOTP valide ou d'un code de secours, ou le mot de passe actuel de l'utilisateur.
2. Vérifier impérativement au niveau du middleware ou du handler que le jeton porteur dispose du facteur `tokens.AMRMFA`. Interdire l'accès à ce point d'entrée pour tout jeton avec `AMR` restreint à `[pwd]`.

---

### SEC-MFA-03 : Absence de données associées (AAD) dans le chiffrement d'enveloppe KEK des secrets TOTP (Transposition de facteurs)

* **Score CVSS v3.1 :** **8.3** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`adapters/pgx/mfa/store.go:39-43`](file:///go/github.com/JLugagne/libauth/adapters/pgx/mfa/store.go#L39-L43)
  - [`adapters/pgx/mfa/store.go:84-88`](file:///go/github.com/JLugagne/libauth/adapters/pgx/mfa/store.go#L84-L88)
  - [`adapters/pgx/mfa/store.go:117-121`](file:///go/github.com/JLugagne/libauth/adapters/pgx/mfa/store.go#L117-L121)

#### Description détaillée du mécanisme
Dans `adapters/pgx/mfa/store.go`, le chiffrement d'enveloppe au repos des secrets partagés TOTP repose sur l'interface :
```go
type KEK interface {
    Seal(plaintext []byte) ([]byte, error)
    Open(sealed []byte) ([]byte, error)
}
```
Lors de `SaveTOTP` et `GetTOTP`, `Seal` et `Open` sont appelés sans aucune donnée associée authentifiée (*Additional Authenticated Data* - AAD). Le texte chiffré stocké dans la colonne `mfa_totp.secret` n'est lié cryptographiquement ni au `tenant_id`, ni au `user_id`.

#### Scénario d'exploitation théorique et impact
Dans un déploiement multi-tenant ou multi-utilisateurs :
1. Un attaquant dispose d'un compte sur le Tenant B (ou d'un compte compromis sur le Tenant A). Il active le MFA et configure son propre smartphone.
2. Grâce à un accès en écriture indirect (injection SQL dans une application adjacente, compte base de données à privilèges limités ou compromission d'une sauvegarde), l'attaquant copie la chaîne chiffrée `secret` de son compte vers la ligne de la victime dans la table `mfa_totp`.
3. Lorsque la victime se connecte, ou lorsque l'attaquant tente de se connecter sous l'identité de la victime avec son mot de passe volé, le serveur déchiffre le ciphertext avec la clé KEK globale.
4. L'algorithme AEAD (AES-GCM) valide le déchiffrement sans erreur car aucun AAD n'atteste de l'identité du propriétaire.
5. L'attaquant peut désormais valider le 2FA de la victime en utilisant le code TOTP généré par sa propre application d'authentification mobile.

#### Recommandation de correction
Faire évoluer l'interface `KEK` pour accepter un contexte AAD :
```go
type KEK interface {
    Seal(plaintext, aad []byte) ([]byte, error)
    Open(sealed, aad []byte) ([]byte, error)
}
```
Passer systématiquement `[]byte(tenantID + ":" + e.UserID.String())` comme AAD lors des opérations `Seal` et `Open`.

---

### SEC-OTP-01 : Absence de temporisation (Cooldown) et réinitialisation du budget d'attaques sur `Issue` (Toll Fraud & DoS)

* **Score CVSS v3.1 :** **8.2** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`
* **Fichiers et lignes concernés :**
  - [`otp/service.go:87-114`](file:///go/github.com/JLugagne/libauth/otp/service.go#L87-L114)
  - [`otp/handlers.go:161-210`](file:///go/github.com/JLugagne/libauth/otp/handlers.go#L161-L210)
  - [`adapters/pgx/otp/store.go:56-66`](file:///go/github.com/JLugagne/libauth/adapters/pgx/otp/store.go#L56-L66)

#### Description détaillée du mécanisme
Le service et le gestionnaire HTTP `otp.IssueHandler` ne mettent en œuvre aucune politique de délai de réémission (cooldown/throttle) entre deux demandes successives d'OTP.
Lors de l'appel à `svc.Issue`, un nouveau code est généré et enregistré via `s.store.SaveOTP`.
Dans `adapters/pgx/otp/store.go` :
```sql
INSERT INTO otp_codes (tenant_id, subject_id, purpose, code_hash, attempts, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, subject_id, purpose) DO UPDATE
SET code_hash = EXCLUDED.code_hash,
    attempts = EXCLUDED.attempts,
    expires_at = EXCLUDED.expires_at,
    created_at = EXCLUDED.created_at
```
L'opération écrase la ligne existante et réinitialise `attempts` à `0` (`EXCLUDED.attempts`).
De plus, `IssueHandler` utilise un sémaphore borné (`DefaultDeliveryConcurrency = 100`) : lorsque ce sémaphore est plein, les requêtes suivantes sont silencieusement ignorées tout en renvoyant `HTTP 204`.

#### Scénario d'exploitation théorique et impact
1. **Contournement de la limite de tentatives par réinitialisation :** Un attaquant tente de deviner un code court à 6 chiffres (espace de $10^6$ possibilités). Après 4 erreurs, il appelle `/otp/issue`, ce qui génère un nouveau code et remet le compteur d'échecs à zéro, lui permettant de poursuivre ses attaques en continu sans jamais verrouiller le compte.
2. **Déni de service par invalidation permanente :** Dès qu'un utilisateur légitime demande un code, l'attaquant déclenche une requête `/otp/issue` sur le même compte. Le code envoyé à l'utilisateur est immédiatement remplacé en base par un nouveau hash. Lorsque l'utilisateur tape le code reçu par SMS/email, celui-ci est rejeté (`invalid_code`).
3. **Fraude aux télécommunications (*Toll Fraud*) et DoS global :** Un attaquant non authentifié émet des milliers de requêtes vers `/otp/issue`. Le serveur déclenche des envois SMS coûteux chez le fournisseur (Twilio, Vonage, etc.), causant un préjudice financier immédiat. Simultanément, le sémaphore `deliverySem` est saturé à 100%, provoquant le largage silencieux des envois d'OTP de tous les utilisateurs légitimes du service.

#### Recommandation de correction
1. Imposer un délai minimal entre deux émissions (ex: 60 secondes de cooldown basé sur `created_at`).
2. Conserver le compteur d'échecs accumulés ou appliquer un budget glissant par fenêtre horaire lors des réémissions.
3. Intégrer un limiteur de débit strict par IP et par identifiant de destination (numéro de téléphone, adresse email).

---

### SEC-PSK-01 : Absence d'implémentation PostgreSQL de `ChallengeStore` menant au rejeu d'assertions Passkey à compteur nul (`SignCount = 0`)

* **Score CVSS v3.1 :** **7.4** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`adapters/pgx/passkey/store.go:1-137`](file:///go/github.com/JLugagne/libauth/adapters/pgx/passkey/store.go#L1-L137)
  - [`passkey/passkey.go:18-22`](file:///go/github.com/JLugagne/libauth/passkey/passkey.go#L18-L22)
  - [`passkey/service.go:35-41`](file:///go/github.com/JLugagne/libauth/passkey/service.go#L35-L41)
  - [`passkey/memory/challengestore.go:16-18`](file:///go/github.com/JLugagne/libauth/passkey/memory/challengestore.go#L16-L18)

#### Description détaillée du mécanisme
La documentation et les spécifications du paquet `passkey` indiquent expressément :
*"Config.ChallengeStore — REQUIRED... The memory and pgx subpackages provide implementations."*
En réalité, **aucun `ChallengeStore` n'est implémenté dans `adapters/pgx/passkey`**. Le module PostgreSQL n'implémente que `passkey.Store` (stockage des credentials).
Dans une architecture de production en cluster (plusieurs répliques derrière un load balancer), les développeurs sont confrontés à une alternative critique :
1. Utiliser `passkey/memory.NewChallengeStore()` : les challenges sont stockés en RAM locale. Lorsqu'une requête `Begin` touche le nœud 1 et `Finish` touche le nœud 2, la cérémonie échoue, ou permet des rejeux si les nœuds ne partagent pas leur état.
2. Configurer `InsecureNoChallengeStore: true` pour contourner le blocage au démarrage de `NewService`.

Sans `ChallengeStore` partagé, la protection anti-rejeu repose uniquement sur le cookie de session et sur la vérification de l'incrémentation du compteur de signatures (`SignCount`).
Or, les authentificateurs de plateforme modernes (Passkeys synchronisées via Apple iCloud Keychain, Google Password Manager, Windows Hello) **renvoient systématiquement `SignCount = 0`**, comme le prévoit la spécification W3C WebAuthn Level 3.
Le contrôle `cred.Authenticator.CloneWarning` est donc totalement inopérant pour ces clés.

#### Scénario d'exploitation théorique et impact
1. Une application est déployée sur plusieurs conteneurs avec `InsecureNoChallengeStore: true` (ou avec `memory.ChallengeStore` non partagé).
2. Un utilisateur se connecte avec une passkey de plateforme (`SignCount = 0`).
3. Un attaquant en position d'écoute sur le réseau interne ou disposant de traces mandataires capture la requête HTTP `FinishLogin` (corps et cookie).
4. L'attaquant rejoue la même requête `FinishLogin` dans la fenêtre de validité de 5 minutes.
5. `FinishLogin` valide à nouveau la signature cryptographique. Le compteur étant à 0, aucun avertissement de clone n'est levé.
6. L'attaquant obtient une session authentifiée valide au nom de la victime.

#### Recommandation de correction
1. Créer une table PostgreSQL dédiée (ex: `passkey_challenges`) et implémenter `passkey.ChallengeStore` dans `adapters/pgx/passkey` avec consommation atomique (`DELETE ... WHERE challenge = $1 RETURNING ...`).
2. Mettre en garde formellement dans la documentation contre l'usage de `passkey/memory.ChallengeStore` dans des environnements distribués.

---

### SEC-PSK-02 : Déni de service par parcours linéaire bloquant $O(N)$ sous verrou exclusif dans `memory.ChallengeStore`

* **Score CVSS v3.1 :** **7.5** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`passkey/memory/challengestore.go:34-40`](file:///go/github.com/JLugagne/libauth/passkey/memory/challengestore.go#L34-L40)
  - [`passkey/memory/challengestore.go:62-68`](file:///go/github.com/JLugagne/libauth/passkey/memory/challengestore.go#L62-L68)

#### Description détaillée du mécanisme
Dans `passkey/memory/challengestore.go` :
```go
func (s *ChallengeStore) Put(_ context.Context, tenantID, challenge string, expiresAt time.Time) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.pruneLocked(time.Now())
    s.entries[challengeKey(tenantID, challenge)] = expiresAt
    return nil
}

func (s *ChallengeStore) pruneLocked(now time.Time) {
    for k, expiry := range s.entries {
        if !now.Before(expiry) {
            delete(s.entries, k)
        }
    }
}
```
À chaque appel de `Put` (déclenché lors de chaque appel non authentifié à `BeginLoginHandler` ou `BeginDiscoverableLoginHandler`), la méthode acquiert le verrou exclusif `s.mu.Lock()` et exécute `s.pruneLocked`.
Cette fonction effectue une itération complète sur **la totalité** des entrées de la map en mémoire.

#### Scénario d'exploitation théorique et impact
1. Les challenges ayant une durée de vie de 5 minutes (`DefaultSessionTTL`), un attaquant distant émet une salve continue de requêtes HTTP POST sur `/passkey/login/begin` ou `/passkey/discoverable/begin`.
2. Chaque insertion accumule des entrées actives dans `s.entries`.
3. Pour $N$ challenges en mémoire, chaque nouvelle requête effectue un parcours complet de $N$ éléments sous verrouillage exclusif global.
4. Le coût computationnel de l'insertion devient quadratique $O(N^2)$. Le verrou `s.mu` reste monopolisé, bloquant toutes les autres goroutines (y compris `Consume`).
5. L'application subit une saturation totale de son CPU et une famine de goroutines, provoquant l'indisponibilité complète des cérémonies Passkey pour tous les utilisateurs.

#### Recommandation de correction
Supprimer l'appel systématique à `pruneLocked` dans `Put`. Utiliser un nettoyage périodique en tâche de fond (janitor) ou une structure de file avec priorité / liste ordonnée par expiration pour ne dépiler que les éléments expirés en $O(1)$.

---

### SEC-PSK-03 : Absence de révocation des identifiants clonés et régression de `sign_count` sous concurrence

* **Score CVSS v3.1 :** **7.4** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
* **Fichiers et lignes concernés :**
  - [`passkey/service.go:255-258`](file:///go/github.com/JLugagne/libauth/passkey/service.go#L255-L258)
  - [`passkey/service.go:316-319`](file:///go/github.com/JLugagne/libauth/passkey/service.go#L316-L319)
  - [`adapters/pgx/passkey/store.go:98-112`](file:///go/github.com/JLugagne/libauth/adapters/pgx/passkey/store.go#L98-L112)

#### Description détaillée du mécanisme
1. **Absence de révocation après détection de clonage :**
   Lors de `FinishLogin` et `FinishDiscoverableLogin`, lorsque `cred.Authenticator.CloneWarning` est vrai (le compteur de signatures de l'authentificateur a régressé par rapport à la valeur enregistrée), le service émet un événement `AccountBlocked` et retourne `ErrCredentialCloned`.
   Cependant, l'identifiant dans `passkey_credentials` n'est **ni révoqué, ni désactivé, ni supprimé**, en contradiction avec la recommandation de la section 6.3.3.8 de la spécification W3C WebAuthn. L'identifiant reste actif en base de données.
2. **Régression de compteur par condition de course (Race Condition) :**
   Dans `adapters/pgx/passkey/store.go`, la mise à jour s'exécute ainsi :
   ```sql
   UPDATE passkey_credentials
   SET public_key = $4, sign_count = $5, data = $6, nickname = $7, last_used_at = $8, transports = $9, backup_eligible = $10, backup_state = $11
   WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3
   ```
   Cette requête ne vérifie pas `AND sign_count <= $5`. Si deux requêtes de connexion légitimes sont traitées de façon concurrente ou désordonnée, une requête portant un compteur inférieur peut écraser un compteur supérieur, entraînant une régression artificielle du compteur en base et bloquant les connexions ultérieures de l'utilisateur légitime pour suspicion de clone.

#### Scénario d'exploitation théorique et impact
Un attaquant ayant réussi à cloner un authentificateur matériel dont le compteur actuel est inférieur à la valeur enregistrée échoue lors de sa première tentative. Mais dès lors que l'utilisateur légitime réutilise sa clé et incrémente son compteur au-delà, ou si l'attaquant réutilise le clone après avoir fait tourner le compteur localement, l'authentification réussira car le credential n'a jamais été révoqué.

#### Recommandation de correction
1. Désactiver ou marquer immédiatement comme révoqué le credential en base lors de la détection de `CloneWarning`.
2. Ajouter la clause `AND sign_count <= $5` dans la requête SQL `UpdateCredential` pour garantir la monotonicité stricte du compteur.

---

### SEC-MFA-04 : Défaut d'architecture Step-Up : Impossibilité d'utiliser les codes de secours pour l'élévation de session

* **Score CVSS v3.1 :** **7.1** (Élevé)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H`
* **Fichiers et lignes concernés :**
  - [`mfa/handlers.go:333-363`](file:///go/github.com/JLugagne/libauth/mfa/handlers.go#L333-L363)
  - [`mfa/handlers.go:179-189`](file:///go/github.com/JLugagne/libauth/mfa/handlers.go#L179-L189)

#### Description détaillée du mécanisme
Le modèle d'élévation de privilège d'`egauth` s'appuie sur `mfa.StepUpHandler` pour convertir un jeton intermédiaire issu de `LoginHandler` en une session complète dotée de `AMR=[pwd, otp, mfa]`.
Cependant, `StepUpHandler` appelle exclusivement `svc.VerifyTOTP(r.Context(), tenant, uid, r.PostForm.Get(cfg.codeField))`.
Il n'existe aucune prise en charge des codes de secours dans `StepUpHandler`.
Parallèlement, `VerifyRecoveryHandler` se contente d'appeler `svc.VerifyRecoveryCode` et de retourner `HTTP 204 No Content` ; il ne manipule ni les cookies, ni l'émetteur de jetons, ni l'élévation AMR.

#### Scénario d'exploitation théorique et impact
Un utilisateur ayant perdu ou endommagé son téléphone tente de se connecter avec l'un de ses codes de secours à 16 caractères :
- S'il saisit son code de secours dans le formulaire de step-up (`StepUpHandler`), le code est évalué par `VerifyTOTP` comme un code TOTP à 6 chiffres malformé, échoue et consomme une tentative du budget de sécurité.
- S'il soumet son code à `VerifyRecoveryHandler`, le code de secours est consommé et détruit en base, mais sa session n'est jamais élevée et aucun cookie de rafraîchissement ne lui est délivré. L'utilisateur demeure bloqué dans un jeton intermédiaire expirant en 5 minutes.
Il est strictement impossible pour un utilisateur légitime de restaurer son accès en autonomie via ses codes de secours.

#### Recommandation de correction
Étendre `StepUpHandler` pour supporter à la fois la vérification TOTP et la vérification des codes de secours (ou implémenter un `StepUpRecoveryHandler`), permettant d'élever la session et d'émettre la paire de jetons complète sur présentation d'un code de secours valide.

---

### SEC-MFA-05 : Déni de service sur les codes de récupération par verrouillage partagé avec le budget TOTP

* **Score CVSS v3.1 :** **6.5** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`
* **Fichiers et lignes concernés :**
  - [`mfa/service.go:301-326`](file:///go/github.com/JLugagne/libauth/mfa/service.go#L301-L326)
  - [`adapters/pgx/mfa/store.go:162-173`](file:///go/github.com/JLugagne/libauth/adapters/pgx/mfa/store.go#L162-L173)

#### Description détaillée du mécanisme
Dans `mfa/service.go`, `VerifyRecoveryCode` conditionne la vérification d'un code de secours au compteur d'échecs partagé de l'enrôlement TOTP :
```go
n, rerr := s.reserveAttempt(ctx, tenantID, userID)
if rerr != nil { return rerr }
if s.overLimit(n) {
    s.emitBlocked(ctx, tenantID, userID, "recovery")
    return ErrTooManyAttempts
}
```
Si le compteur `mfa_totp.failed_attempts` a atteint le seuil critique (`DefaultMaxAttempts = 5`), `overLimit(n)` est vrai et la fonction retourne `ErrTooManyAttempts` **avant même d'examiner le code de secours présenté**.

#### Scénario d'exploitation théorique et impact
Un attaquant ayant dérobé le mot de passe d'un utilisateur cible tente de se connecter. Face au challenge MFA, il soumet 5 codes TOTP erronés. Le facteur est verrouillé pour 15 minutes (`LockoutDuration`).
La victime, constatant un problème ou ayant égaré son smartphone, tente d'utiliser l'un de ses codes de secours d'une entropie de 80 bits.
Bien que le code soit parfaitement authentique, la requête est rejetée avec `too_many_attempts`. L'attaquant, disposant uniquement du premier facteur, prive la victime de son moyen de secours d'urgence.

#### Recommandation de correction
Les codes de récupération disposant d'une entropie cryptographique forte (80 bits) et étant à usage unique strict, ils ne doivent pas partager le budget de verrouillage en ligne des codes TOTP à 6 chiffres. Décorréler leurs compteurs d'échecs.

---

### SEC-MFA-06 : Non-atomicité de la confirmation TOTP (`ConfirmTOTP`) menant à la destruction des codes de secours

* **Score CVSS v3.1 :** **5.8** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:H`
* **Fichiers et lignes concernés :**
  - [`mfa/service.go:236-250`](file:///go/github.com/JLugagne/libauth/mfa/service.go#L236-L250)
  - [`mfa/service.go:411-420`](file:///go/github.com/JLugagne/libauth/mfa/service.go#L411-L420)
  - [`adapters/pgx/mfa/store.go:68-92`](file:///go/github.com/JLugagne/libauth/adapters/pgx/mfa/store.go#L68-L92)

#### Description détaillée du mécanisme
Dans `ConfirmTOTP`, la confirmation de l'enrôlement s'opère en deux temps non transactionnels :
1. `s.store.SaveTOTP` écrit `ConfirmedAt != nil` dans `mfa_totp`.
2. `s.mintRecoveryCodes` génère les codes et appelle `s.store.ReplaceRecoveryCodes` dans `mfa_recovery_codes`.
Si une panne, coupure réseau ou annulation de contexte survient entre ces deux requêtes, le facteur TOTP est définitivement marqué comme confirmé, mais aucun code de secours n'est enregistré. L'utilisateur reçoit une erreur et ne peut plus réitérer `ConfirmTOTP` (qui renvoie `ErrAlreadyEnrolled`).

De plus, en cas de double soumission concurrente du formulaire de confirmation (double-clic ou retry réseau), deux jeux distincts de codes de secours sont générés. L'un écrase l'autre en base via `ReplaceRecoveryCodes`, tandis que le client peut recevoir et imprimer le premier jeu, désormais invalide en base.

#### Scénario d'exploitation théorique et impact
Un utilisateur valide son TOTP sur un réseau mobile instable. Le premier enregistrement passe, le second échoue. L'utilisateur se retrouve avec le 2FA activé sans aucun code de secours de secours. En cas de perte de son mobile, son compte est irrémédiablement inaccessible.

#### Recommandation de correction
Encapsuler la confirmation TOTP et le stockage initial des codes de secours dans une transaction SQL unique, et utiliser un verrou optimiste ou une contrainte `WHERE confirmed_at IS NULL` pour rejeter les confirmations concurrentes.

---

### SEC-PSK-04 : Absence d'isolation tenant dans les cookies de cérémonie Passkey en configuration par défaut

* **Score CVSS v3.1 :** **5.0** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`passkey/handlers.go:50-56`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L50-L56)
  - [`passkey/handlers.go:309-329`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L309-L329)
  - [`passkey/handlers.go:581-600`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L581-L600)

#### Description détaillée du mécanisme
Dans `passkey/handlers.go`, le cookie de cérémonie HMAC `passkey_ceremony` scelle `webauthn.SessionData`.
Par défaut, si l'option `WithTenantCookieKeys` n'est pas configurée, la même clé `cfg.cookieKey` statique est utilisée pour tous les tenants.
Le contenu de `SessionData` sérialisé en JSON ne contient pas le `TenantID`.
Par conséquent, si `InsecureNoChallengeStore` est activé, un cookie de cérémonie généré sur le Tenant A possède une signature HMAC valide sur le Tenant B.

#### Scénario d'exploitation théorique et impact
Dans un système multi-tenant partageant le même nom de domaine ou acceptant des cookies cross-sous-domaines, un cookie de cérémonie initié sur un tenant peu sécurisé peut être réutilisé pour finaliser une cérémonie sur un autre tenant.

#### Recommandation de correction
Inclure systématiquement l'identifiant du tenant dans la charge utile sérialisée ou dans le calcul de la signature HMAC du cookie : `HMAC(key, tenantID + ":" + sessionData)`.

---

### SEC-OTP-02 : Désynchronisation et condition de course lors de l'émission asynchrone d'OTP (`IssueHandler`)

* **Score CVSS v3.1 :** **4.8** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L`
* **Fichiers et lignes concernés :**
  - [`otp/handlers.go:197-208`](file:///go/github.com/JLugagne/libauth/otp/handlers.go#L197-L208)
  - [`otp/handlers.go:273-298`](file:///go/github.com/JLugagne/libauth/otp/handlers.go#L273-L298)

#### Description détaillée du mécanisme
Dans `IssueHandler`, l'exécution de `svc.Issue` a été déplacée à l'intérieur de la goroutine détachée `cfg.dispatchDelivery` afin de masquer la latence de base de données.
Le handler HTTP renvoie immédiatement la réponse `204 No Content` au client avant même que `svc.Issue` n'ait exécuté l'écriture `SaveOTP` en base de données.

#### Scénario d'exploitation théorique et impact
Un client automatisé ou un utilisateur très rapide recevant un OTP (par exemple via une notification push locale ou une intégration SMS rapide) soumet immédiatement le code reçu. La requête de vérification atteint la base de données avant que la goroutine d'émission n'ait terminé `SaveOTP`. `Verify` renvoie alors `ErrCodeNotFound` et rejette la vérification légitime.

#### Recommandation de correction
Effectuer l'appel `svc.Issue` (enregistrement en base de données) de manière synchrone sur le chemin de la requête, et ne détacher sur la goroutine d'arrière-plan que la fonction de livraison `deliver(ctx, ch)` (appel réseau mail/SMS).

---

### SEC-PSK-05 : Suppression des métadonnées d'authentificateur (AAL2/AAL3, UV, BackupState) dans `LoginSuccessFunc`

* **Score CVSS v3.1 :** **4.6** (Moyen)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`passkey/handlers.go:37-40`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L37-L40)
  - [`passkey/handlers.go:235-238`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L235-L238)
  - [`passkey/handlers.go:514-517`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L514-L517)

#### Description détaillée du mécanisme
Dans `FinishLoginHandler` et `FinishDiscoverableLoginHandler`, l'objet `*Credential` retourné par le service est ignoré :
```go
cred, uid, err := svc.FinishDiscoverableLogin(r.Context(), tenant, session, r)
if err != nil { cfg.fail(w, err); return }
_ = cred
if cfg.onLoginSuccess != nil {
    cfg.onLoginSuccess(w, r, uid)
    return
}
```
Le type `LoginSuccessFunc` ne reçoit que `(w, r, userID)`. L'application hôte n'a aucun moyen de savoir si la passkey utilisée était une clé physique non exportable (`BackupEligible=false`) ou une passkey synchronisée dans le cloud (`BackupState=true`), ni si la vérification utilisateur biométrique (UV) a été effectuée.

#### Scénario d'exploitation théorique et impact
Une application appliquant une politique Zero Trust ou exigeant une assurance AAL3 (FIDO non synchronisable pour les administrateurs) ne peut pas inspecter la nature du credential utilisé pour émettre des jetons avec les revendications AMR appropriées (`hwk` vs `pos`).

#### Recommandation de correction
Enrichir la signature de `LoginSuccessFunc` pour transmettre le `*Credential` vérifié :
`type LoginSuccessFunc func(w http.ResponseWriter, r *http.Request, userID uuid.UUID, cred *Credential)`

---

### SEC-MFA-07 : Ordre d'évaluation de la dérive TOTP priorisant l'intervalle passé

* **Score CVSS v3.1 :** **3.7** (Faible)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`
* **Fichiers et lignes concernés :**
  - [`mfa/totp.go:113-122`](file:///go/github.com/JLugagne/libauth/mfa/totp.go#L113-L122)

#### Description détaillée du mécanisme
Dans `validateTOTP` :
```go
step := timeStep(at, period)
for i := -skew; i <= skew; i++ {
    c := step + int64(i)
    if c < 0 { continue }
    candidate := hotp(key, uint64(c), digits)
    if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
        return c, true
    }
}
```
La boucle teste séquentiellement `i = -1`, puis `0`, puis `+1`.
La recommandation RFC 6238 §5.2 stipule de vérifier d'abord le pas de temps actuel `i = 0`, puis la dérive.
En cas de collision de code entre deux intervalles adjacents (probabilité de $1/10^6$ pour 6 chiffres), `validateTOTP` sélectionne le pas $T-1$. Dans `VerifyTOTP`, `MarkTOTPUsed` rejettera la connexion si le pas $T-1$ a déjà été consommé, bien que le code saisi soit parfaitement valide pour le pas actuel $T$.

#### Scénario d'exploitation théorique et impact
Rejet intempestif et consommation d'un essai du budget utilisateur sur une collision de code temporelle.

#### Recommandation de correction
Évaluer d'abord `i = 0`, puis itérer sur les pas alternatifs `[-skew, +skew]`.

---

### SEC-PSK-06 : Absence de vérification Origin / CSRF sur les points d'entrée Passkey

* **Score CVSS v3.1 :** **3.1** (Faible)
* **Vecteur CVSS v3.1 :** `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N`
* **Fichiers et lignes concernés :**
  - [`passkey/handlers.go:129-242`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L129-L242)
  - [`passkey/handlers.go:531-560`](file:///go/github.com/JLugagne/libauth/passkey/handlers.go#L531-L560)

#### Description détaillée du mécanisme
Alors que les packages `mfa` et `otp` appliquent rigoureusement une vérification d'origine stricte par défaut via `originAllowed(r)`, les handlers du package `passkey` en sont totalement dépourvus.
Si `FinishLogin` et `FinishRegistration` délèguent la validation de l'origine de `clientDataJSON` à `go-webauthn`, des endpoints de mutation comme `RenameCredentialHandler` n'intègrent aucun contrôle d'origine CSRF.

#### Scénario d'exploitation théorique et impact
Si les cookies de session sont configurés avec `SameSite=None` (ou dans des contextes cross-origines permissifs), un attaquant peut faire émettre une requête POST vers `/passkey/rename` à l'insu de la victime pour renommer ses clés d'authentification.

#### Recommandation de correction
Appliquer la vérification `originAllowed` de manière homogène sur l'ensemble des handlers d'action POST de `passkey`.

---

## Synthèse Globale des Vulnérabilités et Évaluation CVSS

| Identifiant | Intitulé de la Vulnérabilité | Sévérité | Score CVSS v3.1 | Vecteur CVSS v3.1 |
| :--- | :--- | :---: | :---: | :--- |
| **SEC-MFA-02** | **Révocation du 2FA et destruction des facteurs via jeton intermédiaire (`DisableHandler`)** | **Élevé** | **8.8** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **SEC-MFA-03** | **Absence d'AAD dans le chiffrement KEK des secrets TOTP (Transposition de facteurs)** | **Élevé** | **8.3** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **SEC-OTP-01** | **Absence de cooldown et réinitialisation du compteur sur émission OTP (Toll Fraud & DoS)** | **Élevé** | **8.2** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H` |
| **SEC-MFA-01** | **Contournement complet du 2FA via `ChangePasswordWithReissueHandler`** | **Élevé** | **8.1** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **SEC-PSK-02** | **Déni de service par parcours linéaire bloquant $O(N)$ dans Memory ChallengeStore** | **Élevé** | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-PSK-01** | **Absence de ChallengeStore Postgres & Rejeu de Passkeys Plateforme (SignCount 0)** | **Élevé** | **7.4** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **SEC-PSK-03** | **Absence de révocation des clés clonées et condition de course sur `sign_count`** | **Élevé** | **7.4** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **SEC-MFA-04** | **Défaut Step-Up : Impossibilité d'utiliser les codes de secours pour l'élévation** | **Élevé** | **7.1** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H` |
| **SEC-MFA-05** | **Déni de service sur les codes de secours par verrouillage partagé avec TOTP** | **Moyen** | **6.5** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` |
| **SEC-MFA-06** | **Non-atomicité de `ConfirmTOTP` menant à la destruction des codes de secours** | **Moyen** | **5.8** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:H` |
| **SEC-PSK-04** | **Absence d'isolation tenant dans les cookies de cérémonie Passkey** | **Moyen** | **5.0** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N` |
| **SEC-OTP-02** | **Désynchronisation et race condition sur l'émission asynchrone d'OTP** | **Moyen** | **4.8** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L` |
| **SEC-PSK-05** | **Perte des métadonnées d'assurance authenticator (AAL2/AAL3, UV) dans Passkey** | **Moyen** | **4.6** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` |
| **SEC-MFA-07** | **Ordre d'évaluation de la dérive TOTP priorisant l'intervalle passé** | **Faible** | **3.7** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **SEC-PSK-06** | **Absence de vérification CSRF / Origin sur les handlers Passkey** | **Faible** | **3.1** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N` |

---

## Confirmation sur les vulnérabilités avec score CVSS > 7.5

> [!CAUTION]
> **Présence de vulnérabilités avec un score CVSS v3.1 strictement supérieur à 7.5 :**
> **OUI**, il y a **4 vulnérabilités confirmées** avec un score CVSS v3.1 strictement supérieur à 7.5 :
> 
> 1. **SEC-MFA-02 : Révocation non autorisée du 2FA et destruction des facteurs via un jeton intermédiaire (`DisableHandler`)** — **Score CVSS : 8.8**
> 2. **SEC-MFA-03 : Absence de données associées (AAD) dans le chiffrement d'enveloppe KEK des secrets TOTP (Transposition de facteurs)** — **Score CVSS : 8.3**
> 3. **SEC-OTP-01 : Absence de temporisation (Cooldown) et réinitialisation du budget d'attaques sur `Issue` (Toll Fraud & DoS)** — **Score CVSS : 8.2**
> 4. **SEC-MFA-01 : Contournement complet du 2FA via `ChangePasswordWithReissueHandler`** — **Score CVSS : 8.1**
>
> *(À noter que la vulnérabilité **SEC-PSK-02** atteint exactement le seuil critique de **7.5**).*
