# Audit de Sécurité Global — egauth (libauth)

Ce document récapitule l'ensemble des vulnérabilités identifiées au cours de l'audit de sécurité approfondi réalisé par 6 agents spécialisés.

Les rapports détaillés sont consultables dans :
- [01_tokens_and_keystore.md](./01_tokens_and_keystore.md)
- [02_identity_and_passwords.md](./02_identity_and_passwords.md)
- [03_sessions_webapp_and_csrf.md](./03_sessions_webapp_and_csrf.md)
- [04_mfa_otp_passkey.md](./04_mfa_otp_passkey.md)
- [05_oauth_and_oidc.md](./05_oauth_and_oidc.md)
- [06_global_workflows_and_multitenancy.md](./06_global_workflows_and_multitenancy.md)
- [07_vulnerability_confirmation_tests.md](./07_vulnerability_confirmation_tests.md)
- [ALL_VULNERABILITIES_BY_SEVERITY.md](./ALL_VULNERABILITIES_BY_SEVERITY.md) (Rapport exhaustif classé par criticité)

---

## Synthèse Globale

- **Total de vulnérabilités identifiées :** 77
- **Vulnérabilités Critiques / Élevées avec CVSS v3.1 > 7.5 :** **19 vulnérabilités**
- **Vulnérabilités à exactement 7.5 :** 8 vulnérabilités

---

## Tableau des Vulnérabilités Majeures (Score CVSS v3.1 > 7.5)

| ID | Module | Titre | Sévérité | Score CVSS | Fichiers |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **SEC-OAU-01** | OAuth / OIDC | Collision d'identifiants et usurpation de compte via perte de précision `float64` dans `stringifyID` | **Critique** | **9.8** | `oauth/providers/gitlab.go:70`, `oauth/providers/okta.go:76` |
| **SEC-ID-02** | Identity | Prise de Contrôle de Compte (ATO) via Changement d'Email sans Ré-authentification ni Alerte | **Élevée** | **8.8** | `identity/service.go:811`, `identity/handlers.go:585` |
| **SEC-ID-08** | Identity | Usurpation de Compte par Confusion Sociale sur le Token SMS de Réinitialisation | **Élevée** | **8.8** | `identity/handlers.go:1323`, `identity/service.go:1264` |
| **SEC-MFA-02** | MFA | Révocation du 2FA et destruction des facteurs via jeton intermédiaire (`DisableHandler`) | **Élevée** | **8.8** | `mfa/handlers.go:275-296` |
| **SEC-TOK-01** | Keystore | Absence de données associées (AAD) dans le chiffrement d'enveloppe KEK (Transposition de clés) | **Élevée** | **8.3** | `keystore/kek.go:60`, `keystore/resolve.go:73` |
| **SEC-MFA-03** | MFA | Absence d'AAD dans le chiffrement d'enveloppe KEK des secrets TOTP | **Élevée** | **8.3** | `adapters/pgx/mfa/store.go:62`, `keystore/kek.go:60` |
| **SEC-ID-04** | Identity | Énumération d'Utilisateurs & Lockout DoS via Distinction HTTP 429 (`mapAuthError`) | **Élevée** | **8.2** | `identity/handlers.go:210`, `identity/service.go:548` |
| **SEC-ID-12** | Identity / MFA | Jeton d'Accès Intermédiaire MFA Valide sur les Routes Non Gated par AMR | **Élevée** | **8.2** | `tokens/middleware.go:221`, `tokens/service.go:53` |
| **SEC-OTP-01** | OTP | Absence de cooldown et réinitialisation du budget d'attaques sur émission OTP | **Élevée** | **8.2** | `otp/service.go:94`, `otp/handlers.go:190` |
| **SEC-OAU-02** | OAuth | Chiffrement KEK sans données associées (AAD) pour `client_secret` (Transposition multi-tenant) | **Élevée** | **8.2** | `adapters/pgx/oauth/store.go:102` |
| **SEC-ID-03** | Identity / MFA | Contournement Complet du MFA via la Connexion par Magic Link (`MagicLinkLoginHandler`) | **Élevée** | **8.1** | `identity/handlers.go:961`, `identity/service.go:1052` |
| **SEC-SES-04** | Sessions | Absence totale de vérification CSRF / Origine dans `sessions.RequireSession` | **Élevée** | **8.1** | `sessions/middleware.go:29` |
| **SEC-SES-11** | Webapp | Désactivation silencieuse de la protection CSRF par conflit dans `webapp.NewWebApp` | **Élevée** | **8.1** | `webapp/webapp.go:173-178` |
| **SEC-MFA-01** | MFA | Contournement complet du 2FA via `ChangePasswordWithReissueHandler` | **Élevée** | **8.1** | `identity/handlers.go:742-780` |
| **SEC-OAU-03** | OAuth | Cookie d'état OAuth non signé et non lié à la session (Injection de cookie et Login CSRF) | **Élevée** | **8.1** | `oauth/state.go:50`, `oauth/handlers.go:169` |
| **SEC-GLO-01** | Workflows | Rupture de chaîne de révocation lors de la réinitialisation de mot de passe | **Élevée** | **8.1** | `identity/service.go:718`, `examples/fullstack/main.go:98` |
| **SEC-GLO-02** | Workflows | Contournement complet du MFA/2FA via le flux de connexion OAuth/OIDC | **Élevée** | **8.1** | `oauth/handlers.go:248-265`, `identity/service.go:944` |
| **SEC-GLO-03** | Architecture | Absence d'implémentation de cascade de suppression de tenant (`TenantEraser`) | **Élevée** | **7.9** | `keystore/manager.go:235`, `adapters/pgx/` |
| **SEC-SES-02** | Sessions | Éviction inter-tenants non cloisonnée dans `sessions/memory.BoundedStore` | **Élevée** | **7.7** | `sessions/memory/store.go:249-266` |
| **SEC-OAU-04** | OAuth | SSRF et contournement DNS Rebinding par client HTTP non sécurisé dans `providers.OIDC` | **Élevée** | **7.7** | `oauth/providers/oidc.go:78-88` |
