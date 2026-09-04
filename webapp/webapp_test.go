package webapp_test

import (
	"testing"

	"github.com/JLugagne/egauth/webapp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewWebApp_ConflictingCSRFConfig_RejectsContradiction confirms SEC-SES-11 (CVSS 8.1).
//
// Invariant de sécurité :
// Le constructeur webapp.NewWebApp DOIT interdire et rejeter explicitement toute configuration
// contradictoire où TrustedOrigins est défini ET InsecureNoOriginCheck est activé à true.
// La présence d'une liste blanche d'origines fiables (TrustedOrigins) implique la volonté formelle
// d'activer et de restreindre la protection CSRF ; autoriser InsecureNoOriginCheck en parallèle
// constitue un conflit majeur de configuration de sécurité qui doit échouer immédiatement à la construction (fail-closed).
//
// Comportement vulnérable actuel :
// Dans webapp.NewWebApp (webapp/webapp.go:122-124 et 169-178), la garde ne vérifie que :
//
//	len(cfg.TrustedOrigins) == 0 && !cfg.InsecureNoOriginCheck
//
// Si le développeur configure TrustedOrigins tout en conservant InsecureNoOriginCheck: true,
// NewWebApp accepte silencieusement la configuration, et l'option WithInsecureNoOriginCheck()
// écrase WithTrustedOrigins(). La protection CSRF est totalement désactivée à l'insu de l'administrateur.
func TestNewWebApp_ConflictingCSRFConfig_RejectsContradiction(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedOrigins = []string{"https://app.example.com"}
	cfg.InsecureNoOriginCheck = true

	// INVARIANT VIOLE 1 : Le constructeur doit refuser cette combinaison contradictoire
	_, err := webapp.NewWebApp(cfg)
	require.Error(t, err,
		"SEC-SES-11: webapp.NewWebApp doit rejeter la combinaison contradictoire de TrustedOrigins et InsecureNoOriginCheck")
	assert.Contains(t, err.Error(), "cannot specify both TrustedOrigins and InsecureNoOriginCheck")
}
