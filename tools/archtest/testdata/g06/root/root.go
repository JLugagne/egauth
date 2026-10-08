package egauth

import "github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/kek"

func UpgradeSecretsV016(k kek.KEK) ([]byte, error) { return k.Open(nil) }

func Sneaky(k kek.KEK) ([]byte, error) { return k.Seal(nil) }
