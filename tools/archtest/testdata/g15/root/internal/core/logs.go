package core

import (
	"fmt"
	"log/slog"
)

func Describe() string { return fmt.Sprintf("%d", 1) }

func Value() slog.Value { return slog.GroupValue(slog.String("a", "b")) }

func Leak() {
	slog.Default().Info("x")
	fmt.Println("y")
}
