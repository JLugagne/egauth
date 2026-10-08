package main

type cfg struct{}

type Option func(*cfg)

func WithX() Option { return nil }

func main() {}
