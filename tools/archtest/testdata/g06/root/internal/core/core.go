package core

type Pending struct{}

func (p Pending) Add() Pending { return p }

func NewPending() Pending { return Pending{} }

func NewMFADecision() int { return 0 }

func Renew() {}

func Unseal() {}

func ForTestAttrs() int { return 0 }

func Internal() Pending { return NewPending().Add() }

func NewAccountState() int { return 0 }

func NewVerified() int { return 0 }
