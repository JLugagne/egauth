package principal

type Sealed struct{ b []byte }

type Subject struct{ Tenant, ID string }
