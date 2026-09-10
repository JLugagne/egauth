// Package securitydefaults holds a mechanical guard over the library's exported HTTP handler
// constructors. The guard scans the handler packages' source and fails when an exported
// constructor returning an http.Handler/http.HandlerFunc is not present in the maintained
// registry, so adding a handler forces an explicit statement of the default security control it
// applies before it can pass CI.
package securitydefaults
