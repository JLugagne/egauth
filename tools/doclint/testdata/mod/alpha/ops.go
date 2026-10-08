package alpha

import "net/http"

// Ch is a fixture channel.
var Ch = make(chan int)

// Handle is a fixture handler function.
func Handle(w http.ResponseWriter, r *http.Request) {}
