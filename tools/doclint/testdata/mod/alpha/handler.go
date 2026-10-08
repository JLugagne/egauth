package alpha

import "net/http"

func handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	srv := &http.Server{}
	session := &Server{}
	_, _, _ = ctx, srv, session
	w.WriteHeader(http.StatusOK)
}
