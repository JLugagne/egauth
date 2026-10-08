package cookie

import "net/http"

func Set(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "a"})
	_, _ = r.Cookie("a")
}
