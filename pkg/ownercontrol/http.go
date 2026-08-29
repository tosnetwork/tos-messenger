package ownercontrol

import (
	"encoding/hex"
	"encoding/json"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
	"io"
	"net/http"
)

const maxBody = 1 << 20

type HTTPAuthenticator func(*http.Request, trusted.OwnerCommandEffectV1, trusted.OwnerCommandAuthorizationAttemptV1) (AuthenticatedPrincipal, error)

func Handler(service *Service, authenticate HTTPAuthenticator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/owner-commands", func(w http.ResponseWriter, r *http.Request) {
		if authenticate == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		reader := http.MaxBytesReader(w, r.Body, maxBody)
		decoder := json.NewDecoder(reader)
		decoder.DisallowUnknownFields()
		var request struct {
			Effect   trusted.OwnerCommandEffectV1               `json:"effect"`
			Attempt  trusted.OwnerCommandAuthorizationAttemptV1 `json:"attempt"`
			Evidence SubmissionEvidence                         `json:"evidence"`
		}
		if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		principal, authErr := authenticate(r, request.Effect, request.Attempt)
		if authErr != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		resolution, err := service.Submit(r.Context(), principal, request.Effect, request.Attempt, request.Evidence)
		if err != nil {
			write(w, http.StatusConflict, resolution)
			return
		}
		write(w, http.StatusOK, resolution)
	})
	mux.HandleFunc("GET /v1/owner-command-actions/{namespace}/{action}", func(w http.ResponseWriter, r *http.Request) {
		if authenticate == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		principal, authErr := authenticate(r, trusted.OwnerCommandEffectV1{}, trusted.OwnerCommandAuthorizationAttemptV1{})
		if authErr != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		namespace, err := hex.DecodeString(r.PathValue("namespace"))
		if err != nil {
			http.Error(w, "invalid namespace", 400)
			return
		}
		action, err := hex.DecodeString(r.PathValue("action"))
		if err != nil {
			http.Error(w, "invalid action", 400)
			return
		}
		resolution, err := service.Resolve(r.Context(), principal, namespace, action)
		if err != nil {
			http.Error(w, "resolution indeterminate", http.StatusServiceUnavailable)
			return
		}
		write(w, 200, resolution)
	})
	return mux
}
func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
