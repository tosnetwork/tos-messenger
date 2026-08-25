package intentcarrier

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type HTTPAuthorizer interface {
	Authorize(authorization string, write bool) error
}

// Handler exposes the Carrier profile used by OpenFox HTTPCarrier. The
// response shape is interoperable while the backing implementation is not
// shared with the Gateway Carrier.
func Handler(store *Store, authorize HTTPAuthorizer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/intents/admission-challenge", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(authorize, r, true) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		declared, err := strconv.ParseUint(r.URL.Query().Get("declared_bytes"), 10, 64)
		if err != nil {
			http.Error(w, "invalid declared_bytes", http.StatusBadRequest)
			return
		}
		kind := r.URL.Query().Get("operation_kind")
		if kind == "" {
			kind = "publication.publish"
		}
		challenge, err := store.IssueAdmission(kind, r.URL.Query().Get("actor_id"), r.URL.Query().Get("audience"), declared)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, challenge)
	})
	mux.HandleFunc("POST /v1/intents", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(authorize, r, true) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxObjectBytes+(64<<10))
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request struct {
			Intent    commerce.SignedAgentIntent       `json:"intent"`
			Admission commerce.OperationAdmissionProof `json:"admission"`
			Action    commerce.AuthorizedAction        `json:"authorized_action"`
			Fence     commerce.WriterFence             `json:"writer_fence"`
		}
		if decoder.Decode(&request) != nil || requireEOF(decoder) != nil {
			http.Error(w, "invalid admitted signed Intent", http.StatusBadRequest)
			return
		}
		result, resolution, err := store.Publish(request.Intent, request.Admission, request.Action, request.Fence)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			Result     IntentResult              `json:"result"`
			Resolution commerce.ActionResolution `json:"action_resolution"`
		}{result, resolution})
	})
	mux.HandleFunc("POST /v1/intents/withdrawals", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(authorize, r, true) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxObjectBytes+(64<<10))
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request struct {
			Withdrawal commerce.SignedAgentIntentWithdrawal `json:"withdrawal"`
			Admission  commerce.OperationAdmissionProof     `json:"admission"`
			Action     commerce.AuthorizedAction            `json:"authorized_action"`
			Fence      commerce.WriterFence                 `json:"writer_fence"`
		}
		if decoder.Decode(&request) != nil || requireEOF(decoder) != nil {
			http.Error(w, "invalid admitted withdrawal", http.StatusBadRequest)
			return
		}
		resolution, err := store.Withdraw(request.Withdrawal, request.Admission, request.Action, request.Fence)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			Resolution commerce.ActionResolution `json:"action_resolution"`
		}{resolution})
	})
	mux.HandleFunc("GET /v1/intents/subscribe", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(authorize, r, false) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		query, err := parseQuery(r)
		wait := uint64(20)
		if raw := r.URL.Query().Get("wait_seconds"); raw != "" {
			wait, err = strconv.ParseUint(raw, 10, 8)
		}
		if err != nil || wait > 25 {
			http.Error(w, "invalid subscription query", http.StatusBadRequest)
			return
		}
		page, err := store.Subscribe(r.Context(), query, time.Duration(wait)*time.Second)
		if err != nil {
			http.Error(w, "subscription interrupted", http.StatusRequestTimeout)
			return
		}
		writeJSON(w, http.StatusOK, page)
	})
	mux.HandleFunc("GET /v1/intents/{digest}", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(authorize, r, false) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		result, err := store.Get("sha256:" + r.PathValue("digest"))
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /v1/intents", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(authorize, r, false) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		query, err := parseQuery(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		page, err := store.Search(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, page)
	})
	mux.HandleFunc("GET /v1/intent-actions/{action}", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(authorize, r, true) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		resolution, err := store.ResolveAction("sha256:"+r.PathValue("action"), r.URL.Query().Get("request_digest"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, resolution)
	})
	return mux
}

func parseQuery(r *http.Request) (Query, error) {
	values := r.URL.Query()
	limit := uint64(100)
	var err error
	if raw := values.Get("limit"); raw != "" {
		limit, err = strconv.ParseUint(raw, 10, 32)
	}
	if err != nil {
		return Query{}, errors.New("invalid limit")
	}
	var after uint64
	if raw := values.Get("cursor"); raw != "" {
		if !strings.HasPrefix(raw, "seq:") {
			return Query{}, errors.New("invalid cursor")
		}
		after, err = strconv.ParseUint(strings.TrimPrefix(raw, "seq:"), 10, 64)
		if err != nil || after == 0 {
			return Query{}, errors.New("invalid cursor")
		}
	}
	query := Query{TaxonomyPrefix: values.Get("taxonomy_prefix"), Keywords: values["keyword"], Limit: uint32(limit), AfterSequence: after}
	for _, raw := range values["mode"] {
		query.Modes = append(query.Modes, commerce.IntentMode(strings.ToUpper(raw)))
	}
	for _, raw := range values["subject_class"] {
		query.SubjectClasses = append(query.SubjectClasses, commerce.SubjectClass(strings.ToUpper(raw)))
	}
	return query, nil
}

func authorized(authorizer HTTPAuthorizer, request *http.Request, write bool) bool {
	return authorizer != nil && authorizer.Authorize(request.Header.Get("Authorization"), write) == nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
