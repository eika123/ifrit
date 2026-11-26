package dht

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

func (service *Service) ServeDHT(port int) error {
	httpAddr := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("listen HTTP on %d: %w", port, err)
	}
	return http.Serve(listener, service.router())
}

func (service *Service) router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("GET /%s/items", service.ID()),
		func(w http.ResponseWriter, r *http.Request) {
			key := r.URL.Query().Get("q")
			if key == "" {
				http.Error(w, "missing query parameter q", http.StatusBadRequest)
				return
			}
			kvPairs, found := service.items.GetByKey(key)
			if !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(kvPairs)
		},
	)
	mux.HandleFunc(fmt.Sprintf("PUT /%s/items", service.ID()),
		func(w http.ResponseWriter, r *http.Request) {
			var item Item
			if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
				return
			}
			if item.Key == "" {
				http.Error(w, "missing item key", http.StatusBadRequest)
				return
			}
			_, newlyAdded := service.items.Insert(item)
			if newlyAdded {
				w.WriteHeader(http.StatusCreated)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		},
	)

	return mux
}

// Handler returns the HTTP handler serving GET and PUT /<serviceID>/items.
func (service *Service) Handler() http.Handler {
	return service.router()
}
