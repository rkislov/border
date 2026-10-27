package web

import (
	"context"
	"net/http"
)

type TenantInfo struct{ ID, Name string }
type TenantSpec struct{ ID, Name, Admin, Password string }
type Platform interface {
	List(context.Context) ([]TenantInfo, error)
	Create(context.Context, TenantSpec) error
}

func (a *app) tenantRoutes(m *http.ServeMux) {
	if a.platform == nil {
		return
	}
	m.HandleFunc("GET /api/tenants", func(w http.ResponseWriter, r *http.Request) {
		v, err := a.platform.List(r.Context())
		if err != nil {
			http.Error(w, "tenant catalog unavailable", 503)
			return
		}
		reply(w, v)
	})
	m.HandleFunc("POST /api/tenants", func(w http.ResponseWriter, r *http.Request) {
		var v TenantSpec
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.platform.Create(r.Context(), v), "create isolated tenant")
	})
}
