package store

import (
	"context"
	"github.com/rkislov/border/internal/radprofile"
)

func (s *Store) NASProfile(ctx context.Context, nas string) (radprofile.Config, error) {
	var c radprofile.Config
	err := s.Row(ctx, "SELECT dictionary,access_mode,credential FROM nas WHERE address=?", nas).Scan(&c.Dictionary, &c.Mode, &c.Credential)
	if err == nil {
		err = c.Validate()
	}
	return c, err
}
func (s *Store) NASGrant(ctx context.Context, nas, user, mode string) (radprofile.Grant, error) {
	g := radprofile.Grant{NAS: nas, Username: user, Mode: mode}
	err := s.Row(ctx, "SELECT role,group_name,filter_id,privilege FROM nas_grants WHERE nas=? AND username=? AND mode=?", nas, user, mode).Scan(&g.Role, &g.Group, &g.Filter, &g.Privilege)
	return g, err
}
func (s *Store) NASGrants(ctx context.Context) ([]radprofile.Grant, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT nas,username,mode,role,group_name,filter_id,privilege FROM nas_grants ORDER BY nas,username,mode")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []radprofile.Grant{}
	for rows.Next() {
		var g radprofile.Grant
		if err = rows.Scan(&g.NAS, &g.Username, &g.Mode, &g.Role, &g.Group, &g.Filter, &g.Privilege); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
