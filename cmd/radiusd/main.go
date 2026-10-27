// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/rkislov/border/internal/aaa"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/directory"
	"github.com/rkislov/border/internal/eap"
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/mail"
	"github.com/rkislov/border/internal/pki"
	"github.com/rkislov/border/internal/selfservice"
	"github.com/rkislov/border/internal/store"
	"github.com/rkislov/border/internal/web"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var version = "0.3.1-dev"

func main() {
	if err := command().Execute(); err != nil {
		os.Exit(1)
	}
}
func command() *cobra.Command {
	var driver, dsn string
	root := &cobra.Command{Use: "radiusd", Short: "Border — RADIUS-сервер и веб-панель", Version: version, SilenceUsage: true}
	root.PersistentFlags().StringVar(&driver, "db-driver", env("BORDER_DB_DRIVER", "sqlite"), "sqlite или pgx")
	root.PersistentFlags().StringVar(&dsn, "db", env("BORDER_DB", "border.db"), "SQLite путь или PostgreSQL DSN (предпочтительно BORDER_DB)")
	withStore := func(fn func(*cobra.Command, *store.Store) error) func(*cobra.Command, []string) error {
		return func(c *cobra.Command, _ []string) error {
			s, err := store.Open(driver, dsn)
			if err != nil {
				return err
			}
			defer s.DB.Close()
			return fn(c, s)
		}
	}
	root.AddCommand(&cobra.Command{Use: "init-db", Short: "Создать или обновить схему БД", Args: cobra.NoArgs, RunE: withStore(func(c *cobra.Command, s *store.Store) error { return s.Migrate(c.Context()) })})
	for _, reset := range []bool{false, true} {
		name := "create-admin"
		short := "Создать администратора"
		if reset {
			name = "reset-admin-password"
			short = "Сбросить пароль администратора"
		}
		r := reset
		root.AddCommand(&cobra.Command{Use: name + " USERNAME", Short: short, Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
			fmt.Fprint(c.ErrOrStderr(), "Пароль (12–72 байта): ")
			p, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(c.ErrOrStderr())
			if err != nil {
				return fmt.Errorf("password requires an interactive terminal: %w", err)
			}
			defer clear(p)
			fmt.Fprint(c.ErrOrStderr(), "Повторите пароль: ")
			again, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(c.ErrOrStderr())
			if err != nil {
				return err
			}
			defer clear(again)
			if string(p) != string(again) {
				return fmt.Errorf("passwords do not match")
			}
			s, err := store.Open(driver, dsn)
			if err != nil {
				return err
			}
			defer s.DB.Close()
			return s.Admin(c.Context(), args[0], string(p), r)
		}})
	}

	root.AddCommand(&cobra.Command{Use: "migrate-db", Short: "Перенести SQLite в пустую PostgreSQL БД (BORDER_SOURCE_DB, BORDER_TARGET_DB)", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		sourcePath, targetDSN := os.Getenv("BORDER_SOURCE_DB"), os.Getenv("BORDER_TARGET_DB")
		if sourcePath == "" || targetDSN == "" {
			return fmt.Errorf("set BORDER_SOURCE_DB and BORDER_TARGET_DB; stop radiusd before migration")
		}
		source, err := store.Open("sqlite", sourcePath)
		if err != nil {
			return err
		}
		defer source.DB.Close()
		if err = source.Migrate(c.Context()); err != nil {
			return err
		}
		target, err := store.Open("pgx", targetDSN)
		if err != nil {
			return err
		}
		defer target.DB.Close()
		if err = target.Migrate(c.Context()); err != nil {
			return err
		}
		return store.Transfer(c.Context(), source, target)
	}})
	root.AddCommand(&cobra.Command{Use: "gen-key", Short: "Сгенерировать 32-байтный BORDER_MASTER_KEY (сохраните вне репозитория)", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		_, err := fmt.Fprintln(c.OutOrStdout(), base64.StdEncoding.EncodeToString(b))
		clear(b)
		return err
	}})
	var dir, host string
	cert := &cobra.Command{Use: "gen-certs", Short: "Создать CA, HTTPS и административный клиентский сертификат", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error { return pki.Generate(dir, host) }}
	cert.Flags().StringVar(&dir, "out", "certs", "Каталог сертификатов")
	cert.Flags().StringVar(&host, "host", "localhost", "DNS-имя или IP сервера")
	root.AddCommand(cert)
	var httpAddr, authAddr, acctAddr, certDir, portalAddr, acmeHTTP, publicURL string
	var workers int
	var adminMTLS bool
	serve := &cobra.Command{Use: "serve", Short: "Запустить RADIUS и HTTPS/mTLS-панель", Args: cobra.NoArgs, RunE: withStore(func(c *cobra.Command, s *store.Store) error {
		if workers < 1 || workers > 1024 {
			return fmt.Errorf("workers must be between 1 and 1024")
		}
		tlsConfig, err := serverTLS(certDir)
		if err != nil {
			return err
		}

		if !adminMTLS {
			tlsConfig.ClientAuth = tls.NoClientCert
			tlsConfig.ClientCAs = nil
		}
		var guests *guest.Service
		var codes *auth.Service
		var managedPKI *pki.Manager
		var acmeClient *pki.ACME
		var domain directory.Authenticator
		if rawKey := os.Getenv("BORDER_MASTER_KEY"); rawKey != "" {
			key, err := base64.StdEncoding.DecodeString(rawKey)
			if err != nil {
				return fmt.Errorf("BORDER_MASTER_KEY must be base64 encoded")
			}
			defer clear(key)
			sender, err := mail.FromEnv()
			if err != nil {
				return err
			}
			var notifier mail.Sender
			if sender != nil {
				notifier = sender
			}
			networkVLAN := 0
			if raw := os.Getenv("BORDER_PORTAL_VLAN"); raw != "" {
				networkVLAN, err = strconv.Atoi(raw)
				if err != nil {
					return fmt.Errorf("invalid BORDER_PORTAL_VLAN")
				}
			}
			codes, err = auth.New(s, key, notifier, networkVLAN)
			if err != nil {
				return err
			}
			guests, err = guest.New(s, key)
			if err != nil {
				return err
			}
			defer guests.Close()
			guests.PublicURL = publicURL
			guests.Reconnect = func(ctx context.Context, nas, id, mac string, vlan int) error {
				var current store.Session
				current.NAS = nas
				current.ID = id
				if err := s.Row(ctx, "SELECT mac,username,updated_at FROM sessions WHERE nas=? AND session_id=? AND status='active'", nas, id).Scan(&current.MAC, &current.Username, &current.Updated); err != nil {
					return err
				}
				if current.MAC != mac {
					return fmt.Errorf("NAS session does not match guest device")
				}
				result, err := aaa.ChangeSession(ctx, s, nas, id, "vlan", vlan, current)
				if err != nil {
					return err
				}
				if !result.Acknowledged {
					return fmt.Errorf("NAS rejected CoA")
				}
				return nil
			}
			managedPKI = &pki.Manager{Store: s, Vault: codes.Vault}
			acmeClient, err = pki.NewACME(c.Context(), managedPKI)
			if err != nil {
				return err
			}
			ldap, err := directory.FromEnv()
			if err != nil {
				return err
			}
			if ldap != nil {
				domain = ldap
			}
			tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, err := acmeClient.GetCertificate(hello)
				if err != nil || cert != nil {
					return cert, err
				}
				return &tlsConfig.Certificates[0], nil
			}
		} else if os.Getenv("BORDER_LDAP_URL") != "" || os.Getenv("BORDER_SMTP_ADDRESS") != "" {
			return fmt.Errorf("LDAP/SMTP require BORDER_MASTER_KEY")
		}
		var eapEngine *eap.Engine
		if managedPKI != nil {
			eapPair := tlsConfig.Certificates[0]
			eapEngine, err = eap.New(eap.Config{
				TLSConfig: func(ctx context.Context) (*tls.Config, error) {
					enabled, _, err := s.EAPPolicy(ctx)
					if err != nil {
						return nil, err
					}
					if !enabled {
						return nil, fmt.Errorf("EAP disabled")
					}
					return managedPKI.EAPTLSConfig(ctx, eapPair)
				},
				Authorize: func(ctx context.Context, state tls.ConnectionState) (eap.Authorization, error) {
					enabled, vlan, err := s.EAPPolicy(ctx)
					if err != nil {
						return eap.Authorization{}, err
					}
					if !enabled {
						return eap.Authorization{}, fmt.Errorf("EAP disabled")
					}
					identity, err := managedPKI.AuthorizeClient(ctx, state)
					if err != nil {
						return eap.Authorization{}, err
					}
					if vlan > 0 {
						var id int
						if err = s.Row(ctx, "SELECT id FROM vlan_catalog WHERE id=?", vlan).Scan(&id); err != nil {
							return eap.Authorization{}, err
						}
					}
					return eap.Authorization{Identity: identity, VLAN: vlan}, nil
				},
			})
			if err != nil {
				return err
			}
			defer eapEngine.Close()
		}
		auth, err := net.ListenPacket("udp", authAddr)
		if err != nil {
			return err
		}
		defer auth.Close()
		acct, err := net.ListenPacket("udp", acctAddr)
		if err != nil {
			return err
		}
		defer acct.Close()
		listener, err := net.Listen("tcp", httpAddr)
		if err != nil {
			return err
		}
		defer listener.Close()
		// The initialized schema must exist; startup does not silently create it.
		if _, err = s.NASList(c.Context()); err != nil {
			return fmt.Errorf("initialize database first: radiusd init-db")
		}
		ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		server := &http.Server{Handler: web.HandlerWithOptions(s, managedPKI, acmeClient, adminMTLS, guests), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
		errors := make(chan error, 5)
		starts := []func() error{func() error {
			return aaa.ServeWithOptions(ctx, auth, s, workers, false, aaa.Options{Network: codesVerifier(codes), EAP: eapEngine, Directory: domain})
		}, func() error { return aaa.Serve(ctx, acct, s, workers, true) }, func() error { return server.Serve(tls.NewListener(listener, tlsConfig)) }}

		extraServers := []*http.Server{}
		if codes != nil && portalAddr != "" {
			portalListener, err := net.Listen("tcp", portalAddr)
			if err != nil {
				return err
			}
			defer portalListener.Close()
			portalTLS := tlsConfig.Clone()
			portalTLS.ClientAuth = tls.NoClientCert
			portalTLS.ClientCAs = nil
			portalServer := &http.Server{Handler: selfservice.New(domain, codes, managedPKI, publicURL, guests).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
			extraServers = append(extraServers, portalServer)
			starts = append(starts, func() error { return portalServer.Serve(tls.NewListener(portalListener, portalTLS)) })
		}
		if acmeClient != nil && acmeHTTP != "" {
			challengeListener, err := net.Listen("tcp", acmeHTTP)
			if err != nil {
				return err
			}
			defer challengeListener.Close()
			challengeServer := &http.Server{Handler: acmeClient.HTTPHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
			extraServers = append(extraServers, challengeServer)
			starts = append(starts, func() error { return challengeServer.Serve(challengeListener) })
		}
		if guests != nil {
			stopCleanup := guests.StartCleanup(ctx)
			defer stopCleanup()
		}
		for _, start := range starts {
			go func(fn func() error) { errors <- fn() }(start)
		}
		slog.Info("Border started", "web", httpAddr, "auth", authAddr, "accounting", acctAddr, "workers_per_port", workers)
		var result error
		pending := len(starts)
		select {
		case <-ctx.Done():
		case result = <-errors:
			pending--
		}
		cancel()
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = server.Shutdown(shutdown)
		for _, extra := range extraServers {
			_ = extra.Shutdown(shutdown)
		}
		// Wait for both remaining listeners before the database is closed.
		for i := 0; i < pending; i++ {
			select {
			case <-errors:
			case <-shutdown.Done():
				return shutdown.Err()
			}
		}
		if result == http.ErrServerClosed {
			return nil
		}
		return result
	})}
	serve.Flags().StringVar(&httpAddr, "web", "127.0.0.1:8443", "HTTPS адрес")
	serve.Flags().StringVar(&authAddr, "auth", ":1812", "RADIUS authentication UDP")
	serve.Flags().StringVar(&acctAddr, "accounting", ":1813", "RADIUS accounting UDP")
	serve.Flags().StringVar(&certDir, "certs", "certs", "Каталог server.pem/server.key/ca.pem")
	serve.Flags().IntVar(&workers, "workers", 256, "Число обработчиков на UDP-порт (1–1024)")
	serve.Flags().StringVar(&portalAddr, "portal", "127.0.0.1:9443", "Отдельный HTTPS портал пользователей (при BORDER_MASTER_KEY)")
	serve.Flags().StringVar(&acmeHTTP, "acme-http", "127.0.0.1:8080", "HTTP-01 listener; пробросьте публичный TCP 80 сюда")
	serve.Flags().StringVar(&publicURL, "portal-url", os.Getenv("BORDER_PORTAL_URL"), "Публичный HTTPS URL портала для CRL")
	serve.Flags().BoolVar(&adminMTLS, "admin-mtls", false, "Требовать клиентский сертификат дополнительно к паролю администратора")
	root.AddCommand(serve)
	return root
}
func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
func serverTLS(dir string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid client CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}

func codesVerifier(s *auth.Service) aaa.NetworkVerifier {
	if s == nil {
		return nil
	}
	return s
}
