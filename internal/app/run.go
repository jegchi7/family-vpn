package app

import (
	"context"
	"crypto/tls"
	"familyvpn.local/platform/internal/adminauth"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/guides"
	"familyvpn.local/platform/internal/httpapi"
	portalrepo "familyvpn.local/platform/internal/repository"
	"familyvpn.local/platform/internal/store"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Run(admin bool) error {
	defaultAddr := "127.0.0.1:8080"
	if admin {
		defaultAddr = "127.0.0.1:8081"
	}
	addr := flag.String("listen", defaultAddr, "Numeric loopback listener (local modes only)")
	localAuth := flag.Bool("local-auth", false, "Authentication on numeric loopback TLS only; not production")
	cert := flag.String("tls-cert", "", "Local TLS certificate")
	key := flag.String("tls-key", "", "Local TLS key")
	ttl := flag.Duration("session-ttl", 30*24*time.Hour, "Absolute user session lifetime")
	idle := flag.Duration("session-idle", 7*24*time.Hour, "User session idle lifetime")
	demo := flag.Bool("demo", false, "Explicitly enable read-only demo fixtures; no authentication")
	web := flag.String("web-dir", "web/dist", "Built frontend path")
	dbPath := flag.String("portal-db", "var/demo/portal/state.db", "Existing portal DB matching selected local mode; never control store")
	adminDB := flag.String("admin-db", "var/admin/auth/state.db", "Separate admin credentials DB")
	masterKey := flag.String("master-key", "var/admin-secrets/master.key", "External admin encryption key")
	flag.Parse()
	if !*demo && !*localAuth {
		return fmt.Errorf("production mode is not implemented; use explicit --demo or --local-auth for a local stand")
	}
	if *demo && *localAuth {
		return fmt.Errorf("select exactly one local mode")
	}
	if *localAuth && (*cert == "" || *key == "") {
		return fmt.Errorf("local-auth requires TLS certificate/key")
	}
	if err := httpapi.ValidateListen(*addr); err != nil {
		return err
	}
	if *localAuth {
		host, _, _ := net.SplitHostPort(*addr)
		if err := CheckStandTLS(*cert, *key, host, time.Now()); err != nil {
			return err
		}
		if err := CheckStandAssets(*web); err != nil {
			return err
		}
	}
	var repository *store.PortalStore
	var err error
	var authentication *auth.Service
	var devices portalrepo.DeviceWriter
	var adminAuthentication *adminauth.Service
	var adminData portalrepo.AdminReader
	var guideCatalog *guides.Catalog
	if *localAuth {
		guideCatalog, err = guides.Load()
		if err != nil {
			return err
		}
	}
	if *localAuth && !admin {
		repository, err = store.OpenExistingPortal(context.Background(), *dbPath)
	} else {
		repository, err = store.OpenPortal(context.Background(), *dbPath, true)
	}
	if err != nil {
		return err
	}
	defer repository.Close()
	if *localAuth {
		err = repository.AssertLocalAuth(context.Background())
	} else {
		err = repository.AssertDemo(context.Background())
	}
	if err != nil {
		return err
	}
	if *localAuth && !admin {
		devices = repository
		authentication, err = auth.New(repository, nil, *ttl, *idle)
		if err != nil {
			return err
		}
	}
	if *localAuth && admin {
		adminData = repository
		a, e := store.OpenAdmin(context.Background(), *adminDB, false)
		if e != nil {
			return e
		}
		defer a.Close()
		v, e := adminauth.LoadKey(*masterKey)
		if e != nil {
			return e
		}
		adminAuthentication, e = adminauth.New(a, v, nil)
		if e != nil {
			return e
		}
	}
	srv := &http.Server{Addr: *addr, Handler: httpapi.New(httpapi.Options{Admin: admin, Host: *addr, WebDir: *web, Store: repository, Auth: authentication, AdminAuth: adminAuthentication, Devices: devices, AdminData: adminData, Guides: guideCatalog}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		if *localAuth {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			log.Printf("LOCAL AUTH https://%s (admin=%t); no VPN access", *addr, admin)
			done <- srv.ListenAndServeTLS(*cert, *key)
			return
		}
		log.Printf("READ-ONLY DEMO http://%s (admin=%t); no authentication, no VPS access", *addr, admin)
		done <- srv.ListenAndServe()
	}()
	select {
	case err := <-done:
		if err != http.ErrServerClosed {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}
