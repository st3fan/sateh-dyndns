// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
)

//

func parseRemoteAddr(address string) (string, error) {
	addr, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.Wrapf(err, "could not split remote address <%s>", address)
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return "", errors.Errorf("could not parse remote address <%s>", addr)
	}

	if ip.To4() == nil {
		return "", errors.Errorf("remote address <%s> is not IPv4", addr)
	}

	return addr, err
}

func parseProxyProvidedAddr(r *http.Request) (string, error) {
	if addr := r.Header.Get("X-Real-IP"); addr != "" {
		ip := net.ParseIP(addr)
		if ip == nil {
			return "", errors.Errorf("could not parse proxy provided address <%s>", addr)
		}

		if ip.To4() == nil {
			return "", errors.Errorf("proxy provided address <%s> is not IPv4", addr)
		}

		return addr, nil
	}

	return "", errors.New("no proxy provided address")
}

//

type Updater interface {
	UpdateRecord(ctx context.Context, address string) error
}

type CloudflareUpdater struct {
	api        *cloudflare.API
	token      string
	zoneName   string
	recordName string
}

func (u *CloudflareUpdater) UpdateRecord(ctx context.Context, address string) error {
	// Get the Zone ID

	zoneID, err := u.api.ZoneIDByName(u.zoneName)
	if err != nil {
		return err
	}

	// Find the Record

	listRecordsParams := cloudflare.ListDNSRecordsParams{
		Type: "A",
		Name: u.recordName + "." + u.zoneName,
	}

	records, _, err := u.api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), listRecordsParams)
	if err != nil {
		return err
	}

	if len(records) != 1 {
		return errors.Errorf("expected 1 record but found %d", len(records))
	}

	// If the record is already up to date then we don't have to do anything

	if records[0].Content == address {
		return nil
	}

	// Update the record

	updateParams := cloudflare.UpdateDNSRecordParams{
		ID:      records[0].ID,
		Content: address,
	}

	if _, err := u.api.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), updateParams); err != nil {
		log.Printf("could not update record: %s", err)
	}

	return nil
}

func newCloudflareUpdater(token string, zoneName string, recordName string) (*CloudflareUpdater, error) {
	api, err := cloudflare.NewWithAPIToken(token)
	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if _, err := api.VerifyAPIToken(context.Background()); err != nil {
		return nil, err
	}

	return &CloudflareUpdater{
		api:        api,
		token:      token,
		zoneName:   zoneName,
		recordName: recordName,
	}, nil
}

//

type configuration struct {
	BindPort        int    `envconfig:"BIND_PORT" default:"8080"`
	BindAddress     string `envconfig:"BIND_ADDRESS" default:"0.0.0.0"`
	CloudFlareToken string `envconfig:"CLOUDFLARE_API_TOKEN" required:"true"`
	ZoneName        string `envconfig:"ZONE_NAME" required:"true"`
	RecordName      string `envconfig:"RECORD_NAME" required:"true"`
	AccessToken     string `envconfig:"ACCESS_TOKEN" required:"true"`
	UseProxyHeaders bool   `envconfig:"USE_PROXY_HEADERS" default:"false"`
}

func newConfigurationFromEnvironment() (configuration, error) {
	var cfg configuration
	if err := envconfig.Process("", &cfg); err != nil {
		return configuration{}, errors.Wrap(err, "can't parse configuration from environment")
	}

	return cfg, nil
}

//

type application struct {
	cfg                configuration
	router             *mux.Router
	server             *http.Server
	updater            *CloudflareUpdater
	lastUpdatedAddress string
}

func parseAuthorization(authorization string) (string, error) {
	fields := strings.Fields(authorization)
	if len(fields) != 2 || fields[0] != "Bearer" {
		return "", errors.Errorf("invalid authorization header")
	}
	return fields[1], nil
}

func (app *application) getRemoteAddress(r *http.Request) (string, error) {
	if app.cfg.UseProxyHeaders {
		address, err := parseProxyProvidedAddr(r)
		if err != nil {
			return "", errors.Wrap(err, "could not parse proxy provided address")
		}
		return address, nil
	} else {
		address, err := parseRemoteAddr(r.RemoteAddr)
		if err != nil {
			return "", errors.Wrap(err, "could not parse remote address")
		}
		return address, nil
	}
}

func (app *application) handleUpdate(w http.ResponseWriter, r *http.Request) {
	address, err := app.getRemoteAddress(r)
	if err != nil {
		log.Printf("Failed to get remote address: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	accessToken, err := parseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		log.Printf("Failed to parse authorization from <%s>: %s", r.RemoteAddr, err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if accessToken != app.cfg.AccessToken {
		log.Printf("Incorrect authorization from <%s>", r.RemoteAddr)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// We don't have to do anything if we already updated to this address
	if app.lastUpdatedAddress == address {
		return
	}

	if err := app.updater.UpdateRecord(context.Background(), address); err != nil {
		log.Printf("Failed to update <%s.%s> to <%s>: %s", app.cfg.RecordName, app.cfg.ZoneName, address, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	app.lastUpdatedAddress = address
}

func (app *application) handleHealth(w http.ResponseWriter, r *http.Request) {
}

func (app *application) run() error {
	return app.server.ListenAndServe()
}

func newApplication(cfg configuration) (*application, error) {
	updater, err := newCloudflareUpdater(cfg.CloudFlareToken, cfg.ZoneName, cfg.RecordName)
	if err != nil {
		return nil, errors.Wrap(err, "can't create updater")
	}

	app := &application{
		cfg:     cfg,
		updater: updater,
	}

	app.router = mux.NewRouter()
	app.router.HandleFunc("/update", app.handleUpdate).Methods("POST")
	app.router.HandleFunc("/health", app.handleHealth).Methods("GET")

	app.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.BindAddress, cfg.BindPort),
		Handler: app.router,
	}

	return app, nil
}

//

func main() {
	// If we are running under systemd then no need to log datestamps
	if os.Getenv("INVOCATION_ID") != "" {
		log.SetFlags(0)
	}

	log.Printf("Hello this is sateh-dyndns")

	cfg, err := newConfigurationFromEnvironment()
	if err != nil {
		log.Fatalf("Failed to parse config from environment: %s", err)
	}

	app, err := newApplication(cfg)
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}

	log.Printf("Starting server on <%s:%d>", cfg.BindAddress, cfg.BindPort)

	if err := app.run(); err != nil {
		log.Fatalf("Failed to run application: %s", err)
	}
}
