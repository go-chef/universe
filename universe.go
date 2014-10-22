/*
 * Copyright (c) 2013-2014, Jeremy Bingham (<jbingham@gmail.com>)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// A standalone version of /universe. Mostly experimental, but potentially
// useful nonetheless.

package main

import (
	"compress/gzip"
	"crypto/tls"
	"encoding/gob"
	"github.com/ctdk/goas/v2/logger"
	"github.com/ctdk/goiardi/actor"
	"github.com/ctdk/goiardi/authentication"
	"github.com/ctdk/goiardi/config"
	"github.com/ctdk/goiardi/cookbook"
	"github.com/ctdk/goiardi/datastore"
	"github.com/ctdk/goiardi/organization"
	"github.com/ctdk/goiardi/universe"
	"github.com/ctdk/goiardi/user"
	"github.com/ctdk/goiardi/util"
	"github.com/gorilla/mux"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
)

type interceptHandler struct {
	router *mux.Router
}

func main() {
	// use the goiardi config lib for now
	config.ParseConfigOptions()

	// later, we'll probably need to only allow Postgres, since this will
	// generally be running alongside Chef Server. For testing, though, use
	// the in-mem data file. Generally, of course, this should NOT be shared
	// between processes.
	/* Here goes nothing, db... */
	if config.UsingDB() {
		var derr error
		if config.Config.UseMySQL {
			datastore.Dbh, derr = datastore.ConnectDB("mysql", config.Config.MySQL)
		} else if config.Config.UsePostgreSQL {
			datastore.Dbh, derr = datastore.ConnectDB("postgres", config.Config.PostgreSQL)
		}
		if derr != nil {
			logger.Criticalf(derr.Error())
			os.Exit(1)
		}
	}
	gobRegister()
	ds := datastore.New()
	if config.Config.FreezeData {
		if config.Config.DataStoreFile != "" {
			uerr := ds.Load(config.Config.DataStoreFile)
			if uerr != nil {
				logger.Criticalf(uerr.Error())
				os.Exit(1)
			}
		}
	}
	handleSignals()
	muxer := mux.NewRouter()
	muxer.NotFoundHandler = http.HandlerFunc(notFoundHandler)
	muxer.HandleFunc("/organizations/{org}/universe", universe.UniverseHandler)
	h := &interceptHandler{router: muxer}

	listenAddr := config.ListenAddr()
	var err error
	srv := &http.Server{Addr: listenAddr, Handler: h}
	if config.Config.UseSSL {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS10}
		err = srv.ListenAndServeTLS(config.Config.SSLCert, config.Config.SSLKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil {
		logger.Criticalf("ListenAndServe: %s", err.Error())
		os.Exit(1)
	}
}

func handleSignals() {
	c := make(chan os.Signal, 1)
	// SIGTERM is not exactly portable, but Go has a fake signal for it
	// with Windows so it being there should theoretically not break it
	// running on windows
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	// if we receive a SIGINT or SIGTERM, do cleanup here.
	go func() {
		for sig := range c {
			if sig == os.Interrupt || sig == syscall.SIGTERM {
				if config.UsingDB() {
					datastore.Dbh.Close()
				}
				os.Exit(0)
			} else if sig == syscall.SIGHUP {
				logger.Infof("Reloading configuration...")
				config.ParseConfigOptions()
			}
		}
	}()
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	util.JSONErrorReport(w, r, "not found", http.StatusNotFound)
	return
}

func (h *interceptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	/* knife sometimes sends URL paths that start with //. Redirecting
	 * worked for GETs, but since it was breaking POSTs and screwing with
	 * GETs with query params, we just clean up the path and move on. */

	/* log the URL */
	logger.Debugf("Serving %s -- %s", r.URL.Path, r.Method)

	if r.Method != "CONNECT" {
		if p := cleanPath(r.URL.Path); p != r.URL.Path {
			r.URL.Path = p
		}
	}

	/* Make configurable, I guess, but Chef wants it to be 1000000 */
	if !strings.HasPrefix(r.URL.Path, "/file_store") && r.ContentLength > config.Config.JSONReqMaxSize {
		http.Error(w, "Content-length too long!", http.StatusRequestEntityTooLarge)
		return
	} else if r.ContentLength > config.Config.ObjMaxSize {
		http.Error(w, "Content-length waaaaaay too long!", http.StatusRequestEntityTooLarge)
		return
	}

	w.Header().Set("X-Goiardi", "yes")
	w.Header().Set("X-Goiardi-Version", config.Version)
	w.Header().Set("X-Chef-Version", config.ChefVersion)
	apiInfo := util.JoinStr("flavor=osc;version:", config.ChefVersion, ";goiardi=", config.Version)
	w.Header().Set("X-Ops-API-Info", apiInfo)

	userID := r.Header.Get("X-OPS-USERID")
	if rs := r.Header.Get("X-Ops-Request-Source"); rs == "web" {
		/* If use-auth is on and disable-webui is on, and this is a
		 * webui connection, it needs to fail. */
		if config.Config.DisableWebUI {
			w.Header().Set("Content-Type", "application/json")
			logger.Warningf("Attempting to log in through webui, but webui is disabled")
			util.JSONErrorReport(w, r, "invalid action", http.StatusUnauthorized)
			return
		}

		/* Check that the user in question with the web request exists.
		 * If not, fail. */
		pathArray := strings.Split(r.URL.Path[1:], "/")
		var org *organization.Organization
		if pathArray[0] == "organization" {
			var err error
			org, err = organization.Get(pathArray[1])
			if err != nil {
				util.JSONErrorReport(w, r, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if _, uherr := actor.GetReqUser(org, userID); uherr != nil {
			w.Header().Set("Content-Type", "application/json")
			logger.Warningf("Attempting to use invalid user %s through X-Ops-Request-Source = web", userID)
			util.JSONErrorReport(w, r, "invalid action", http.StatusUnauthorized)
			return
		}
		userID = "chef-webui"
	}
	/* Only perform the authorization check if that's configured. Bomb with
	 * an error if the check of the headers, timestamps, etc. fails. */
	/* No clue why /principals doesn't require authorization. Hrmph. */
	if config.Config.UseAuth && !strings.HasPrefix(r.URL.Path, "/file_store") && !(strings.HasPrefix(r.URL.Path, "/principals") && r.Method == "GET") {
		herr := authentication.CheckHeader(userID, r)
		if herr != nil {
			w.Header().Set("Content-Type", "application/json")
			logger.Errorf("Authorization failure: %s\n", herr.Error())
			w.Header().Set("Www-Authenticate", `X-Ops-Sign version="1.0" version="1.1" version="1.2"`)
			util.JSONErrorReport(w, r, herr.Error(), herr.Status())
			return
		}
	}

	// Experimental: decompress gzipped requests
	if r.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			logger.Errorf("Failure decompressing gzipped request body: %s\n", err.Error())
			util.JSONErrorReport(w, r, err.Error(), http.StatusBadRequest)
			return
		}
		r.Body = reader
	}

	//http.DefaultServeMux.ServeHTTP(w, r)
	// Now instead of using the default ServeHTTP, we use the gorilla mux
	// one. We aren't able to use it directly, however, because the chef
	// clients and knife get unhappy unless we're able to do the above work
	// before serving the reuquests.
	h.router.ServeHTTP(w, r)
}

func cleanPath(p string) string {
	/* Borrowing cleanPath from net/http */
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}
	return np
}

func gobRegister() {
	mis := map[int]interface{}{}
	gob.Register(mis)
	msss := make(map[string][]string)
	gob.Register(msss)
	msi := make(map[string][]int)
	gob.Register(msi)
	o := new(organization.Organization)
	gob.Register(o)
	gob.Register(new(user.User))
	gob.Register(new(cookbook.Cookbook))
	m := make(map[string]interface{})
	gob.Register(m)
}
