// Copyright © 2024 Michael Fero
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
	"github.com/mikefero/kheper/internal/api"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/utils"
	middleware "github.com/oapi-codegen/nethttp-middleware"
	"github.com/riandyrn/otelchi"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var (
	singleton *http.Server
	once      sync.Once
)

// Opts are the options used to create a new admin API server.
type Opts struct {
	// Database is the database to use for retrieving data.
	Database *database.Database
	// Port is the port to run the API server on.
	Port int
	// ReadTimeout is the timeout for reading the request body.
	ReadTimeout time.Duration
	// ReadHeaderTimeout is the timeout for reading the headers.
	ReadHeaderTimeout time.Duration
	// WriteTimeout is the timeout for writing the response.
	WriteTimeout time.Duration
	// OpenTelemetryEnabled is a flag to indicate whether OpenTelemetry is
	// enabled or not.
	OpenTelemetryEnabled bool
	// Logger is the logger to use for logging.
	Logger *zap.Logger
}

type handler struct {
	db     *database.Database
	logger *zap.Logger
}

// NewServer creates a new server for the admin API. This function is safe to
// call multiple times and will only create the server once.
// Note: Ensure that upon error the application is properly terminated.
func NewServer(opts Opts) (*http.Server, error) {
	// Validate the options
	if opts.Database == nil {
		return nil, errors.New("database must be set")
	}
	if err := utils.ValidatePort(opts.Port); err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	if opts.ReadTimeout <= 0 {
		return nil, errors.New("read timeout must be > 0")
	}
	if opts.ReadHeaderTimeout <= 0 {
		return nil, errors.New("read header timeout must be > 0")
	}
	if opts.WriteTimeout <= 0 {
		return nil, errors.New("write timeout must be > 0")
	}
	if opts.Logger == nil {
		return nil, errors.New("logger must be set")
	}

	var err error
	once.Do(func() {
		var swagger *openapi3.T
		swagger, err = api.GetSwagger()
		if err != nil {
			err = fmt.Errorf("unable to retrieve swagger: %w", err)
		}

		logger := opts.Logger.With(zap.String("component", "router"))
		options := &middleware.Options{
			ErrorHandler: func(w http.ResponseWriter, detail string, status int) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(status)
				err := json.NewEncoder(w).Encode(api.Error{
					Status: status,
					Title:  http.StatusText(status),
					Detail: detail,
				})
				if err != nil {
					logger.Error("unable to encode response error", zap.Error(err))
				}
			},
		}
		validator := middleware.OapiRequestValidatorWithOptions(swagger, options)

		// Create the router and add the middleware
		router := chi.NewRouter()
		router.Use(chiLogger(logger))
		router.Use(chiPanicHandler(logger))
		if opts.OpenTelemetryEnabled {
			router.Use(otelchi.Middleware("kheper", otelchi.WithChiRoutes(router)))
			router.Use(traceResponse)
		}
		router.Use(validator)

		// Create the handler
		api.HandlerFromMux(&handler{
			db:     opts.Database,
			logger: logger,
		}, router)

		// Create the server
		singleton = &http.Server{
			Handler:           router,
			ReadTimeout:       opts.ReadTimeout,
			ReadHeaderTimeout: opts.ReadHeaderTimeout,
			WriteTimeout:      opts.WriteTimeout,
			Addr:              fmt.Sprintf(":%d", opts.Port),
		}
	})

	if err != nil {
		return nil, fmt.Errorf("unable to create database: %w", err)
	}
	return singleton, nil
}

func chiLogger(logger *zap.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info("request",
				zap.String("method", r.Method),
				zap.String("remote-address", r.RemoteAddr),
				zap.String("url", r.URL.String()),
			)

			// Handle the next request in the chain.
			next.ServeHTTP(w, r)
		})
	}
}

func chiPanicHandler(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recoverError := recover(); recoverError != nil {
					stackBuf := make([]byte, 1024)
					n := runtime.Stack(stackBuf, false)
					stackTrace := string(stackBuf[:n])
					err, ok := recoverError.(error)
					if !ok {
						logger.Error("panic",
							zap.String("method", r.Method),
							zap.String("remote-address", r.RemoteAddr),
							zap.String("url", r.URL.String()),
							zap.Any("error", recoverError),
							zap.String("stacktrace", stackTrace),
						)
					} else {
						logger.Error("panic",
							zap.String("method", r.Method),
							zap.String("remote-address", r.RemoteAddr),
							zap.String("url", r.URL.String()),
							zap.Error(err),
							zap.String("stacktrace", stackTrace),
						)
					}

					w.WriteHeader(http.StatusInternalServerError)
					encErr := json.NewEncoder(w).Encode(api.Error{
						Status: http.StatusInternalServerError,
						Title:  http.StatusText(http.StatusInternalServerError),
						Detail: "A critical failure has occurred on the server",
					})
					if encErr != nil {
						logger.Error("unable to encode database insert response error",
							zap.String("method", r.Method),
							zap.String("remote-address", r.RemoteAddr),
							zap.String("url", r.URL.String()),
							zap.Error(err))
					}
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func traceResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		if span != nil {
			spanContext := span.SpanContext()
			if spanContext.IsValid() {
				w.Header().Set("X-Trace-Id", spanContext.TraceID().String())
				w.Header().Set("X-Span-Id", spanContext.SpanID().String())
			}
		}
		next.ServeHTTP(w, r)
	})
}
