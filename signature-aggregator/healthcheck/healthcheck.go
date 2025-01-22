package healthcheck

import (
	"context"
	"net/http"

	"github.com/alexliesenfeld/health"
)

func HandleHealthCheckRequest(uint16 apiPort) {
	healthChecker := health.NewChecker(
		health.WithCheck(health.Check{
			Name: "signature-aggregator-health",
			Check: func(context.Context) error {
			},
		}),
	)

	readinessCheck := health.NewChecker(
		health.WithCheck(health.Check{
			Name: "signature-aggregator-readiness",
			Check: func(context.Context) error {

			},
		}),
	)
	http.Handle("/health", health.NewHandler(healthChecker))
	http.Handle("/ready", health.NewHandler(readinessCheck))
}
