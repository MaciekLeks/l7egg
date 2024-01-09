package metrics

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog/v2"
	"net/http"
)

var (
	CommonNameTotalRequests = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "l7egg_common_name_total_requests",
			Help: "Gauge for requests from different Common Names",
		},
		[]string{"in_acl", "cn", "cidr", "port"},
	)
)

func init() {
	prometheus.MustRegister(CommonNameTotalRequests)
}

func RunServer(ctx context.Context, address string) *http.Server {
	logger := klog.FromContext(ctx)
	http.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: address}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			logger.Error(err, "Prometheus: ListenAndServe() error")
		}
	}()
	return srv
}
