package tick

import (
	"context"
	"crypto/rand"
	"math/big"
	"time"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Ticker struct {
	Interval time.Duration
	Jitter   time.Duration

	Logger *zap.Logger
	Tracer trace.Tracer
}

func (t *Ticker) Start(ctx context.Context, f func(context.Context)) {
	// Create a jittered ping interval function
	pingInterval := func() time.Duration {
		jitter, err := rand.Int(rand.Reader, big.NewInt(t.Jitter.Nanoseconds()))
		if err != nil {
			t.Logger.Error("unable to generate jitter", zap.Error(err))
			jitter = big.NewInt(0)
		}
		t.Logger.Debug("ping interval",
			zap.Duration("interval", t.Interval),
			zap.Duration("jitter", time.Duration(jitter.Int64())),
		)
		return t.Interval + time.Duration(jitter.Int64())
	}

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(pingInterval()):
			var span trace.Span
			if t.Tracer != nil {
				ctx, span = t.Tracer.Start(ctx, "ping-interval")
			}
			f(ctx)
			if span != nil {
				span.End()
			}
		}
	}()
}
