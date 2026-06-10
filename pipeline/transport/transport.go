// Package transport defines the pub-sub boundary between Pipeline
// Components. This is the Hub swap point for the messaging backend: nats/ is
// the OSS default; SQS/SNS and others replace it without touching component
// logic. Components never import a broker client directly.
package transport

// Publisher publishes events to one subject.
type Publisher interface {
	Publish(data []byte) error
	// Healthy reports whether the underlying connection can serve traffic
	// (drives component health endpoints).
	Healthy() bool
	Close() error
}

// Subscriber consumes events from one subject.
type Subscriber interface {
	// Subscribe registers handler and confirms the subscription with the
	// broker before returning. Handlers are invoked sequentially per
	// subscription.
	Subscribe(handler func(data []byte)) error
	// Drain stops delivery after in-flight handlers complete.
	Drain() error
}
