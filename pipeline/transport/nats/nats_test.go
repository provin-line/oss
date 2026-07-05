package nats_test

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/pipeline/transport"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
)

// newAccountServer embeds a nats-server with a single operator-trusted account and
// returns its client URL plus that account's nkey seed. Publisher/Subscriber connect
// as this account (minting an ephemeral user JWT) — the production form of the
// slice-16 capstone's natsClient helper. Account isolation across accounts is the
// chainmanager's concern (proven in slice-16); this harness isolates the transport's
// own pub/sub behaviour within one account.
func newAccountServer(t *testing.T) (url, accountSeed string) {
	_, url, accountSeed = newAccountServerWithSrv(t)
	return url, accountSeed
}

// newAccountServerWithSrv is newAccountServer plus the server handle, so a test can
// shut the broker down mid-run (outage path).
func newAccountServerWithSrv(t *testing.T) (srv *server.Server, url, accountSeed string) {
	t.Helper()
	op, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatalf("create operator: %v", err)
	}
	opPub, _ := op.PublicKey()

	acc, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	accPub, _ := acc.PublicKey()
	accSeed, _ := acc.Seed()

	ac := jwt.NewAccountClaims(accPub)
	ajwt, err := ac.Encode(op)
	if err != nil {
		t.Fatalf("encode account JWT: %v", err)
	}
	mr := &server.MemAccResolver{}
	if err := mr.Store(accPub, ajwt); err != nil {
		t.Fatalf("resolver store: %v", err)
	}
	s := natstest.RunServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedKeys: []string{opPub}, AccountResolver: mr,
	})
	t.Cleanup(s.Shutdown)
	return s, s.ClientURL(), string(accSeed)
}

func mustConnect(t *testing.T, url, seed string) *natstransport.Conn {
	t.Helper()
	c, err := natstransport.Connect(natstransport.Config{URL: url, AccountSeed: seed})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestInterfaceSatisfaction(t *testing.T) {
	var _ transport.Publisher = (*natstransport.Publisher)(nil)
	var _ transport.Subscriber = (*natstransport.Subscriber)(nil)
}

func TestConn_PublishSubscribeRoundTrip(t *testing.T) {
	url, seed := newAccountServer(t)
	conn := mustConnect(t, url, seed)

	const subject = "did:dplaax:example:org:pub"
	sub := conn.Subscriber(subject)
	got := make(chan []byte, 1)
	if err := sub.Subscribe(func(data []byte) { got <- data }); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	pub := conn.Publisher(subject)
	if err := pub.Publish([]byte("event")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case b := <-got:
		if string(b) != "event" {
			t.Fatalf("payload: got %q want %q", b, "event")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("round-trip: message not delivered")
	}
}

// TestPublisher_PublishErrorsWhenServerGone asserts the flush-on-Publish contract
// (Codex review P2): Publish must surface a delivery failure rather than silently
// buffering it, so the Loop's emission log cannot record an undelivered message as
// delivered. With the broker gone, a non-flushing Publish returns nil (the PUB is
// queued for the reconnect buffer); flush-on-Publish instead waits for broker
// acknowledgement and returns an error.
//
// The distinguishing behaviour is only observable in the reconnect/outage window (a
// clean Close flushes its buffer, and on loopback the async flusher fires almost
// immediately). It is usually fast (the dead socket is detected on write), but may
// wait out the flush timeout if detection lags, so it is gated behind -short.
func TestPublisher_PublishErrorsWhenServerGone(t *testing.T) {
	if testing.Short() {
		t.Skip("outage path may wait out the flush timeout; skipped in -short")
	}
	srv, url, seed := newAccountServerWithSrv(t)
	conn := mustConnect(t, url, seed)
	pub := conn.Publisher("subj")

	// Confirm the happy path works, then kill the broker.
	if err := pub.Publish([]byte("pre")); err != nil {
		t.Fatalf("Publish (server up): %v", err)
	}
	srv.Shutdown()
	srv.WaitForShutdown()

	if err := pub.Publish([]byte("post")); err == nil {
		t.Fatal("Publish after broker shutdown: want error (undelivered), got nil")
	}
}

func TestPublisher_HealthyReflectsConnection(t *testing.T) {
	url, seed := newAccountServer(t)
	c, err := natstransport.Connect(natstransport.Config{URL: url, AccountSeed: seed})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	pub := c.Publisher("subj")
	if !pub.Healthy() {
		t.Fatal("Healthy: want true while connected")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if pub.Healthy() {
		t.Fatal("Healthy: want false after Conn.Close")
	}
}

func TestSubscriber_SubscribeTwiceErrors(t *testing.T) {
	url, seed := newAccountServer(t)
	conn := mustConnect(t, url, seed)

	sub := conn.Subscriber("subj")
	if err := sub.Subscribe(func([]byte) {}); err != nil {
		t.Fatalf("first Subscribe: %v", err)
	}
	if err := sub.Subscribe(func([]byte) {}); err == nil {
		t.Fatal("second Subscribe: want error, got nil")
	}
}

// TestSubscriber_DrainWaitsForInflight asserts the load-bearing contract (D-17a-5):
// Drain must block until an in-flight handler completes. A direct mapping to nats.go
// Subscription.Drain() (which returns before the background drain finishes) would
// fail this.
func TestSubscriber_DrainWaitsForInflight(t *testing.T) {
	url, seed := newAccountServer(t)
	conn := mustConnect(t, url, seed)

	const subject = "subj"
	sub := conn.Subscriber(subject)
	entered := make(chan struct{})
	release := make(chan struct{})
	handlerDone := make(chan struct{})
	if err := sub.Subscribe(func([]byte) {
		entered <- struct{}{}
		<-release
		close(handlerDone)
	}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	pub := conn.Publisher(subject)
	if err := pub.Publish([]byte("x")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never entered")
	}

	drainDone := make(chan error, 1)
	go func() { drainDone <- sub.Drain() }()

	// Drain must NOT return while the handler is blocked.
	select {
	case <-drainDone:
		t.Fatal("Drain returned before in-flight handler completed")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-drainDone:
		if err != nil {
			t.Fatalf("Drain: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Drain did not return after handler completed")
	}
	select {
	case <-handlerDone:
	default:
		t.Fatal("Drain returned but handler had not completed")
	}
}

// TestSubscriber_SequentialDelivery asserts D-17a-8: handlers are invoked sequentially
// per subscription (never re-entered) and in publish order — the invariant the Loop's
// mutex-free sequence discipline relies on.
func TestSubscriber_SequentialDelivery(t *testing.T) {
	url, seed := newAccountServer(t)
	conn := mustConnect(t, url, seed)

	const (
		subject = "subj"
		n       = 200
	)
	sub := conn.Subscriber(subject)
	var inFlight int32
	var maxConcurrent int32
	order := make([]byte, 0, n)
	done := make(chan struct{})
	if err := sub.Subscribe(func(data []byte) {
		c := atomic.AddInt32(&inFlight, 1)
		if c > atomic.LoadInt32(&maxConcurrent) {
			atomic.StoreInt32(&maxConcurrent, c)
		}
		order = append(order, data[0]) // no lock needed IF delivery is sequential
		atomic.AddInt32(&inFlight, -1)
		if len(order) == n {
			close(done)
		}
	}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	pub := conn.Publisher(subject)
	for i := 0; i < n; i++ {
		if err := pub.Publish([]byte{byte(i)}); err != nil {
			t.Fatalf("Publish %d: %v", i, err)
		}
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("only %d/%d delivered", len(order), n)
	}
	if mc := atomic.LoadInt32(&maxConcurrent); mc != 1 {
		t.Fatalf("handler re-entered: max concurrency %d (want 1)", mc)
	}
	for i := 0; i < n; i++ {
		if order[i] != byte(i) {
			t.Fatalf("out of order at %d: got %d", i, order[i])
		}
	}
}

// TestPublisher_CloseDoesNotCloseSharedConn asserts D-17a-3: one Publisher's Close
// (flush-only) must not tear down the shared connection that sibling Publishers /
// Subscribers on the same Conn depend on.
func TestPublisher_CloseDoesNotCloseSharedConn(t *testing.T) {
	url, seed := newAccountServer(t)
	conn := mustConnect(t, url, seed)

	const subject = "subj"
	sub := conn.Subscriber(subject)
	got := make(chan []byte, 1)
	if err := sub.Subscribe(func(data []byte) { got <- data }); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	p1 := conn.Publisher(subject)
	p2 := conn.Publisher(subject)

	if err := p1.Close(); err != nil {
		t.Fatalf("p1.Close: %v", err)
	}
	// The shared conn must still be healthy and p2 must still deliver.
	if !p2.Healthy() {
		t.Fatal("sibling publisher unhealthy after p1.Close")
	}
	if err := p2.Publish([]byte("after-sibling-close")); err != nil {
		t.Fatalf("p2.Publish: %v", err)
	}
	select {
	case b := <-got:
		if string(b) != "after-sibling-close" {
			t.Fatalf("payload: got %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sibling publisher message not delivered after p1.Close")
	}
}

func TestConnect_FailClosed(t *testing.T) {
	_, goodSeed := newAccountServer(t)
	// A valid operator seed is a valid nkey seed but NOT an account seed.
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()

	cases := []struct {
		name string
		cfg  natstransport.Config
	}{
		{"empty url", natstransport.Config{URL: "", AccountSeed: goodSeed}},
		{"garbage url", natstransport.Config{URL: "://nope", AccountSeed: goodSeed}},
		{"empty seed", natstransport.Config{URL: "nats://127.0.0.1:4222", AccountSeed: ""}},
		{"garbage seed", natstransport.Config{URL: "nats://127.0.0.1:4222", AccountSeed: "not-a-seed"}},
		{"non-account seed", natstransport.Config{URL: "nats://127.0.0.1:4222", AccountSeed: string(opSeed)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := natstransport.Connect(tc.cfg)
			if err == nil {
				_ = c.Close()
				t.Fatalf("Connect(%s): want error, got nil", tc.name)
			}
		})
	}
}

// newTrustedOptions builds operator-trusted server options plus one account, so a
// test can control WHEN the broker starts (boot-race paths).
func newTrustedOptions(t *testing.T, port int) (opts *server.Options, accountSeed string) {
	t.Helper()
	op, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatalf("create operator: %v", err)
	}
	opPub, _ := op.PublicKey()
	acc, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	accPub, _ := acc.PublicKey()
	accSeed, _ := acc.Seed()
	ac := jwt.NewAccountClaims(accPub)
	ajwt, err := ac.Encode(op)
	if err != nil {
		t.Fatalf("encode account JWT: %v", err)
	}
	mr := &server.MemAccResolver{}
	if err := mr.Store(accPub, ajwt); err != nil {
		t.Fatalf("resolver store: %v", err)
	}
	return &server.Options{
		Host: "127.0.0.1", Port: port, NoLog: true, NoSigs: true,
		TrustedKeys: []string{opPub}, AccountResolver: mr,
	}, string(accSeed)
}

// reservePort picks a currently-free loopback TCP port.
func reservePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// The ConnectWait budget covers a broker that starts AFTER the node: the dial
// retries with backoff until the broker accepts, then succeeds.
func TestConnect_WaitsForLateBroker(t *testing.T) {
	port := reservePort(t)
	opts, seed := newTrustedOptions(t, port)

	srvCh := make(chan *server.Server, 1)
	go func() {
		time.Sleep(750 * time.Millisecond)
		srvCh <- natstest.RunServer(opts)
	}()
	// Registered from the main goroutine: a t.Cleanup from the background
	// goroutine could land after the test finished and silently never run.
	t.Cleanup(func() { (<-srvCh).Shutdown() })

	c, err := natstransport.Connect(natstransport.Config{
		URL:         fmt.Sprintf("nats://127.0.0.1:%d", port),
		AccountSeed: seed,
		ConnectWait: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect with ConnectWait against a late broker: %v", err)
	}
	_ = c.Close()
}

// ConnectWait zero preserves the fail-fast contract: no broker, immediate error.
func TestConnect_ZeroWaitFailsFast(t *testing.T) {
	port := reservePort(t)
	_, seed := newTrustedOptions(t, port)
	start := time.Now()
	_, err := natstransport.Connect(natstransport.Config{
		URL:         fmt.Sprintf("nats://127.0.0.1:%d", port),
		AccountSeed: seed,
	})
	if err == nil {
		t.Fatal("Connect with no broker and zero ConnectWait: want error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("zero-wait connect took %s, want fast failure", elapsed)
	}
}

// The budget is bounded: with no broker the retry loop gives up after roughly
// ConnectWait, and the error surfaces the dial failure.
func TestConnect_WaitBudgetExhausted(t *testing.T) {
	port := reservePort(t)
	_, seed := newTrustedOptions(t, port)
	start := time.Now()
	_, err := natstransport.Connect(natstransport.Config{
		URL:         fmt.Sprintf("nats://127.0.0.1:%d", port),
		AccountSeed: seed,
		ConnectWait: 700 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Connect with no broker: want error after budget")
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("budgeted connect took %s, want roughly the 700ms budget (hard bound)", elapsed)
	}
}

// Config-validation failures are config errors, not outages: they never consume
// the retry budget.
func TestConnect_ValidationSkipsWait(t *testing.T) {
	start := time.Now()
	_, err := natstransport.Connect(natstransport.Config{
		URL:         "nats://127.0.0.1:4222",
		AccountSeed: "not-a-seed",
		ConnectWait: 10 * time.Second,
	})
	if err == nil {
		t.Fatal("Connect with a garbage seed: want error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("validation failure took %s, want immediate (no retry budget)", elapsed)
	}
}
