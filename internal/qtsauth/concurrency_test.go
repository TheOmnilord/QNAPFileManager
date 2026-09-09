package qtsauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidationConcurrencyBound(t *testing.T) {
	for _, configured := range []int{0, 2} {
		t.Run(fmt.Sprint(configured), func(t *testing.T) {
			limit := configured
			if limit == 0 {
				limit = DefaultMaxConcurrentValidations
			}
			entered := make(chan struct{}, 64)
			release := make(chan struct{})
			var active, peak atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				entered <- struct{}{}
				<-release
				fmt.Fprint(w, "<r><authPassed>0</authPassed></r>")
			}))
			defer endpoint.Close()
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			v := newTestVerifier(endpoint)
			v.MaxConcurrentValidations = configured
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					_, err := v.Verify(context.Background(), Cred{Kind: KindSID, Token: fmt.Sprint(i)})
					if !errors.Is(err, ErrNotAuthenticated) {
						t.Errorf("bogus token: %v", err)
					}
				}(i)
			}
			for i := 0; i < limit; i++ {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("validation did not fill available slots")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if _, err := v.Verify(ctx, Cred{Kind: KindSID, Token: "cancelled-waiter"}); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queued cancellation: %v", err)
			}
			v.mu.Lock()
			flights := len(v.inflight)
			v.mu.Unlock()
			if flights != limit || int(peak.Load()) != limit {
				t.Errorf("inflight=%d peak=%d, limit=%d", flights, peak.Load(), limit)
			}
			unblock()
			wg.Wait()
			if int(peak.Load()) > limit || len(v.inflight) != 0 || len(v.validationSlots) != 0 {
				t.Fatal("validation limit exceeded or slots leaked")
			}
		})
	}
}
