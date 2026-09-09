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

func TestValidationWaitersIncludeSingleFlight(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprint(shared), func(t *testing.T) {
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-release
				fmt.Fprint(w, "<r><authPassed>0</authPassed></r>")
			}))
			defer endpoint.Close()
			defer unblock()
			v := newTestVerifier(endpoint)
			results := make(chan error, 200)
			for i := 0; i < 200; i++ {
				go func(i int) {
					token := fmt.Sprint(i)
					if shared {
						token = "same"
					}
					_, err := v.Verify(context.Background(), Cred{Kind: KindSID, Token: token})
					results <- err
				}(i)
			}
			active := DefaultMaxConcurrentValidations
			if shared {
				active = 1
			}
			admitted := active + DefaultMaxValidationWaiters
			for i := 0; i < 200-admitted; i++ {
				select {
				case err := <-results:
					if !errors.Is(err, ErrOverloaded) {
						t.Fatalf("excess waiter: %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("excess waiter blocked")
				}
			}
			v.mu.Lock()
			waiting, flights := v.waiters, len(v.inflight)
			v.mu.Unlock()
			if waiting != DefaultMaxValidationWaiters || flights != active {
				t.Fatalf("waiting=%d active=%d", waiting, flights)
			}
			unblock()
			for i := 0; i < admitted; i++ {
				if err := <-results; !errors.Is(err, ErrNotAuthenticated) {
					t.Errorf("admitted request: %v", err)
				}
			}
			v.mu.Lock()
			defer v.mu.Unlock()
			if v.waiters != 0 || len(v.validationSlots) != 0 || len(v.inflight) != 0 {
				t.Fatal("admission capacity leaked")
			}
		})
	}
}
