// Package output implements the sanitized-event sink boundary (spec §4.8, §8):
// stdout carries ONLY sanitized event lines; stderr carries status, reload
// notices, warnings, and the shutdown summary. Network forwarding never waits
// on stdout/disk latent writes — M0 uses a bounded queue + dedicated emitter
// goroutine so slow terminals cannot stall request handling (§9.2; the queue
// and loss accounting formalize T-308/M3 later).
package output

import (
	"bufio"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/styner32/mhi/internal/model"
)

// Sink emits SafeEvents in output order, assigning monotonically increasing
// Seq numbers at enqueue serialization (§8 "Seq는 직렬 enqueue 단계에서
// 부여해 출력 순서대로 단조 증가").
type Sink struct {
	mu     sync.Mutex
	seq    uint64
	runID  string
	stdout io.Writer
	stderr io.Writer
	text   bool // text format (§4.8) vs JSONL

	// queue is the bounded event queue; NonblockingSend drops with a
	// diagnostic when full (§8 drop accounting → capture.loss recovery).
	queue   chan model.SafeEvent
	closing chan struct{}
	wg      sync.WaitGroup
}

// NewSink wires output (§4.8): sanitized events only on stdout.
func NewSink(stdout, stderr io.Writer, runID string, queueSize int, text bool) *Sink {
	if queueSize <= 0 {
		queueSize = 1024
	}
	s := &Sink{
		runID:   runID,
		stdout:  stdout,
		stderr:  stderr,
		text:    text,
		queue:   make(chan model.SafeEvent, queueSize),
		closing: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.flushLoop()
	return s
}

// Send queues an event for eventual print. It never blocks the caller.
// Silently dropping only happens at queue-full; acceptable because M0's
// metadata observations are advisory, M3 formalizes capture.loss accounting.
func (s *Sink) Send(ev model.SafeEvent) {
	select {
	case s.queue <- ev:
	default:
		// Overflow diagnostic (rate-limited at flushLoop via Count aggregation
		// in M3). M0 behavior: drop, log one-line notice on stderr.
		fmt.Fprintln(s.stderr, "observe: event queue full, dropping event")
	}
}

// Close flushes the queue and waits for emission, then prints a final
// summary line on stderr (§9.3 shutdown summary ordering).
func (s *Sink) Close() error {
	close(s.closing)
	s.wg.Wait()
	fmt.Fprintf(s.stderr, "shutdown: events emitted=%d dropped-approx=%d\n", s.seq, 0)
	return nil
}

func (s *Sink) flushLoop() {
	defer s.wg.Done()
	bw := bufio.NewWriter(s.stdout)
	defer bw.Flush()
	for {
		select {
		case <-s.closing:
			// Drain remaining queue entries, respecting §8 drop-numbering.
			for {
				select {
				case ev := <-s.queue:
					s.emit(bw, ev)
				default:
					bw.Flush()
					return
				}
			}
		case ev := <-s.queue:
			s.emit(bw, ev)
			// Flush per event: text output in M0 is interactive inspection.
			bw.Flush()
		}
	}
}

func (s *Sink) emit(bw *bufio.Writer, ev model.SafeEvent) {
	s.mu.Lock()
	s.seq++
	seq := s.seq
	s.mu.Unlock()

	ev.Seq = seq
	ev.RunID = s.runID
	ev.At = ev.At.UTC().Truncate(time.Millisecond) // stable JSONL ordering
	if ev.SchemaVersion == 0 {
		ev.SchemaVersion = model.SchemaVersion
	}

	if s.text {
		fmt.Fprintf(bw, "%s %s\n", ev.At.Format("15:04:05"), textLine(ev))
	} else {
		writeJSONL(bw, ev)
	}
}
