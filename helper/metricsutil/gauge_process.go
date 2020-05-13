package metricsutil

import (
	"context"
	"math/rand"
	"sort"
	"time"

	log "github.com/hashicorp/go-hclog"
)

// GaugeLabelValues is one gauge in a set sharing a single key, that
// are measured in a batch.
type GaugeLabelValues struct {
	Labels []Label
	Value  float32
}

// GaugeCollector is a callback function that returns an unfiltered
// set of label-value pairs. It may be cancelled if it takes too long.
type GaugeCollector = func(context.Context) ([]GaugeLabelValues, error)

// collectionBound is a hard limit on how long a collection process
// may take, as a fraction of the current interval.
const collectionBound = 0.02

// collectionTarget is a soft limit; if exceeded, the collection interval
// will be doubled.
const collectionTarget = 0.01

// A GaugeCollectionProcess is responsible for one particular gauge metric.
// It handles a delay on initial startup; limiting the cardinality; and exponential
// backoff on the requested interval.
type GaugeCollectionProcess struct {
	Stop             chan bool
	key              []string
	labels           []Label
	collector        GaugeCollector
	sink             *ClusterMetricSink
	originalInterval time.Duration
	currentInterval  time.Duration
	ticker           *time.Ticker
	logger           log.Logger
}

// NewGaugeCollectionProcess creates a new collection process for the callback
// function given as an argument, and starts it running.
// A label should be provided for metrics about this collection process.
func (m *ClusterMetricSink) NewGaugeCollectionProcess(
	key []string,
	id []Label,
	collector GaugeCollector,
	logger log.Logger,
) (*GaugeCollectionProcess, error) {
	process := &GaugeCollectionProcess{
		Stop:             make(chan bool),
		key:              key,
		labels:           id,
		collector:        collector,
		sink:             m,
		originalInterval: m.GaugeInterval,
		currentInterval:  m.GaugeInterval,
		logger:           logger,
	}
	go process.Run()
	return process, nil
}

// delayStart randomly delays by up to one extra interval
// so that collection processes do not all run at the time time.
// If we knew all the procsses in advance, we could just schedule them
// evenly, but a new one could be added per secret engine.
func (p *GaugeCollectionProcess) delayStart() bool {
	randomDelay := time.Duration(rand.Intn(int(p.currentInterval)))
	delayTick := time.NewTimer(randomDelay)
	defer delayTick.Stop()

	select {
	case <-p.Stop:
		return true
	case <-delayTick.C:
		break
	}
	return false
}

// resetTicker stops the old ticker and starts a new one at the current
// interval setting.
func (p *GaugeCollectionProcess) resetTicker() {
	if p.ticker != nil {
		p.ticker.Stop()
	}
	p.ticker = time.NewTicker(p.currentInterval)
}

// collectAndFilterGauges executes the callback function,
// limits the cardinality, and streams the results to the metrics sink.
func (p *GaugeCollectionProcess) collectAndFilterGauges() {
	// Run for only an allotted amount of time.
	timeout := time.Duration(collectionBound * float64(p.currentInterval))
	ctx, cancel := context.WithTimeout(context.Background(),
		timeout)
	defer cancel()

	start := time.Now()
	values, err := p.collector(ctx)
	end := time.Now()
	duration := end.Sub(start)

	p.sink.AddDurationWithLabels([]string{"metrics", "collection"},
		duration,
		p.labels)

	// If over threshold, back off by doubling the measurement interval.
	// Currently a restart is the only way to bring it back down.
	threshold := time.Duration(collectionTarget * float64(p.currentInterval))
	if duration > threshold {
		p.logger.Warn("gauge collection time exceeded target", "target", threshold, "actual", duration, "id", p.labels)
		p.currentInterval *= 2
		p.resetTicker()
	}

	if err != nil {
		p.logger.Error("error collecting gauge", "id", p.labels, "error", err)
		return
	}

	// Filter to top N.
	// This does not guarantee total cardinality is <= N, but it does slow things down
	// a little if the cardinality *is* too high and the gauge needs to be disabled.
	if len(values) > p.sink.MaxGaugeCardinality {
		sort.Slice(values, func(a, b int) bool {
			return values[a].Value > values[b].Value
		})
		values = values[:p.sink.MaxGaugeCardinality]
	}

	// Dumping 500 metrics in one big chunk is somewhat unfriendly to UDP-based
	// transport, and to the rest of the metrics trying to get through.
	// Let's smooth things out over the course of a second.
	// 1 second / 500 = 2 ms each, so we can send 25 per 50 milliseconds.
	// That should be one or two packets.
	sendTick := time.NewTicker(50 * time.Millisecond)
	batchSize := 25
	for i, lv := range values {
		if i > 0 && i%batchSize == 0 {
			<-sendTick.C
		}
		p.sink.SetGaugeWithLabels(p.key, lv.Value, lv.Labels)
	}
	sendTick.Stop()
}

func (p *GaugeCollectionProcess) Run() {
	// Wait a random amount of time
	stopped := p.delayStart()
	if stopped {
		return
	}

	// Create a ticker to start each cycle
	p.resetTicker()

	// Loop until we get a signal to stop
	for {
		select {
		case <-p.ticker.C:
			p.collectAndFilterGauges()
		case <-p.Stop:
			break
		}
	}

	// Can't use defer because this might
	// not be the original ticker.
	p.ticker.Stop()
}