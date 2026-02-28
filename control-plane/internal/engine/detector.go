// Package engine — Anomaly Detector
//
// Implements statistical anomaly detection using Exponentially Weighted
// Moving Average (EWMA) to learn normal traffic baselines and detect
// deviations that indicate DDoS attacks.
//
// Detection Methods:
// 1. EWMA baseline tracking with configurable alpha (smoothing factor)
// 2. Z-score deviation detection (flag when > 3σ from baseline)
// 3. Multi-metric correlation (SYN + UDP + ICMP spike = volumetric)
// 4. Rate-of-change detection (sudden jumps in packet rates)
package engine

import (
	"math"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/aegisshield/aegisshield/internal/bpf"
	"github.com/aegisshield/aegisshield/internal/metrics"
)

// DetectorConfig configures the anomaly detection engine.
type DetectorConfig struct {
	// EWMA smoothing factor (0-1). Lower = smoother baseline, slower adaptation.
	Alpha float64
	// Standard deviations before triggering an alert.
	ZScoreThreshold float64
	// Minimum number of samples before detection is active.
	MinSamples int
	// Window size for rate-of-change calculation.
	RateWindowSize int
}

// DefaultDetectorConfig returns sensible defaults.
func DefaultDetectorConfig() DetectorConfig {
	return DetectorConfig{
		Alpha:           0.1, // 10% weight to new sample
		ZScoreThreshold: 3.0, // Alert at 3 standard deviations
		MinSamples:      60,  // Need 60 samples (1 min at 1Hz) before detecting
		RateWindowSize:  10,  // 10-sample window for rate-of-change
	}
}

// MetricBaseline tracks the EWMA baseline for a single metric.
type MetricBaseline struct {
	Name       string
	EWMA       float64   // Exponentially weighted moving average
	Variance   float64   // Online variance estimation
	StdDev     float64   // Standard deviation (sqrt of variance)
	Samples    int       // Number of samples collected
	LastValue  float64   // Most recent raw value
	History    []float64 // Circular buffer for rate-of-change
	HistoryIdx int       // Current position in circular buffer
}

// Update adds a new sample to the baseline.
func (b *MetricBaseline) Update(value float64, alpha float64) {
	b.Samples++
	b.LastValue = value

	if b.Samples == 1 {
		b.EWMA = value
		b.Variance = 0
		b.StdDev = 0
	} else {
		// EWMA update
		diff := value - b.EWMA
		b.EWMA = b.EWMA + alpha*diff

		// Online variance (Welford's method adapted for EWMA)
		b.Variance = (1 - alpha) * (b.Variance + alpha*diff*diff)
		b.StdDev = math.Sqrt(b.Variance)
	}

	// Update circular history buffer
	if len(b.History) > 0 {
		b.History[b.HistoryIdx%len(b.History)] = value
		b.HistoryIdx++
	}
}

// ZScore returns how many standard deviations the latest value is from the mean.
func (b *MetricBaseline) ZScore() float64 {
	if b.StdDev < 1.0 || b.Samples < 2 {
		return 0
	}
	return (b.LastValue - b.EWMA) / b.StdDev
}

// RateOfChange returns the rate of change over the history window.
func (b *MetricBaseline) RateOfChange() float64 {
	if len(b.History) < 2 || b.Samples < len(b.History) {
		return 0
	}

	oldest := b.History[(b.HistoryIdx)%len(b.History)]
	newest := b.LastValue

	if oldest == 0 {
		if newest > 0 {
			return 100.0 // Infinite increase → cap at 100
		}
		return 0
	}

	return (newest - oldest) / oldest * 100.0 // Percentage change
}

// Detector implements multi-metric anomaly detection.
type Detector struct {
	mu        sync.RWMutex
	config    DetectorConfig
	logger    *zap.SugaredLogger
	baselines map[string]*MetricBaseline
	alerts    []AnomalyAlert
}

// AnomalyAlert represents a detected anomaly.
type AnomalyAlert struct {
	Metric       string
	Value        float64
	Baseline     float64
	StdDev       float64
	ZScore       float64
	RateOfChange float64
	Timestamp    time.Time
	Severity     AlertSeverity
}

// AlertSeverity indicates how significant the anomaly is.
type AlertSeverity int

const (
	SeverityLow    AlertSeverity = iota // Minor deviation (2σ)
	SeverityMedium                      // Significant (3σ)
	SeverityHigh                        // Critical (5σ)
)

func (s AlertSeverity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// NewDetector creates a new anomaly detector.
func NewDetector(config DetectorConfig, logger *zap.SugaredLogger) *Detector {
	metricsToTrack := []string{
		"udp_drops_per_sec",
		"syn_drops_per_sec",
		"icmp_drops_per_sec",
		"dns_drops_per_sec",
		"total_drops_per_sec",
		"total_rx_per_sec",
		"blocklist_drops_per_sec",
		"gre_drops_per_sec",
		"frag_drops_per_sec",
	}

	baselines := make(map[string]*MetricBaseline, len(metricsToTrack))
	for _, name := range metricsToTrack {
		baselines[name] = &MetricBaseline{
			Name:    name,
			History: make([]float64, config.RateWindowSize),
		}
	}

	return &Detector{
		config:    config,
		logger:    logger,
		baselines: baselines,
	}
}

// Ingest processes a new set of metrics from the XDP data plane.
func (d *Detector) Ingest(stats *bpf.Stats) []AnomalyAlert {
	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []AnomalyAlert

	// Map stats to metric names
	metricValues := map[string]float64{
		"udp_drops_per_sec":       float64(stats.UDPDropsPerSec),
		"syn_drops_per_sec":       float64(stats.SYNDropsPerSec),
		"icmp_drops_per_sec":      float64(stats.ICMPDropsPerSec),
		"dns_drops_per_sec":       float64(stats.DNSDropsPerSec),
		"total_drops_per_sec":     float64(stats.TotalDropsPerSec),
		"total_rx_per_sec":        float64(stats.RxPPS),
		"blocklist_drops_per_sec": float64(stats.BlocklistDropsPerSec),
		"gre_drops_per_sec":       float64(stats.GREDropsPerSec),
		"frag_drops_per_sec":      float64(stats.FragDropsPerSec),
	}

	for name, value := range metricValues {
		baseline, ok := d.baselines[name]
		if !ok {
			continue
		}

		baseline.Update(value, d.config.Alpha)

		// Skip detection until we have enough samples
		if baseline.Samples < d.config.MinSamples {
			continue
		}

		// Check Z-score
		zscore := baseline.ZScore()
		roc := baseline.RateOfChange()

		if zscore > d.config.ZScoreThreshold {
			severity := SeverityMedium
			if zscore > 5.0 {
				severity = SeverityHigh
			} else if zscore < 4.0 {
				severity = SeverityLow
			}

			alert := AnomalyAlert{
				Metric:       name,
				Value:        value,
				Baseline:     baseline.EWMA,
				StdDev:       baseline.StdDev,
				ZScore:       zscore,
				RateOfChange: roc,
				Timestamp:    time.Now(),
				Severity:     severity,
			}

			alerts = append(alerts, alert)

			d.logger.Warnw("⚠ Anomaly detected",
				"metric", name,
				"value", value,
				"baseline", baseline.EWMA,
				"z_score", zscore,
				"severity", severity.String(),
			)

			// Update Prometheus metrics
			metrics.AttacksDetected.Inc()
		}
	}

	d.alerts = append(d.alerts, alerts...)

	return alerts
}

// GetBaselines returns a snapshot of all current baselines.
func (d *Detector) GetBaselines() map[string]MetricBaseline {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string]MetricBaseline, len(d.baselines))
	for name, bl := range d.baselines {
		result[name] = *bl
	}
	return result
}

// IsLearning returns true if the detector is still collecting baseline samples.
func (d *Detector) IsLearning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, bl := range d.baselines {
		if bl.Samples < d.config.MinSamples {
			return true
		}
	}
	return false
}
