package main

import "time"

var avgWindows = []time.Duration{
	time.Second,
	3 * time.Second,
	5 * time.Second,
	10 * time.Second,
}

type ipStats struct {
	IP          string
	InBytes     uint64
	OutBytes    uint64
	InRate      float64
	OutRate     float64
	Connections []connection
	History     []statSample
}

type statSample struct {
	At       time.Time
	InBytes  uint64
	OutBytes uint64
}

func (s ipStats) Total() uint64 {
	return s.InBytes + s.OutBytes
}

func (s ipStats) TotalRate() float64 {
	return s.InRate + s.OutRate
}

func (s *ipStats) trimHistory(now time.Time) {
	s.History = trimStatHistory(s.History, now)
}

func trimStatHistory(history []statSample, now time.Time) []statSample {
	maxWindow := avgWindows[len(avgWindows)-1] + time.Second
	keepFrom := 0
	for keepFrom < len(history) && now.Sub(history[keepFrom].At) > maxWindow {
		keepFrom++
	}
	if keepFrom > 0 {
		return append([]statSample(nil), history[keepFrom:]...)
	}
	return history
}

func (s *ipStats) ratesForWindow(now time.Time, window time.Duration) (float64, float64) {
	return ratesForHistory(s.History, now, window)
}

func ratesForHistory(history []statSample, now time.Time, window time.Duration) (float64, float64) {
	if len(history) < 2 {
		return 0, 0
	}
	current := history[len(history)-1]
	base := history[0]
	for i := len(history) - 2; i >= 0; i-- {
		if now.Sub(history[i].At) >= window {
			base = history[i]
			break
		}
		base = history[i]
	}
	elapsed := current.At.Sub(base.At).Seconds()
	if elapsed <= 0 {
		return 0, 0
	}
	return float64(current.InBytes-base.InBytes) / elapsed, float64(current.OutBytes-base.OutBytes) / elapsed
}
