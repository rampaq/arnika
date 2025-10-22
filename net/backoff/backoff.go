package backoff

import "time"

// Backoff is used to wait for variable amount of time, based on number retries = of calls to Next()
type Backoff interface {
	// Next increases the number of retries by one
	Next()
	// Duration returns a duration of the current backoff time. Use this with time.Sleep() or time.After()
	Duration() time.Duration
	// Resets the retry counter
	Reset()
}

var exp = map[int]int{
	0: 1,
	1: 2,
	2: 4,
	3: 8,
	4: 16,
	5: 32,
	6: 64,
}

type ExpBackoff struct {
	retry int
}

func NewExponential() Backoff {
	return &ExpBackoff{0}
}

func (b *ExpBackoff) Next() {
	b.retry++
}

func (b *ExpBackoff) Reset() {
	b.retry = 0
}

func (b *ExpBackoff) Duration() time.Duration {
	var d int
	if 0 <= b.retry && b.retry <= 6 {
		d = exp[b.retry]
	} else {
		d = 120
	}
	return time.Second * time.Duration(d)
}

type FibonacciBackoff struct {
	retry int
}

func NewFibonacci() Backoff {
	return &FibonacciBackoff{0}
}

func (b *FibonacciBackoff) Next() {
	b.retry++
}

func (b *FibonacciBackoff) Reset() {
	b.retry = 0
}

func (b *FibonacciBackoff) Duration() time.Duration {
	d := fibonacciRecursion((20 + b.retry)/10)
	return time.Second * time.Duration(d)
}

func fibonacciRecursion(n int) int {
	if n <= 1 {
		return n
	} else if n > 11 {
		return 120
	}
	return fibonacciRecursion(n-1) + fibonacciRecursion(n-2)
}
