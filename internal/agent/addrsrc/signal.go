package addrsrc

// signal does a coalescing, non-blocking send on ch.
func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
