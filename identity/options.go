package identity

import "time"

// WithDeliveryQueueTimeout sets a bounded wait timeout for semaphore slot acquisition
// when the delivery concurrency cap (WithDeliveryConcurrency) is saturated.
// If positive, dispatchDelivery will wait up to this duration for an available slot
// before dropping the delivery and returning service_busy (HTTP 429).
// If zero or negative (default), slot acquisition is non-blocking.
func WithDeliveryQueueTimeout(d time.Duration) HandlerOption {
	return func(h *handlerConfig) { h.deliveryQueueTimeout = d }
}
