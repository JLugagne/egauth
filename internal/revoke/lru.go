package revoke

type node[K comparable, V any] struct {
	key        K
	val        V
	prev, next *node[K, V]
}

type lru[K comparable, V any] struct {
	capacity int
	items    map[K]*node[K, V]
	head     *node[K, V]
	tail     *node[K, V]
}

func newLRU[K comparable, V any](capacity int) *lru[K, V] {
	return &lru[K, V]{capacity: capacity, items: make(map[K]*node[K, V])}
}

func (l *lru[K, V]) len() int { return len(l.items) }

func (l *lru[K, V]) get(k K) (V, bool) {
	n, ok := l.items[k]
	if !ok {
		var zero V
		return zero, false
	}
	l.unlink(n)
	l.pushFront(n)
	return n.val, true
}

func (l *lru[K, V]) put(k K, v V) {
	if n, ok := l.items[k]; ok {
		n.val = v
		l.unlink(n)
		l.pushFront(n)
		return
	}
	n := &node[K, V]{key: k, val: v}
	l.items[k] = n
	l.pushFront(n)
	for len(l.items) > l.capacity && l.tail != nil {
		old := l.tail
		l.unlink(old)
		delete(l.items, old.key)
	}
}

func (l *lru[K, V]) remove(k K) {
	n, ok := l.items[k]
	if !ok {
		return
	}
	l.unlink(n)
	delete(l.items, k)
}

func (l *lru[K, V]) clear() {
	clear(l.items)
	l.head, l.tail = nil, nil
}

func (l *lru[K, V]) pushFront(n *node[K, V]) {
	n.prev, n.next = nil, l.head
	if l.head != nil {
		l.head.prev = n
	}
	l.head = n
	if l.tail == nil {
		l.tail = n
	}
}

func (l *lru[K, V]) unlink(n *node[K, V]) {
	if n.prev != nil {
		n.prev.next = n.next
	} else {
		l.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else {
		l.tail = n.prev
	}
	n.prev, n.next = nil, nil
}
