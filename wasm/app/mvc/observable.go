package mvc

type Observable struct {
	listeners []func(*Event)
}

type Event struct {
	Name   string
	Target any
	Data   any
}

func (o *Observable) AddListener(listener func(*Event)) {
	o.listeners = append(o.listeners, listener)
}

func (o *Observable) Notify(event *Event) {
	for _, listener := range o.listeners {
		listener(event)
	}
}
