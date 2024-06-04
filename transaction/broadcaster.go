package transaction

type BroadcastSuccess struct {
	Txid    string `json:"txid"`
	Message string `json:"message"`
}

type BroadcastFailure struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}

func (e *BroadcastFailure) Error() string {
	return e.Description
}

type Broadcaster interface {
	Broadcast(tx *Transaction) (*BroadcastSuccess, *BroadcastFailure)
}

func (t *Transaction) Broadcast(b Broadcaster) (*BroadcastSuccess, *BroadcastFailure) {
	return b.Broadcast(t)
}
