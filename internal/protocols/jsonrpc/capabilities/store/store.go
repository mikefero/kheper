package store

import (
	"context"
	"sync/atomic"

	"github.com/Kong/go-openrpc/runtime"
	"github.com/google/uuid"
	"github.com/mikefero/kheper/internal/database"
)

type MethodStore interface {
	RecordMethodCall(runtime.Params, runtime.Response) error
	RecordErrorResponse(err error) error
}

type methodStore struct {
	db      *database.Database
	nodeId  uuid.UUID
	counter atomic.Int64
}

func NewMethodStore(db *database.Database, nodeId uuid.UUID) MethodStore {
	return &methodStore{
		db:     db,
		nodeId: nodeId,
	}
}

func (s *methodStore) RecordMethodCall(params runtime.Params, resp runtime.Response) error {
	return s.db.SaveRPC(context.Background(), database.RPCMethodRecord{
		NodeId:   s.nodeId,
		Seq:      s.counter.Add(1),
		Params:   params,
		Response: resp,
	})
}

func (s *methodStore) RecordErrorResponse(err error) error {
	return s.db.SaveRPC(context.Background(), database.RPCMethodRecord{
		NodeId: s.nodeId,
		Seq:    s.counter.Add(1),
		Error:  err,
	})
}
