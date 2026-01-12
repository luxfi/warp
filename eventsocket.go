// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"
	"errors"
	"os"
	"syscall"

	consensuscore "github.com/luxfi/consensus/core"
	"github.com/luxfi/codec/wrappers"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
	"github.com/luxfi/warp/socket"
)

var _ consensuscore.Acceptor = (*EventSockets)(nil)

// EventSockets is a set of named eventSockets
type EventSockets struct {
	consensusSocket *eventSocket
	decisionsSocket *eventSocket
}

// newEventSockets creates a *ChainIPCs with both consensus and decisions IPCs
func newEventSockets(
	ctx ipcContext,
	chainID ids.ID,
	blockAcceptorGroup interface{},
	txAcceptorGroup interface{},
	vertexAcceptorGroup interface{},
) (*EventSockets, error) {
	consensusIPC, err := newEventIPCSocket(
		ctx,
		chainID,
		ipcConsensusIdentifier,
		blockAcceptorGroup,
		vertexAcceptorGroup,
	)
	if err != nil {
		return nil, err
	}

	decisionsIPC, err := newEventIPCSocket(
		ctx,
		chainID,
		ipcDecisionsIdentifier,
		blockAcceptorGroup,
		txAcceptorGroup,
	)
	if err != nil {
		return nil, err
	}

	return &EventSockets{
		consensusSocket: consensusIPC,
		decisionsSocket: decisionsIPC,
	}, nil
}

// Accept delivers a message to the underlying eventSockets
func (ipcs *EventSockets) Accept(ctx context.Context, containerID ids.ID, container []byte) error {
	if ipcs.consensusSocket != nil {
		if err := ipcs.consensusSocket.Accept(ctx, containerID, container); err != nil {
			return err
		}
	}

	if ipcs.decisionsSocket != nil {
		if err := ipcs.decisionsSocket.Accept(ctx, containerID, container); err != nil {
			return err
		}
	}

	return nil
}

// stop closes the underlying eventSockets
func (ipcs *EventSockets) stop() error {
	errs := wrappers.Errs{}

	if ipcs.consensusSocket != nil {
		errs.Add(ipcs.consensusSocket.stop())
	}

	if ipcs.decisionsSocket != nil {
		errs.Add(ipcs.decisionsSocket.stop())
	}

	return errs.Err
}

// ConsensusURL returns the URL of socket receiving consensus events
func (ipcs *EventSockets) ConsensusURL() string {
	return ipcs.consensusSocket.URL()
}

// DecisionsURL returns the URL of socket receiving decisions events
func (ipcs *EventSockets) DecisionsURL() string {
	return ipcs.decisionsSocket.URL()
}

// eventSocket is a single IPC socket for a single chain
type eventSocket struct {
	url          string
	log          log.Logger
	socket       *socket.Socket
	unregisterFn func() error
}

// newEventIPCSocket creates a *eventSocket for the given chain and
// EventDispatcher that writes to a local IPC socket
func newEventIPCSocket(
	ctx ipcContext,
	chainID ids.ID,
	name string,
	linearAcceptorGroup interface{},
	luxAcceptorGroup interface{},
) (*eventSocket, error) {
	var (
		url     = ipcURL(ctx, chainID, name)
		ipcName = ipcIdentifierPrefix + "-" + name
	)

	err := os.Remove(url)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return nil, err
	}

	eis := &eventSocket{
		log:    ctx.log,
		url:    url,
		socket: socket.NewSocket(url, ctx.log),
		unregisterFn: func() error {
			// TODO: AcceptorGroup interface removed from consensus package
			// Need to implement proper registration mechanism or remove this feature
			ctx.log.Warn("acceptor deregistration not implemented")
			return nil
		},
	}

	if err := eis.socket.Listen(); err != nil {
		if err := eis.socket.Close(); err != nil {
			return nil, err
		}
		return nil, err
	}

	// TODO: AcceptorGroup interface removed from consensus package
	// Need to implement proper registration mechanism or remove this feature
	ctx.log.Warn("acceptor registration not implemented",
		log.Stringer("chainID", chainID),
		log.String("name", ipcName),
	)

	return eis, nil
}

// Accept delivers a message to the eventSocket
func (eis *eventSocket) Accept(_ context.Context, _ ids.ID, container []byte) error {
	eis.socket.Send(container)
	return nil
}

// stop unregisters the event handler and closes the eventSocket
func (eis *eventSocket) stop() error {
	eis.log.Info("closing Chain IPC")
	if err := eis.unregisterFn(); err != nil {
		return err
	}
	return eis.socket.Close()
}

// URL returns the URL of the socket
func (eis *eventSocket) URL() string {
	return eis.url
}
