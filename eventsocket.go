// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/luxfi/codec/wrappers"
	"github.com/luxfi/ids"
	log "github.com/luxfi/log"
	"github.com/luxfi/warp/socket"
)

// AcceptorContext is a minimal interface for acceptor callbacks.
// This avoids importing runtime which would create a circular dependency.
type AcceptorContext interface {
	GetChainID() ids.ID
}

// Acceptor is implemented when a struct is monitoring if a message is accepted.
// This mirrors the interface in github.com/luxfi/node/consensus but uses
// AcceptorContext instead of *runtime.Runtime to avoid circular imports.
type Acceptor interface {
	Accept(ctx AcceptorContext, containerID ids.ID, container []byte) error
}

// AcceptorGroup manages multiple acceptors per chain.
// This mirrors the interface in github.com/luxfi/node/consensus but uses
// the local Acceptor interface to avoid circular imports.
type AcceptorGroup interface {
	RegisterAcceptor(chainID ids.ID, acceptorName string, acceptor Acceptor, dieOnError bool) error
	DeregisterAcceptor(chainID ids.ID, acceptorName string) error
}

var _ Acceptor = (*eventSocketAcceptor)(nil)

// eventSocketAcceptor adapts an eventSocket to the Acceptor interface
type eventSocketAcceptor struct {
	socket *eventSocket
}

func (a *eventSocketAcceptor) Accept(_ AcceptorContext, containerID ids.ID, container []byte) error {
	return a.socket.Accept(context.Background(), containerID, container)
}

// EventSockets is a set of named eventSockets
type EventSockets struct {
	consensusSocket *eventSocket
	decisionsSocket *eventSocket
}

// newEventSockets creates a *ChainIPCs with both consensus and decisions IPCs
func newEventSockets(
	ctx ipcContext,
	chainID ids.ID,
	blockAcceptorGroup AcceptorGroup,
	txAcceptorGroup AcceptorGroup,
	vertexAcceptorGroup AcceptorGroup,
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
	linearAcceptorGroup AcceptorGroup,
	luxAcceptorGroup AcceptorGroup,
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
	}

	// Create the adapter that implements Acceptor
	acceptor := &eventSocketAcceptor{socket: eis}

	// Register with both acceptor groups
	if err := linearAcceptorGroup.RegisterAcceptor(chainID, ipcName, acceptor, false); err != nil {
		return nil, err
	}
	if err := luxAcceptorGroup.RegisterAcceptor(chainID, ipcName, acceptor, false); err != nil {
		// Rollback the first registration on failure
		_ = linearAcceptorGroup.DeregisterAcceptor(chainID, ipcName)
		return nil, err
	}

	// Set up the deregistration function for cleanup
	eis.unregisterFn = func() error {
		errs := wrappers.Errs{}
		errs.Add(linearAcceptorGroup.DeregisterAcceptor(chainID, ipcName))
		errs.Add(luxAcceptorGroup.DeregisterAcceptor(chainID, ipcName))
		return errs.Err
	}

	if err := eis.socket.Listen(); err != nil {
		// Clean up registrations on listen failure
		_ = eis.unregisterFn()
		if closeErr := eis.socket.Close(); closeErr != nil {
			return nil, closeErr
		}
		return nil, err
	}

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
