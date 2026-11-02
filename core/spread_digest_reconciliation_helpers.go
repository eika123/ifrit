package core

import (
	"bytes"
	"errors"

	log "github.com/inconshreveable/log15"
	pb "github.com/joonnna/ifrit/protobuf"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (n *Node) computeControlAndDataDeltas(remoteId string, args *pb.State, reply *pb.StateResponse) error {
	hasFingerprints := args.GetFingerprintView() != nil || args.GetFingerprintAccusations() != nil || args.GetFingerprintData() != nil || args.GetFingerprintCertificates() != nil

	if hasFingerprints {
		var peerSess *PeerReconcileSession
		var seq uint64
		if n.sessionManager != nil {
			selfId := ""
			if n.self != nil {
				selfId = n.self.Id
			}
			peerSess = n.sessionManager.GetOrCreate(remoteId)
			var err error
			var ok bool
			seq, ok, err = peerSess.TryStartInboundReconciling(selfId, remoteId)
			if !ok {
				if errors.Is(err, ErrSessionBusy) {
					return status.Error(codes.Aborted, ErrSessionBusy.Error())
				}
				if err != nil {
					return err
				}
				return status.Error(codes.Aborted, ErrSessionBusy.Error())
			}
		}

		n.computeCertificateDeltas(args, reply)
		n.computeNoteDeltas(args, reply)
		n.computeAccusationDeltas(args, reply)
		n.computeDataDeltas(args, reply)

		if peerSess != nil {
			peerSess.SetDeltas(seq, ExtractReconcileDeltas(reply))
			peerSess.TransitionAfterReconcile(seq, false)
		}
	}

	return nil
}

// computeStoreDeltas runs a generic set difference computation against store using the provided constructor closure.
func computeStoreDeltas[T any](
	store ReverseIndexStore[T, revIdxStore.DigestSymbol],
	callerFingerprint []byte,
	localFingerprint []byte,
	incomingDigests []uint64,
	constructor SessionConstructor[T, revIdxStore.DigestSymbol],
) (localDelta []T, localDigests, requestedDigests []uint64, err error) {
	if callerFingerprint == nil || bytes.Equal(callerFingerprint, localFingerprint) || store == nil {
		return nil, nil, nil, nil
	}
	if constructor == nil {
		constructor = DefaultSessionConstructor[T]()
	}

	session, err := constructor(store)
	if err != nil {
		return nil, nil, nil, err
	}

	incomingSymbols := revIdxStore.AsDigestSymbols(incomingDigests)
	delta, locDigs, reqDigs := ReconcileStoreWithSession(session, incomingSymbols)

	return delta, revIdxStore.AsUint64Slice(locDigs), revIdxStore.AsUint64Slice(reqDigs), nil
}

func (n *Node) computeCertificateDeltas(args *pb.State, reply *pb.StateResponse) bool {
	protoDef := n.ReconciliationProtocol()
	localDelta, localDigests, requestedDigests, err := computeStoreDeltas(
		n.view.CertStore(),
		args.GetFingerprintCertificates(),
		n.CertFingerprintBytes(),
		args.GetCertificateDigests(),
		protoDef.NewCertSession,
	)
	if err != nil {
		log.Error("Failed to compute certificate deltas", "err", err)
		return false
	}
	if len(localDelta) == 0 && len(requestedDigests) == 0 {
		return false
	}

	reply.RequestedCertificateDigests = requestedDigests
	reply.AvailableCertificateDigests = localDigests

	return true
}

func (n *Node) computeAccusationDeltas(args *pb.State, reply *pb.StateResponse) bool {
	callerFp := args.GetFingerprintAccusations()
	if callerFp != nil {
		protoDef := n.ReconciliationProtocol()
		localDelta, localDigests, requestedDigests, err := computeStoreDeltas(
			n.view.AccusationStore(),
			callerFp,
			n.AccusationFingerprintBytes(),
			args.GetAccusationDigests(),
			protoDef.NewAccSession,
		)
		if err != nil {
			log.Error("Failed to compute accusation deltas", "err", err)
			return false
		}
		if len(localDelta) == 0 && len(requestedDigests) == 0 {
			return false
		}

		reply.RequestedAccusationDigests = requestedDigests
		reply.AvailableAccusationDigests = localDigests
		return true
	}
	return false
}

func (n *Node) computeNoteDeltas(args *pb.State, reply *pb.StateResponse) bool {
	callerFp := args.GetFingerprintView()
	if callerFp != nil {
		protoDef := n.ReconciliationProtocol()
		localDelta, localDigests, requestedDigests, err := computeStoreDeltas(
			n.view.NoteStore(),
			callerFp,
			n.ViewFingerprintBytes(),
			args.GetNoteDigests(),
			protoDef.NewNoteSession,
		)
		if err != nil {
			log.Error("Failed to compute note deltas", "err", err)
			return false
		}
		if len(localDelta) == 0 && len(requestedDigests) == 0 {
			return false
		}

		reply.RequestedNoteDigests = requestedDigests
		reply.AvailableNoteDigests = localDigests
		return true
	}
	return false
}

func (n *Node) computeDataDeltas(args *pb.State, reply *pb.StateResponse) bool {
	callerFp := args.GetFingerprintData()
	if callerFp != nil {
		if bytes.Equal(callerFp, n.FingerprintData()) {
			return false
		}

		reconciler := n.GetDataReconciler()
		if reconciler == nil {
			return false
		}

		localDiff, remoteDiff, err := reconciler.Reconcile(revIdxStore.AsDigestSymbols(args.GetDataDigests()))
		if err != nil {
			log.Error("Failed to compute data deltas", "err", err)
			return false
		}
		reply.RequestedDataDigests = revIdxStore.AsUint64Slice(remoteDiff)
		reply.AvailableDataDigests = revIdxStore.AsUint64Slice(localDiff)
		return len(localDiff) > 0 || len(remoteDiff) > 0
	}
	return false
}

