package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"strings"

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"golang.org/x/crypto/pbkdf2"
)

func main() {
	client := liteclient.NewConnectionPool()
	err := client.AddConnectionsFromConfigUrl(context.Background(), "https://ton.org/testnet-global.config.json")
	if err != nil {
		log.Fatalf("failed to connect to lite server: %v", err)
	}

	api := ton.NewAPIClient(client)

	seedPhrase := "forget guide boost unable flip stuff animal name brand eyebrow adapt tip pull tribe exile fabric manage elephant dice trash security cook title arch"

	walletInstance, err := wallet.FromSeed(api, strings.Split(seedPhrase, " "), wallet.V4R2)
	if err != nil {
		log.Fatalf("failed to create wallet from seed: %v", err)
	}

	contractAddr := address.MustParseAddr("kQDgoBXen_jCWmKZG7B_DPy555G0saiYvJM0rOq15n3HTWIN") // адрес смарт фактори

	queryID := rand.Uint64()
	amount := tlb.MustFromTON("0.5").Nano()
	receiverAddress := walletInstance.Address() // адреса валлета нашего
	init := true

	publicKey, err := extractPublicKey(strings.Split(seedPhrase, " "))
	if err != nil {
		log.Fatalf("failed to extract public key: %v", err)
	}

	bodyCell := createDepositNativeBodyWithKey(queryID, amount, receiverAddress, init, publicKey)

	err = sendInternalMessage(walletInstance, contractAddr, amount, bodyCell)
	if err != nil {
		log.Fatalf("failed to send message: %v", err)
	}

	fmt.Println("Message sent successfully!")
}

func extractPublicKey(mnemonic []string) ([]byte, error) {
	mac := hmac.New(sha512.New, []byte(strings.Join(mnemonic, " ")))
	hash := mac.Sum(nil)
	k := pbkdf2.Key(hash, []byte("TON default seed"), 100000, 32, sha512.New) // In TON libraries, "TON default seed" is used as salt when getting keys
	// 32 is a key len

	privateKey := ed25519.NewKeyFromSeed(k) // get private key
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return publicKey, nil
}

func createDepositNativeBodyWithKey(queryID uint64, amount *big.Int, receiverAddress *address.Address, init bool, publicKey []byte) *cell.Cell {
	builder := cell.BeginCell()

	// #29bb3721
	builder.MustStoreUInt(0x29bb3721, 32)

	// query_id:uint64
	builder.MustStoreUInt(queryID, 64)

	// amount:Coins
	builder.MustStoreCoins(amount.Uint64())

	// receiver_address:MsgAddressInt
	builder.MustStoreAddr(receiverAddress)

	// init:Bool
	builder.MustStoreBoolBit(init)

	// key_init:InitializationRequest
	builder.MustStoreBoolBit(true) // need_key_init$1

	// user_public_keys:(HashmapE 256 Cell)
	// dict := cell.NewDict(256)
	// dict.Set(cell.BeginCell().MustStoreUInt(0, 256).EndCell(), cell.BeginCell().MustStoreSlice(publicKey, 256).EndCell())
	// builder.MustStoreDict(dict)

	return builder.EndCell()
}

func sendInternalMessage(walletInstance *wallet.Wallet, contractAddr *address.Address, amount *big.Int, body *cell.Cell) error {
	ctx := context.Background()

	err := walletInstance.Send(ctx, &wallet.Message{
		Mode: wallet.PayGasSeparately,
		InternalMessage: &tlb.InternalMessage{
			IHRDisabled: true,
			Bounce:      true,
			DstAddr:     contractAddr,
			Amount:      tlb.MustFromNano(amount, 9),
			Body:        body,
		},
	})
	return err
}
