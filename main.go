package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"log"
	"math/big"
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

	// contractAddr := address.MustParseAddr("kQDgoBXen_jCWmKZG7B_DPy555G0saiYvJM0rOq15n3HTWIN") // адрес смарт фактори
	nftAddr := address.MustParseAddr("kQB9r7UptPUZ71DAWwl-JYnPJ_4VSDoHfxqvHnUvBm4ljb8A")
	// queryID := uint64(0)
	// amount := tlb.MustFromTON("0.5").Nano()
	//
	// publicKey, err := extractPublicKey(strings.Split(seedPhrase, " "))
	//  if err != nil {
	//  	log.Fatalf("failed to extract public key: %v", err)
	// }
	//
	// bodyCell := createDepositNativeBodyWithKey(queryID, publicKey)
	//
	// err = sendInternalMessage(walletInstance, contractAddr, amount, bodyCell)
	// if err != nil {
	// 	log.Fatalf("failed to send message: %v", err)
	// }
	//
	// fmt.Println("Message sent successfully!")
	// 	collection := nft.NewCollectionClient(api, contractAddr)
	// collectionData, err := collection.GetCollectionData(context.Background())
	// if err != nil {
	//     panic(err)
	// }
	// 	fmt.Println("collectionData: ", collectionData)
	// hash := big.NewInt(0).SetBytes(walletInstance.Address().Data())
	// fmt.Println(hash)
	// callGetterGetNFTAddressByIndex(api, contractAddr, hash)
	cell := createDepositNativeBodyWithoutKey(0, walletInstance.WalletAddress(), false, false)

	err = sendInternalMessage(walletInstance, nftAddr, big.NewInt(1000000000), cell)
	if err != nil {
		log.Fatalf("failed to send message: %v", err)
	}
}

func extractPublicKey(mnemonic []string) ([]byte, error) {
	mac := hmac.New(sha512.New, []byte(strings.Join(mnemonic, " ")))
	hash := mac.Sum(nil)
	k := pbkdf2.Key(hash, []byte("TON default seed"), 100000, 32, sha512.New)

	privateKey := ed25519.NewKeyFromSeed(k)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return publicKey, nil
}

func createDepositNativeBodyWithKey(queryID uint64, publicKey []byte) *cell.Cell {
	builder := cell.BeginCell()

	builder.MustStoreUInt(0x764019e5, 32)
	builder.MustStoreUInt(queryID, 64)
	dict := cell.NewDict(256)
	dict.Set(cell.BeginCell().MustStoreUInt(0, 256).EndCell(), cell.BeginCell().MustStoreSlice(publicKey, 256).EndCell())
	builder.MustStoreDict(dict)

	return builder.EndCell()
}

// Вызов геттера get_nft_address_by_index
func callGetterGetNFTAddressByIndex(api *ton.APIClient, contractAddr *address.Address, index *big.Int) *address.Address {
	ctx := context.Background()
	master, _ := api.GetMasterchainInfo(ctx)

	result, err := api.RunGetMethod(ctx, master, contractAddr, "get_nft_address_by_index", index)
	if err != nil {
		fmt.Printf("error: %v", err)
	}
	fmt.Printf("result: %v", result.AsTuple()...)
	val, _ := result.MustSlice(0).MustToCell().BeginParse().LoadAddr()
	val.SetTestnetOnly(true)
	val.SetBounce(true)

	fmt.Printf("result: %v", val)
	return val
}

// Создание тела сообщения deposit_native без передачи публичного ключа
func createDepositNativeBodyWithoutKey(queryID uint64, receiverAddress *address.Address, init bool, set_key bool) *cell.Cell {
	builder := cell.BeginCell()
	builder.MustStoreUInt(0x29bb3721, 32)
	builder.MustStoreUInt(queryID, 64)
	builder.MustStoreCoins(100000000)
	builder.MustStoreAddr(receiverAddress)
	builder.MustStoreBoolBit(init)
	builder.MustStoreBoolBit(set_key) 
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
