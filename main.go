package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"golang.org/x/crypto/pbkdf2"
)

var (
	userPrivateKey ed25519.PrivateKey // Приватный ключ пользователя
	userPublicKey  ed25519.PublicKey  // Публичный ключ пользователя
	shift          uint64             // Получено от бэкенда
	bitNumber      uint64             // Получено от бэкенда
	refShift       *uint64            // shift родительского интента, если есть
	refBitNumber   *uint64            // bit_number родительского интента, если есть
)

type IntentData struct {
	IntentBOC string `json:"tx"`
	Signature string `json:"signature"`
	Format string`json:"format"` 
}

func main() {
	// client := liteclient.NewConnectionPool()
	// err := client.AddConnectionsFromConfigUrl(context.Background(), "https://ton.org/testnet-global.config.json")
	// if err != nil {
	// 	log.Fatalf("failed to connect to lite server: %v", err)
	// }
	//
	// api := ton.NewAPIClient(client)

	seedPhrase := "forget guide boost unable flip stuff animal name brand eyebrow adapt tip pull tribe exile fabric manage elephant dice trash security cook title arch"
	userPublicKey, userPrivateKey = extractPublicKey(strings.Split(seedPhrase, " "))
	shift = 1021
	bitNumber = 512
	// walletInstance, err := wallet.FromSeed(api, strings.Split(seedPhrase, " "), wallet.V4R2)
	// if err != nil {
	// 	log.Fatalf("failed to create wallet from seed: %v", err)
	// }
	var err error
	ammAddr, err := address.ParseRawAddr("0:38dc7ce7c6e3d5d43d61324bad11e78fdb8bc8b48fe28c2d8cd5d710b345a0d0") // Пример адреса
	if err != nil {
		log.Fatal(err)
	}
	saAddr, err := address.ParseRawAddr("0:7dafb529b4f519ef50c05b097e2589cf27fe15483a077f1aaf1e752f066e258d") // Адрес смарт-аккаунта пользователя
	if err != nil {
		log.Fatal(err)
	}

	// Генерация ключей для примера (в реальности используйте существующие)
	// pubKey, privKey, err := ed25519.GenerateKey(nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// userPrivateKey = privKey
	// userPublicKey = pubKey

	// Создание ордера
	marketOrderCell := createMarketOrder()
	userOrderCell := createUserOrder(marketOrderCell)

	// Создание интента
	intentCell, err := createUserIntent(
		shift, bitNumber, // query_id
		refShift, refBitNumber, // reference_query_id
		ammAddr, saAddr, // адреса
		false,         // isLong (short)
		userOrderCell, // ордер
	)
	if err != nil {
		log.Fatalf("Failed to create user intent: %v", err)
	}

	// Сериализация в BOC для подписи
	intentBOC := intentCell.ToBOCWithFlags(false)

	fmt.Printf("Intent BOC (hex): %x\n", intentBOC)
	signature := ed25519.Sign(userPrivateKey, intentBOC)
	fmt.Printf("Signature (hex): %x\n", signature)

	backendURL := "https://api.stage.stormtrade.dev/instant-trading/tx/broadcast"

	// Создаем структуру данных
	data := IntentData{
		IntentBOC: fmt.Sprintf("%x", intentBOC),
		Signature: fmt.Sprintf("%x", signature),
		Format: "hex",
	}

	// Преобразуем данные в JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}

	// Создаем HTTP клиент с таймаутом
	client := &http.Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Создаем POST запрос
	req, err := http.NewRequestWithContext(ctx, "POST", backendURL, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	// Устанавливаем заголовки
	req.Header.Set("Content-Type", "application/json")
	// Если нужна авторизация:
	// req.Header.Set("Authorization", "Bearer YOUR_TOKEN")

	// Отправляем запрос
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Читаем ответ
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}

	// Проверяем статус
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("Success! Response: %s\n", string(body))
	} else {
		fmt.Printf("Error: Status %d, Body: %s\n", resp.StatusCode, string(body))
	}

	// contractAddr := address.MustParseAddr("kQDgoBXen_jCWmKZG7B_DPy555G0saiYvJM0rOq15n3HTWIN") // адрес смарт фактори
	// vaultAddr := extractPublicKeyaddress.MustParseRawAddr("0:929ca0bef8881c6b5defaed9d523e23415827102f70924d643c597d101519e58")
	// nftAddr := address.MustParseRawAddr("0:7dafb529b4f519ef50c05b097e2589cf27fe15483a077f1aaf1e752f066e258d")
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
	// cell := createDepositNativeBodyWithoutKey(0, walletInstance.WalletAddress(), false, false)
	// cell := CreateWithdrawMessage(vaultAddr, big.NewInt(3_000_000_000))

	// err = sendInternalMessage(walletInstance, vaultAddr, big.NewInt(5000000000), cell)
	// if err != nil {
	// 	log.Fatalf("failed to send message: %v", err)
	// }
}

func extractPublicKey(mnemonic []string) ([]byte, []byte) {
	mac := hmac.New(sha512.New, []byte(strings.Join(mnemonic, " ")))
	hash := mac.Sum(nil)
	k := pbkdf2.Key(hash, []byte("TON default seed"), 100000, 32, sha512.New)

	privateKey := ed25519.NewKeyFromSeed(k)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return publicKey, privateKey
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
	builder.MustStoreCoins(5_000_000_00)
	builder.MustStoreAddr(receiverAddress)
	builder.MustStoreBoolBit(init)
	builder.MustStoreBoolBit(set_key)
	return builder.EndCell()
}

func CreateWithdrawMessage(vaultAddress *address.Address, amount *big.Int) *cell.Cell {
	builder := cell.BeginCell()
	builder.MustStoreUInt(0x6eec039d, 32)
	builder.MustStoreUInt(0, 64)
	builder.MustStoreAddr(vaultAddress)
	builder.MustStoreBigCoins(amount)
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

func createMarketOrder() *cell.Cell {
	builder := cell.BeginCell()
	// market_order#3 expiration:uint32 direction:Direction amount:Coins leverage:uint64
	// limit_price:Coins stop_price:Coins stop_trigger_price:Coins take_trigger_price:Coins = CreateOrder;

	builder.MustStoreUInt(3, 4) // market_order#3

	expiration := uint32(time.Now().Add(10 * time.Minute).Unix()) // Через 10 минут
	builder.MustStoreUInt(uint64(expiration), 32)

	// direction:Direction (short$1)
	builder.MustStoreBoolBit(true) // short

	// amount:Coins (например, 1 TON)
	builder.MustStoreCoins(tlb.MustFromTON("1").Nano().Uint64())

	// leverage:uint64 (например, 10x)
	builder.MustStoreUInt(10, 64)

	// limit_price:Coins (0 для рыночного ордера)
	builder.MustStoreCoins(0)
	// stop_price:Coins
	builder.MustStoreCoins(tlb.MustFromTON("0.9").Nano().Uint64())
	// stop_trigger_price:Coins
	builder.MustStoreCoins(tlb.MustFromTON("0.91").Nano().Uint64())
	// take_trigger_price:Coins
	builder.MustStoreCoins(tlb.MustFromTON("1.1").Nano().Uint64())

	return builder.EndCell()
}

// Создание UserOrder (обертка над CreateOrder)
func createUserOrder(createOrderCell *cell.Cell) *cell.Cell {
	builder := cell.BeginCell()
	// _ order:CreateOrder = UserOrder;
	builder.MustStoreBuilder(createOrderCell.ToBuilder())
	return builder.EndCell()
}

// Создание UserIntentPayload
func createUserIntentPayload(ammAddr, saAddr *address.Address, isLong bool, orderCell *cell.Cell) (*cell.Cell, error) {
	builder := cell.BeginCell()

	// user_intent_payload#_ amm_address:MsgAddressInt sa_address:MsgAddressInt direction:Direction order:^UserOrder = UserIntentPayload;

	// amm_address:MsgAddressInt
	err := builder.StoreAddr(ammAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to store amm_address: %w", err)
	}

	// sa_address:MsgAddressInt
	err = builder.StoreAddr(saAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to store sa_address: %w", err)
	}

	// direction:Direction (long$0 или short$1)
	builder.MustStoreBoolBit(!isLong) // long$0 если true, short$1 если false

	// order:^UserOrder
	err = builder.StoreRef(orderCell)
	if err != nil {
		return nil, fmt.Errorf("failed to store order ref: %w", err)
	}

	return builder.EndCell(), nil
}

// Создание UserQueryId
func createUserQueryId(shift, bitNumber uint64) (*cell.Cell, error) {
	if shift > 5999 {
		return nil, fmt.Errorf("shift %d is out of range [0, 5999]", shift)
	}
	if bitNumber > 1022 {
		return nil, fmt.Errorf("bit_number %d is out of range [0, 1022]", bitNumber)
	}

	builder := cell.BeginCell()
	// _ shift:(## 13) bit_number:(## 10) = UserQueryId;
	builder.MustStoreUInt(shift, 13)
	builder.MustStoreUInt(bitNumber, 10)
	return builder.EndCell(), nil
}

// Создание Maybe UserQueryId
func createMaybeUserQueryId(shift, bitNumber *uint64) (*cell.Cell, error) {
	builder := cell.BeginCell()
	if shift == nil || bitNumber == nil {
		// Nothing
		builder.MustStoreBoolBit(false)
	} else {
		// Just
		builder.MustStoreBoolBit(true)
		qidCell, err := createUserQueryId(*shift, *bitNumber)
		if err != nil {
			return nil, err
		}
		builder.MustStoreBuilder(qidCell.ToBuilder())
	}
	return builder.EndCell(), nil
}

// Создание основного UserIntent
func createUserIntent(queryShift, queryBitNumber uint64, refShift, refBitNumber *uint64, ammAddr, saAddr *address.Address, isLong bool, orderCell *cell.Cell) (*cell.Cell, error) {
	// 1. Создать UserIntentPayload
	payloadCell, err := createUserIntentPayload(ammAddr, saAddr, isLong, orderCell)
	if err != nil {
		return nil, fmt.Errorf("failed to create intent payload: %w", err)
	}

	// 2. Создать query_id
	queryIdCell, err := createUserQueryId(queryShift, queryBitNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to create query_id: %w", err)
	}

	// 3. Создать reference_query_id
	refQueryIdCell, err := createMaybeUserQueryId(refShift, refBitNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to create reference_query_id: %w", err)
	}

	// 4. created_at (на 10 секунд раньше)
	createdAt := uint32(time.Now().Add(-10 * time.Second).Unix())

	// 5. public_key (256 бит)
	// Предполагаем, что userPublicKey уже заполнен

	builder := cell.BeginCell()
	// _ query_id:UserQueryId created_at:uint32 reference_query_id:(Maybe UserQueryId) public_key:bits256 intent:^UserIntentPayload = UserIntent;

	// query_id
	builder.MustStoreBuilder(queryIdCell.ToBuilder())

	// created_at
	builder.MustStoreUInt(uint64(createdAt), 32)

	// reference_query_id
	builder.MustStoreBuilder(refQueryIdCell.ToBuilder())

	// public_key (предполагаем, что userPublicKey длиной 32 байта)
	if len(userPublicKey) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(userPublicKey))
	}
	builder.MustStoreSlice(userPublicKey, 256)

	// intent:^UserIntentPayload
	err = builder.StoreRef(payloadCell)
	if err != nil {
		return nil, fmt.Errorf("failed to store intent ref: %w", err)
	}

	return builder.EndCell(), nil
}
