package main

/*
#include <stdint.h> // for uint32_t

// If crypto.Address and crypto.PubKey are fixed-size byte arrays, define their sizes
#define ADDRESS_SIZE 20 // Example size, adjust according to actual crypto.Address size
#define PUBKEY_SIZE  58 // Example size, adjust according to actual crypto.PubKey size

// Define a C-compatible KeyInfo struct
typedef struct {
	uint32_t Type;
	const char* Name;
	const uint8_t PubKey[PUBKEY_SIZE];
	const uint8_t Address[ADDRESS_SIZE];
} KeyInfo;

typedef struct {
	KeyInfo* Info;
	char* Password;
} UserAccount;

// Define the Coin type in C, assuming both Denom and Amount are strings
typedef struct {
    char *Denom;
    uint64_t Amount;
} Coin;

// If Coins is a dynamic array or slice of Coin, you will need a struct to represent it
typedef struct {
    Coin *Array;     // Pointer to the first Coin element
    size_t Length;   // Number of elements in the Coins array
} Coins;

// Then define the BaseAccount struct in C
typedef struct {
    uint8_t Address[ADDRESS_SIZE];
    Coins*   Coins;              // Assuming Coins is represented as above
    uint8_t PubKey[PUBKEY_SIZE];
    uint64_t AccountNumber;
    uint64_t Sequence;
} BaseAccount;
*/
import "C"
import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"time"
	"unsafe"
	"var/gno_sdk/service"

	"github.com/gnolang/gno/gno.land/pkg/gnoclient"
	rpcclient "github.com/gnolang/gno/tm2/pkg/bft/rpc/client"
	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/gnolang/gno/tm2/pkg/crypto/bip39"
	crypto_keys "github.com/gnolang/gno/tm2/pkg/crypto/keys"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const (
	Success C.int = 1
	Fail          = 0
)

var serviceEx, _ = service.NewGnoNativeService()

//export SetRemote
func SetRemote(remote *C.char) C.int {
	serviceEx.Client.RPCClient = rpcclient.NewHTTP(C.GoString(remote), "/websocket")
	serviceEx.Remote = C.GoString(remote)
	return Success
}

//export GetRemote
func GetRemote() *C.char {
	return C.CString(serviceEx.Remote)
}

func getSigner() *gnoclient.SignerFromKeybase {
	signer, ok := serviceEx.Client.Signer.(*gnoclient.SignerFromKeybase)
	if !ok {
		// We only set s.client.Signer in initService, so this shouldn't happen.
		panic("signer is not gnoclient.SignerFromKeybase")
	}
	return signer
}

//export SetChainID
func SetChainID(chainID *C.char) C.int {
	getSigner().ChainID = C.GoString(chainID)
	return Success
}

//export GetChainID
func GetChainID() *C.char {
	return C.CString(getSigner().ChainID)
}

//export GenerateRecoveryPhrase
func GenerateRecoveryPhrase() *C.char {
	const mnemonicEntropySize = 256
	entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
	if err != nil {
		return C.CString("")
	}

	phrase, err := bip39.NewMnemonic(entropySeed[:])
	if err != nil {
		return C.CString("")
	}

	return C.CString(phrase)
}

// ToCKeyInfo converts KeyInfo to its C representation.
func convertKeyInfo(key crypto_keys.Info) *C.KeyInfo {
	// Allocate memory for KeyInfo in C.
	cKeyInfo := (*C.KeyInfo)(C.malloc(C.sizeof_KeyInfo))
	if cKeyInfo == nil {
		// Handle allocation failure if needed
		return nil
	}

	// Set fields in the KeyInfo struct.
	cKeyInfo.Type = C.uint32_t(key.GetType())
	cKeyInfo.Name = C.CString(key.GetName()) // This will need to be freed in C.

	// Copy the public key bytes.
	pubKeyBytes := key.GetPubKey().Bytes()
	if len(pubKeyBytes) > len(cKeyInfo.PubKey) {
		// Handle error: the public key is too big for the allocated array.
		// C.free(unsafe.Pointer(cKeyInfo))
		return nil
	}
	for i, b := range pubKeyBytes {
		cKeyInfo.PubKey[i] = C.uint8_t(b)
	}

	// Copy the address bytes.
	addressBytes := key.GetAddress().Bytes()
	if len(addressBytes) > len(cKeyInfo.Address) {
		// Handle error: the address is too big for the allocated array.
		// C.free(unsafe.Pointer(cKeyInfo.Name))
		// C.free(unsafe.Pointer(cKeyInfo))
		return nil
	}
	for i, b := range addressBytes {
		cKeyInfo.Address[i] = C.uint8_t(b)
	}

	// Return the heap-allocated KeyInfo.
	return cKeyInfo
}

//export ListKeyInfo
func ListKeyInfo(length *C.int) **C.KeyInfo {
	serviceEx.Logger.Debug("ListKeyInfo called")

	keys, err := getSigner().Keybase.List()
	if err != nil {
		*length = 0
		return nil
	}

	*length = C.int(len(keys))

	var keyInfoPtr *C.KeyInfo // Define the variable with the correct type for sizeof

	// Allocate memory for the array of pointers to KeyInfo structs
	keyInfos := (**C.KeyInfo)(C.malloc(C.size_t(len(keys)) * C.size_t(unsafe.Sizeof(keyInfoPtr))))
	if keyInfos == nil {
		*length = 0
		return nil
	}

	// Cast the C array to a Go slice so we can index it
	goSlice := (*[1 << 30]*C.KeyInfo)(unsafe.Pointer(keyInfos))[:len(keys):len(keys)]

	for i, key := range keys {
		goSlice[i] = convertKeyInfo(key)
	}

	return keyInfos
}

//export HasKeyByName
func HasKeyByName(name *C.char) C.int {
	serviceEx.Logger.Debug("HasKeyByName called")
	has, err := getSigner().Keybase.HasByName(C.GoString(name))
	if err != nil {
		return Fail
	}

	if has {
		return Success
	} else {
		return Fail
	}
}

//export HasKeyByAddress
func HasKeyByAddress(address *C.uint8_t, len C.int) C.int {
	serviceEx.Logger.Debug("HasKeyByAddress called")
	has, err := getSigner().Keybase.HasByAddress(crypto.AddressFromBytes(C.GoBytes(unsafe.Pointer(address), len)))
	if err != nil {
		return Fail
	}

	if has {
		return Success
	} else {
		return Fail
	}
}

//export HasKeyByNameOrAddress
func HasKeyByNameOrAddress(nameOrBech32 *C.char) C.int {
	serviceEx.Logger.Debug("HasKeyByNameOrAddress called")
	has, err := getSigner().Keybase.HasByNameOrAddress(C.GoString(nameOrBech32))
	if err != nil {
		return Fail
	}

	if has {
		return Success
	} else {
		return Fail
	}
}

//export GetKeyInfoByName
func GetKeyInfoByName(name *C.char) *C.KeyInfo {
	serviceEx.Logger.Debug("GetKeyInfoByName called")

	key, err := getSigner().Keybase.GetByName(C.GoString(name))
	if err != nil {
		return nil
	}

	return convertKeyInfo(key)
}

//export GetKeyInfoByAddress
func GetKeyInfoByAddress(address *C.uint8_t) *C.KeyInfo {
	serviceEx.Logger.Debug("GetKeyInfoByAddress called")

	key, err := getSigner().Keybase.GetByAddress(crypto.AddressFromBytes(C.GoBytes(unsafe.Pointer(address), C.ADDRESS_SIZE)))
	if err != nil {
		return nil
	}

	return convertKeyInfo(key)
}

//export GetKeyInfoByNameOrAddress
func GetKeyInfoByNameOrAddress(nameOrBech32 *C.char) *C.KeyInfo {
	serviceEx.Logger.Debug("GetKeyInfoByAddress called")

	key, err := getSigner().Keybase.GetByNameOrAddress(C.GoString(nameOrBech32))
	if err != nil {
		return nil
	}

	return convertKeyInfo(key)
}

//export CreateAccount
func CreateAccount(nameOrBech32 *C.char, mnemonic *C.char, bip39Passwd *C.char, password *C.char, account C.int, index C.int) *C.KeyInfo {
	serviceEx.Logger.Debug("CreateAccount called", zap.String("NameOrBech32", C.GoString(nameOrBech32)))

	key, err := getSigner().Keybase.CreateAccount(C.GoString(nameOrBech32), C.GoString(mnemonic),
		C.GoString(bip39Passwd), C.GoString(password), uint32(account), uint32(index))
	if err != nil {
		serviceEx.Logger.Debug("CreateAccount", zap.String("error", err.Error()))
		return nil
	}

	return convertKeyInfo(key)
}

//export SelectAccount
func SelectAccount(nameOrBech32 *C.char) *C.UserAccount {
	serviceEx.Logger.Debug("SelectAccount called", zap.String("NameOrBech32", C.GoString(nameOrBech32)))

	key, err := getSigner().Keybase.GetByNameOrAddress(C.GoString(nameOrBech32))
	if err != nil {
		serviceEx.Logger.Debug("SelectAccount", zap.String("error", err.Error()))
		return nil
	}

	info := convertKeyInfo(key)
	if info == nil {
		// Handle case where convertKeyInfo fails.
		return nil
	}

	serviceEx.Lock.Lock()
	defer serviceEx.Lock.Unlock()

	account, ok := serviceEx.UserAccounts[C.GoString(nameOrBech32)]
	if !ok {
		account = &service.UserAccount{}
		serviceEx.UserAccounts[C.GoString(nameOrBech32)] = account
	}
	account.KeyInfo = key
	serviceEx.ActiveAccount = account

	getSigner().Account = C.GoString(nameOrBech32)
	getSigner().Password = account.Password

	// Allocate memory for UserAccount in C.
	cUserAccount := (*C.UserAccount)(C.malloc(C.sizeof_UserAccount))
	if cUserAccount == nil {
		// Handle allocation failure if needed
		// C.free(unsafe.Pointer(info.Name)) // Free the CString allocated in convertKeyInfo
		// C.free(unsafe.Pointer(info))      // Free the KeyInfo struct
		return nil
	}

	// Set fields in the UserAccount struct.
	cUserAccount.Info = info
	cUserAccount.Password = C.CString(account.Password) // This will need to be freed in C.

	return cUserAccount
}

//export SetPassword
func SetPassword(password *C.char) C.int {
	serviceEx.Logger.Debug("SetPassword called")
	serviceEx.Lock.Lock()
	defer serviceEx.Lock.Unlock()
	if serviceEx.ActiveAccount == nil {
		serviceEx.Logger.Debug("SetPassword", zap.String("error", "No Active Account"))
		return Fail
	}
	serviceEx.ActiveAccount.Password = C.GoString(password)

	getSigner().Password = C.GoString(password)

	// Check the password.
	if err := getSigner().Validate(); err != nil {
		serviceEx.Logger.Debug("SetPassword", zap.String("error", err.Error()))
		return Fail
	}

	return Success
}

//export GetActiveAccount
func GetActiveAccount() *C.UserAccount {
	serviceEx.Logger.Debug("GetActiveAccount called")

	serviceEx.Lock.RLock()
	account := serviceEx.ActiveAccount
	serviceEx.Lock.RUnlock()

	if account == nil {
		serviceEx.Logger.Debug("GetActiveAccount", zap.String("error", "No Active Account"))
		return nil
	}

	info := convertKeyInfo(account.KeyInfo)
	if info == nil {
		// Handle case where convertKeyInfo fails.
		return nil
	}

	// Allocate memory for UserAccount in C.
	cUserAccount := (*C.UserAccount)(C.malloc(C.sizeof_UserAccount))
	if cUserAccount == nil {
		// Handle allocation failure if needed
		// C.free(unsafe.Pointer(info.Name)) // Free the CString allocated in convertKeyInfo
		// C.free(unsafe.Pointer(info))      // Free the KeyInfo struct
		return nil
	}

	// Set fields in the UserAccount struct.
	cUserAccount.Info = info
	cUserAccount.Password = C.CString(account.Password) // This will need to be freed in C.

	return cUserAccount
}

//export QueryAccount
func QueryAccount(address *C.uint8_t) *C.BaseAccount {
	addressData := crypto.AddressFromBytes(C.GoBytes(unsafe.Pointer(address), C.ADDRESS_SIZE))
	serviceEx.Logger.Debug("QueryAccount", zap.String("address", addressData.String()))

	account, _, err := serviceEx.Client.QueryAccount(addressData)
	if err != nil {
		serviceEx.Logger.Debug("QueryAccount", zap.String("error", err.Error()))
		return nil
	}

	// Allocate memory for BaseAccount in C.
	cAccount := (*C.BaseAccount)(C.malloc(C.sizeof_BaseAccount))
	if cAccount == nil {
		// Handle allocation failure if needed
		return nil
	}

	// Allocate memory for Coins in C.
	cAccount.Coins = (*C.Coins)(C.malloc(C.sizeof_Coins))
	if cAccount.Coins == nil {
		// Handle allocation failure if needed
		// C.free(unsafe.Pointer(cAccount))
		return nil
	}
	cAccount.Coins.Length = C.size_t(len(account.Coins))
	cAccount.Coins.Array = (*C.Coin)(C.malloc(C.sizeof_Coin * cAccount.Coins.Length))
	if cAccount.Coins.Array == nil {
		// Handle allocation failure if needed
		// C.free(unsafe.Pointer(cAccount.Coins))
		// C.free(unsafe.Pointer(cAccount))
		return nil
	}

	cCoinPtr := cAccount.Coins.Array
	for _, coin := range account.Coins {
		// Allocate and set the C string equivalents
		cCoinPtr.Denom = C.CString(coin.Denom)
		cCoinPtr.Amount = C.uint64_t(coin.Amount)
		// Move the pointer to the next array element; this is equivalent to incrementing an array index
		cCoinPtr = (*C.Coin)(unsafe.Pointer(uintptr(unsafe.Pointer(cCoinPtr)) + C.sizeof_Coin))
	}

	// Copy the account address bytes to the C struct.
	addressBytes := account.Address.Bytes()
	if len(addressBytes) > len(cAccount.Address) {
		// Handle error: the address is too big for the allocated array.
		// Remember to free all previously allocated memory.
		// C.free(unsafe.Pointer(cAccount.Coins.Array))
		// C.free(unsafe.Pointer(cAccount.Coins))
		// C.free(unsafe.Pointer(cAccount))
		return nil
	}
	for i, b := range addressBytes {
		cAccount.Address[i] = C.uint8_t(b)
	}

	// Copy the public key bytes to the C struct if a public key is present.
	if account.PubKey != nil {
		pubKeyBytes := account.PubKey.Bytes()
		if len(pubKeyBytes) > len(cAccount.PubKey) {
			// Handle error: the public key is too big for the allocated array.
			// Remember to free all previously allocated memory.
			// C.free(unsafe.Pointer(cAccount.Coins.Array))
			// C.free(unsafe.Pointer(cAccount.Coins))
			// C.free(unsafe.Pointer(cAccount))
			return nil
		}
		for i, b := range pubKeyBytes {
			cAccount.PubKey[i] = C.uint8_t(b)
		}
	}

	cAccount.AccountNumber = C.uint64_t(account.AccountNumber)
	cAccount.Sequence = C.uint64_t(account.Sequence)

	return cAccount
}

//export DeleteAccount
func DeleteAccount(nameOrBech32 *C.char, password *C.char, skipPassword C.int) C.int {
	serviceEx.Logger.Debug("DeleteAccount called")
	if err := getSigner().Keybase.Delete(C.GoString(nameOrBech32), C.GoString(password), skipPassword > 0); err != nil {
		serviceEx.Logger.Debug("DeleteAccount,", zap.String("error", err.Error()))
		return Fail
	}

	serviceEx.Lock.Lock()
	delete(serviceEx.UserAccounts, C.GoString(nameOrBech32))
	if serviceEx.ActiveAccount != nil &&
		(serviceEx.ActiveAccount.KeyInfo.GetName() == C.GoString(nameOrBech32) || crypto.AddressToBech32(serviceEx.ActiveAccount.KeyInfo.GetAddress()) == C.GoString(nameOrBech32)) {
		// The deleted account was the active account.
		serviceEx.ActiveAccount = nil
	}
	serviceEx.Lock.Unlock()
	return Success
}

//export Query
func Query(path *C.char, data *C.uint8_t, lenght C.int, retLen *C.int) *C.uint8_t {
	serviceEx.Logger.Debug("Query", zap.String("path", C.GoString(path)), zap.ByteString("data", convertToByteSlice(data, lenght)))

	cfg := gnoclient.QueryCfg{
		Path: C.GoString(path),
		Data: convertToByteSlice(data, lenght),
	}

	bres, err := serviceEx.Client.Query(cfg)
	if err != nil {
		serviceEx.Logger.Debug("Query", zap.String("error", err.Error()))
		*retLen = 0
		return nil
	}

	*retLen = C.int(len(bres.Response.Data))
	return (*C.uint8_t)(unsafe.Pointer(&bres.Response.Data[0]))
}

// Convert C data and length to Go byte slice
func convertToByteSlice(data *C.uint8_t, length C.int) []byte {
	// Create a slice header
	var sliceHeader reflect.SliceHeader
	sliceHeader.Data = uintptr(unsafe.Pointer(data))
	sliceHeader.Len = int(length)
	sliceHeader.Cap = int(length)

	// Convert slice header to a []byte
	byteSlice := *(*[]byte)(unsafe.Pointer(&sliceHeader))

	return byteSlice
}

//export Render
func Render(packagePath *C.char, args *C.char) *C.char {
	serviceEx.Logger.Debug("Render", zap.String("packagePath", C.GoString(packagePath)), zap.String("args", C.GoString(args)))

	result, _, err := serviceEx.Client.Render(C.GoString(packagePath), C.GoString(args))
	if err != nil {
		serviceEx.Logger.Debug("Render", zap.String("error", err.Error()))
		return nil
	}

	return C.CString(result)
}

//export QEval
func QEval(packagePath *C.char, expression *C.char) *C.char {
	serviceEx.Logger.Debug("QEval", zap.String("packagePath", C.GoString(packagePath)), zap.String("expression", C.GoString(expression)))

	result, _, err := serviceEx.Client.QEval(C.GoString(packagePath), C.GoString(expression))
	if err != nil {
		serviceEx.Logger.Debug("QEval", zap.String("error", err.Error()))
		return nil
	}

	return C.CString(result)
}

//export Call
func Call(packagePath *C.char, fnc *C.char, args **C.char, gasFee *C.char, gasWanted C.uint64_t, send *C.char, memo *C.char, retLen *C.int) *C.uint8_t {
	serviceEx.Logger.Debug("Call", zap.String("package", C.GoString(packagePath)), zap.String("function", C.GoString(fnc)), zap.Any("args", cArrayToStrings(args)))

	serviceEx.Lock.RLock()
	if serviceEx.ActiveAccount == nil {
		serviceEx.Lock.RUnlock()
		return nil
	}
	serviceEx.Lock.RUnlock()

	cfg := gnoclient.BaseTxCfg{
		GasFee:    C.GoString(gasFee),
		GasWanted: int64(gasWanted),
		Memo:      C.GoString(memo),
	}

	msgs := make([]gnoclient.MsgCall, 0)

	// for _, msg := range req.Msg.Msgs {
	msgs = append(msgs, gnoclient.MsgCall{
		PkgPath:  C.GoString(packagePath),
		FuncName: C.GoString(fnc),
		Args:     cArrayToStrings(args),
		Send:     C.GoString(send),
	})
	// }

	bres, err := serviceEx.Client.Call(cfg, msgs...)
	if err != nil {
		serviceEx.Logger.Debug("Call", zap.String("error", err.Error()))
		return nil
	}

	*retLen = C.int(len(bres.DeliverTx.Data))
	return (*C.uint8_t)(unsafe.Pointer(&bres.DeliverTx.Data[0]))
}

//export Send
func Send(address *C.uint8_t, gasFee *C.char, gasWanted C.uint64_t, send *C.char, memo *C.char, retLen *C.int) *C.uint8_t {
	serviceEx.Logger.Debug("Send", zap.String("toAddress", crypto.AddressToBech32(crypto.AddressFromBytes(C.GoBytes(unsafe.Pointer(address), C.ADDRESS_SIZE)))), zap.String("send", C.GoString(send)))

	serviceEx.Lock.RLock()
	if serviceEx.ActiveAccount == nil {
		serviceEx.Lock.RUnlock()
		return nil
	}
	serviceEx.Lock.RUnlock()

	cfg := gnoclient.BaseTxCfg{
		GasFee:    C.GoString(gasFee),
		GasWanted: int64(gasWanted),
		Memo:      C.GoString(memo),
	}

	msgs := make([]gnoclient.MsgSend, 0)

	// for _, msg := range req.Msg.Msgs {
	msgs = append(msgs, gnoclient.MsgSend{
		ToAddress: crypto.AddressFromBytes(C.GoBytes(unsafe.Pointer(address), C.ADDRESS_SIZE)),
		Send:      C.GoString(send),
	})
	// }

	_, err := serviceEx.Client.Send(cfg, msgs...)
	if err != nil {
		serviceEx.Logger.Debug("Send", zap.String("error", err.Error()))
		return nil
	}

	// *retLen = C.int(len(bres.DeliverTx.Data))
	// return (*C.uint8_t)(unsafe.Pointer(&bres.DeliverTx.Data[0]))
	return nil
}

// cArrayToStrings converts a null-terminated array of C strings to a Go slice of strings.
func cArrayToStrings(cArray **C.char) []string {
	// The length of the C array is not known, so we need to find the null terminator.
	var goStrings []string
	for {
		// Get the pointer to the current C string.
		ptr := uintptr(unsafe.Pointer(cArray))

		// Dereference the pointer to get the actual C string.
		cStr := *(**C.char)(unsafe.Pointer(ptr))

		// If the C string is null, we've reached the end of the array.
		if cStr == nil {
			break
		}

		// Convert the C string to a Go string and append it to the slice.
		goStrings = append(goStrings, C.GoString(cStr))

		// Move to the next C string in the array.
		cArray = (**C.char)(unsafe.Pointer(ptr + unsafe.Sizeof(uintptr(0))))
	}

	return goStrings
}

//export AddressToBech32
func AddressToBech32(address *C.uint8_t) *C.char {
	serviceEx.Logger.Debug("AddressToBech32", zap.ByteString("address", C.GoBytes(unsafe.Pointer(address), C.ADDRESS_SIZE)))
	bech32Address := crypto.AddressToBech32(crypto.AddressFromBytes(C.GoBytes(unsafe.Pointer(address), C.ADDRESS_SIZE)))
	return C.CString(bech32Address)
}

//export AddressFromBech32
func AddressFromBech32(bech32Address *C.char) unsafe.Pointer {
	address, err := crypto.AddressFromBech32(C.GoString(bech32Address))
	serviceEx.Logger.Debug("AddressFromBech32", zap.String("bech32Address", C.GoString(bech32Address)))
	if err != nil {
		serviceEx.Logger.Debug("AddressFromBech32", zap.String("error", err.Error()))
		return nil
	}
	// Allocate C memory to hold the result
	cBytes := C.malloc(C.size_t(len(address.Bytes())))

	// Copy Go bytes into the allocated C memory
	copy((*[1 << 30]byte)(cBytes)[:], address.Bytes())

	return cBytes
}

// define the ConnectionInitMessage struct
type ConnectionInitMessage struct {
	Type string `json:"type"`
}

// define the SubscriptionMessage struct
type SubscriptionMessage struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Payload struct {
		Query     string `json:"query"`
		Variables string `json:"variables,omitempty"`
	} `json:"payload"`
}
type Transaction struct {
	Index       int                 `json:"index"`
	Hash        string              `json:"hash"`
	BlockHeight int                 `json:"block_height"`
	GasUsed     int                 `json:"gas_used"`
	Messages    []Message           `json:"messages"`
	Response    TransactionResponse `json:"response"`
}

type Message struct {
	Route   string       `json:"route"`
	TypeURL string       `json:"typeUrl"`
	Value   MessageValue `json:"value"`
}

type MessageValue struct {
	Typename string `json:"__typename"`
}
type TransactionResponse struct {
	Log string `json:"log"`
}

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	u := url.URL{Scheme: "ws", Host: "0.0.0.0:8546", Path: "/graphql/query"}
	log.Println("connecting to", u.String())

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()

	if err := sendConnectionInitMessage(c); err != nil {
		log.Fatal("send connection_init:", err)
	}

	if err := handleConnectionAck(c); err != nil {
		log.Fatal("handle connection_ack:", err)
	}

	subscriptionQuery := `
    subscription {
        transactions(filter: {success: true}) {
            index
            hash
            block_height
            gas_used
            messages {
                route
                typeUrl
                value {
                    __typename
                    ... on MsgAddPackage {
                        creator
                        package {
                            name
                            path
                        }
                    }
                }
            }
            response {
                log
            }
        }
    }`

	if err := sendSubscription(c, subscriptionQuery); err != nil {
		log.Fatal("send subscription:", err)
	}

	done := make(chan struct{})
	go processMessages(c, done)

	select {
	case <-interrupt:
		log.Println("interrupt signal received, closing connection")
	case <-done:
		log.Println("connection closed")
	}

	if err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); err != nil {
		log.Println("write close:", err)
		return
	}

	select {
	case <-done:
	case <-time.After(time.Second):
	}
}

func sendConnectionInitMessage(c *websocket.Conn) error {
	connInit := ConnectionInitMessage{
		Type: "connection_init",
	}
	return c.WriteJSON(connInit)
}

func handleConnectionAck(c *websocket.Conn) error {
	_, _, err := c.ReadMessage()
	return err
}

func sendSubscription(c *websocket.Conn, query string) error {
	subMsg := SubscriptionMessage{
		Type: "start",
		ID:   "1",
	}
	subMsg.Payload.Query = query
	return c.WriteJSON(subMsg)
}

func processMessages(c *websocket.Conn, done chan<- struct{}) {
	defer close(done)
	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			return
		}

		// Check the type of message and handle it accordingly
		var msgType struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(message, &msgType); err != nil {
			log.Println("json unmarshal:", err)
			continue
		}

		switch msgType.Type {
		case "ka":
			log.Println("Received keep-alive message")
			// Handle keep-alive message
		case "data":
			log.Println("Received new transaction message")
			var data struct {
				Payload struct {
					Data struct {
						Transactions Transaction `json:"transactions"`
					} `json:"data"`
				} `json:"payload"`
			}
			if err := json.Unmarshal(message, &data); err != nil {
				log.Println("json unmarshal:", err)
				continue
			}
			handleTransaction(data.Payload.Data.Transactions)
		default:
			log.Println("Unknown message type:", msgType.Type)
		}
	}
}

// handleTransaction function to process the transaction data
func handleTransaction(transaction Transaction) {
	// Process the transaction data here
	log.Println("Index:", transaction.Index)
	log.Println("Hash:", transaction.Hash)
	log.Println("Block Height:", transaction.BlockHeight)
	log.Println("Gas Used:", transaction.GasUsed)
	log.Println("Response Log:", transaction.Response.Log)

	// Process messages
	for _, message := range transaction.Messages {
		log.Println("Message Route:", message.Route)
		log.Println("Message TypeURL:", message.TypeURL)
		log.Println("Message Typename:", message.Value.Typename)
	}
}

func logErrorMessage(message map[string]interface{}) {
	// Assuming the message contains error details
	// Log the error details
	log.Println("Received error:", message)
}
