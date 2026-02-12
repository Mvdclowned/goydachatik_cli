package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

// ANSI
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Gray   = "\033[90m"
)

// Структура сообщений
type Message struct {
	Type      string `json:"type"`
	Room      string `json:"room"`
	Sender    string `json:"sender"`
	Content   []byte `json:"content"`    // Текст или системные данные
	PublicKey []byte `json:"public_key"` // Публичный ключ
}

// Глобальные переменные
var (
	privKey   []byte
	pubKeyX   *big.Int
	pubKeyY   *big.Int
	sharedKey []byte
	
	username string
	room     string
	conn     *websocket.Conn
)

func main() {
	serverAddr := flag.String("server", "localhost:8080", "Адрес сервера (например, localhost:8080 или домен ngrok)")
	flag.Parse()

	// 1. Генерация
	fmt.Println(Yellow + "🔐 Generating Elliptic Curve keys..." + Reset)
	privKey, pubKeyX, pubKeyY = GenerateKeys()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Nickname: ")
	uInput, _ := reader.ReadString('\n')
	username = strings.TrimSpace(uInput)

	fmt.Print("Enter Room (Secret Channel): ")
	rInput, _ := reader.ReadString('\n')
	room = strings.TrimSpace(rInput)

	// 2. Обработка ngrok и протоколов
	finalAddr := *serverAddr
	finalAddr = strings.TrimPrefix(finalAddr, "https://")
	finalAddr = strings.TrimPrefix(finalAddr, "http://")
	finalAddr = strings.TrimSuffix(finalAddr, "/")

	scheme := "ws"
	if !strings.HasPrefix(finalAddr, "localhost") && !strings.HasPrefix(finalAddr, "127.0.0.1") {
		scheme = "wss" // ngrok требует шифрованный вебсокет
	}

	u := url.URL{Scheme: scheme, Host: finalAddr, Path: "/ws"}
	fmt.Printf(Gray+"Attempting connection to %s..."+Reset+"\n", u.String())

	var err error
	conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		if strings.Contains(err.Error(), "bad handshake") {
			fmt.Println(Red + " Ошибка: Bad Handshake." + Reset)
			fmt.Println(Yellow + "Если используешь ngrok, открой ссылку в браузере и нажми Visit Site. " + Reset)
		}
		log.Fatal(Red+"Connection error: ", err, Reset)
	}
	defer conn.Close()

	// 3. Рукопожатие
	announceJoin()
	sendPublicKey()

	// Поток чтения
	go readLoop()

	fmt.Println(Green + ">>> SECURE CHANNEL ESTABLISHED <<<" + Reset)
	fmt.Println(Gray + "Waiting for partner to exchange keys..." + Reset)

	// 4. Цикл отправки
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" { continue }

		if sharedKey == nil {
			fmt.Println(Red + "⚠️  WAIT! No secure connection yet. Need a partner in the room." + Reset)
			continue
		}

		// Шифрование AES-GCM
		encryptedBytes := EncryptAES(sharedKey, text)

		msg := Message{
			Type:    "msg",
			Room:    room,
			Sender:  username,
			Content: encryptedBytes,
		}
		
		err := conn.WriteJSON(msg)
		if err != nil {
			fmt.Println(Red + "Failed to send message." + Reset)
			return
		}
		fmt.Print("\033[1A\033[K") // Очистка строки ввода
		fmt.Printf("%s<%s>%s %s\n", Green, "YOU", Reset, text)
	}
}

// Уведомление о входе
func announceJoin() {
	msg := Message{
		Type:    "system",
		Room:    room,
		Sender:  username,
		Content: []byte(">>> " + username + " joined the secure channel"),
	}
	conn.WriteJSON(msg)
}

// Отправка публичного ключа
func sendPublicKey() {
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), pubKeyX, pubKeyY)
	handshakeMsg := Message{
		Type:      "pubkey",
		Room:      room,
		Sender:    username,
		PublicKey: pubKeyBytes,
	}
	conn.WriteJSON(handshakeMsg)
}

func readLoop() {
	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			fmt.Println(Red + "\nDisconnected from server." + Reset)
			os.Exit(0)
		}

		if msg.Sender == username { continue }

		switch msg.Type {
		case "pubkey":
			// Получен ключ собеседника
			fmt.Printf(Yellow + "🔑 Received Public Key from %s. Deriving secrets...\n" + Reset, msg.Sender)
			x, y := elliptic.Unmarshal(elliptic.P256(), msg.PublicKey)
			if x == nil { continue }
			sharedKey = DeriveSharedSecret(privKey, x, y)
			fmt.Println(Green + "🔒 E2E ENCRYPTION ACTIVE. Key exchange successful." + Reset)

		case "msg":
			// Получение зашифрованного сообщения
			if sharedKey == nil {
				fmt.Println(Red + "🔒 Encrypted message received, but no key!" + Reset)
			} else {
				decryptedText, err := DecryptAES(sharedKey, msg.Content)
				if err != nil {
					fmt.Println(Red + "Error decrypting message!" + Reset)
				} else {
					fmt.Printf("%s<%s>%s %s\n", Cyan, msg.Sender, Reset, decryptedText)
				}
			}

		case "system":
			// Системные уведомления
			sysText := string(msg.Content)
			if strings.Contains(sysText, "disconnected") {
				fmt.Printf("%s%s%s\n", Red, sysText, Reset)
			} else {
				fmt.Printf("%s%s%s\n", Gray, sysText, Reset)
			}
			
			// Если кто-то зашел, отправляем ему свой ключ в ответ
			if strings.Contains(sysText, "joined") {
				if !strings.Contains(sysText, username) {
					fmt.Println(Yellow + "🔄 New user detected. Sending Public Key..." + Reset)
					sendPublicKey()
				}
			}
		}
	}
}

// Криптография

func GenerateKeys() ([]byte, *big.Int, *big.Int) {
	curve := elliptic.P256()
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil { log.Fatal(err) }
	return priv, x, y
}

func DeriveSharedSecret(myPriv []byte, theirX, theirY *big.Int) []byte {
	curve := elliptic.P256()
	x, _ := curve.ScalarMult(theirX, theirY, myPriv)
	hashed := sha256.Sum256(x.Bytes())
	return hashed[:]
}

func EncryptAES(key []byte, plaintext string) []byte {
	block, _ := aes.NewCipher(key)
	aesGCM, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesGCM.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
}

func DecryptAES(key []byte, ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return "", err }
	aesGCM, err := cipher.NewGCM(block)
	if err != nil { return "", err }
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize { return "", fmt.Errorf("bad cipher") }
	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, actualCiphertext, nil)
	if err != nil { return "", err }
	return string(plaintext), nil
}