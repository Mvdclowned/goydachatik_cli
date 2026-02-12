package main

import (
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type Message struct {
	Type      string `json:"type"` // "pubkey" или "msg"
	Room      string `json:"room"`
	Sender    string `json:"sender"`
	Content   []byte `json:"content"`   // Зашифрованные данные (AES)
	PublicKey []byte `json:"public_key"` // Публичный ключ (ECDH)
}

var clients = make(map[*websocket.Conn]string) // Соединение -> Комната
var broadcast = make(chan Message)
var mutex = &sync.Mutex{}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func main() {
	http.HandleFunc("/ws", handleConnections)
	go handleMessages()

	log.Println("🛡️  E2E Relay Server started on :8080")
	log.Println("😶 I can't read your messages even if I wanted to.")

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	// Пока не знаем комнату
	mutex.Lock()
	clients[ws] = "" 
	mutex.Unlock()

	for {
		var msg Message
		err := ws.ReadJSON(&msg)
		if err != nil {
			mutex.Lock()
			delete(clients, ws)
			mutex.Unlock()
			break
		}

		// Запоминаем комнату клиента при первом сообщении
		if msg.Room != "" {
			mutex.Lock()
			clients[ws] = msg.Room
			mutex.Unlock()
		}

		// Просто пересылаем всем. Сервер не пытается расшифровать Content.
		broadcast <- msg
	}
}

func handleMessages() {
	for {
		msg := <-broadcast
		mutex.Lock()
		for client, room := range clients {
			// Шлем только тем, кто в той же комнате
			if room == msg.Room {
				err := client.WriteJSON(msg)
				if err != nil {
					client.Close()
					delete(clients, client)
				}
			}
		}
		mutex.Unlock()
	}
}