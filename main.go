package main

import (
	"fmt"
	"log"
	"net/http"
	"text/template"
	"time"
	"database/sql"
	"encoding/json"
	"context"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v3"
	"github.com/pion/webrtc/v3/pkg/media"
)

// var upgrader = websocket.Upgrader{
// 	CheckOrigin: func(r *http.Request) bool {
// 		return true
// 	},
// }

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

var jwtSecret = []byte("your_secret_key_here")

type User struct {
    U_ID     int    `json:"u_id"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

func main() {
    router := mux.NewRouter()
    router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "index.html")
    })
    router.HandleFunc("/register", registerHandler).Methods("POST")
    router.HandleFunc("/login", loginHandler).Methods("POST")

    // Защищаем маршрут с помощью authMiddleware
    protectedRoutes := router.PathPrefix("/").Subrouter()
    protectedRoutes.Use(authMiddleware)
    protectedRoutes.HandleFunc("/ws", wsHandler)

    log.Printf("Server started on localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", router))
}


func connectToDatabase() *sql.DB {
    dsn := "root:root@tcp(localhost:3306)/diplom?charset=utf8&parseTime=True&loc=Local"

    db, err := sql.Open("mysql", dsn)
    if err != nil {
        log.Fatalf("Error connecting to database: %v", err)
    }

    return db
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    db := connectToDatabase()
    defer db.Close()

    _, err = db.Exec("INSERT INTO user (email, password) VALUES (?, ?)", user.Email, user.Password)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
}


func loginHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    db := connectToDatabase()
    defer db.Close()

    row := db.QueryRow("SELECT u_id, password FROM user WHERE email = ?", user.Email) // Изменено с "id"
    var storedPassword string
    err = row.Scan(&user.U_ID, &storedPassword) // Изменено с "ID"
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    if storedPassword != user.Password {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Создаем новый JWT-токен
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "u_id":  user.U_ID, // Изменено с "id"
        "email": user.Email,
    })

    // Подписываем токен с нашим секретным ключом
    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Отправляем токен клиенту
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "token": tokenString,
    })
}


func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "No token provided", http.StatusUnauthorized)
            return
        }

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
            }
            return jwtSecret, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // Добавим информацию о пользователе в контекст запроса
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            http.Error(w, "Invalid token claims", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), "u_id", claims["u_id"])
        ctx = context.WithValue(ctx, "userEmail", claims["email"])
        r = r.WithContext(ctx)

        next.ServeHTTP(w, r)
    })
}


func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("home.html"))
	tmpl.Execute(w, nil)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error during WebSocket upgrade: %v", err)
		return
	}
	defer conn.Close()

	peerConnection, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		log.Fatalf("Error creating peer connection: %v", err)
	}

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		go func() {
			codec := track.Codec()
			codecCapability := webrtc.RTPCodecCapability{
				MimeType:     codec.MimeType,
				ClockRate:    codec.ClockRate,
				Channels:     codec.Channels,
				SDPFmtpLine:  codec.SDPFmtpLine,
				RTCPFeedback: codec.RTCPFeedback,
			}
			newTrack, err := webrtc.NewTrackLocalStaticSample(codecCapability, track.RID(), track.RID())
			if err != nil {
				log.Fatalf("Error creating new local track: %v", err)
			}

			_, err = peerConnection.AddTrack(newTrack)
			if err != nil {
				log.Fatalf("Error adding new track to peer connection: %v", err)
			}

			for {
				rtpPacket, _, err := track.ReadRTP()
				if err != nil {
					log.Fatalf("Error reading RTP packet from track: %v", err)
				}

				data, err := rtpPacket.Marshal()
				if err != nil {
					log.Fatalf("Error marshaling RTP packet: %v", err)
				}

				sample := media.Sample{Data: data, Duration: time.Duration(20) * time.Millisecond}
				if err := newTrack.WriteSample(sample); err != nil {
					log.Fatalf("Error writing sample to new track: %v", err)
				}
			}
		}()
	})

	offer := webrtc.SessionDescription{}
	err = conn.ReadJSON(&offer)
	if err != nil {
		log.Printf("Error reading JSON from WebSocket: %v", err)
		return
	}

	err = peerConnection.SetRemoteDescription(offer)
	if err != nil {
		log.Fatalf("Error setting remote description: %v", err)
	}

	answer, err := peerConnection.CreateAnswer(nil)
	if err != nil {
		log.Fatalf("Error creating answer: %v", err)
	}

	err = peerConnection.SetLocalDescription(answer)
	if err != nil {
		log.Fatalf("Error setting local description: %v", err)
	}

	err = conn.WriteJSON(answer)
	if err != nil {
		log.Printf("Error writing JSON to WebSocket: %v", err)
		return
	}

	select {}
}