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
	"golang.org/x/crypto/bcrypt"
)

// var upgrader = websocket.Upgrader{
// 	CheckOrigin: func(r *http.Request) bool {
// 		return true
// 	},
// }

func connectToDatabase() *sql.DB {
    dsn := "root:root@tcp(localhost:3306)/conference?charset=utf8mb4&parseTime=True&loc=Local"
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        log.Fatalf("Error opening database: %v", err)
    }
    err = db.Ping()
    if err != nil {
        log.Fatalf("Error connecting to database: %v", err)
    }
    return db
}


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
	http.HandleFunc("/conference", homeHandler)

    // Защищаем маршрут с помощью authMiddleware
    protectedRoutes := router.PathPrefix("/").Subrouter()
    protectedRoutes.Use(authMiddleware)
    protectedRoutes.HandleFunc("/ws", wsHandler)

    log.Printf("Server started on localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", router))
}

func createToken(u_id int) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "u_id": u_id,
    })

    tokenString, err := token.SignedString([]byte(jwtSecret))
    if err != nil {
        return "", err
    }

    return tokenString, nil
}


func registerHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    if user.Email == "" || user.Password == "" {
        http.Error(w, "Email and password are required", http.StatusBadRequest)
        return
    }

    db := connectToDatabase()
    defer db.Close()

    var existingUserID int
    err = db.QueryRow("SELECT u_id FROM user WHERE email = ?", user.Email).Scan(&existingUserID)
    if err != sql.ErrNoRows && existingUserID != 0 {
        http.Error(w, "A user with this email already exists", http.StatusConflict)
        return
    }

    // Хеширование пароля перед сохранением в базе данных
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    result, err := db.Exec("INSERT INTO user (email, password) VALUES (?, ?)", user.Email, string(hashedPassword))
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    lastInsertId, err := result.LastInsertId()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    user.U_ID = int(lastInsertId)

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(user)
}



func loginHandler(w http.ResponseWriter, r *http.Request) {
    var user User

    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Bad Request", http.StatusBadRequest)
        return
    }

    db := connectToDatabase()
    defer db.Close()

    var dbUser User
    err = db.QueryRow("SELECT u_id, email, password FROM user WHERE email=?", user.Email).Scan(&dbUser.U_ID, &dbUser.Email, &dbUser.Password)
    if err != nil {
        if err == sql.ErrNoRows {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        log.Printf("Error querying user: %v", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password))
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    token, err := createToken(dbUser.U_ID)
    if err != nil {
        log.Printf("Error creating token: %v", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{"token": token})
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
	// http.ServeFile(w, r, "home.html")
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