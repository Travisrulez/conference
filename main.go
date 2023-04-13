package main

import (
	"fmt"
	"log"
	"net/http"
	"text/template"
	"time"

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

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/ws", wsHandler)

	fmt.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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