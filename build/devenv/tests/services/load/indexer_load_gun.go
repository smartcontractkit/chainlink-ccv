package load

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"
)

type IndexerLoadGun struct {
	sentTimes       map[protocol.Bytes32]time.Time
	metrics         []Metrics
	sentMsgCh       chan protocol.QueryResponse
	metricsCh       chan Metrics
	doneCh          chan struct{}
	closeOnce       sync.Once
	mu              sync.RWMutex
	wg              sync.WaitGroup
	httpClient      *http.Client
	verifySemaphore chan struct{} // Limits concurrent verification requests
}

type Metrics struct {
	Nonce     protocol.Nonce
	MessageID protocol.Bytes32
	SentTime  time.Time
	Latency   time.Duration
}

func NewIndexerLoadGun() *IndexerLoadGun {
	// Create HTTP client with larger connection pool to prevent connection exhaustion
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 200,
		MaxConnsPerHost:     200,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false, // Keep connections alive but with larger pool
	}

	// Create semaphore to limit concurrent verification requests
	// This prevents overwhelming the API with too many concurrent requests
	maxConcurrentVerifications := 100
	verifySemaphore := make(chan struct{}, maxConcurrentVerifications)

	gun := &IndexerLoadGun{
		sentTimes:       make(map[protocol.Bytes32]time.Time),
		metrics:         make([]Metrics, 0),
		sentMsgCh:       make(chan protocol.QueryResponse, 100),
		metricsCh:       make(chan Metrics, 100),
		doneCh:          make(chan struct{}),
		closeOnce:       sync.Once{},
		mu:              sync.RWMutex{},
		wg:              sync.WaitGroup{},
		verifySemaphore: verifySemaphore,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
	}

	return gun
}

func (i *IndexerLoadGun) Call(gen *wasp.Generator) *wasp.Response {
	ccvData := defaultMessageGenerator(uint64(len(i.sentTimes)))
	messageID := ccvData.MessageID

	sentTime := time.Now()
	timestamp := sentTime.Unix()

	// Wrap CCVData in QueryResponse before marshaling
	queryResponse := protocol.QueryResponse{
		Timestamp: &timestamp,
		Data:      ccvData,
	}

	// Send to indexer
	jsonData, err := json.Marshal(queryResponse)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("POST", "http://localhost:9111/message", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := i.httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// Read and discard body for proper connection reuse
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatal(resp.Status)
	}

	i.mu.Lock()
	i.sentTimes[messageID] = sentTime
	i.mu.Unlock()

	i.sentMsgCh <- queryResponse

	return &wasp.Response{Data: struct {
		MessageID protocol.Bytes32
		SentTime  time.Time
	}{
		MessageID: messageID,
		SentTime:  time.Now(),
	}}
}

func (i *IndexerLoadGun) Metrics() []Metrics {
	i.mu.RLock()
	metrics := make([]Metrics, len(i.metrics))
	copy(metrics, i.metrics)
	i.mu.RUnlock()
	return metrics
}

func (i *IndexerLoadGun) VerifyMessagesAsync(ctx context.Context) chan struct{} {
	go i.run(ctx)
	return i.doneCh
}

func (i *IndexerLoadGun) run(ctx context.Context) {
	defer close(i.doneCh)

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-i.sentMsgCh:
			if !ok {
				i.wg.Wait()

				// Drain the metrics channel
				for metric := range i.metricsCh {
					i.mu.Lock()
					i.metrics = append(i.metrics, metric)
					if len(i.metrics) == len(i.sentTimes) {
						i.mu.Unlock()
						break
					} else {
						i.mu.Unlock()
					}
				}

				i.doneCh <- struct{}{}
				return
			}

			i.wg.Add(1)
			go i.handleMessage(ctx, msg, 30*time.Second, 200*time.Millisecond)
		case metric := <-i.metricsCh:
			i.mu.Lock()
			i.metrics = append(i.metrics, metric)
			i.mu.Unlock()
		}
	}
}

func (i *IndexerLoadGun) handleMessage(ctx context.Context, msg protocol.QueryResponse, messageTimeout, retryInterval time.Duration) {
	defer i.wg.Done()

	messageID := msg.Data.MessageID
	nonce := msg.Data.Nonce

	// Get the sent time for this message
	i.mu.RLock()
	sentTime, exists := i.sentTimes[messageID]
	i.mu.RUnlock()

	if !exists {
		log.Printf("Message %s not found in sentTimes map", messageID.String())
		return
	}

	// Set up timeout and retry logic
	deadline := time.Now().Add(messageTimeout)
	// Add larger initial random delay to spread out verification requests
	time.Sleep(time.Duration(rand.Int64N(500)) * time.Millisecond)

	for {
		select {
		case <-ctx.Done():
			// If the context is done, return
			return
		default:
			// Check if we've exceeded the timeout
			if time.Now().After(deadline) {
				log.Printf("Timeout reached for message %s after %v", messageID.String(), messageTimeout)
				return
			}

			// Try to verify the message
			if i.verifyMessage(messageID) {
				// Message found! Calculate latency and record metrics
				latency := time.Since(sentTime)
				i.metricsCh <- Metrics{
					Nonce:     nonce,
					MessageID: messageID,
					SentTime:  sentTime,
					Latency:   latency,
				}
				return
			}

			// Message not found yet, wait before retrying
			// Add significant jitter (0-200ms) to prevent request waves
			jitter := time.Duration(rand.Int64N(200)) * time.Millisecond
			time.Sleep(retryInterval + jitter)
		}
	}
}

func (i *IndexerLoadGun) verifyMessage(messageID protocol.Bytes32) bool {
	// Acquire semaphore to limit concurrent requests
	i.verifySemaphore <- struct{}{}
	defer func() {
		<-i.verifySemaphore
	}()

	// Build the URL
	url := fmt.Sprintf("http://localhost:8102/v1/messageid/%s", messageID.String())

	// Make GET request to indexer using shared HTTP client with connection pooling
	resp, err := i.httpClient.Get(url)
	if err != nil {
		log.Printf("ERROR: Verification failed for message %s: %v", messageID.String(), err)
		return false
	}

	// Important: Must read and close body properly for connection reuse
	// Not reading the body can cause EOF errors on subsequent requests
	statusOK := resp.StatusCode == http.StatusOK

	if resp.StatusCode == http.StatusTooManyRequests {
		log.Fatal("Rate Limit Exceeded, this should not happen. Cancelling test.")
	}

	// Read and discard the body to allow connection reuse
	// This is critical - closing without reading causes EOF errors
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Return true if message exists (status 200), false otherwise
	return statusOK
}

func (i *IndexerLoadGun) CloseSentChannel() {
	i.closeOnce.Do(func() {
		close(i.sentMsgCh)
	})
}

func defaultMessageGenerator(nonce uint64) protocol.CCVData {
	sourceAddr, _ := protocol.RandomAddress()
	destAddr, _ := protocol.RandomAddress()
	onRampAddr, _ := protocol.RandomAddress()
	offRampAddr, _ := protocol.RandomAddress()
	sender, _ := protocol.RandomAddress()
	receiver, _ := protocol.RandomAddress()
	sourceChainSelector := rand.Uint64()
	destChainSelector := rand.Uint64()

	message := protocol.Message{
		Version:              protocol.MessageVersion,
		SourceChainSelector:  protocol.ChainSelector(sourceChainSelector),
		DestChainSelector:    protocol.ChainSelector(destChainSelector),
		Nonce:                protocol.Nonce(nonce),
		OnRampAddressLength:  uint8(len(onRampAddr)),
		OnRampAddress:        onRampAddr,
		OffRampAddressLength: uint8(len(offRampAddr)),
		OffRampAddress:       offRampAddr,
		Finality:             1,
		SenderLength:         uint8(len(sender)),
		Sender:               sender,
		ReceiverLength:       uint8(len(receiver)),
		Receiver:             receiver,
		DataLength:           0,
		Data:                 []byte{},
		TokenTransferLength:  0,
		TokenTransfer:        []byte{},
		DestBlobLength:       0,
		DestBlob:             []byte{},
	}

	messageID, _ := message.MessageID()

	return protocol.CCVData{
		SourceVerifierAddress: sourceAddr,
		DestVerifierAddress:   destAddr,
		Message:               message,
		Nonce:                 message.Nonce,
		SourceChainSelector:   message.SourceChainSelector,
		DestChainSelector:     message.DestChainSelector,
		MessageID:             messageID,
		CCVData:               []byte{},
		BlobData:              []byte{},
		ReceiptBlobs:          []protocol.ReceiptWithBlob{},
		Timestamp:             time.Now().Unix(),
	}
}
