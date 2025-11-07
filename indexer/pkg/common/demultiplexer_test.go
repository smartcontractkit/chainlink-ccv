package common

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDemultiplexer(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	require.NotNil(t, d)
	assert.NotNil(t, d.wait)
}

func TestCreate(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	ch := d.Create("key1")
	require.NotNil(t, ch)

	// Channel should be registered
	d.mu.Lock()
	_, exists := d.wait["key1"]
	d.mu.Unlock()
	assert.True(t, exists)
}

func TestResolve_Success(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	ch := d.Create("key1")

	d.Resolve("key1", 42, nil)

	result := <-ch
	assert.Equal(t, 42, result.Value())
	assert.NoError(t, result.Err())

	// Channel should be closed
	_, ok := <-ch
	assert.False(t, ok)

	// Key should be removed
	d.mu.Lock()
	_, exists := d.wait["key1"]
	d.mu.Unlock()
	assert.False(t, exists)
}

func TestResolve_Error(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	ch := d.Create("key1")
	err := errors.New("test error")

	d.Resolve("key1", 0, err)

	result := <-ch
	assert.Equal(t, 0, result.Value())
	assert.Equal(t, err, result.Err())

	// Channel should be closed
	_, ok := <-ch
	assert.False(t, ok)
}

func TestResolve_NonExistentKey(t *testing.T) {
	d := NewDemultiplexer[string, int]()

	// Should not panic
	d.Resolve("nonexistent", 0, nil)

	// Map should remain empty
	d.mu.Lock()
	assert.Empty(t, d.wait)
	d.mu.Unlock()
}

func TestCreate_Overwrite(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	_ = d.Create("key1")    // First channel (will be overwritten)
	ch2 := d.Create("key1") // Overwrite

	// Resolve should only go to ch2
	d.Resolve("key1", 100, nil)

	// ch2 should receive the result
	result := <-ch2
	assert.Equal(t, 100, result.Value())

	// Verify ch2 is closed
	_, ok := <-ch2
	assert.False(t, ok)
}

func TestResult_Methods(t *testing.T) {
	r := Result[int]{v: 42, err: nil}
	assert.Equal(t, 42, r.Value())
	assert.NoError(t, r.Err())

	r2 := Result[int]{v: 0, err: errors.New("error")}
	assert.Equal(t, 0, r2.Value())
	assert.Error(t, r2.Err())
}

func TestPending_Empty(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	pending := d.Pending()
	assert.Empty(t, pending)
	assert.Len(t, pending, 0)
}

func TestPending_SingleKey(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	_ = d.Create("key1")

	pending := d.Pending()
	require.Len(t, pending, 1)
	assert.Contains(t, pending, "key1")
}

func TestPending_MultipleKeys(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	_ = d.Create("key1")
	_ = d.Create("key2")
	_ = d.Create("key3")

	pending := d.Pending()
	require.Len(t, pending, 3)
	assert.Contains(t, pending, "key1")
	assert.Contains(t, pending, "key2")
	assert.Contains(t, pending, "key3")
}

func TestPending_AfterResolve(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	ch1 := d.Create("key1")
	_ = d.Create("key2")
	_ = d.Create("key3")

	// Resolve one key
	d.Resolve("key1", 42, nil)
	<-ch1 // Consume the result

	pending := d.Pending()
	require.Len(t, pending, 2)
	assert.NotContains(t, pending, "key1")
	assert.Contains(t, pending, "key2")
	assert.Contains(t, pending, "key3")
}

func TestPending_AfterResolveAll(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	ch1 := d.Create("key1")
	ch2 := d.Create("key2")

	d.Resolve("key1", 42, nil)
	d.Resolve("key2", 100, nil)

	<-ch1 // Consume results
	<-ch2

	pending := d.Pending()
	assert.Empty(t, pending)
	assert.Len(t, pending, 0)
}

func TestPending_AfterResolveNonExistent(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	_ = d.Create("key1")
	_ = d.Create("key2")

	// Resolve a non-existent key
	d.Resolve("nonexistent", 0, nil)

	pending := d.Pending()
	require.Len(t, pending, 2)
	assert.Contains(t, pending, "key1")
	assert.Contains(t, pending, "key2")
}

func TestPending_AfterOverwrite(t *testing.T) {
	d := NewDemultiplexer[string, int]()
	_ = d.Create("key1") // First channel
	_ = d.Create("key1") // Overwrite
	_ = d.Create("key2")

	pending := d.Pending()
	require.Len(t, pending, 2)
	assert.Contains(t, pending, "key1")
	assert.Contains(t, pending, "key2")
}

func TestPending_ConcurrentAccess(t *testing.T) {
	d := NewDemultiplexer[int, string]()

	// Create keys concurrently
	done := make(chan bool)
	go func() {
		for i := range 10 {
			d.Create(i)
		}
		done <- true
	}()
	go func() {
		for i := 10; i < 20; i++ {
			d.Create(i)
		}
		done <- true
	}()

	<-done
	<-done

	// Pending should have all 20 keys
	pending := d.Pending()
	assert.Len(t, pending, 20)

	// Verify all keys are present
	keyMap := make(map[int]bool)
	for _, k := range pending {
		keyMap[k] = true
	}
	for i := range 20 {
		assert.True(t, keyMap[i], "key %d should be in pending", i)
	}
}
