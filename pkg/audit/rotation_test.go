package audit_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/codelaboratoryltd/bng/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDefaultRotationConfig(t *testing.T) {
	config := audit.DefaultRotationConfig()

	assert.NotEmpty(t, config.Directory)
	assert.NotEmpty(t, config.FilePrefix)
	assert.Greater(t, config.MaxSizeBytes, int64(0))
	assert.Greater(t, config.MaxAgeDuration, time.Duration(0))
	assert.Greater(t, config.MaxFiles, 0)
	assert.True(t, config.Compress)
	assert.Equal(t, "json", config.Format)
}

func TestRotatingFileExporter_Create(t *testing.T) {
	tmpDir := t.TempDir()
	logger := zap.NewNop()

	config := audit.RotationConfig{
		Directory:      tmpDir,
		FilePrefix:     "test-audit",
		MaxSizeBytes:   1024 * 1024,
		MaxAgeDuration: time.Hour,
		MaxFiles:       5,
		Compress:       false,
		Format:         "json",
	}

	exporter, err := audit.NewRotatingFileExporter(config, logger)
	require.NoError(t, err)
	require.NotNil(t, exporter)
	defer exporter.Close()

	assert.Equal(t, "rotating_file", exporter.Name())

	// Check that log file was created
	expectedFile := filepath.Join(tmpDir, "test-audit.log")
	_, err = os.Stat(expectedFile)
	assert.NoError(t, err)
}

func TestRotatingFileExporter_Export(t *testing.T) {
	tmpDir := t.TempDir()
	logger := zap.NewNop()

	config := audit.RotationConfig{
		Directory:      tmpDir,
		FilePrefix:     "test-audit",
		MaxSizeBytes:   1024 * 1024,
		MaxAgeDuration: time.Hour,
		MaxFiles:       5,
		Compress:       false,
		Format:         "json",
	}

	exporter, err := audit.NewRotatingFileExporter(config, logger)
	require.NoError(t, err)
	defer exporter.Close()

	// Export an event
	event := &audit.Event{
		ID:        "test-1",
		Type:      audit.EventSessionStart,
		Timestamp: time.Now(),
		DeviceID:  "bng-1",
	}

	err = exporter.Export(context.Background(), event)
	require.NoError(t, err)

	// Check stats
	stats := exporter.Stats()
	assert.Equal(t, int64(1), stats.TotalWrites)
	assert.Greater(t, stats.CurrentSize, int64(0))
}

func TestRotatingFileExporter_ExportBatch(t *testing.T) {
	tmpDir := t.TempDir()
	logger := zap.NewNop()

	config := audit.RotationConfig{
		Directory:      tmpDir,
		FilePrefix:     "test-audit",
		MaxSizeBytes:   1024 * 1024,
		MaxAgeDuration: time.Hour,
		MaxFiles:       5,
		Compress:       false,
		Format:         "json",
	}

	exporter, err := audit.NewRotatingFileExporter(config, logger)
	require.NoError(t, err)
	defer exporter.Close()

	// Export a batch of events
	events := []*audit.Event{
		{ID: "test-1", Type: audit.EventSessionStart, Timestamp: time.Now()},
		{ID: "test-2", Type: audit.EventSessionStop, Timestamp: time.Now()},
		{ID: "test-3", Type: audit.EventAuthSuccess, Timestamp: time.Now()},
	}

	err = exporter.ExportBatch(context.Background(), events)
	require.NoError(t, err)

	stats := exporter.Stats()
	assert.Equal(t, int64(3), stats.TotalWrites)
}

func TestRotatingFileExporter_SizeRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logger := zap.NewNop()

	// Very small max size to trigger rotation
	config := audit.RotationConfig{
		Directory:      tmpDir,
		FilePrefix:     "test-audit",
		MaxSizeBytes:   500, // 500 bytes
		MaxAgeDuration: time.Hour,
		MaxFiles:       5,
		Compress:       false,
		Format:         "json",
	}

	exporter, err := audit.NewRotatingFileExporter(config, logger)
	require.NoError(t, err)
	defer exporter.Close()

	// Export enough events to trigger rotation
	for i := 0; i < 20; i++ {
		event := &audit.Event{
			ID:           "test-" + string(rune('A'+i)),
			Type:         audit.EventSessionStart,
			Timestamp:    time.Now(),
			DeviceID:     "bng-1",
			SubscriberID: "subscriber-12345",
			SessionID:    "session-" + string(rune('A'+i)),
		}
		err = exporter.Export(context.Background(), event)
		require.NoError(t, err)
	}

	stats := exporter.Stats()
	assert.Greater(t, stats.TotalRotations, int64(0), "Should have rotated at least once")
}

func TestRotatingFileExporter_ForceRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logger := zap.NewNop()

	config := audit.RotationConfig{
		Directory:      tmpDir,
		FilePrefix:     "test-audit",
		MaxSizeBytes:   1024 * 1024,
		MaxAgeDuration: time.Hour,
		MaxFiles:       5,
		Compress:       false,
		Format:         "json",
	}

	exporter, err := audit.NewRotatingFileExporter(config, logger)
	require.NoError(t, err)
	defer exporter.Close()

	// Write something
	event := &audit.Event{
		ID:   "test-1",
		Type: audit.EventSessionStart,
	}
	err = exporter.Export(context.Background(), event)
	require.NoError(t, err)

	// Force rotation
	err = exporter.ForceRotation()
	require.NoError(t, err)

	stats := exporter.Stats()
	assert.Equal(t, int64(1), stats.TotalRotations)
}

func TestRotatingFileExporter_TextFormat(t *testing.T) {
	tmpDir := t.TempDir()
	logger := zap.NewNop()

	config := audit.RotationConfig{
		Directory:      tmpDir,
		FilePrefix:     "test-audit",
		MaxSizeBytes:   1024 * 1024,
		MaxAgeDuration: time.Hour,
		MaxFiles:       5,
		Compress:       false,
		Format:         "text", // Use text format
	}

	exporter, err := audit.NewRotatingFileExporter(config, logger)
	require.NoError(t, err)
	defer exporter.Close()

	event := &audit.Event{
		ID:        "test-1",
		Type:      audit.EventSessionStart,
		Timestamp: time.Now(),
		DeviceID:  "bng-1",
	}

	err = exporter.Export(context.Background(), event)
	require.NoError(t, err)

	// Read and verify format
	content, err := os.ReadFile(filepath.Join(tmpDir, "test-audit.log"))
	require.NoError(t, err)

	// Text format should contain syslog-style output
	assert.Contains(t, string(content), "device=bng-1")
	assert.Contains(t, string(content), "type=SESSION_START")
}

func TestRotatingFileExporter_Close(t *testing.T) {
	tmpDir := t.TempDir()
	logger := zap.NewNop()

	config := audit.RotationConfig{
		Directory:      tmpDir,
		FilePrefix:     "test-audit",
		MaxSizeBytes:   1024 * 1024,
		MaxAgeDuration: time.Hour,
		MaxFiles:       5,
		Compress:       false,
		Format:         "json",
	}

	exporter, err := audit.NewRotatingFileExporter(config, logger)
	require.NoError(t, err)

	// Export an event
	event := &audit.Event{
		ID:   "test-1",
		Type: audit.EventSessionStart,
	}
	err = exporter.Export(context.Background(), event)
	require.NoError(t, err)

	// Close should work
	err = exporter.Close()
	assert.NoError(t, err)

	// Double close should be safe
	err = exporter.Close()
	assert.NoError(t, err)
}

func TestRotatingFileExporter_InvalidDirectory(t *testing.T) {
	logger := zap.NewNop()

	config := audit.RotationConfig{
		Directory:      "/nonexistent/invalid/path/that/does/not/exist",
		FilePrefix:     "test-audit",
		MaxSizeBytes:   1024 * 1024,
		MaxAgeDuration: time.Hour,
		MaxFiles:       5,
	}

	_, err := audit.NewRotatingFileExporter(config, logger)
	assert.Error(t, err)
}

func TestRotatingFileExporter_Stats(t *testing.T) {
	tmpDir := t.TempDir()
	logger := zap.NewNop()

	config := audit.RotationConfig{
		Directory:      tmpDir,
		FilePrefix:     "test-audit",
		MaxSizeBytes:   1024 * 1024,
		MaxAgeDuration: time.Hour,
		MaxFiles:       5,
		Compress:       false,
		Format:         "json",
	}

	exporter, err := audit.NewRotatingFileExporter(config, logger)
	require.NoError(t, err)
	defer exporter.Close()

	// Initial stats
	stats := exporter.Stats()
	assert.NotEmpty(t, stats.CurrentFile)
	assert.Equal(t, int64(0), stats.TotalWrites)
	assert.Equal(t, int64(0), stats.TotalRotations)
	assert.Equal(t, int64(0), stats.TotalErrors)

	// Export events
	for i := 0; i < 5; i++ {
		event := &audit.Event{ID: "test", Type: audit.EventSessionStart}
		_ = exporter.Export(context.Background(), event)
	}

	stats = exporter.Stats()
	assert.Equal(t, int64(5), stats.TotalWrites)
	assert.Greater(t, stats.CurrentSize, int64(0))
}

func TestRotatingFileExporter_DefaultValues(t *testing.T) {
	tmpDir := t.TempDir()
	logger := zap.NewNop()

	// Minimal config - should use defaults
	config := audit.RotationConfig{
		Directory:  tmpDir,
		FilePrefix: "test-audit",
	}

	exporter, err := audit.NewRotatingFileExporter(config, logger)
	require.NoError(t, err)
	defer exporter.Close()

	// Should work with default values
	event := &audit.Event{
		ID:   "test-1",
		Type: audit.EventSessionStart,
	}
	err = exporter.Export(context.Background(), event)
	assert.NoError(t, err)
}
