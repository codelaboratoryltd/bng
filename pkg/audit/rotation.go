package audit

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RotatingFileExporter exports audit events to a rotating log file.
type RotatingFileExporter struct {
	config RotationConfig
	logger *zap.Logger
	mu     sync.Mutex

	currentFile     *os.File
	currentSize     int64
	currentFileName string
	startTime       time.Time

	// Stats
	rotations int64
	writes    int64
	errors    int64
}

// RotationConfig holds configuration for log rotation.
type RotationConfig struct {
	// Directory is the directory where log files are stored.
	Directory string

	// FilePrefix is the prefix for log file names.
	FilePrefix string

	// MaxSizeBytes is the maximum size in bytes before rotation.
	// Default: 100 MB
	MaxSizeBytes int64

	// MaxAgeDuration is the maximum age of a file before rotation.
	// Default: 24 hours
	MaxAgeDuration time.Duration

	// MaxFiles is the maximum number of rotated files to keep.
	// Default: 30
	MaxFiles int

	// Compress enables gzip compression of rotated files.
	Compress bool

	// Format is the log format: "json" or "text"
	Format string

	// FileMode is the permission mode for log files.
	FileMode os.FileMode

	// DirMode is the permission mode for the log directory.
	DirMode os.FileMode
}

// DefaultRotationConfig returns sensible defaults for rotation.
func DefaultRotationConfig() RotationConfig {
	return RotationConfig{
		Directory:      "/var/log/bng-audit",
		FilePrefix:     "audit",
		MaxSizeBytes:   100 * 1024 * 1024, // 100 MB
		MaxAgeDuration: 24 * time.Hour,
		MaxFiles:       30,
		Compress:       true,
		Format:         "json",
		FileMode:       0640,
		DirMode:        0750,
	}
}

// NewRotatingFileExporter creates a new rotating file exporter.
func NewRotatingFileExporter(config RotationConfig, logger *zap.Logger) (*RotatingFileExporter, error) {
	// Apply defaults
	if config.MaxSizeBytes == 0 {
		config.MaxSizeBytes = 100 * 1024 * 1024
	}
	if config.MaxAgeDuration == 0 {
		config.MaxAgeDuration = 24 * time.Hour
	}
	if config.MaxFiles == 0 {
		config.MaxFiles = 30
	}
	if config.Format == "" {
		config.Format = "json"
	}
	if config.FileMode == 0 {
		config.FileMode = 0640
	}
	if config.DirMode == 0 {
		config.DirMode = 0750
	}

	// Ensure directory exists
	if err := os.MkdirAll(config.Directory, config.DirMode); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	exp := &RotatingFileExporter{
		config:    config,
		logger:    logger,
		startTime: time.Now(),
	}

	// Open initial file
	if err := exp.openNewFile(); err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger.Info("Rotating file exporter initialized",
		zap.String("directory", config.Directory),
		zap.Int64("max_size_bytes", config.MaxSizeBytes),
		zap.Duration("max_age", config.MaxAgeDuration),
		zap.Int("max_files", config.MaxFiles),
		zap.Bool("compress", config.Compress),
	)

	return exp, nil
}

// Name returns the exporter name.
func (e *RotatingFileExporter) Name() string {
	return "rotating_file"
}

// Export writes an event to the log file.
func (e *RotatingFileExporter) Export(ctx context.Context, event *Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if rotation is needed
	if e.shouldRotate() {
		if err := e.rotate(); err != nil {
			e.errors++
			e.logger.Error("Failed to rotate log file", zap.Error(err))
			// Continue writing to current file
		}
	}

	// Format event
	var data []byte
	var err error
	switch e.config.Format {
	case "json":
		data, err = json.Marshal(event)
		if err != nil {
			e.errors++
			return fmt.Errorf("failed to marshal event: %w", err)
		}
		data = append(data, '\n')
	default:
		data = []byte(FormatSyslog(event) + "\n")
	}

	// Write to file
	n, err := e.currentFile.Write(data)
	if err != nil {
		e.errors++
		return fmt.Errorf("failed to write event: %w", err)
	}

	e.currentSize += int64(n)
	e.writes++

	return nil
}

// ExportBatch writes multiple events to the log file.
func (e *RotatingFileExporter) ExportBatch(ctx context.Context, events []*Event) error {
	for _, event := range events {
		if err := e.Export(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the exporter.
func (e *RotatingFileExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.currentFile != nil {
		if err := e.currentFile.Sync(); err != nil {
			e.logger.Warn("Failed to sync log file", zap.Error(err))
		}
		if err := e.currentFile.Close(); err != nil {
			return fmt.Errorf("failed to close log file: %w", err)
		}
		e.currentFile = nil
	}

	e.logger.Info("Rotating file exporter closed",
		zap.Int64("total_writes", e.writes),
		zap.Int64("total_rotations", e.rotations),
		zap.Int64("total_errors", e.errors),
	)

	return nil
}

// shouldRotate checks if rotation is needed.
func (e *RotatingFileExporter) shouldRotate() bool {
	// Size-based rotation
	if e.currentSize >= e.config.MaxSizeBytes {
		return true
	}

	// Time-based rotation
	if time.Since(e.startTime) >= e.config.MaxAgeDuration {
		return true
	}

	return false
}

// rotate performs log rotation.
func (e *RotatingFileExporter) rotate() error {
	// Sync and close current file
	if e.currentFile != nil {
		if err := e.currentFile.Sync(); err != nil {
			e.logger.Warn("Failed to sync before rotation", zap.Error(err))
		}
		if err := e.currentFile.Close(); err != nil {
			return fmt.Errorf("failed to close current file: %w", err)
		}
	}

	// Rename current file with timestamp
	if e.currentFileName != "" {
		rotatedName := e.generateRotatedName(e.currentFileName)
		if err := os.Rename(e.currentFileName, rotatedName); err != nil {
			return fmt.Errorf("failed to rename log file: %w", err)
		}

		// Compress if enabled
		if e.config.Compress {
			go e.compressFile(rotatedName)
		}
	}

	// Open new file
	if err := e.openNewFile(); err != nil {
		return fmt.Errorf("failed to open new log file: %w", err)
	}

	e.rotations++

	// Cleanup old files
	e.cleanupOldFiles()

	e.logger.Info("Log file rotated",
		zap.String("new_file", e.currentFileName),
		zap.Int64("rotations", e.rotations),
	)

	return nil
}

// openNewFile opens a new log file.
func (e *RotatingFileExporter) openNewFile() error {
	filename := filepath.Join(e.config.Directory, fmt.Sprintf("%s.log", e.config.FilePrefix))

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, e.config.FileMode)
	if err != nil {
		return err
	}

	// Get current size
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}

	e.currentFile = file
	e.currentFileName = filename
	e.currentSize = info.Size()
	e.startTime = time.Now()

	return nil
}

// generateRotatedName generates the name for a rotated file.
func (e *RotatingFileExporter) generateRotatedName(originalName string) string {
	timestamp := time.Now().Format("20060102-150405")
	ext := filepath.Ext(originalName)
	base := originalName[:len(originalName)-len(ext)]
	return fmt.Sprintf("%s-%s%s", base, timestamp, ext)
}

// compressFile compresses a rotated log file.
func (e *RotatingFileExporter) compressFile(filename string) {
	// Open source file
	source, err := os.Open(filename)
	if err != nil {
		e.logger.Warn("Failed to open file for compression", zap.Error(err))
		return
	}
	defer source.Close()

	// Create compressed file
	gzFilename := filename + ".gz"
	dest, err := os.Create(gzFilename)
	if err != nil {
		e.logger.Warn("Failed to create compressed file", zap.Error(err))
		return
	}
	defer dest.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(dest)
	defer gzWriter.Close()

	// Copy data
	if _, err := io.Copy(gzWriter, source); err != nil {
		e.logger.Warn("Failed to compress file", zap.Error(err))
		os.Remove(gzFilename)
		return
	}

	// Close writers to flush
	gzWriter.Close()
	dest.Close()
	source.Close()

	// Remove original file
	if err := os.Remove(filename); err != nil {
		e.logger.Warn("Failed to remove original file after compression", zap.Error(err))
	}

	e.logger.Debug("Compressed log file", zap.String("file", gzFilename))
}

// cleanupOldFiles removes old rotated files beyond MaxFiles limit.
func (e *RotatingFileExporter) cleanupOldFiles() {
	pattern := filepath.Join(e.config.Directory, e.config.FilePrefix+"*.log*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		e.logger.Warn("Failed to list log files for cleanup", zap.Error(err))
		return
	}

	// Filter out the current file
	var rotatedFiles []string
	for _, f := range files {
		if f != e.currentFileName {
			rotatedFiles = append(rotatedFiles, f)
		}
	}

	// Sort by modification time (oldest first)
	sort.Slice(rotatedFiles, func(i, j int) bool {
		infoI, _ := os.Stat(rotatedFiles[i])
		infoJ, _ := os.Stat(rotatedFiles[j])
		if infoI == nil || infoJ == nil {
			return false
		}
		return infoI.ModTime().Before(infoJ.ModTime())
	})

	// Remove oldest files if over limit
	if len(rotatedFiles) > e.config.MaxFiles {
		toRemove := rotatedFiles[:len(rotatedFiles)-e.config.MaxFiles]
		for _, f := range toRemove {
			if err := os.Remove(f); err != nil {
				e.logger.Warn("Failed to remove old log file", zap.String("file", f), zap.Error(err))
			} else {
				e.logger.Debug("Removed old log file", zap.String("file", f))
			}
		}
	}
}

// Stats returns exporter statistics.
func (e *RotatingFileExporter) Stats() RotatingFileStats {
	e.mu.Lock()
	defer e.mu.Unlock()

	return RotatingFileStats{
		CurrentFile:    e.currentFileName,
		CurrentSize:    e.currentSize,
		TotalWrites:    e.writes,
		TotalRotations: e.rotations,
		TotalErrors:    e.errors,
		FileAge:        time.Since(e.startTime),
	}
}

// RotatingFileStats holds statistics for the rotating file exporter.
type RotatingFileStats struct {
	CurrentFile    string
	CurrentSize    int64
	TotalWrites    int64
	TotalRotations int64
	TotalErrors    int64
	FileAge        time.Duration
}

// ForceRotation forces an immediate log rotation.
func (e *RotatingFileExporter) ForceRotation() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rotate()
}
