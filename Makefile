APP_CLIENT := dns-scanner-client
APP_SERVER := dns-scanner-server
BUILD_DIR := build
LDFLAGS := -s -w

.PHONY: all clean client server linux windows darwin android run-client run-server

all: linux windows darwin android

client:
	@echo "Building client for current OS..."
	go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_CLIENT) ./cmd/client/

server:
	@echo "Building server for current OS..."
	go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_SERVER) ./cmd/server/

linux:
	@echo "Building for Linux..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_CLIENT)-linux-amd64 ./cmd/client/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_SERVER)-linux-amd64 ./cmd/server/
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_CLIENT)-linux-arm64 ./cmd/client/
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_SERVER)-linux-arm64 ./cmd/server/

windows:
	@echo "Building for Windows..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_CLIENT)-windows-amd64.exe ./cmd/client/
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_SERVER)-windows-amd64.exe ./cmd/server/
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_CLIENT)-windows-arm64.exe ./cmd/client/
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_SERVER)-windows-arm64.exe ./cmd/server/

darwin:
	@echo "Building for macOS..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_CLIENT)-darwin-amd64 ./cmd/client/
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_SERVER)-darwin-amd64 ./cmd/server/
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_CLIENT)-darwin-arm64 ./cmd/client/
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_SERVER)-darwin-arm64 ./cmd/server/

android:
	@echo "Building for Android..."
	CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_CLIENT)-android-arm64 ./cmd/client/
	CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_SERVER)-android-arm64 ./cmd/server/

run-client:
	go run ./cmd/client/

run-server:
	go run ./cmd/server/

clean:
	rm -rf $(BUILD_DIR)
