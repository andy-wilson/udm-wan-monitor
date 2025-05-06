package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Config represents the application configuration
type Config struct {
	Monitoring struct {
		CheckInterval int      `json:"check_interval"`
		DebugInterval int      `json:"debug_interval"`
		LogFilePath   string   `json:"log_file_path"`
		WanInterfaces []string `json:"wan_interfaces"`
	} `json:"monitoring"`
	UnifiAPI struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		APIPrefix   string `json:"api_prefix"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		SiteID      string `json:"site_id"`
		InsecureSSL bool   `json:"insecure_ssl"`
	} `json:"unifi_api"`
	Events struct {
		NewInterface   string `json:"new_interface"`
		Reconnected    string `json:"reconnected"`
		Disconnected   string `json:"disconnected"`
		IPChanged      string `json:"ip_changed"`
		GatewayChanged string `json:"gateway_changed"`
	} `json:"events"`
}

// Interface status
type InterfaceStatus struct {
	Name      string
	Type      string
	Up        bool
	IPAddress string
	Gateway   string
	DNS       []string
}

// Auth response
type AuthResponse struct {
	Meta struct {
		RC string `json:"rc"`
	} `json:"meta"`
	Data []struct {
		Token string `json:"token"`
	} `json:"data"`
}

// Event represents a UniFi event
type Event struct {
	Key       string      `json:"key"`
	Time      int64       `json:"time"`
	Msg       string      `json:"msg"`
	Subsystem string      `json:"subsystem"`
	Site      string      `json:"site"`
	Archived  bool        `json:"archived"`
	Data      interface{} `json:"data"`
}

// Controller represents a UniFi controller connection
type Controller struct {
	config     *Config
	baseURL    string
	client     *http.Client
	csrfToken  string
	cookies    []*http.Cookie
	lastStatus map[string]InterfaceStatus
	authTime   time.Time
}

// NewController creates a new UniFi controller client
func NewController(config *Config) (*Controller, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	// Create transport with TLS configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.UnifiAPI.InsecureSSL,
		},
	}

	client := &http.Client{
		Jar:       jar,
		Transport: transport,
	}

	controller := &Controller{
		config:     config,
		baseURL:    fmt.Sprintf("https://%s:%d%s", config.UnifiAPI.Host, config.UnifiAPI.Port, config.UnifiAPI.APIPrefix),
		client:     client,
		lastStatus: make(map[string]InterfaceStatus),
	}

	return controller, nil
}

// setupLogging configures the logger to write to both stdout and a file
func setupLogging(config *Config) (*os.File, error) {
	logFile, err := os.OpenFile(config.Monitoring.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	log.SetFlags(log.Ldate | log.Ltime)

	return logFile, nil
}

// Login authenticates with the UniFi controller
func (c *Controller) Login() error {
	// Login URL for UniFi OS devices (in my case a UDM-SE, but works for all flavour of UDM)
	loginURL := fmt.Sprintf("https://%s:%d/api/auth/login", c.config.UnifiAPI.Host, c.config.UnifiAPI.Port)

	credentials := map[string]string{
		"username": c.config.UnifiAPI.Username,
		"password": c.config.UnifiAPI.Password,
	}

	jsonData, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	req, err := http.NewRequest("POST", loginURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create login request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed with status code %d: %s", resp.StatusCode, string(body))
	}

	// Store all cookies
	c.cookies = resp.Cookies()

	// Extract CSRF token from cookies if present
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "TOKEN" || cookie.Name == "X-CSRF-Token" || cookie.Name == "csrf_token" {
			c.csrfToken = cookie.Value
			log.Printf("Found CSRF token: %s", cookie.Name)
		}
	}

	// Store authentication time
	c.authTime = time.Now()

	log.Println("Successfully authenticated with UniFi controller")
	return nil
}

// parseIPOutput parses the output of 'ip addr' command
func parseIPOutput(output string) map[string]InterfaceStatus {
	interfaces := make(map[string]InterfaceStatus)

	lines := strings.Split(output, "\n")
	var currentIface string
	var currentInterface InterfaceStatus

	for _, line := range lines {
		// New interface entry starts with a number followed by colon
		if strings.Contains(line, ": ") && !strings.HasPrefix(line, " ") {
			// Save previous interface if we were processing one
			if currentIface != "" {
				interfaces[currentIface] = currentInterface
			}

			// Extract interface name
			parts := strings.Split(line, ": ")
			if len(parts) >= 2 {
				nameParts := strings.Split(parts[1], "@")
				currentIface = nameParts[0]
				currentInterface = InterfaceStatus{
					Name:      currentIface,
					Type:      "wan",
					Up:        strings.Contains(line, "UP") && strings.Contains(line, "LOWER_UP"),
					IPAddress: "",
					Gateway:   "",
					DNS:       []string{},
				}
			}
		} else if strings.Contains(line, "inet ") && currentIface != "" {
			// Extract IP address
			parts := strings.Split(line, "inet ")
			if len(parts) >= 2 {
				ipParts := strings.Split(parts[1], "/")
				if len(ipParts) >= 1 {
					currentInterface.IPAddress = strings.TrimSpace(ipParts[0])
				}
			}
		}
	}

	// Add the last interface
	if currentIface != "" {
		interfaces[currentIface] = currentInterface
	}

	return interfaces
}

// parseRouteOutput parses the output of 'ip route' command to extract default routes
func parseRouteOutput(output string, interfaces map[string]InterfaceStatus) map[string]InterfaceStatus {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "default via ") {
			parts := strings.Split(line, " ")
			if len(parts) >= 5 {
				gateway := parts[2]
				iface := parts[4]
				if status, ok := interfaces[iface]; ok {
					status.Gateway = gateway
					interfaces[iface] = status
				}
			}
		}
	}

	return interfaces
}

// parseDNSOutput parses the output of cat /etc/resolv.conf to extract DNS servers
func parseDNSOutput(output string, interfaces map[string]InterfaceStatus) map[string]InterfaceStatus {
	var dnsServers []string

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "nameserver ") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				dnsServers = append(dnsServers, parts[1])
			}
		}
	}

	// Add DNS servers to all WAN interfaces
	for name, status := range interfaces {
		for _, wanInterface := range []string{"wan", "wan2", "eth8", "eth9"} {
			if name == wanInterface {
				status.DNS = dnsServers
				interfaces[name] = status
				break
			}
		}
	}

	return interfaces
}

// getWANStatusShell retrieves the current status of WAN interfaces using shell commands
func (c *Controller) getWANStatusShell() ([]InterfaceStatus, error) {
	// Get network interface information using ip command
	cmd := exec.Command("ip", "addr")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute 'ip addr' command: %v", err)
	}

	ipOutput := stdout.String()
	interfaces := parseIPOutput(ipOutput)

	// Get routing table
	cmd = exec.Command("ip", "route")
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute 'ip route' command: %v", err)
	}

	routeOutput := stdout.String()
	interfaces = parseRouteOutput(routeOutput, interfaces)

	// Get DNS servers
	cmd = exec.Command("cat", "/etc/resolv.conf")
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to read resolv.conf: %v", err)
	}

	dnsOutput := stdout.String()
	interfaces = parseDNSOutput(dnsOutput, interfaces)

	// Filter only WAN interfaces
	var wanInterfaces []InterfaceStatus

	for _, name := range c.config.Monitoring.WanInterfaces {
		if status, ok := interfaces[name]; ok {
			wanInterfaces = append(wanInterfaces, status)
		}
	}

	return wanInterfaces, nil
}

// createUniFiEvent creates an event in the UniFi controller, notifying via the configured UniFi events
func (c *Controller) createUniFiEvent(message string, key string) error {
	// Check if we need to refresh the authentication
	if time.Since(c.authTime) > 10*time.Minute {
		log.Println("Auth token may have expired. Re-authenticating...")
		if err := c.Login(); err != nil {
			return fmt.Errorf("failed to re-authenticate: %v", err)
		}
	}

	eventURL := fmt.Sprintf("%s/api/s/%s/cmd/evtmgr", c.baseURL, c.config.UnifiAPI.SiteID)

	// Create the event data using the proper format for the evtmgr endpoint
	eventData := map[string]interface{}{
		"cmd": "insert-event",
		"data": map[string]interface{}{
			"key":       key,
			"time":      time.Now().Unix(),
			"datetime":  time.Now().Format(time.RFC3339),
			"msg":       message,
			"subsystem": "wan",
			"site_id":   c.config.UnifiAPI.SiteID,
			"archived":  false,
			"data":      map[string]string{"message": message},
		},
	}

	jsonData, err := json.Marshal(eventData)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %v", err)
	}

	req, err := http.NewRequest("POST", eventURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create event request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Apply all cookies
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}

	// Apply CSRF token if available
	if c.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("event creation request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("event creation failed with status code %d: %s", resp.StatusCode, string(body))
	}

	// Read the response body to check for API errors
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read event creation response: %v", err)
	}

	// Parse the response to check for API errors
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse event creation response: %v", err)
	}

	// Check for API errors
	if meta, ok := result["meta"].(map[string]interface{}); ok {
		if rc, ok := meta["rc"].(string); ok && rc != "ok" {
			return fmt.Errorf("API error creating event: %s", body)
		}
	}

	log.Printf("Successfully created UniFi event: %s", message)
	return nil
}

// Fallback event creation through direct shell command (in case API doesn't work)
func (c *Controller) createEventShell(message string, key string) error {
	// Replace single quotes to avoid command injection
	message = strings.ReplaceAll(message, "'", "\\'")
	key = strings.ReplaceAll(key, "'", "\\'")

	// Create a logger entry using the 'logger' command
	cmd := exec.Command("logger", "-t", "wan-monitor", fmt.Sprintf("[%s] %s", key, message))
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to log event using logger command: %v", err)
	}

	log.Printf("Successfully logged event via syslog: [%s] %s", key, message)
	return nil
}

// statusText returns a string representation of the interface status
func statusText(up bool) string {
	if up {
		return "UP"
	}
	return "DOWN"
}

// monitorWANStatus periodically checks WAN status and sends notifications on changes
func (c *Controller) monitorWANStatus() {
	ticker := time.NewTicker(time.Duration(c.config.Monitoring.CheckInterval) * time.Second)
	defer ticker.Stop()

	// Create a separate ticker for periodic status updates if debug interval is set
	debugInterval := c.config.Monitoring.DebugInterval
	if debugInterval <= 0 {
		debugInterval = 300 // Default to 5 minutes if not set
	}

	debugTicker := time.NewTicker(time.Duration(debugInterval) * time.Second)
	defer debugTicker.Stop()

	// Counter for monitoring loop iterations
	loopCounter := 0

	// Get initial status
	initialStatus, err := c.getWANStatusShell()
	if err != nil {
		log.Printf("Failed to get initial WAN status: %v", err)
	} else {
		// Store initial status
		for _, status := range initialStatus {
			c.lastStatus[status.Name] = status
			log.Printf("Initial %s status: up=%v, IP=%s, Gateway=%s",
				status.Name, status.Up, status.IPAddress, status.Gateway)
		}
	}

	log.Printf("Starting monitoring loop. Will check interfaces every %d seconds (debug updates every %d seconds)",
		c.config.Monitoring.CheckInterval, debugInterval)

	for {
		select {
		case <-ticker.C:
			// Increment loop counter
			loopCounter++

			// Get current WAN status
			currentStatus, err := c.getWANStatusShell()
			if err != nil {
				log.Printf("Failed to get WAN status: %v", err)
				continue
			}

			// Check for changes
			for _, status := range currentStatus {
				lastStat, exists := c.lastStatus[status.Name]

				// If this is the first time we're seeing this interface or there was a status change
				if !exists || lastStat.Up != status.Up || lastStat.IPAddress != status.IPAddress || lastStat.Gateway != status.Gateway {
					var message string
					var eventKey string

					if !exists {
						message = fmt.Sprintf("New interface detected: %s is %s with IP %s and Gateway %s",
							status.Name,
							statusText(status.Up),
							status.IPAddress,
							status.Gateway)
						eventKey = c.config.Events.NewInterface
					} else if lastStat.Up != status.Up {
						if status.Up {
							message = fmt.Sprintf("Interface %s is now UP. IP: %s, Gateway: %s",
								status.Name,
								status.IPAddress,
								status.Gateway)
							eventKey = c.config.Events.Reconnected
						} else {
							message = fmt.Sprintf("Interface %s is now DOWN",
								status.Name)
							eventKey = c.config.Events.Disconnected
						}
					} else if lastStat.IPAddress != status.IPAddress {
						message = fmt.Sprintf("Interface %s IP changed from %s to %s",
							status.Name,
							lastStat.IPAddress,
							status.IPAddress)
						eventKey = c.config.Events.IPChanged
					} else if lastStat.Gateway != status.Gateway {
						message = fmt.Sprintf("Interface %s Gateway changed from %s to %s",
							status.Name,
							lastStat.Gateway,
							status.Gateway)
						eventKey = c.config.Events.GatewayChanged
					}

					// Log the change
					log.Println(message)

					// Create UniFi event for the change
					if err := c.createUniFiEvent(message, eventKey); err != nil {
						log.Printf("Failed to create UniFi event via API: %v", err)
						log.Println("Trying event creation via shell...")

						// Try to re-login if authentication might have failed
						if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") {
							log.Println("Attempting to re-authenticate...")
							if err := c.Login(); err != nil {
								log.Printf("Failed to re-login: %v", err)
							}
						}

						// Fallback to shell event creation
						if err := c.createEventShell(message, eventKey); err != nil {
							log.Printf("Failed to create event via shell: %v", err)
						}
					}

					// Update last known status
					c.lastStatus[status.Name] = status
				}
			}

		case <-debugTicker.C:
			// Print periodic status update
			log.Printf("--- Monitor still running: completed %d checks ---", loopCounter)

			// Print current status of all interfaces
			for name, status := range c.lastStatus {
				log.Printf("Interface %s status: up=%v, IP=%s, Gateway=%s",
					name, status.Up, status.IPAddress, status.Gateway)
			}
		}
	}
}

// loadConfig loads the configuration from the specified file
func loadConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %v", err)
	}

	// Set default values if not specified
	if config.Monitoring.DebugInterval <= 0 {
		config.Monitoring.DebugInterval = 300 // 5 minutes
	}

	return &config, nil
}

func main() {
	// Define command line flags
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	log.Println("Starting UniFi Dream Machine WAN Interface Monitor")
	log.Printf("Using configuration file: %s", *configPath)

	// Load configuration
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup logging to file
	logFile, err := setupLogging(config)
	if err != nil {
		log.Printf("Warning: Could not set up file logging: %v", err)
	} else {
		defer logFile.Close()
	}

	// Create controller client
	controller, err := NewController(config)
	if err != nil {
		log.Fatalf("Failed to create controller client: %v", err)
	}

	// Login to the UniFi API
	if err := controller.Login(); err != nil {
		log.Printf("Failed to login to controller: %v", err)
		log.Println("Continuing without API authentication - will use shell-based event creation")
	}

	// Handle graceful shutdown
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signals
		log.Println("Shutting down...")
		os.Exit(0)
	}()

	// Start monitoring
	controller.monitorWANStatus()
}
