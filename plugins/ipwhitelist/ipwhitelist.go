package ipwhitelist

import (
    "bufio"
    "context"
    "fmt"
    "io"
    "net"
    "net/http"
    "strings"
    "sync"
    "time"

    "github.com/go-logr/logr"
    "github.com/robinbraemer/event"
    "go.minekube.com/common/minecraft/color"
    c "go.minekube.com/common/minecraft/component"
    "go.minekube.com/gate/pkg/edition/java/proxy"
)

const (
    // Default whitelist URL - change this to your URL
    defaultWhitelistURL = "https://captcha-raidvm.kontakt-26a.workers.dev/api/ips"
    
    // Update interval for fetching the whitelist
    updateInterval = 5 * time.Second
    
    // HTTP timeout for requests
    httpTimeout = 10 * time.Second
)

// Plugin is an IP whitelist plugin that restricts access based on IP addresses
var Plugin = proxy.Plugin{
    Name: "IPWhitelist",
    Init: func(ctx context.Context, p *proxy.Proxy) error {
        log := logr.FromContextOrDiscard(ctx)
        log.Info("Hello from IPWhitelist plugin!")

        // Create context for the plugin lifecycle
        pluginCtx, cancel := context.WithCancel(ctx)

        pl := &plugin{
            proxy:          p,
            log:            log,
            whitelist:      make(map[string]bool),
            whitelistMutex: sync.RWMutex{},
            whitelistURL:   defaultWhitelistURL,
            httpClient: &http.Client{
                Timeout: httpTimeout,
            },
            ctx:    pluginCtx,
            cancel: cancel,
        }

        // Set default fallback whitelist
        pl.setDefaultWhitelist()

        // Subscribe to PreLogin event to block non-whitelisted IPs
        event.Subscribe(p.Event(), 0, pl.onPreLogin)

        // Start the whitelist updater goroutine
        go pl.startWhitelistUpdater()

        log.Info("IPWhitelist plugin initialized", "url", pl.whitelistURL, "updateInterval", updateInterval)

        return nil
    },
}

type plugin struct {
    proxy          *proxy.Proxy
    log            logr.Logger
    whitelist      map[string]bool
    whitelistMutex sync.RWMutex
    whitelistURL   string
    httpClient     *http.Client
    ctx            context.Context
    cancel         context.CancelFunc
}

// setDefaultWhitelist sets a fallback whitelist in case URL is unreachable
func (p *plugin) setDefaultWhitelist() {
    p.whitelistMutex.Lock()
    defer p.whitelistMutex.Unlock()
    
    // Clear existing whitelist
    p.whitelist = map[string]bool{}
    
    p.log.Info("Set default fallback whitelist", "entries", len(p.whitelist))
}

// startWhitelistUpdater starts a goroutine that periodically updates the whitelist
func (p *plugin) startWhitelistUpdater() {
    // Try to load whitelist immediately
    p.updateWhitelist()
    
    ticker := time.NewTicker(updateInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-p.ctx.Done():
            p.log.Info("Stopping whitelist updater")
            return
        case <-ticker.C:
            p.updateWhitelist()
        }
    }
}

// updateWhitelist fetches the whitelist from the configured URL
func (p *plugin) updateWhitelist() {
    p.log.V(1).Info("Updating whitelist from URL", "url", p.whitelistURL)
    
    req, err := http.NewRequestWithContext(p.ctx, "GET", p.whitelistURL, nil)
    if err != nil {
        p.log.Error(err, "Failed to create HTTP request for whitelist")
        return
    }
    
    resp, err := p.httpClient.Do(req)
    if err != nil {
        p.log.Error(err, "Failed to fetch whitelist from URL", "url", p.whitelistURL)
        return
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        p.log.Error(fmt.Errorf("unexpected status code: %d", resp.StatusCode), 
            "Failed to fetch whitelist", "url", p.whitelistURL)
        return
    }
    
    // Parse the response
    newWhitelist, err := p.parseWhitelist(resp.Body)
    if err != nil {
        p.log.Error(err, "Failed to parse whitelist")
        return
    }
    
    // Update the whitelist atomically
    p.whitelistMutex.Lock()
    oldCount := len(p.whitelist)
    p.whitelist = newWhitelist
    newCount := len(p.whitelist)
    p.whitelistMutex.Unlock()
    
    p.log.Info("Updated whitelist successfully", 
        "oldEntries", oldCount, 
        "newEntries", newCount,
        "url", p.whitelistURL)
}

// parseWhitelist parses the whitelist from an io.Reader
// Expected format: one IP/CIDR per line, empty lines and lines starting with # are ignored
func (p *plugin) parseWhitelist(r io.Reader) (map[string]bool, error) {
    whitelist := make(map[string]bool)
    scanner := bufio.NewScanner(r)
    
    lineNum := 0
    for scanner.Scan() {
        lineNum++
        line := strings.TrimSpace(scanner.Text())
        
        // Skip empty lines and comments
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        
        // Validate IP or CIDR
        if p.isValidIPOrCIDR(line) {
            whitelist[line] = true
        } else {
            p.log.V(1).Info("Skipping invalid IP/CIDR in whitelist", "line", lineNum, "content", line)
        }
    }
    
    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("error reading whitelist: %w", err)
    }
    
    return whitelist, nil
}

// isValidIPOrCIDR validates if a string is a valid IP address or CIDR range
func (p *plugin) isValidIPOrCIDR(entry string) bool {
    // Check if it's a CIDR range
    if strings.Contains(entry, "/") {
        _, _, err := net.ParseCIDR(entry)
        return err == nil
    }
    
    // Check if it's a valid IP address
    ip := net.ParseIP(entry)
    return ip != nil
}

// isIPWhitelisted checks if an IP address is in the whitelist (thread-safe)
func (p *plugin) isIPWhitelisted(addr net.Addr) bool {
    ipStr := getIPFromAddr(addr)
    
    p.whitelistMutex.RLock()
    defer p.whitelistMutex.RUnlock()
    
    // Check exact IP match first
    if p.whitelist[ipStr] {
        return true
    }
    
    // Check CIDR ranges
    for whitelistedEntry := range p.whitelist {
        if strings.Contains(whitelistedEntry, "/") {
            _, cidr, err := net.ParseCIDR(whitelistedEntry)
            if err != nil {
                continue
            }
            ip := net.ParseIP(ipStr)
            if ip != nil && cidr.Contains(ip) {
                return true
            }
        }
    }
    
    return false
}

// getIPFromAddr extracts the IP address from a net.Addr
func getIPFromAddr(addr net.Addr) string {
    switch v := addr.(type) {
    case *net.TCPAddr:
        return v.IP.String()
    case *net.UDPAddr:
        return v.IP.String()
    default:
        // Fallback: try to parse the string representation
        host, _, err := net.SplitHostPort(addr.String())
        if err == nil {
            return host
        }
        return addr.String()
    }
}

// onPreLogin handles the PreLoginEvent to block non-whitelisted IPs
func (p *plugin) onPreLogin(e *proxy.PreLoginEvent) {
    clientIP := getIPFromAddr(e.Conn().RemoteAddr())
    
    p.log.Info("Player login attempt", "username", e.Username(), "ip", clientIP)
    
    if !p.isIPWhitelisted(e.Conn().RemoteAddr()) {
        p.log.Info("Blocked non-whitelisted IP", "username", e.Username(), "ip", clientIP)
        
        // Create a styled kick message
        kickMessage := &c.Text{
            Content: "You are not whitelisted!",
            S: c.Style{
                Color: color.Red,
                Bold:  c.True,
            },
            Extra: []c.Component{
                &c.Text{
                    Content: "\n\nYour IP address is not authorized to access this server.",
                    S: c.Style{
                        Color: color.White,
                    },
                },
                &c.Text{
                    Content: "\nPlease contact an administrator for access.",
                    S: c.Style{
                        Color: color.Gray,
                        Italic: c.True,
                    },
                },
                &c.Text{
                    Content: "\n\nIP: " + clientIP,
                    S: c.Style{
                        Color: color.DarkGray,
                    },
                },
            },
        }
        
        // Deny the login with the kick message
        e.Deny(kickMessage)
    }
}

 