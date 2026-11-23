package monitor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// nodeBrief extracts a credential-free "scheme@host:port" summary from a node
// URI for log lines. Credentials in the URI are dropped, and base64-encoded
// VMess links extract only host:port without dumping base64/UUIDs.
func nodeBrief(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	lower := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(lower, "vmess://") && !strings.Contains(uri, "@"):
		return vmessBrief(uri)
	case strings.HasPrefix(lower, "ssr://"), strings.HasPrefix(lower, "shadowsocksr://"):
		return ""
	case (strings.HasPrefix(lower, "ss://") || strings.HasPrefix(lower, "shadowsocks://")) && !strings.Contains(uri, "@"):
		return ""
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	if port := u.Port(); port != "" {
		return fmt.Sprintf("%s@%s", u.Scheme, net.JoinHostPort(host, port))
	}
	return fmt.Sprintf("%s@%s", u.Scheme, host)
}

func vmessBrief(uri string) string {
	payload := strings.TrimPrefix(uri, "vmess://")
	if idx := strings.Index(payload, "#"); idx != -1 {
		payload = payload[:idx]
	}
	payload = strings.TrimSpace(payload)
	var decoded []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err = enc.DecodeString(payload)
		if err == nil {
			break
		}
	}
	if err != nil {
		return ""
	}
	var fields struct {
		Add  string `json:"add"`
		Port any    `json:"port"`
	}
	if json.Unmarshal(decoded, &fields) != nil || strings.TrimSpace(fields.Add) == "" {
		return ""
	}
	host := strings.TrimSpace(fields.Add)
	var portStr string
	switch v := fields.Port.(type) {
	case float64:
		if v > 0 {
			portStr = strconv.Itoa(int(v))
		}
	case string:
		if p, convErr := strconv.Atoi(strings.TrimSpace(v)); convErr == nil && p > 0 {
			portStr = strconv.Itoa(p)
		}
	}
	if portStr != "" {
		return fmt.Sprintf("vmess@%s", net.JoinHostPort(host, portStr))
	}
	return fmt.Sprintf("vmess@%s", host)
}

// classifyProbeError maps a raw probe error to a stable category code and a
// human-readable summary, so log readers can tell *why* a node failed without
// parsing opaque sing-box / net error strings.
//
// Cases are matched top-down; more specific signatures must come before generic
// ones (transport handshake before a bare status code, dial-stage failures
// before read-stage timeouts, and a bare "context canceled" last so a per-probe
// deadline is classified as a node fault rather than a cancellation).
func classifyProbeError(err error) (category, summary string) {
	if err == nil {
		return "", ""
	}
	s := err.Error()
	switch {
	// Placeholder address left by broken subscription parsing. Only the sentinel
	// 127.127.127.1 is treated as a parse artifact; a genuine 127.0.0.1 dial
	// error falls through to the dial-stage bucket below for an accurate cause.
	case strings.Contains(s, "127.127.127.1"):
		return "addr_invalid", "节点地址无效(疑似订阅解析异常或占位地址)"

	// Transport-layer handshake failures from sing-box outbounds: the server or
	// a CDN in front of it rejected the websocket / http-upgrade / v2ray upgrade.
	case strings.Contains(s, "http-upgrade") || strings.Contains(s, "httpupgrade") ||
		strings.Contains(s, "unexpected status") || strings.Contains(s, "unexpected HTTP") ||
		strings.Contains(s, "v2ray-"):
		return "transport_handshake", "传输层握手失败(节点服务端异常或被CDN拦截)"

	// TLS handshake / certificate verification failures (strict probe mode).
	case strings.Contains(s, "tls:") || strings.Contains(s, "handshake") || strings.Contains(s, "certificate"):
		return "tls_failed", "TLS握手失败(证书无效或疑似劫持)"

	// Response byte stream is not the expected protocol frame.
	case strings.Contains(s, "unknown version") || strings.Contains(s, "malformed"):
		return "proto_mismatch", "协议不匹配(响应非预期,疑似TLS/HTTP混淆或劫持)"

	// TCP dial-stage failures: the node host itself is unreachable.
	case strings.Contains(s, "dial tcp") || strings.Contains(s, "dial udp"):
		switch {
		case strings.Contains(s, "i/o timeout") || strings.Contains(s, "timeout"):
			return "dial_timeout", "节点不可达(TCP连接超时,可能被封或已下线)"
		case strings.Contains(s, "connection refused"):
			return "dial_refused", "端口未开放(连接被拒绝)"
		case strings.Contains(s, "no route to host"):
			return "dial_no_route", "网络不可达(无路由到主机)"
		case strings.Contains(s, "connection reset"):
			return "dial_reset", "TCP连接被重置(疑似网络封锁)"
		default:
			return "dial_failed", "TCP连接失败(节点不可达)"
		}

	// Read-stage timeouts: connected through the node, but the probe response
	// did not arrive in time (slow / unstable exit link).
	case strings.Contains(s, "i/o timeout") || strings.Contains(s, "deadline exceeded"):
		return "read_timeout", "节点响应超时(链路过慢或不稳定)"

	// Connection torn down mid-probe.
	case strings.Contains(s, "EOF") || strings.Contains(s, "reset by peer") ||
		strings.Contains(s, "broken pipe") || strings.Contains(s, "connection reset"):
		return "conn_reset", "连接被对端中断(EOF,节点异常或疑似劫持)"

	// True cancellation with no transport-stage signal: the batch deadline
	// cascaded or the client disconnected mid-probe. Checked LAST and limited to
	// "context canceled" — a "context deadline exceeded" is NOT excused here, it
	// is matched above as dial_timeout / read_timeout because a per-probe deadline
	// expiring is a genuine node fault (unreachable or too slow), not a non-fault.
	case strings.Contains(s, "context canceled"):
		return "cancelled", "探测被取消(批量超时或连接中断,非节点故障)"

	default:
		return "other", "探测失败(未知原因)"
	}
}

// FormatProbeFailure renders a single-line, human-readable probe failure that
// identifies the node (tag + protocol@host:port) and classifies the error.
// Example:
//
//	"example [vless@1.2.3.4:443] (dial_timeout) 节点不可达(TCP连接超时,可能被封或已下线) | dial tcp 1.2.3.4:443: i/o timeout"
func FormatProbeFailure(tag, uri string, err error) string {
	brief := nodeBrief(uri)
	category, summary := classifyProbeError(err)
	var b strings.Builder
	b.WriteString(tag)
	if brief != "" {
		b.WriteString(" [")
		b.WriteString(brief)
		b.WriteString("]")
	}
	b.WriteString(" (")
	b.WriteString(category)
	b.WriteString(") ")
	b.WriteString(summary)
	b.WriteString(" | ")
	b.WriteString(err.Error())
	return b.String()
}
