package monitor

import (
	"easy_proxies/internal/config"
	"easy_proxies/internal/ipmeta"
)

func sameNodeIdentity(a, b NodeInfo) bool {
	oldNode, newNode := config.NodeConfig{URI: a.URI}, config.NodeConfig{URI: b.URI}
	return oldNode.NodeKey() == newNode.NodeKey()
}

// Only derived fields are copied. Listen addresses, ports, URI and original
// names remain owned by registration, including during an in-flight lookup.
func copyExitMetadata(dst *NodeInfo, src NodeInfo) {
	dst.ExitIP = src.ExitIP
	dst.CountryCode = src.CountryCode
	dst.Country = src.Country
	dst.Region = src.Region
	dst.Provider = src.Provider
	dst.ASN = src.ASN
	dst.OrgDomain = src.OrgDomain
	dst.OrgShort = src.OrgShort
	dst.NetworkType = src.NetworkType
	dst.Abuse = src.Abuse
}

func formatNodeName(info *NodeInfo) {
	if info.OriginalName == "" {
		info.OriginalName = info.Name
	}
	var score *int
	if info.Abuse != nil {
		score = info.Abuse.Score
	}
	info.OrgShort = ipmeta.ShortOrg(info.Provider, info.OrgDomain)
	info.Name = ipmeta.DisplayName(info.OriginalName, info.CountryCode, info.ExitIP, info.Provider, info.OrgDomain, info.NetworkType, score)
}
