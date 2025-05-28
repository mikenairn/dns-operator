package registry

import (
	"sigs.k8s.io/external-dns/endpoint"
	"strings"
)

const (
	recordTemplate              = "%{record_type}"
	providerSpecificForceUpdate = "txt/force-update"
)

type affixNameMapper struct {
	prefix              string
	suffix              string
	wildcardReplacement string
}

var _ nameMapper = affixNameMapper{}

func newaffixNameMapper(prefix, suffix, wildcardReplacement string) affixNameMapper {
	return affixNameMapper{prefix: strings.ToLower(prefix), suffix: strings.ToLower(suffix), wildcardReplacement: strings.ToLower(wildcardReplacement)}
}

// extractRecordTypeDefaultPosition extracts record type from the default position
// when not using '%{record_type}' in the prefix/suffix
func extractRecordTypeDefaultPosition(name string) (baseName, recordType string) {
	nameS := strings.Split(name, "-")
	for _, t := range getSupportedTypes() {
		if nameS[0] == strings.ToLower(t) {
			return strings.TrimPrefix(name, nameS[0]+"-"), t
		}
	}
	return name, ""
}

// dropAffixExtractType strips TXT record to find an endpoint name it manages
// it also returns the record type
func (pr affixNameMapper) dropAffixExtractType(name string) (baseName, recordType string) {
	prefix := pr.prefix
	suffix := pr.suffix

	if pr.recordTypeInAffix() {
		for _, t := range getSupportedTypes() {
			tLower := strings.ToLower(t)
			iPrefix := strings.ReplaceAll(prefix, recordTemplate, tLower)
			iSuffix := strings.ReplaceAll(suffix, recordTemplate, tLower)

			if pr.isPrefix() && strings.HasPrefix(name, iPrefix) {
				return strings.TrimPrefix(name, iPrefix), t
			}

			if pr.isSuffix() && strings.HasSuffix(name, iSuffix) {
				return strings.TrimSuffix(name, iSuffix), t
			}
		}

		// handle old TXT records
		prefix = pr.dropAffixTemplate(prefix)
		suffix = pr.dropAffixTemplate(suffix)
	}

	if pr.isPrefix() && strings.HasPrefix(name, prefix) {
		return extractRecordTypeDefaultPosition(strings.TrimPrefix(name, prefix))
	}

	if pr.isSuffix() && strings.HasSuffix(name, suffix) {
		return extractRecordTypeDefaultPosition(strings.TrimSuffix(name, suffix))
	}

	return "", ""
}

func (pr affixNameMapper) dropAffixTemplate(name string) string {
	return strings.ReplaceAll(name, recordTemplate, "")
}

func (pr affixNameMapper) isPrefix() bool {
	return len(pr.suffix) == 0
}

func (pr affixNameMapper) isSuffix() bool {
	return len(pr.prefix) == 0 && len(pr.suffix) > 0
}

func (pr affixNameMapper) fromTXTName(txtDNSName string) (endpointName string, recordType string) {
	lowerDNSName := strings.ToLower(txtDNSName)

	// drop prefix
	if pr.isPrefix() {
		return pr.dropAffixExtractType(lowerDNSName)
	}

	// drop suffix
	if pr.isSuffix() {
		dc := strings.Count(pr.suffix, ".")
		DNSName := strings.SplitN(lowerDNSName, ".", 2+dc)
		domainWithSuffix := strings.Join(DNSName[:1+dc], ".")

		r, rType := pr.dropAffixExtractType(domainWithSuffix)
		return r + "." + DNSName[1+dc], rType
	}
	return "", ""
}

func (pr affixNameMapper) recordTypeInAffix() bool {
	if strings.Contains(pr.prefix, recordTemplate) {
		return true
	}
	if strings.Contains(pr.suffix, recordTemplate) {
		return true
	}
	return false
}

func (pr affixNameMapper) normalizeAffixTemplate(afix, recordType string) string {
	if strings.Contains(afix, recordTemplate) {
		return strings.ReplaceAll(afix, recordTemplate, recordType)
	}
	return afix
}

func (pr affixNameMapper) toTXTName(endpointDNSName, recordType string) string {
	DNSName := strings.SplitN(endpointDNSName, ".", 2)
	recordType = strings.ToLower(recordType)
	recordT := recordType + "-"

	prefix := pr.normalizeAffixTemplate(pr.prefix, recordType)
	suffix := pr.normalizeAffixTemplate(pr.suffix, recordType)

	// If specified, replace a leading asterisk in the generated txt record name with some other string
	if pr.wildcardReplacement != "" && DNSName[0] == "*" {
		DNSName[0] = pr.wildcardReplacement
	}

	if !pr.recordTypeInAffix() {
		DNSName[0] = recordT + DNSName[0]
	}

	if len(DNSName) < 2 {
		return prefix + DNSName[0] + suffix
	}

	return prefix + DNSName[0] + suffix + "." + DNSName[1]
}

func getSupportedTypes() []string {
	return []string{endpoint.RecordTypeA, endpoint.RecordTypeAAAA, endpoint.RecordTypeCNAME, endpoint.RecordTypeNS}
}
