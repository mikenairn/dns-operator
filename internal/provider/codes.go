package provider

import "github.com/kuadrant/dns-operator/internal/common/slice"

// nolint
type countryCodes struct {
	alpha2Code string
}

var iso3166Codes = []*countryCodes{
	{"AF"},
	{"AL"},
	{"DZ"},
	{"AS"},
	{"AD"},
	{"AO"},
	{"AI"},
	{"AQ"},
	{"AG"},
	{"AR"},
	{"AM"},
	{"AW"},
	{"AU"},
	{"AT"},
	{"AZ"},
	{"BS"},
	{"BH"},
	{"BD"},
	{"BB"},
	{"BY"},
	{"BE"},
	{"BZ"},
	{"BJ"},
	{"BM"},
	{"BT"},
	{"BO"},
	{"BQ"},
	{"BA"},
	{"BW"},
	{"BV"},
	{"BR"},
	{"IO"},
	{"BN"},
	{"BG"},
	{"BF"},
	{"BI"},
	{"CV"},
	{"KH"},
	{"CM"},
	{"CA"},
	{"KY"},
	{"CF"},
	{"TD"},
	{"CL"},
	{"CN"},
	{"CX"},
	{"CC"},
	{"CO"},
	{"KM"},
	{"CD"},
	{"CG"},
	{"CK"},
	{"CR"},
	{"HR"},
	{"CU"},
	{"CW"},
	{"CY"},
	{"CZ"},
	{"CI"},
	{"DK"},
	{"DJ"},
	{"DM"},
	{"DO"},
	{"EC"},
	{"EG"},
	{"SV"},
	{"GQ"},
	{"ER"},
	{"EE"},
	{"SZ"},
	{"ET"},
	{"FK"},
	{"FO"},
	{"FJ"},
	{"FI"},
	{"FR"},
	{"GF"},
	{"PF"},
	{"TF"},
	{"GA"},
	{"GM"},
	{"GE"},
	{"DE"},
	{"GH"},
	{"GI"},
	{"GR"},
	{"GL"},
	{"GD"},
	{"GP"},
	{"GU"},
	{"GT"},
	{"GG"},
	{"GN"},
	{"GW"},
	{"GY"},
	{"HT"},
	{"HM"},
	{"VA"},
	{"HN"},
	{"HK"},
	{"HU"},
	{"IS"},
	{"IN"},
	{"ID"},
	{"IR"},
	{"IQ"},
	{"IE"},
	{"IM"},
	{"IL"},
	{"IT"},
	{"JM"},
	{"JP"},
	{"JE"},
	{"JO"},
	{"KZ"},
	{"KE"},
	{"KI"},
	{"KP"},
	{"KR"},
	{"KW"},
	{"KG"},
	{"LA"},
	{"LV"},
	{"LB"},
	{"LS"},
	{"LR"},
	{"LY"},
	{"LI"},
	{"LT"},
	{"LU"},
	{"MO"},
	{"MG"},
	{"MW"},
	{"MY"},
	{"MV"},
	{"ML"},
	{"MT"},
	{"MH"},
	{"MQ"},
	{"MR"},
	{"MU"},
	{"YT"},
	{"MX"},
	{"FM"},
	{"MD"},
	{"MC"},
	{"MN"},
	{"ME"},
	{"MS"},
	{"MA"},
	{"MZ"},
	{"MM"},
	{"NA"},
	{"NR"},
	{"NP"},
	{"NL"},
	{"NC"},
	{"NZ"},
	{"NI"},
	{"NE"},
	{"NG"},
	{"NU"},
	{"NF"},
	{"MK"},
	{"MP"},
	{"NO"},
	{"OM"},
	{"PK"},
	{"PW"},
	{"PS"},
	{"PA"},
	{"PG"},
	{"PY"},
	{"PE"},
	{"PH"},
	{"PN"},
	{"PL"},
	{"PT"},
	{"PR"},
	{"QA"},
	{"RO"},
	{"RU"},
	{"RW"},
	{"RE"},
	{"BL"},
	{"SH"},
	{"KN"},
	{"LC"},
	{"MF"},
	{"PM"},
	{"VC"},
	{"WS"},
	{"SM"},
	{"ST"},
	{"SA"},
	{"SN"},
	{"RS"},
	{"SC"},
	{"SL"},
	{"SG"},
	{"SX"},
	{"SK"},
	{"SI"},
	{"SB"},
	{"SO"},
	{"ZA"},
	{"GS"},
	{"SS"},
	{"ES"},
	{"LK"},
	{"SD"},
	{"SR"},
	{"SJ"},
	{"SE"},
	{"CH"},
	{"SY"},
	{"TW"},
	{"TJ"},
	{"TZ"},
	{"TH"},
	{"TL"},
	{"TG"},
	{"TK"},
	{"TO"},
	{"TT"},
	{"TN"},
	{"TR"},
	{"TM"},
	{"TC"},
	{"TV"},
	{"UG"},
	{"UA"},
	{"AE"},
	{"GB"},
	{"UM"},
	{"US"},
	{"UY"},
	{"UZ"},
	{"VU"},
	{"VE"},
	{"VN"},
	{"VG"},
	{"VI"},
	{"WF"},
	{"EH"},
	{"YE"},
	{"ZM"},
	{"ZW"},
}

func GetISO3166Alpha2Codes() []string {
	var codes []string
	for _, v := range iso3166Codes {
		codes = append(codes, v.alpha2Code)
	}
	return codes
}

// IsISO3166Alpha2Code returns true if it's a valid ISO_3166 Alpha 2 country code (https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)
func IsISO3166Alpha2Code(code string) bool {
	return slice.ContainsString(GetISO3166Alpha2Codes(), code)
}

const (
	AWS_CONTINENT_CODE_AFRICA        = "AF"
	AWS_CONTINENT_CODE_ANTARTICA     = "AN"
	AWS_CONTINENT_CODE_ASIA          = "AS"
	AWS_CONTINENT_CODE_EUROPE        = "EU"
	AWS_CONTINENT_CODE_OCEANIA       = "OC"
	AWS_CONTINENT_CODE_NORTH_AMERICA = "NA"
	AWS_CONTINENT_CODE_SOUTH_AMERICA = "SA"
)

var AWSContinentCodes = []string{
	AWS_CONTINENT_CODE_AFRICA,
	AWS_CONTINENT_CODE_ANTARTICA,
	AWS_CONTINENT_CODE_ASIA,
	AWS_CONTINENT_CODE_EUROPE,
	AWS_CONTINENT_CODE_OCEANIA,
	AWS_CONTINENT_CODE_NORTH_AMERICA,
	AWS_CONTINENT_CODE_SOUTH_AMERICA,
}

func IsContinentCode(code string) bool {
	return slice.ContainsString(AWSContinentCodes, code)
}