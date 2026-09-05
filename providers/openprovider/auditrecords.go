package openprovider

import (
	"fmt"
	"slices"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/rejectif"
)

var supportedRecordTypes = []string{
	"A",
	"AAAA",
	"CAA",
	"CNAME",
	"MX",
	"NS",
	"SPF",
	"SRV",
	"TLSA",
	"TXT",
}

var supportedCAATags = []string{"issue", "issuewild", "iodef"}

// AuditRecords returns errors for records that OpenProvider cannot represent.
func AuditRecords(records []*models.RecordConfig) []error {
	auditor := rejectif.Auditor{}
	auditor.TypesSupported(supportedRecordTypes)
	auditor.Add("NS", rejectUnsupportedNS)
	auditor.Add("MX", rejectif.MxNull)
	auditor.Add("SRV", rejectif.SrvHasNullTarget)
	auditor.Add("TXT", rejectif.TxtIsEmpty)
	auditor.Add("TXT", rejectif.TxtHasDoubleQuotes)
	auditor.Add("TXT", rejectif.TxtHasBackslash)
	auditor.Add("CAA", rejectUnsupportedCAAFlag)
	auditor.Add("CAA", rejectUnsupportedCAATag)
	auditor.Add("CAA", rejectUnsupportedCAAFields)
	return auditor.Audit(records)
}

func rejectUnsupportedNS(rc *models.RecordConfig) error {
	if rc.GetLabel() != apexLabel {
		return fmt.Errorf("NS records are only supported at the OpenProvider zone apex")
	}
	return nil
}

func rejectUnsupportedCAAFlag(rc *models.RecordConfig) error {
	if rc.CaaFlag != 0 {
		return fmt.Errorf("CAA flag %d is not supported by OpenProvider", rc.CaaFlag)
	}
	return nil
}

func rejectUnsupportedCAATag(rc *models.RecordConfig) error {
	if !slices.Contains(supportedCAATags, rc.CaaTag) {
		return fmt.Errorf("CAA tag %q is not supported by OpenProvider", rc.CaaTag)
	}
	return nil
}

func rejectUnsupportedCAAFields(rc *models.RecordConfig) error {
	if strings.Contains(rc.GetTargetField(), ";") {
		return fmt.Errorf("CAA target fields are not supported by OpenProvider")
	}
	return nil
}
