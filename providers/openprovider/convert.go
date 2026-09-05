package openprovider

import (
	"fmt"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/txtutil"
)

const apexLabel = "@"

func toRecordConfig(record apiRecord, origin string) (*models.RecordConfig, error) {
	rtype := strings.ToUpper(record.Type)
	rc := &models.RecordConfig{
		Type:     rtype,
		TTL:      uint32(record.TTL),
		Original: record,
	}
	setRecordLabel(rc, record.Name, origin)

	value := record.Value
	var err error
	switch rtype {
	case "MX":
		err = rc.SetTargetMX(uint16(record.Prio), absoluteTarget(value, origin))
	case "SRV":
		fields := strings.Fields(value)
		if len(fields) != 3 {
			return nil, fmt.Errorf("OPENPROVIDER: SRV record %q has invalid value", record.Name)
		}
		err = rc.SetTargetSRVPriorityString(uint16(record.Prio), strings.Join([]string{fields[0], fields[1], absoluteTarget(fields[2], origin)}, " "))
	case "TXT", "SPF":
		var decoded string
		decoded, err = txtutil.ParseQuoted(value)
		if err == nil {
			err = rc.SetTargetTXT(decoded)
		}
	case "CNAME":
		err = rc.SetTarget(absoluteTarget(value, origin))
	default:
		err = rc.PopulateFromString(rtype, value, origin)
	}
	if err != nil {
		return nil, fmt.Errorf("OPENPROVIDER: parse %s record %q: %w", rtype, record.Name, err)
	}
	return rc, nil
}

func fromRecordConfig(rc *models.RecordConfig) apiRecord {
	record := apiRecord{
		Type: rc.Type,
		TTL:  int(rc.TTL),
	}
	if rc.GetLabel() != apexLabel {
		record.Name = rc.GetLabel()
	}

	switch rc.Type {
	case "MX":
		record.Prio = int(rc.MxPreference)
		record.Value = strings.TrimSuffix(rc.GetTargetField(), ".")
	case "SRV":
		record.Prio = int(rc.SrvPriority)
		record.Value = fmt.Sprintf("%d %d %s", rc.SrvWeight, rc.SrvPort, strings.TrimSuffix(rc.GetTargetField(), "."))
	case "TXT", "SPF":
		record.Value = txtutil.EncodeQuoted(rc.GetTargetTXTJoined())
	case "CNAME":
		record.Value = strings.TrimSuffix(rc.GetTargetField(), ".")
	case "CAA":
		record.Value = fmt.Sprintf("%d %s %q", rc.CaaFlag, rc.CaaTag, rc.GetTargetField())
	case "TLSA":
		record.Value = fmt.Sprintf("%d %d %d %s", rc.TlsaUsage, rc.TlsaSelector, rc.TlsaMatchingType, rc.GetTargetField())
	default:
		record.Value = rc.GetTargetField()
	}
	return record
}

func setRecordLabel(rc *models.RecordConfig, name, origin string) {
	rc.SetLabel(relativeRecordName(name, origin), origin)
}

func absoluteTarget(target, origin string) string {
	if target == "" || target == "." || strings.HasSuffix(target, ".") {
		return target
	}
	if !strings.Contains(target, ".") {
		return target + "." + origin + "."
	}
	return target + "."
}

func isApexRecordName(name, origin string) bool {
	name = strings.TrimSuffix(name, ".")
	return name == "" || name == apexLabel || strings.EqualFold(name, origin)
}
