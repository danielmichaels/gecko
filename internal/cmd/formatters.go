package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/danielmichaels/gecko/internal/dto"

	"github.com/olekukonko/tablewriter"
)

type Formatter interface {
	Output(v interface{}) string
}

type OutputFunc func(v interface{}) string

func (o OutputFunc) Output(v interface{}) string {
	return o(v)
}

// getHeaderFromTag returns the header name for a struct field based on the "json" tag.
// If the "json" tag is present, it uses the first part of the tag (before the first comma).
// Otherwise, it uses the uppercase version of the field name.
func getHeaderFromTag(field reflect.StructField) string {
	if tag := field.Tag.Get("json"); tag != "" {
		name := strings.Split(tag, ",")[0]
		return strings.ToUpper(name)
	}
	return strings.ToUpper(field.Name)
}

// structToTable takes an any value and converts it to a formatted table string.
// If the input is a slice, it will extract headers from the first element and convert each
// element to a row in the table. If the input is a single struct, it will extract headers
// from the struct fields and convert the struct to a single row.
// If the input is neither a slice nor a struct, it will return "Unsupported data type".
func structToTable(data any) string {
	val := reflect.ValueOf(data)
	var headers []string
	var rows [][]string

	// Determine if the input is a slice or a single struct
	if val.Kind() == reflect.Slice {
		if val.Len() == 0 {
			return "No data available"
		}
		// Use the first element to extract headers
		elemType := val.Index(0).Type()
		for i := 0; i < elemType.NumField(); i++ {
			headers = append(headers, getHeaderFromTag(elemType.Field(i)))
		}
		// Convert each element to a row
		for i := 0; i < val.Len(); i++ {
			item := val.Index(i)
			var row []string
			for j := 0; j < item.NumField(); j++ {
				row = append(row, fmt.Sprintf("%v", item.Field(j)))
			}
			rows = append(rows, row)
		}
	} else if val.Kind() == reflect.Struct {
		// Extract headers from the struct
		elemType := val.Type()
		for i := 0; i < elemType.NumField(); i++ {
			headers = append(headers, getHeaderFromTag(elemType.Field(i)))
		}
		// Convert the struct to a single row
		var row []string
		for i := 0; i < val.NumField(); i++ {
			row = append(row, fmt.Sprintf("%v", val.Field(i)))
		}
		rows = append(rows, row)
	} else {
		return "Unsupported data type"
	}

	buf := &bytes.Buffer{}
	table := tablewriter.NewWriter(buf)
	table.SetHeader(headers)
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.AppendBulk(rows)
	table.Render()

	return buf.String()
}

var formatters = map[string]Formatter{
	"text": OutputFunc(func(v any) string {
		return structToTable(v)
	}),
	"json": OutputFunc(func(v any) string {
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	}),
}

func formatOutput(v any, format string) string {
	formatter := formatters[format]
	return formatter.Output(v)
}

func printARecordsTable(records []dto.ARecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("A Records:")
	headers := []string{"ID", "IPv4 Address", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			r.IPv4Address,
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of AAAA records
func printAAAARecordsTable(records []dto.AAAARecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("AAAA Records:")
	headers := []string{"ID", "IPv6 Address", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			r.IPv6Address,
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of MX records
func printMXRecordsTable(records []dto.MXRecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("MX Records:")
	headers := []string{"ID", "Target", "Preference", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			r.Target,
			fmt.Sprintf("%d", r.Preference),
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of TXT records
func printTXTRecordsTable(records []dto.TXTRecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("TXT Records:")
	headers := []string{"ID", "Value", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			r.Value,
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of NS records
func printNSRecordsTable(records []dto.NSRecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("NS Records:")
	headers := []string{"ID", "Nameserver", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			r.Nameserver,
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of CNAME records
func printCNAMERecordsTable(records []dto.CNAMERecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("CNAME Records:")
	headers := []string{"ID", "Target", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			r.Target,
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of SOA records
func printSOARecordsTable(records []dto.SOARecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("SOA Records:")
	headers := []string{"ID", "Primary NS", "Admin Email", "Serial", "TTL", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			r.Nameserver,
			r.Email,
			fmt.Sprintf("%d", r.Serial),
			fmt.Sprintf("%d", r.MinimumTTL),
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Additional print functions for other record types...
// Similar functions for PTR, SRV, CAA, DNSKEY, DS, RRSIG records

// Generic table printing function
func printTable(headers []string, rows [][]string) {
	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header row
	fmt.Print("| ")
	for i, h := range headers {
		fmt.Printf("%-*s | ", widths[i], h)
	}
	fmt.Println()

	// Print separator
	fmt.Print("+-")
	for i, w := range widths {
		fmt.Print(strings.Repeat("-", w))
		if i < len(widths)-1 {
			fmt.Print("-+-")
		} else {
			fmt.Print("-+")
		}
	}
	fmt.Println()

	// Print data rows
	for _, row := range rows {
		fmt.Print("| ")
		for i, cell := range row {
			if i < len(widths) {
				fmt.Printf("%-*s | ", widths[i], cell)
			}
		}
		fmt.Println()
	}
}

// Helper function to print a table of PTR records
func printPTRRecordsTable(records []dto.PTRRecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("PTR Records:")
	headers := []string{"ID", "Value", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			r.Target,
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of SRV records
func printSRVRecordsTable(records []dto.SRVRecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("SRV Records:")
	headers := []string{"ID", "Target", "Port", "Priority", "Weight", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			r.Target,
			fmt.Sprintf("%d", r.Port),
			fmt.Sprintf("%d", r.Priority),
			fmt.Sprintf("%d", r.Weight),
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of CAA records
func printCAARecordsTable(records []dto.CAARecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("CAA Records:")
	headers := []string{"ID", "Tag", "Value", "Flags", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			r.Tag,
			r.Value,
			fmt.Sprintf("%d", r.Flags),
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of DNSKEY records
func printDNSKEYRecordsTable(records []dto.DNSKEYRecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("DNSKEY Records:")
	headers := []string{"ID", "Flags", "Protocol", "Algorithm", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			fmt.Sprintf("%d", r.Flags),
			fmt.Sprintf("%d", r.Protocol),
			fmt.Sprintf("%d", r.Algorithm),
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of DS records
func printDSRecordsTable(records []dto.DSRecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("DS Records:")
	headers := []string{"ID", "Key Tag", "Algorithm", "Digest Type", "Created At"}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			fmt.Sprintf("%d", r.KeyTag),
			fmt.Sprintf("%d", r.Algorithm),
			fmt.Sprintf("%d", r.DigestType),
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}

// Helper function to print a table of RRSIG records
func printRRSIGRecordsTable(records []dto.RRSIGRecord) {
	if len(records) == 0 {
		return
	}

	fmt.Println("RRSIG Records:")
	headers := []string{
		"ID",
		"Type Covered",
		"Algorithm",
		"Labels",
		"Key Tag",
		"Signer",
		"Created At",
	}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		row := []string{
			r.DomainID,
			string(r.TypeCovered),
			fmt.Sprintf("%d", r.Algorithm),
			fmt.Sprintf("%d", r.Labels),
			fmt.Sprintf("%d", r.KeyTag),
			r.SignerName,
			r.CreatedAt,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)
	fmt.Println()
}
