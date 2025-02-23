package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

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
