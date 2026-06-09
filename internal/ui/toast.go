package ui

import (
	"strconv"
	"sync/atomic"
	"time"

	datastar "github.com/starfederation/datastar-go/datastar"

	"github.com/danielmichaels/gecko/internal/ui/templates"
)

// toastSeq hands out monotonically increasing ids so every appended toast has a
// unique element id; idiomorph keys on id, so duplicates would morph together
// instead of stacking.
var toastSeq atomic.Uint64

// newToast builds a ToastView with a unique element id and the current time.
// Variant is one of ok|crit|warn|info.
func newToast(variant, tag, title, desc string) templates.ToastView {
	return templates.ToastView{
		ID:        strconv.FormatUint(toastSeq.Add(1), 36),
		Variant:   variant,
		Tag:       tag,
		Title:     title,
		Desc:      desc,
		Timestamp: time.Now().Format("15:04:05"),
	}
}

// pushToast appends a toast onto the shared #toast-stack over the open SSE stream.
func pushToast(sse *datastar.ServerSentEventGenerator, t templates.ToastView) {
	_ = sse.PatchElementTempl(
		templates.Toast(t),
		datastar.WithSelectorID("toast-stack"),
		datastar.WithModeAppend(),
	)
}
