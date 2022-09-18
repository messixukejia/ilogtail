// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcommon // import "go.opentelemetry.io/collector/pdata/pcommon"

import (
	"encoding/hex"

	"go.opentelemetry.io/collector/pdata/internal/data"
)

// EmptyTraceID represents the empty (all zero bytes) TraceID.
var EmptyTraceID = NewTraceID([16]byte{})

// TraceID is a trace identifier.
type TraceID struct {
	orig [16]byte
}

// Deprecated: [v0.59.0] use EmptyTraceID.
func InvalidTraceID() TraceID {
	return EmptyTraceID
}

// NewTraceID returns a new TraceID from the given byte array.
func NewTraceID(bytes [16]byte) TraceID {
	return TraceID{orig: bytes}
}

// Bytes returns the byte array representation of the TraceID.
func (ms TraceID) Bytes() [16]byte {
	return ms.orig
}

// HexString returns hex representation of the TraceID.
func (ms TraceID) HexString() string {
	if ms.IsEmpty() {
		return ""
	}
	return hex.EncodeToString(ms.orig[:])
}

// IsEmpty returns true if id doesn't contain at least one non-zero byte.
func (ms TraceID) IsEmpty() bool {
	return data.TraceID(ms.orig).IsEmpty()
}
