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

// This file contains data structures that are common for all telemetry types,
// such as timestamps, attributes, etc.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"

	"go.opentelemetry.io/collector/pdata/internal"
	otlpcommon "go.opentelemetry.io/collector/pdata/internal/data/protogen/common/v1"
)

// ValueType specifies the type of Value.
type ValueType int32

const (
	ValueTypeEmpty ValueType = iota
	ValueTypeString
	ValueTypeInt
	ValueTypeDouble
	ValueTypeBool
	ValueTypeMap
	ValueTypeSlice
	ValueTypeBytes
)

// String returns the string representation of the ValueType.
func (avt ValueType) String() string {
	switch avt {
	case ValueTypeEmpty:
		return "EMPTY"
	case ValueTypeString:
		return "STRING"
	case ValueTypeBool:
		return "BOOL"
	case ValueTypeInt:
		return "INT"
	case ValueTypeDouble:
		return "DOUBLE"
	case ValueTypeMap:
		return "MAP"
	case ValueTypeSlice:
		return "SLICE"
	case ValueTypeBytes:
		return "BYTES"
	}
	return ""
}

// Value is a mutable cell containing any value. Typically used as an element of Map or Slice.
// Must use one of NewValue+ functions below to create new instances.
//
// Intended to be passed by value since internally it is just a pointer to actual
// value representation. For the same reason passing by value and calling setters
// will modify the original, e.g.:
//
//	func f1(val Value) { val.SetIntVal(234) }
//	func f2() {
//	    v := NewValueString("a string")
//	    f1(v)
//	    _ := v.Type() // this will return ValueTypeInt
//	}
//
// Important: zero-initialized instance is not valid for use. All Value functions below must
// be called only on instances that are created via NewValue+ functions.
type Value internal.Value

// NewValueEmpty creates a new Value with an empty value.
func NewValueEmpty() Value {
	return newValue(&otlpcommon.AnyValue{})
}

// NewValueString creates a new Value with the given string value.
func NewValueString(v string) Value {
	return newValue(&otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: v}})
}

// NewValueInt creates a new Value with the given int64 value.
func NewValueInt(v int64) Value {
	return newValue(&otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_IntValue{IntValue: v}})
}

// NewValueDouble creates a new Value with the given float64 value.
func NewValueDouble(v float64) Value {
	return newValue(&otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_DoubleValue{DoubleValue: v}})
}

// NewValueBool creates a new Value with the given bool value.
func NewValueBool(v bool) Value {
	return newValue(&otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_BoolValue{BoolValue: v}})
}

// NewValueMap creates a new Value of map type.
func NewValueMap() Value {
	return newValue(&otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_KvlistValue{KvlistValue: &otlpcommon.KeyValueList{}}})
}

// NewValueSlice creates a new Value of array type.
func NewValueSlice() Value {
	return newValue(&otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_ArrayValue{ArrayValue: &otlpcommon.ArrayValue{}}})
}

// NewValueBytes creates a new Value with the given ImmutableByteSlice value.
func NewValueBytes(v ImmutableByteSlice) Value {
	return newValue(&otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_BytesValue{BytesValue: v.getOrig()}})
}

func newValue(orig *otlpcommon.AnyValue) Value {
	return Value(internal.NewValue(orig))
}

func (v Value) getOrig() *otlpcommon.AnyValue {
	return internal.GetOrigValue(internal.Value(v))
}

func newValueFromRaw(iv interface{}) Value {
	switch tv := iv.(type) {
	case nil:
		return NewValueEmpty()
	case string:
		return NewValueString(tv)
	case int:
		return NewValueInt(int64(tv))
	case int8:
		return NewValueInt(int64(tv))
	case int16:
		return NewValueInt(int64(tv))
	case int32:
		return NewValueInt(int64(tv))
	case int64:
		return NewValueInt(tv)
	case uint:
		return NewValueInt(int64(tv))
	case uint8:
		return NewValueInt(int64(tv))
	case uint16:
		return NewValueInt(int64(tv))
	case uint32:
		return NewValueInt(int64(tv))
	case uint64:
		return NewValueInt(int64(tv))
	case float32:
		return NewValueDouble(float64(tv))
	case float64:
		return NewValueDouble(tv)
	case bool:
		return NewValueBool(tv)
	case []byte:
		return NewValueBytes(NewImmutableByteSlice(tv))
	case map[string]interface{}:
		mv := NewValueMap()
		NewMapFromRaw(tv).CopyTo(mv.MapVal())
		return mv
	case []interface{}:
		av := NewValueSlice()
		NewSliceFromRaw(tv).CopyTo(av.SliceVal())
		return av
	default:
		return NewValueString(fmt.Sprintf("<Invalid value type %T>", tv))
	}
}

// Type returns the type of the value for this Value.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) Type() ValueType {
	switch v.getOrig().Value.(type) {
	case *otlpcommon.AnyValue_StringValue:
		return ValueTypeString
	case *otlpcommon.AnyValue_BoolValue:
		return ValueTypeBool
	case *otlpcommon.AnyValue_IntValue:
		return ValueTypeInt
	case *otlpcommon.AnyValue_DoubleValue:
		return ValueTypeDouble
	case *otlpcommon.AnyValue_KvlistValue:
		return ValueTypeMap
	case *otlpcommon.AnyValue_ArrayValue:
		return ValueTypeSlice
	case *otlpcommon.AnyValue_BytesValue:
		return ValueTypeBytes
	}
	return ValueTypeEmpty
}

// StringVal returns the string value associated with this Value.
// If the Type() is not ValueTypeString then returns empty string.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) StringVal() string {
	return v.getOrig().GetStringValue()
}

// IntVal returns the int64 value associated with this Value.
// If the Type() is not ValueTypeInt then returns int64(0).
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) IntVal() int64 {
	return v.getOrig().GetIntValue()
}

// DoubleVal returns the float64 value associated with this Value.
// If the Type() is not ValueTypeDouble then returns float64(0).
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) DoubleVal() float64 {
	return v.getOrig().GetDoubleValue()
}

// BoolVal returns the bool value associated with this Value.
// If the Type() is not ValueTypeBool then returns false.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) BoolVal() bool {
	return v.getOrig().GetBoolValue()
}

// MapVal returns the map value associated with this Value.
// If the Type() is not ValueTypeMap then returns an invalid map. Note that using
// such map can cause panic.
//
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) MapVal() Map {
	kvlist := v.getOrig().GetKvlistValue()
	if kvlist == nil {
		return Map{}
	}
	return newMap(&kvlist.Values)
}

// SliceVal returns the slice value associated with this Value.
// If the Type() is not ValueTypeSlice then returns an invalid slice. Note that using
// such slice can cause panic.
//
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) SliceVal() Slice {
	arr := v.getOrig().GetArrayValue()
	if arr == nil {
		return Slice{}
	}
	return newSlice(&arr.Values)
}

// BytesVal returns the ImmutableByteSlice value associated with this Value.
// If the Type() is not ValueTypeBytes then returns an empty slice.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) BytesVal() ImmutableByteSlice {
	return ImmutableByteSlice(internal.NewImmutableByteSlice(v.getOrig().GetBytesValue()))
}

// SetStringVal replaces the string value associated with this Value,
// it also changes the type to be ValueTypeString.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) SetStringVal(sv string) {
	v.getOrig().Value = &otlpcommon.AnyValue_StringValue{StringValue: sv}
}

// SetIntVal replaces the int64 value associated with this Value,
// it also changes the type to be ValueTypeInt.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) SetIntVal(iv int64) {
	v.getOrig().Value = &otlpcommon.AnyValue_IntValue{IntValue: iv}
}

// SetDoubleVal replaces the float64 value associated with this Value,
// it also changes the type to be ValueTypeDouble.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) SetDoubleVal(dv float64) {
	v.getOrig().Value = &otlpcommon.AnyValue_DoubleValue{DoubleValue: dv}
}

// SetBoolVal replaces the bool value associated with this Value,
// it also changes the type to be ValueTypeBool.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) SetBoolVal(bv bool) {
	v.getOrig().Value = &otlpcommon.AnyValue_BoolValue{BoolValue: bv}
}

// SetBytesVal replaces the ImmutableByteSlice value associated with this Value,
// it also changes the type to be ValueTypeBytes.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) SetBytesVal(bv ImmutableByteSlice) {
	v.getOrig().Value = &otlpcommon.AnyValue_BytesValue{BytesValue: bv.getOrig()}
}

// SetEmptyMapVal sets value to an empty map and returns it.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) SetEmptyMapVal() Map {
	kv := &otlpcommon.AnyValue_KvlistValue{KvlistValue: &otlpcommon.KeyValueList{}}
	v.getOrig().Value = kv
	return newMap(&kv.KvlistValue.Values)
}

// SetEmptySliceVal sets value to an empty slice and returns it.
// Calling this function on zero-initialized Value will cause a panic.
func (v Value) SetEmptySliceVal() Slice {
	av := &otlpcommon.AnyValue_ArrayValue{ArrayValue: &otlpcommon.ArrayValue{}}
	v.getOrig().Value = av
	return newSlice(&av.ArrayValue.Values)
}

// copyTo copies the value to Value. Will panic if dest is nil.
func (v Value) copyTo(dest *otlpcommon.AnyValue) {
	switch ov := v.getOrig().Value.(type) {
	case *otlpcommon.AnyValue_KvlistValue:
		kv, ok := dest.Value.(*otlpcommon.AnyValue_KvlistValue)
		if !ok {
			kv = &otlpcommon.AnyValue_KvlistValue{KvlistValue: &otlpcommon.KeyValueList{}}
			dest.Value = kv
		}
		if ov.KvlistValue == nil {
			kv.KvlistValue = nil
			return
		}
		// Deep copy to dest.
		newMap(&ov.KvlistValue.Values).CopyTo(newMap(&kv.KvlistValue.Values))
	case *otlpcommon.AnyValue_ArrayValue:
		av, ok := dest.Value.(*otlpcommon.AnyValue_ArrayValue)
		if !ok {
			av = &otlpcommon.AnyValue_ArrayValue{ArrayValue: &otlpcommon.ArrayValue{}}
			dest.Value = av
		}
		if ov.ArrayValue == nil {
			av.ArrayValue = nil
			return
		}
		// Deep copy to dest.
		newSlice(&ov.ArrayValue.Values).CopyTo(newSlice(&av.ArrayValue.Values))
	case *otlpcommon.AnyValue_BytesValue:
		bv, ok := dest.Value.(*otlpcommon.AnyValue_BytesValue)
		if !ok {
			bv = &otlpcommon.AnyValue_BytesValue{}
			dest.Value = bv
		}
		bv.BytesValue = make([]byte, len(ov.BytesValue))
		copy(bv.BytesValue, ov.BytesValue)
	default:
		// Primitive immutable type, no need for deep copy.
		dest.Value = v.getOrig().Value
	}
}

// CopyTo copies the attribute to a destination.
func (v Value) CopyTo(dest Value) {
	v.copyTo(dest.getOrig())
}

// Equal checks for equality, it returns true if the objects are equal otherwise false.
func (v Value) Equal(av Value) bool {
	if v.getOrig() == av.getOrig() {
		return true
	}

	if v.getOrig().Value == nil || av.getOrig().Value == nil {
		return v.getOrig().Value == av.getOrig().Value
	}

	if v.Type() != av.Type() {
		return false
	}

	switch v := v.getOrig().Value.(type) {
	case *otlpcommon.AnyValue_StringValue:
		return v.StringValue == av.getOrig().GetStringValue()
	case *otlpcommon.AnyValue_BoolValue:
		return v.BoolValue == av.getOrig().GetBoolValue()
	case *otlpcommon.AnyValue_IntValue:
		return v.IntValue == av.getOrig().GetIntValue()
	case *otlpcommon.AnyValue_DoubleValue:
		return v.DoubleValue == av.getOrig().GetDoubleValue()
	case *otlpcommon.AnyValue_ArrayValue:
		vv := v.ArrayValue.GetValues()
		avv := av.getOrig().GetArrayValue().GetValues()
		if len(vv) != len(avv) {
			return false
		}

		for i := range avv {
			if !newValue(&vv[i]).Equal(newValue(&avv[i])) {
				return false
			}
		}
		return true
	case *otlpcommon.AnyValue_KvlistValue:
		cc := v.KvlistValue.GetValues()
		avv := av.getOrig().GetKvlistValue().GetValues()
		if len(cc) != len(avv) {
			return false
		}

		m := newMap(&avv)

		for i := range cc {
			newAv, ok := m.Get(cc[i].Key)
			if !ok {
				return false
			}

			if !newAv.Equal(newValue(&cc[i].Value)) {
				return false
			}
		}
		return true
	case *otlpcommon.AnyValue_BytesValue:
		return bytes.Equal(v.BytesValue, av.getOrig().GetBytesValue())
	}

	return false
}

// AsString converts an OTLP Value object of any type to its equivalent string
// representation. This differs from StringVal which only returns a non-empty value
// if the ValueType is ValueTypeString.
func (v Value) AsString() string {
	switch v.Type() {
	case ValueTypeEmpty:
		return ""

	case ValueTypeString:
		return v.StringVal()

	case ValueTypeBool:
		return strconv.FormatBool(v.BoolVal())

	case ValueTypeDouble:
		return float64AsString(v.DoubleVal())

	case ValueTypeInt:
		return strconv.FormatInt(v.IntVal(), 10)

	case ValueTypeMap:
		jsonStr, _ := json.Marshal(v.MapVal().AsRaw())
		return string(jsonStr)

	case ValueTypeBytes:
		return base64.StdEncoding.EncodeToString(v.BytesVal().getOrig())

	case ValueTypeSlice:
		jsonStr, _ := json.Marshal(v.SliceVal().AsRaw())
		return string(jsonStr)

	default:
		return fmt.Sprintf("<Unknown OpenTelemetry attribute value type %q>", v.Type())
	}
}

// See https://cs.opensource.google/go/go/+/refs/tags/go1.17.7:src/encoding/json/encode.go;l=585.
// This allows us to avoid using reflection.
func float64AsString(f float64) string {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return fmt.Sprintf("json: unsupported value: %s", strconv.FormatFloat(f, 'g', -1, 64))
	}

	// Convert as if by ES6 number to string conversion.
	// This matches most other JSON generators.
	// See golang.org/issue/6384 and golang.org/issue/14135.
	// Like fmt %g, but the exponent cutoffs are different
	// and exponents themselves are not padded to two digits.
	scratch := [64]byte{}
	b := scratch[:0]
	abs := math.Abs(f)
	fmt := byte('f')
	if abs != 0 && (abs < 1e-6 || abs >= 1e21) {
		fmt = 'e'
	}
	b = strconv.AppendFloat(b, f, fmt, -1, 64)
	if fmt == 'e' {
		// clean up e-09 to e-9
		n := len(b)
		if n >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}
	return string(b)
}

func (v Value) asRaw() interface{} {
	switch v.Type() {
	case ValueTypeEmpty:
		return nil
	case ValueTypeString:
		return v.StringVal()
	case ValueTypeBool:
		return v.BoolVal()
	case ValueTypeDouble:
		return v.DoubleVal()
	case ValueTypeInt:
		return v.IntVal()
	case ValueTypeBytes:
		return v.BytesVal().AsRaw()
	case ValueTypeMap:
		return v.MapVal().AsRaw()
	case ValueTypeSlice:
		return v.SliceVal().AsRaw()
	}
	return fmt.Sprintf("<Unknown OpenTelemetry value type %q>", v.Type())
}

func newAttributeKeyValueString(k string, v string) otlpcommon.KeyValue {
	orig := otlpcommon.KeyValue{Key: k}
	akv := newValue(&orig.Value)
	akv.SetStringVal(v)
	return orig
}

func newAttributeKeyValueInt(k string, v int64) otlpcommon.KeyValue {
	orig := otlpcommon.KeyValue{Key: k}
	akv := newValue(&orig.Value)
	akv.SetIntVal(v)
	return orig
}

func newAttributeKeyValueDouble(k string, v float64) otlpcommon.KeyValue {
	orig := otlpcommon.KeyValue{Key: k}
	akv := newValue(&orig.Value)
	akv.SetDoubleVal(v)
	return orig
}

func newAttributeKeyValueBool(k string, v bool) otlpcommon.KeyValue {
	orig := otlpcommon.KeyValue{Key: k}
	akv := newValue(&orig.Value)
	akv.SetBoolVal(v)
	return orig
}

func newAttributeKeyValueNull(k string) otlpcommon.KeyValue {
	orig := otlpcommon.KeyValue{Key: k}
	return orig
}

func newAttributeKeyValue(k string, av Value) otlpcommon.KeyValue {
	orig := otlpcommon.KeyValue{Key: k}
	av.copyTo(&orig.Value)
	return orig
}

func newAttributeKeyValueBytes(k string, v ImmutableByteSlice) otlpcommon.KeyValue {
	orig := otlpcommon.KeyValue{Key: k}
	akv := newValue(&orig.Value)
	akv.SetBytesVal(v)
	return orig
}

// Map stores a map of string keys to elements of Value type.
type Map internal.Map

// NewMap creates a Map with 0 elements.
func NewMap() Map {
	orig := []otlpcommon.KeyValue(nil)
	return Map(internal.NewMap(&orig))
}

func (m Map) getOrig() *[]otlpcommon.KeyValue {
	return internal.GetOrigMap(internal.Map(m))
}

// NewMapFromRaw creates a Map with values from the given map[string]interface{}.
func NewMapFromRaw(rawMap map[string]interface{}) Map {
	if len(rawMap) == 0 {
		kv := []otlpcommon.KeyValue(nil)
		return newMap(&kv)
	}
	origs := make([]otlpcommon.KeyValue, len(rawMap))
	ix := 0
	for k, iv := range rawMap {
		origs[ix].Key = k
		newValueFromRaw(iv).copyTo(&origs[ix].Value)
		ix++
	}
	return Map(internal.NewMap(&origs))
}

func newMap(orig *[]otlpcommon.KeyValue) Map {
	return Map(internal.NewMap(orig))
}

// Clear erases any existing entries in this Map instance.
func (m Map) Clear() {
	*m.getOrig() = nil
}

// EnsureCapacity increases the capacity of this Map instance, if necessary,
// to ensure that it can hold at least the number of elements specified by the capacity argument.
func (m Map) EnsureCapacity(capacity int) {
	if capacity <= cap(*m.getOrig()) {
		return
	}
	oldOrig := *m.getOrig()
	*m.getOrig() = make([]otlpcommon.KeyValue, 0, capacity)
	copy(*m.getOrig(), oldOrig)
}

// Get returns the Value associated with the key and true. Returned
// Value is not a copy, it is a reference to the value stored in this map.
// It is allowed to modify the returned value using Value.Set* functions.
// Such modification will be applied to the value stored in this map.
//
// If the key does not exist returns an invalid instance of the KeyValue and false.
// Calling any functions on the returned invalid instance will cause a panic.
func (m Map) Get(key string) (Value, bool) {
	for i := range *m.getOrig() {
		akv := &(*m.getOrig())[i]
		if akv.Key == key {
			return newValue(&akv.Value), true
		}
	}
	return newValue(nil), false
}

// Remove removes the entry associated with the key and returns true if the key
// was present in the map, otherwise returns false.
func (m Map) Remove(key string) bool {
	for i := range *m.getOrig() {
		akv := &(*m.getOrig())[i]
		if akv.Key == key {
			*akv = (*m.getOrig())[len(*m.getOrig())-1]
			*m.getOrig() = (*m.getOrig())[:len(*m.getOrig())-1]
			return true
		}
	}
	return false
}

// RemoveIf removes the entries for which the function in question returns true
func (m Map) RemoveIf(f func(string, Value) bool) {
	newLen := 0
	for i := 0; i < len(*m.getOrig()); i++ {
		akv := &(*m.getOrig())[i]
		if f(akv.Key, newValue(&akv.Value)) {
			continue
		}
		if newLen == i {
			// Nothing to move, element is at the right place.
			newLen++
			continue
		}
		(*m.getOrig())[newLen] = (*m.getOrig())[i]
		newLen++
	}
	*m.getOrig() = (*m.getOrig())[:newLen]
}

// Insert adds the Value to the map when the key does not exist.
// No action is applied to the map where the key already exists.
//
// Calling this function with a zero-initialized Value struct will cause a panic.
//
// Important: this function should not be used if the caller has access to
// the raw value to avoid an extra allocation.
//
// NOTE: The method will be deprecated in 0.60.0. Replace it with the following function calls:
// For primitive types, use Insert<Type> methods, e.g. InsertString.
// For complex and unknown types, use:
//
//	_, ok := m.Get(k)
//	if !ok {
//		v.CopyTo(m.UpsertEmpty(k)) // or use m.UpsertEmpty<Type> for complex types.
//	}
func (m Map) Insert(k string, v Value) {
	if _, existing := m.Get(k); !existing {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValue(k, v))
	}
}

// InsertNull adds a null Value to the map when the key does not exist.
// No action is applied to the map where the key already exists.
// Deprecated: [0.59.0] Use Get and UpsertEmpty instead.
func (m Map) InsertNull(k string) {
	if _, existing := m.Get(k); !existing {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueNull(k))
	}
}

// InsertString adds the string Value to the map when the key does not exist.
// No action is applied to the map where the key already exists.
func (m Map) InsertString(k string, v string) {
	if _, existing := m.Get(k); !existing {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueString(k, v))
	}
}

// InsertInt adds the int Value to the map when the key does not exist.
// No action is applied to the map where the key already exists.
func (m Map) InsertInt(k string, v int64) {
	if _, existing := m.Get(k); !existing {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueInt(k, v))
	}
}

// InsertDouble adds the double Value to the map when the key does not exist.
// No action is applied to the map where the key already exists.
func (m Map) InsertDouble(k string, v float64) {
	if _, existing := m.Get(k); !existing {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueDouble(k, v))
	}
}

// InsertBool adds the bool Value to the map when the key does not exist.
// No action is applied to the map where the key already exists.
func (m Map) InsertBool(k string, v bool) {
	if _, existing := m.Get(k); !existing {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueBool(k, v))
	}
}

// InsertBytes adds the ImmutableByteSlice Value to the map when the key does not exist.
// No action is applied to the map where the key already exists.
func (m Map) InsertBytes(k string, v ImmutableByteSlice) {
	if _, existing := m.Get(k); !existing {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueBytes(k, v))
	}
}

// Update updates an existing Value with a value.
// No action is applied to the map where the key does not exist.
//
// Calling this function with a zero-initialized Value struct will cause a panic.
//
// Important: this function should not be used if the caller has access to
// the raw value to avoid an extra allocation.
//
// Deprecated: [0.59.0] Replace it with the following function calls:
// For primitive types, use Update<Type> methods, e.g. UpdateString.
// For complex and unknown types, use:
//
//	toVal, ok := m.Get(k)
//	if ok {
//		v.CopyTo(toVal) // or use m.UpsertEmpty<Type> for complex types.
//	}
func (m Map) Update(k string, v Value) {
	if av, existing := m.Get(k); existing {
		v.copyTo(av.getOrig())
	}
}

// UpdateString updates an existing string Value with a value.
// No action is applied to the map where the key does not exist.
func (m Map) UpdateString(k string, v string) {
	if av, existing := m.Get(k); existing {
		av.SetStringVal(v)
	}
}

// UpdateInt updates an existing int Value with a value.
// No action is applied to the map where the key does not exist.
func (m Map) UpdateInt(k string, v int64) {
	if av, existing := m.Get(k); existing {
		av.SetIntVal(v)
	}
}

// UpdateDouble updates an existing double Value with a value.
// No action is applied to the map where the key does not exist.
func (m Map) UpdateDouble(k string, v float64) {
	if av, existing := m.Get(k); existing {
		av.SetDoubleVal(v)
	}
}

// UpdateBool updates an existing bool Value with a value.
// No action is applied to the map where the key does not exist.
func (m Map) UpdateBool(k string, v bool) {
	if av, existing := m.Get(k); existing {
		av.SetBoolVal(v)
	}
}

// UpdateBytes updates an existing ImmutableByteSlice Value with a value.
// No action is applied to the map where the key does not exist.
func (m Map) UpdateBytes(k string, v ImmutableByteSlice) {
	if av, existing := m.Get(k); existing {
		av.SetBytesVal(v)
	}
}

// Upsert performs the Insert or Update action. The Value is
// inserted to the map that did not originally have the key. The key/value is
// updated to the map where the key already existed.
//
// Calling this function with a zero-initialized Value struct will cause a panic.
//
// Important: this function should not be used if the caller has access to
// the raw value to avoid an extra allocation.
//
// Deprecated: [0.59.0] Replace it with the following function calls:
// For primitive types, use Upsert<Type> methods, e.g. UpsertString.
// For complex types, use UpsertEmpty<Type> methods, e.g. UpsertEmptyMap, and fill it with the data.
// If you don't know the value type, replace it with v.CopyTo(m.UpsertEmpty()).
func (m Map) Upsert(k string, v Value) {
	if av, existing := m.Get(k); existing {
		v.copyTo(av.getOrig())
	} else {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValue(k, v))
	}
}

// UpsertEmpty inserts or updates an empty value to the map under given key
// and return the updated/inserted value.
func (m Map) UpsertEmpty(k string) Value {
	if av, existing := m.Get(k); existing {
		av.getOrig().Value = nil
		return newValue(av.getOrig())
	}
	*m.getOrig() = append(*m.getOrig(), otlpcommon.KeyValue{Key: k})
	return newValue(&(*m.getOrig())[len(*m.getOrig())-1].Value)
}

// UpsertString performs the Insert or Update action. The Value is
// inserted to the map that did not originally have the key. The key/value is
// updated to the map where the key already existed.
func (m Map) UpsertString(k string, v string) {
	if av, existing := m.Get(k); existing {
		av.SetStringVal(v)
	} else {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueString(k, v))
	}
}

// UpsertInt performs the Insert or Update action. The int Value is
// inserted to the map that did not originally have the key. The key/value is
// updated to the map where the key already existed.
func (m Map) UpsertInt(k string, v int64) {
	if av, existing := m.Get(k); existing {
		av.SetIntVal(v)
	} else {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueInt(k, v))
	}
}

// UpsertDouble performs the Insert or Update action. The double Value is
// inserted to the map that did not originally have the key. The key/value is
// updated to the map where the key already existed.
func (m Map) UpsertDouble(k string, v float64) {
	if av, existing := m.Get(k); existing {
		av.SetDoubleVal(v)
	} else {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueDouble(k, v))
	}
}

// UpsertBool performs the Insert or Update action. The bool Value is
// inserted to the map that did not originally have the key. The key/value is
// updated to the map where the key already existed.
func (m Map) UpsertBool(k string, v bool) {
	if av, existing := m.Get(k); existing {
		av.SetBoolVal(v)
	} else {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueBool(k, v))
	}
}

// UpsertBytes performs the Insert or Update action. The ImmutableByteSlice Value is
// inserted to the map that did not originally have the key. The key/value is
// updated to the map where the key already existed.
func (m Map) UpsertBytes(k string, v ImmutableByteSlice) {
	if av, existing := m.Get(k); existing {
		av.SetBytesVal(v)
	} else {
		*m.getOrig() = append(*m.getOrig(), newAttributeKeyValueBytes(k, v))
	}
}

// UpsertEmptyMap inserts or updates an empty map under given key and returns it.
func (m Map) UpsertEmptyMap(k string) Map {
	kvl := otlpcommon.AnyValue_KvlistValue{KvlistValue: &otlpcommon.KeyValueList{Values: []otlpcommon.KeyValue(nil)}}
	if av, existing := m.Get(k); existing {
		av.getOrig().Value = &kvl
	} else {
		*m.getOrig() = append(*m.getOrig(), otlpcommon.KeyValue{Key: k, Value: otlpcommon.AnyValue{Value: &kvl}})
	}
	return Map(internal.NewMap(&kvl.KvlistValue.Values))
}

// UpsertEmptySlice inserts or updates an empty clice under given key and returns it.
func (m Map) UpsertEmptySlice(k string) Slice {
	vl := otlpcommon.AnyValue_ArrayValue{ArrayValue: &otlpcommon.ArrayValue{Values: []otlpcommon.AnyValue(nil)}}
	if av, existing := m.Get(k); existing {
		av.getOrig().Value = &vl
	} else {
		*m.getOrig() = append(*m.getOrig(), otlpcommon.KeyValue{Key: k, Value: otlpcommon.AnyValue{Value: &vl}})
	}
	return Slice(internal.NewSlice(&vl.ArrayValue.Values))
}

// Sort sorts the entries in the Map so two instances can be compared.
// Returns the same instance to allow nicer code like:
//
//	assert.EqualValues(t, expected.Sort(), actual.Sort())
func (m Map) Sort() Map {
	// Intention is to move the nil values at the end.
	sort.SliceStable(*m.getOrig(), func(i, j int) bool {
		return (*m.getOrig())[i].Key < (*m.getOrig())[j].Key
	})
	return m
}

// Len returns the length of this map.
//
// Because the Map is represented internally by a slice of pointers, and the data are comping from the wire,
// it is possible that when iterating using "Range" to get access to fewer elements because nil elements are skipped.
func (m Map) Len() int {
	return len(*m.getOrig())
}

// Range calls f sequentially for each key and value present in the map. If f returns false, range stops the iteration.
//
// Example:
//
//	sm.Range(func(k string, v Value) bool {
//	    ...
//	})
func (m Map) Range(f func(k string, v Value) bool) {
	for i := range *m.getOrig() {
		kv := &(*m.getOrig())[i]
		if !f(kv.Key, Value(internal.NewValue(&kv.Value))) {
			break
		}
	}
}

// CopyTo copies all elements from the current map to the dest.
func (m Map) CopyTo(dest Map) {
	newLen := len(*m.getOrig())
	oldCap := cap(*dest.getOrig())
	if newLen <= oldCap {
		// New slice fits in existing slice, no need to reallocate.
		*dest.getOrig() = (*dest.getOrig())[:newLen:oldCap]
		for i := range *m.getOrig() {
			akv := &(*m.getOrig())[i]
			destAkv := &(*dest.getOrig())[i]
			destAkv.Key = akv.Key
			newValue(&akv.Value).copyTo(&destAkv.Value)
		}
		return
	}

	// New slice is bigger than exist slice. Allocate new space.
	origs := make([]otlpcommon.KeyValue, len(*m.getOrig()))
	for i := range *m.getOrig() {
		akv := &(*m.getOrig())[i]
		origs[i].Key = akv.Key
		newValue(&akv.Value).copyTo(&origs[i].Value)
	}
	*dest.getOrig() = origs
}

// AsRaw converts an OTLP Map to a standard go map
func (m Map) AsRaw() map[string]interface{} {
	rawMap := make(map[string]interface{})
	m.Range(func(k string, v Value) bool {
		rawMap[k] = v.asRaw()
		return true
	})
	return rawMap
}

// NewSliceFromRaw creates a Slice with values from the given []interface{}.
func NewSliceFromRaw(rawSlice []interface{}) Slice {
	if len(rawSlice) == 0 {
		v := []otlpcommon.AnyValue(nil)
		return newSlice(&v)
	}
	origs := make([]otlpcommon.AnyValue, len(rawSlice))
	for ix, iv := range rawSlice {
		newValueFromRaw(iv).copyTo(&origs[ix])
	}
	return newSlice(&origs)
}

// AsRaw converts the Slice to a standard go slice.
func (es Slice) AsRaw() []interface{} {
	rawSlice := make([]interface{}, 0, es.Len())
	for i := 0; i < es.Len(); i++ {
		rawSlice = append(rawSlice, es.At(i).asRaw())
	}
	return rawSlice
}
