// Copyright 2021 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package opentelemetry

import (
	"net/http"

	"github.com/alibaba/ilogtail/helper/decoder/common"
	"github.com/alibaba/ilogtail/pkg/protocol"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
)

// Decoder impl
type Decoder struct {
}

// Decode impl
func (d *Decoder) Decode(data []byte, req *http.Request) (logs []*protocol.Log, err error) {
	switch req.Header.Get("Content-Type") {
	case "application/x-protobuf":
		otlp_req := pmetricotlp.NewRequest()
		err = otlp_req.UnmarshalProto(data)

		rms := otlp_req.Metrics().ResourceMetrics()
		for i := 0; i < rms.Len(); i++ {
			buf.logEntry("ResourceMetrics #%d", i)
			rm := rms.At(i)
			buf.logEntry("Resource SchemaURL: %s", rm.SchemaUrl())
			buf.logAttributes("Resource attributes", rm.Resource().Attributes())
			ilms := rm.ScopeMetrics()
			for j := 0; j < ilms.Len(); j++ {
				buf.logEntry("ScopeMetrics #%d", j)
				ilm := ilms.At(j)
				buf.logEntry("ScopeMetrics SchemaURL: %s", ilm.SchemaUrl())
				buf.logInstrumentationScope(ilm.Scope())
				metrics := ilm.Metrics()
				for k := 0; k < metrics.Len(); k++ {
					buf.logEntry("Metric #%d", k)
					metric := metrics.At(k)
					buf.logMetricDescriptor(metric)
					buf.logMetricDataPoints(metric)
				}
			}
		}

	case "application/json":
		otlp_req := pmetricotlp.NewRequest()
		err = otlp_req.UnmarshalJSON(data)
	default:

	}

	return logs, err
}

func (d *Decoder) ParseRequest(res http.ResponseWriter, req *http.Request, maxBodySize int64) (data []byte, statusCode int, err error) {
	return common.CollectBody(res, req, maxBodySize)
}
