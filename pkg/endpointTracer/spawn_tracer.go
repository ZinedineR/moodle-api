package endpointTracer

import (
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const tracerName = "go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

// reference from gin otel middleware
// go.opentelemetry.io\contrib\instrumentation\github.com\gin-gonic\gin\otelgin@v0.34.0\gintrace.go

func SpawnTracer(ctx *gin.Context, serviceName string) {
	traceProvider := otel.GetTracerProvider()
	tracer := traceProvider.Tracer(tracerName, oteltrace.WithInstrumentationVersion(otelgin.SemVersion()))
	propagators := otel.GetTextMapPropagator()
	kontek := propagators.Extract(ctx.Request.Context(), propagation.HeaderCarrier(ctx.Request.Header))
	opts := []oteltrace.SpanStartOption{
		oteltrace.WithAttributes(semconv.NetAttributesFromHTTPRequest("tcp", ctx.Request)...),
		oteltrace.WithAttributes(semconv.EndUserAttributesFromHTTPRequest(ctx.Request)...),
		oteltrace.WithAttributes(semconv.HTTPServerAttributesFromHTTPRequest(serviceName, ctx.FullPath(), ctx.Request)...),
		oteltrace.WithSpanKind(oteltrace.SpanKindServer),
	}
	spanName := ctx.FullPath()

	kontek, span := tracer.Start(kontek, spanName, opts...)
	defer span.End()

	status := ctx.Writer.Status()
	attrs := semconv.HTTPAttributesFromHTTPStatusCode(status)
	spanStatus, spanMessage := semconv.SpanStatusFromHTTPStatusCodeAndSpanKind(status, oteltrace.SpanKindServer)
	span.SetAttributes(attrs...)
	span.SetStatus(spanStatus, spanMessage)
}
