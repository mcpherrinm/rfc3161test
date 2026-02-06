// Package server provides the HTTP handler for the TSA server.
package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/mcpherrinm/rfc3161test/tsp"
)

const (
	contentTypeQuery = "application/timestamp-query"
	contentTypeReply = "application/timestamp-reply"
	maxBodySize      = 64 * 1024
)

// Handler returns an http.Handler that processes RFC 3161 timestamp requests.
func Handler(signer *tsp.Signer) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handleTimestamp(writer, request, signer)
	})
}

func handleTimestamp(writer http.ResponseWriter, request *http.Request, signer *tsp.Signer) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if request.Header.Get("Content-Type") != contentTypeQuery {
		http.Error(writer, "invalid content type", http.StatusBadRequest)

		return
	}

	body, err := io.ReadAll(io.LimitReader(request.Body, maxBodySize+1))
	if err != nil {
		http.Error(writer, "read error", http.StatusInternalServerError)

		return
	}

	if len(body) > maxBodySize {
		http.Error(writer, "request too large", http.StatusRequestEntityTooLarge)

		return
	}

	respDER, err := processRequest(body, signer)
	if err != nil {
		http.Error(writer, fmt.Sprintf("internal error: %v", err), http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", contentTypeReply)
	_, _ = writer.Write(respDER)
}

func processRequest(body []byte, signer *tsp.Signer) ([]byte, error) {
	req, err := tsp.ParseRequest(body)
	if err != nil {
		var reqErr *tsp.RequestError

		if errors.As(err, &reqErr) {
			errResp, marshalErr := tsp.CreateErrorResponse(reqErr.FailureInfo)
			if marshalErr != nil {
				return nil, fmt.Errorf("marshal error response: %w", marshalErr)
			}

			return errResp, nil
		}

		errResp, marshalErr := tsp.CreateErrorResponse(tsp.FailureBadDataFormat)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal error response: %w", marshalErr)
		}

		return errResp, nil
	}

	respDER, err := signer.CreateResponse(req)
	if err != nil {
		return nil, fmt.Errorf("create response: %w", err)
	}

	return respDER, nil
}
