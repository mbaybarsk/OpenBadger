package nodes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/observations"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Client{
		baseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		httpClient: httpClient,
	}
}

func (c *Client) Enroll(ctx context.Context, bootstrapToken string, request EnrollRequest) (EnrollResponse, error) {
	var response EnrollResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/nodes/enroll", bootstrapToken, request, &response); err != nil {
		return EnrollResponse{}, err
	}

	return response, nil
}

func (c *Client) Heartbeat(ctx context.Context, authToken string, request HeartbeatRequest) (HeartbeatResponse, error) {
	var response HeartbeatResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/nodes/heartbeat", authToken, request, &response); err != nil {
		return HeartbeatResponse{}, err
	}

	return response, nil
}

func (c *Client) LeaseJob(ctx context.Context, authToken string, request jobtypes.LeaseRequest) (jobtypes.Record, bool, error) {
	if c == nil || c.baseURL == "" {
		return jobtypes.Record{}, false, fmt.Errorf("node client base url is required")
	}

	body, err := json.Marshal(request)
	if err != nil {
		return jobtypes.Record{}, false, fmt.Errorf("marshal request: %w", err)
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/jobs/lease", bytes.NewReader(body))
	if err != nil {
		return jobtypes.Record{}, false, fmt.Errorf("build request: %w", err)
	}

	httpRequest.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(authToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(authToken))
	}

	httpResponse, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return jobtypes.Record{}, false, fmt.Errorf("send request: %w", err)
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode == http.StatusNoContent {
		return jobtypes.Record{}, false, nil
	}

	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		message, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, 4096))
		if readErr != nil {
			return jobtypes.Record{}, false, fmt.Errorf("request failed with status %d", httpResponse.StatusCode)
		}

		return jobtypes.Record{}, false, fmt.Errorf("request failed with status %d: %s", httpResponse.StatusCode, strings.TrimSpace(string(message)))
	}

	var response jobtypes.LeaseResponse
	if err := json.NewDecoder(httpResponse.Body).Decode(&response); err != nil {
		return jobtypes.Record{}, false, fmt.Errorf("decode response: %w", err)
	}

	return response.Job, true, nil
}

func (c *Client) UpdateJobStatus(ctx context.Context, authToken string, jobID string, request jobtypes.StatusRequest) (jobtypes.Record, error) {
	var response jobtypes.StatusResponse
	path := "/api/v1/jobs/" + url.PathEscape(strings.TrimSpace(jobID)) + "/status"
	if err := c.doJSON(ctx, http.MethodPost, path, authToken, request, &response); err != nil {
		return jobtypes.Record{}, err
	}

	return response.Job, nil
}

func (c *Client) UploadObservationBatch(ctx context.Context, authToken string, request observations.BatchRequest) (observations.BatchResponse, error) {
	var response observations.BatchResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/observations/batch", authToken, request, &response); err != nil {
		return observations.BatchResponse{}, err
	}

	return response, nil
}

func (c *Client) doJSON(ctx context.Context, method string, path string, bearerToken string, request any, response any) error {
	if c == nil || c.baseURL == "" {
		return fmt.Errorf("node client base url is required")
	}

	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpRequest, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	httpRequest.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(bearerToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearerToken))
	}

	httpResponse, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		message, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("request failed with status %d", httpResponse.StatusCode)
		}

		return fmt.Errorf("request failed with status %d: %s", httpResponse.StatusCode, strings.TrimSpace(string(message)))
	}

	if response == nil {
		return nil
	}

	if err := json.NewDecoder(httpResponse.Body).Decode(response); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}
