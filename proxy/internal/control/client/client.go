package client

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/control"
)

// Call sends one control op and returns the response data JSON.
func Call(socketPath, op string, data any) (json.RawMessage, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var raw json.RawMessage
	if data != nil {
		raw, err = json.Marshal(data)
		if err != nil {
			return nil, err
		}
	}
	req := control.Request{Op: op, Data: raw}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		return nil, fmt.Errorf("no response")
	}
	var resp control.Response
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		if resp.Error != "" {
			return nil, fmt.Errorf("%s", resp.Error)
		}
		return nil, fmt.Errorf("control error")
	}
	return resp.Data, nil
}
