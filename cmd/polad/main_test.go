// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/nttcom/pola/internal/config"
)

func TestStartGoBGPUpdate(t *testing.T) {
	t.Run("returns nil when TED is not configured", func(t *testing.T) {
		c := &config.Config{
			Global: config.Global{},
		}

		ch := startGoBGPUpdate(context.Background(), c, zap.NewNop())

		require.Nil(t, ch)
	})

	t.Run("returns channel when TED is configured", func(t *testing.T) {
		c := &config.Config{
			Global: config.Global{
				TED: &config.TED{
					Enable: true,
					ASN:    65000,
					Source: "gobgp",
				},
				GoBGP: config.GoBGP{
					GRPCClient: config.GRPCClient{
						Address: "127.0.0.1",
						Port:    "0",
					},
				},
			},
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ch := startGoBGPUpdate(ctx, c, zap.NewNop())

		require.NotNil(t, ch)
	})
}
