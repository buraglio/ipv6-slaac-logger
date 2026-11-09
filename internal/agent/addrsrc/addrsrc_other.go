//go:build !linux && !darwin && !windows

package addrsrc

import (
	"context"
	"errors"
)

// Temporary stub; replaced by the real backend.
type stub struct{}

// New returns the platform address source.
func New() Source { return stub{} }

func (stub) List() ([]Addr, error) { return nil, errors.ErrUnsupported }

func (stub) Watch(context.Context) (<-chan struct{}, error) { return nil, errors.ErrUnsupported }
