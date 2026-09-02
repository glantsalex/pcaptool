// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dnsname

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "mixed case", in: "Api.Example.COM", want: "api.example.com"},
		{name: "surrounding whitespace", in: " \tapi.example.com\n", want: "api.example.com"},
		{name: "single trailing dot", in: "api.example.com.", want: "api.example.com"},
		{name: "whitespace then trailing dot", in: " Api.Example.COM. \n", want: "api.example.com"},
		{name: "empty", in: "", want: ""},
		{name: "canonical", in: "api.example.com", want: "api.example.com"},
		{name: "only one trailing dot", in: "api.example.com..", want: "api.example.com."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Normalize(tt.in); got != tt.want {
				t.Fatalf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
