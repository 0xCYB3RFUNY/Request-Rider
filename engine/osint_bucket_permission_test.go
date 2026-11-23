package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckBucketPermissions(t *testing.T) {
	t.Run("PublicListableBucket", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>test-bucket</Name>
    <Prefix></Prefix>
    <Marker></Marker>
    <Contents>
        <Key>secret.pdf</Key>
        <Size>1234</Size>
    </Contents>
</ListBucketResult>`))
				return
			}
			if r.Method == http.MethodPut {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		perm, listable := checkBucketPermissions(context.Background(), ts.Client(), ts.URL, "aws_s3", http.StatusOK)
		if perm != "public_listable" {
			t.Fatalf("expected perm to be public_listable, got %s", perm)
		}
		if !listable {
			t.Fatalf("expected listable to be true")
		}
	})

	t.Run("AccessDeniedBucket", func(t *testing.T) {
		perm, listable := checkBucketPermissions(context.Background(), nil, "https://example.invalid", "aws_s3", http.StatusForbidden)
		if perm != "access_denied" {
			t.Fatalf("expected perm to be access_denied, got %s", perm)
		}
		if listable {
			t.Fatalf("expected listable to be false")
		}
	})

	t.Run("RedirectBucket", func(t *testing.T) {
		perm, listable := checkBucketPermissions(context.Background(), nil, "https://example.invalid", "aws_s3", http.StatusMovedPermanently)
		if perm != "redirect" {
			t.Fatalf("expected perm to be redirect, got %s", perm)
		}
		if listable {
			t.Fatalf("expected listable to be false")
		}
	})

	t.Run("PublicReadableWithoutListing", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><body>Index of files</body></html>`))
				return
			}
			if r.Method == http.MethodPut {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		perm, listable := checkBucketPermissions(context.Background(), ts.Client(), ts.URL, "aws_s3", http.StatusOK)
		if perm != "public_readable" {
			t.Fatalf("expected perm to be public_readable, got %s", perm)
		}
		if listable {
			t.Fatalf("expected listable to be false")
		}
	})

	t.Run("PublicWritableBucket", func(t *testing.T) {
		var putReceived, deleteReceived bool
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`Normal response`))
				return
			}
			if r.Method == http.MethodPut {
				putReceived = true
				w.WriteHeader(http.StatusCreated)
				return
			}
			if r.Method == http.MethodDelete {
				deleteReceived = true
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		perm, _ := checkBucketPermissions(context.Background(), ts.Client(), ts.URL, "aws_s3", http.StatusOK)
		if perm != "public_writable" {
			t.Fatalf("expected perm to be public_writable, got %s", perm)
		}
		if !putReceived {
			t.Fatalf("expected PUT request to be sent")
		}
		if !deleteReceived {
			t.Fatalf("expected DELETE cleanup request to be sent")
		}
	})
}
