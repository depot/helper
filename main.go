package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const Version = 3

func main() {
	rawConfig, err := base64.StdEncoding.DecodeString(os.Getenv("CONFIG"))
	if err != nil {
		log.Fatal(err)
	}

	rawManifest, err := base64.StdEncoding.DecodeString(os.Getenv("MANIFEST"))
	if err != nil {
		log.Fatal(err)
	}

	var manifest Manifest
	err = json.Unmarshal(rawManifest, &manifest)
	if err != nil {
		log.Fatal(err)
	}

	// Bind to port before sending the version-alive byte.
	ln, err := net.Listen("tcp", ":8888")
	if err != nil {
		log.Fatal(err)
	}

	transport := NewTransport(os.Stdin, os.Stdout)
	go transport.Run()

	registry := NewRegistry(rawConfig, rawManifest, manifest, transport)
	srv := &http.Server{
		Addr:    ":8888",
		Handler: registry,
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		if err := os.Stdin.Close(); err != nil {
			log.Fatalf("stdin close: %v", err)
		}
		if err := os.Stdout.Close(); err != nil {
			log.Fatalf("stdout close: %v", err)
		}

		transport.Close()

		if err := srv.Shutdown(context.Background()); err != nil {
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	// Report that network and transport are ready.
	_, err = os.Stderr.Write([]byte{Version})
	if err != nil {
		log.Fatal(err)
	}

	if err := srv.Serve(ln); err != http.ErrServerClosed {
		log.Fatalf("HTTP server: %v", err)
	}

	<-idleConnsClosed
}

// Registry is a small docker registry serving a single image by forwarding requests to the BuildKit cache.
type Registry struct {
	RawConfig    []byte
	ConfigDigest Digest

	RawManifest    []byte
	ManifestDigest Digest
	Manifest       Manifest

	Transport *Transport
}

func NewRegistry(rawConfig, rawManifest []byte, manifest Manifest, transport *Transport) *Registry {
	return &Registry{
		RawConfig:      rawConfig,
		ConfigDigest:   FromBytes(rawConfig),
		RawManifest:    rawManifest,
		ManifestDigest: FromBytes(rawManifest),
		Manifest:       manifest,
		Transport:      transport,
	}
}

func (r *Registry) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if isConfig(req, r.ConfigDigest) {
		r.handleConfig(resp, req)
		return
	}

	if isBlob(req) {
		r.handleBlobs(resp, req)
		return
	}

	if isManifest(req) {
		r.handleManifests(resp, req)
		return
	}

	resp.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	if req.URL.Path != "/v2/" && req.URL.Path != "/v2" {
		writeError(resp, http.StatusNotFound, "METHOD_UNKNOWN", "We don't understand your method + url")
		return
	}
}

func isManifest(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "manifests"
}

func (r *Registry) handleManifests(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Length", strconv.FormatInt(int64(len(r.RawManifest)), 10))
	resp.Header().Set("Docker-Content-Digest", r.ManifestDigest.String())
	resp.Header().Set("Content-Type", r.Manifest.MediaType)

	if req.Method == http.MethodGet {
		_, _ = io.Copy(resp, bytes.NewReader(r.RawManifest))
	}
}

func isConfig(req *http.Request, config Digest) bool {
	return strings.HasSuffix(req.URL.Path, config.String())
}

func (r *Registry) handleConfig(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Length", strconv.FormatInt(int64(len(r.RawConfig)), 10))
	resp.Header().Set("Docker-Content-Digest", r.ConfigDigest.String())

	if req.Method == http.MethodGet {
		_, _ = io.Copy(resp, bytes.NewReader(r.RawConfig))
	}
}

func isBlob(req *http.Request) bool {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	if elem[len(elem)-1] == "" {
		elem = elem[:len(elem)-1]
	}
	if len(elem) < 3 {
		return false
	}
	return elem[len(elem)-2] == "blobs" || (elem[len(elem)-3] == "blobs" &&
		elem[len(elem)-2] == "uploads")
}

func (r *Registry) handleBlobs(resp http.ResponseWriter, req *http.Request) {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	if elem[len(elem)-1] == "" {
		elem = elem[:len(elem)-1]
	}
	// Must have a path of form /v2/{name}/blobs/{upload,sha256:}
	if len(elem) < 4 {
		writeError(resp, http.StatusBadRequest, "NAME_INVALID", "blobs must be attached to a repo")
		return
	}
	blobSHA := elem[len(elem)-1]

	var found bool
	for _, layer := range r.Manifest.Layers {
		if layer.Digest.String() == blobSHA {
			resp.Header().Set("Content-Length", strconv.FormatInt(layer.Size, 10))
			resp.Header().Set("Docker-Content-Digest", layer.Digest.String())
			found = true
		}
	}

	if !found {
		log.Printf("Unknown blob: %s", blobSHA)
		writeError(resp, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
		return
	}
	if req.Method != http.MethodGet {
		return
	}

	ch := make(chan *Packet, 16)
	id, err := r.Transport.GetBlob(Digest(blobSHA), ch)
	if err != nil {
		writeError(resp, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "unable to get blob")
	}

	var bodyWritten bool
	for {
		select {
		case <-req.Context().Done():
			return
		case packet, ok := <-ch:
			if !ok {
				return
			}

			if packet.IsEOF() {
				return
			}

			if packet.IsError() {
				if !bodyWritten {
					writeError(resp, packet.ErrorStatus(), "NOT_FOUND", "unable to get blob")
				}
				return
			}

			_, err := resp.Write(packet.Data)
			if err != nil {
				r.Transport.CancelBlob(id)
				return
			}

			bodyWritten = true
		}
	}
}

func writeError(resp http.ResponseWriter, status int, code, message string) {
	resp.WriteHeader(status)
	type err struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	type wrap struct {
		Errors []err `json:"errors"`
	}
	_ = json.NewEncoder(resp).Encode(wrap{
		Errors: []err{
			{
				Code:    code,
				Message: message,
			},
		},
	})
}

type Transport struct {
	r *bufio.Reader
	w io.Writer

	mu        sync.Mutex
	responses map[ID]chan *Packet

	id   atomic.Uint32
	done atomic.Bool
}

func NewTransport(r io.Reader, w io.Writer) *Transport {
	return &Transport{
		r:         bufio.NewReader(r),
		w:         w,
		responses: make(map[ID]chan *Packet),
	}
}

func (t *Transport) GetBlob(d Digest, ch chan *Packet) (ID, error) {
	id := ID(t.id.Add(1))

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.done.Load() {
		close(ch)
		return 0, errors.New("transport closed")
	}

	t.responses[id] = ch
	_, err := NewBlobRequest(id, d).Write(t.w)
	if err != nil {
		return 0, err
	}

	return id, nil
}

func (t *Transport) CancelBlob(id ID) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ch, ok := t.responses[id]
	delete(t.responses, id)
	if ok {
		close(ch)
	}
}

func (t *Transport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.done.Store(true)
}

func (t *Transport) Run() {
	for {
		packet, err := Read(t.r)
		if err != nil {
			t.Close()
			return
		}

		t.mu.Lock()
		if t.done.Load() {
			t.mu.Unlock()
			return
		}

		ch, ok := t.responses[packet.ID]
		if !ok {
			t.mu.Unlock()
			continue
		}

		ch <- packet
		if packet.IsEOF() || packet.IsError() {
			close(ch)
			delete(t.responses, packet.ID)
		}
		t.mu.Unlock()
	}
}

type ID uint16

type Packet struct {
	ID   ID
	Len  int32 // sign bit is used to indicate success or error.
	Data []byte
}

func NewBlobRequest(id ID, digest Digest) *Packet {
	return &Packet{
		ID:   id,
		Len:  int32(len(digest)),
		Data: []byte(digest),
	}
}

func (p *Packet) IsError() bool {
	return p.Len < 0
}

func (p *Packet) ErrorStatus() int {
	return int(-1 * p.Len)
}

func (p *Packet) IsEOF() bool {
	return p.Len == 0
}

func (p *Packet) BlobRequest() (id ID, d Digest) {
	id = p.ID
	d = Digest(p.Data)
	return
}

func (p *Packet) Write(w io.Writer) (int, error) {
	bs := make([]byte, 6)
	binary.BigEndian.PutUint16(bs[0:2], uint16(p.ID))
	binary.BigEndian.PutUint32(bs[2:6], uint32(p.Len))

	_, err := w.Write(bs)
	if err != nil {
		return 0, err
	}

	if p.Len > 0 {
		return w.Write(p.Data)
	}

	return 0, nil
}

// If no more to read then will return io.EOF as error.
func Read(r *bufio.Reader) (*Packet, error) {
	bs := make([]byte, 6)
	_, err := io.ReadFull(r, bs)
	if err != nil {
		return nil, err
	}

	id := binary.BigEndian.Uint16(bs[0:2])
	len := int32(binary.BigEndian.Uint32(bs[2:6]))
	packet := &Packet{
		ID:  ID(id),
		Len: len,
	}

	if len > 0 {
		bs = make([]byte, len)
		_, err = io.ReadFull(r, bs)
		if err != nil {
			return nil, err
		}
		packet.Data = bs
	}

	return packet, nil
}

type Digest string

func FromBytes(bs []byte) Digest {
	hash := crypto.SHA256.New()
	_, _ = hash.Write(bs)
	return Digest(fmt.Sprintf("sha256:%x", hash.Sum(nil)))
}

func (d Digest) String() string {
	return string(d)
}

// Manifest provides `application/vnd.oci.image.manifest.v1+json` mediatype structure when marshalled to JSON.
type Manifest struct {
	SchemaVersion int `json:"schemaVersion"`

	// MediaType specificies the type of this document data structure e.g. `application/vnd.oci.image.manifest.v1+json`
	MediaType string `json:"mediaType,omitempty"`

	// Config references a configuration object for a container, by digest.
	// The referenced configuration object is a JSON blob that the runtime uses to set up the container.
	Config Descriptor `json:"config"`

	// Layers is an indexed list of layers referenced by the manifest.
	Layers []Descriptor `json:"layers"`

	// Annotations contains arbitrary metadata for the image manifest.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Descriptor describes the disposition of targeted content.
// This structure provides `application/vnd.oci.descriptor.v1+json` mediatype
// when marshalled to JSON.
type Descriptor struct {
	// MediaType is the media type of the object this schema refers to.
	MediaType string `json:"mediaType,omitempty"`

	// Digest is the digest of the targeted content.
	Digest Digest `json:"digest"`

	// Size specifies the size in bytes of the blob.
	Size int64 `json:"size"`

	// URLs specifies a list of URLs from which this object MAY be downloaded
	URLs []string `json:"urls,omitempty"`

	// Annotations contains arbitrary metadata relating to the targeted content.
	Annotations map[string]string `json:"annotations,omitempty"`

	// Platform describes the platform which the image in the manifest runs on.
	//
	// This should only be used when referring to a manifest.
	Platform *Platform `json:"platform,omitempty"`
}

type Platform struct {
	// Architecture field specifies the CPU architecture, for example
	// `amd64` or `ppc64`.
	Architecture string `json:"architecture"`

	// OS specifies the operating system, for example `linux` or `windows`.
	OS string `json:"os"`

	// OSVersion is an optional field specifying the operating system
	// version, for example on Windows `10.0.14393.1066`.
	OSVersion string `json:"os.version,omitempty"`

	// OSFeatures is an optional field specifying an array of strings,
	// each listing a required OS feature (for example on Windows `win32k`).
	OSFeatures []string `json:"os.features,omitempty"`

	// Variant is an optional field specifying a variant of the CPU, for
	// example `v7` to specify ARMv7 when architecture is `arm`.
	Variant string `json:"variant,omitempty"`
}
