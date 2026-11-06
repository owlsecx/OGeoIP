// ============================================================
//
//	OGeoIP — IP Geolocation · rDNS · ASN (offline MaxMind engine)
//	Author  : khaled.s.haddad
//	Website : owlsec.org
//	Language: Go (stdlib only) — OWL suite
//
//	Geolocates IP addresses fully offline by reading a MaxMind
//	GeoLite2/GeoIP2 .mmdb database directly: a from-scratch MMDB
//	reader (binary search tree + data-section decoder, record
//	sizes 24/28/32, IPv4-in-IPv6 handling) with no third-party
//	libraries and no HTTP geolocation API. Adds scope/reserved
//	classification (RFC 1918/6598/5737/…), forward & reverse DNS,
//	and ASN / BGP-prefix lookups via the Team Cymru DNS service.
//	Country/city data never leaves the machine.
//
// ============================================================
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	GY  = "\033[90m"       // gray    — muted
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }
func kv(k, v string)   { fmt.Println("  " + col("│  ", CY) + col(pad(k+":", 16), DIM) + col(v, W)) }

const BANNER = `
 ██████╗  ██████╗ ███████╗ ██████╗ ██╗██████╗
██╔═══██╗██╔════╝ ██╔════╝██╔═══██╗██║██╔══██╗
██║   ██║██║  ███╗█████╗  ██║   ██║██║██████╔╝
██║   ██║██║   ██║██╔══╝  ██║   ██║██║██╔═══╝
╚██████╔╝╚██████╔╝███████╗╚██████╔╝██║██║
 ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝╚═╝
`

const APPNAME = "OGeoIP"
const SUITE = "Owl Recon Suite"
const TAGLINE = "IP Geolocation · Offline MaxMind Engine"
const SUBLINE = "MMDB reader · Scope/Reserved · rDNS/Forward · ASN & BGP prefix · Bulk · JSON"
const VERSION = "1.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"

// banner prints the cyan ANSI-Shadow wordmark and the suite identity block.
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

// sectionHeader prints a ⬡ heading between two cyan rules.
func sectionHeader(s string) {
	rule()
	fmt.Println("  " + col("⬡  "+s, B+CY))
	rule()
	fmt.Println()
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func vlen(s string) int { return utf8.RuneCountInString(stripANSI(s)) }
func pad(s string, n int) string {
	if l := vlen(s); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}
func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n < 1 {
		return ""
	}
	return string(r[:n-1]) + "…"
}

// table prints aligned columns with a cyan frame.
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = vlen(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && vlen(c) > w[i] {
				w[i] = vlen(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", CY))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), CY))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(pad(col(v, W), w[i]))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", CY))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ============================================================
//  MaxMind DB (MMDB) reader — stdlib only, from scratch.
//  Format: binary search tree (record_size 24/28/32), a 16-byte
//  zero separator, the data section, then a metadata section
//  introduced by the marker \xab\xcd\xef "MaxMind.com".
// ============================================================

var metaMarker = []byte{0xab, 0xcd, 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'}

const dataSeparatorSize = 16

type mmReader struct {
	buf            []byte
	nodeCount      uint
	recordSize     uint
	nodeByteSize   uint
	searchTreeSize uint
	dataStart      uint // searchTreeSize + 16; pointers are relative to this
	ipVersion      int
	databaseType   string
	buildEpoch     uint64
	languages      []string
	description    string
}

func openMMDB(path string) (*mmReader, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(buf) < len(metaMarker)+2 {
		return nil, errors.New("file too small to be an MMDB")
	}
	// Find the LAST occurrence of the metadata marker.
	idx := lastIndex(buf, metaMarker)
	if idx < 0 {
		return nil, errors.New("not a MaxMind DB (metadata marker not found)")
	}
	metaStart := uint(idx + len(metaMarker))
	r := &mmReader{buf: buf}
	d := &decoder{buf: buf, ptrBase: metaStart}
	metaV, _, err := d.decode(metaStart)
	if err != nil {
		return nil, fmt.Errorf("metadata decode: %w", err)
	}
	meta, ok := metaV.(map[string]interface{})
	if !ok {
		return nil, errors.New("metadata is not a map")
	}
	r.nodeCount = uint(asUint(meta["node_count"]))
	r.recordSize = uint(asUint(meta["record_size"]))
	r.ipVersion = int(asUint(meta["ip_version"]))
	r.databaseType, _ = meta["database_type"].(string)
	r.buildEpoch = asUint(meta["build_epoch"])
	if desc, ok := meta["description"].(map[string]interface{}); ok {
		if en, ok := desc["en"].(string); ok {
			r.description = en
		}
	}
	if langs, ok := meta["languages"].([]interface{}); ok {
		for _, l := range langs {
			if s, ok := l.(string); ok {
				r.languages = append(r.languages, s)
			}
		}
	}
	if r.recordSize != 24 && r.recordSize != 28 && r.recordSize != 32 {
		return nil, fmt.Errorf("unsupported record size %d", r.recordSize)
	}
	if r.nodeCount == 0 {
		return nil, errors.New("metadata missing node_count")
	}
	r.nodeByteSize = r.recordSize * 2 / 8
	r.searchTreeSize = r.nodeCount * r.nodeByteSize
	r.dataStart = r.searchTreeSize + dataSeparatorSize
	if r.searchTreeSize > uint(idx) {
		return nil, errors.New("corrupt MMDB: search tree overruns metadata")
	}
	return r, nil
}

func lastIndex(hay, needle []byte) int {
	for i := len(hay) - len(needle); i >= 0; i-- {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// readNode returns record `index` (0=left/bit0, 1=right/bit1) of a node.
func (r *mmReader) readNode(node uint, index int) uint {
	base := node * r.nodeByteSize
	b := r.buf
	switch r.recordSize {
	case 24:
		off := base + uint(index)*3
		return uint(b[off])<<16 | uint(b[off+1])<<8 | uint(b[off+2])
	case 28:
		if index == 0 {
			return (uint(b[base+3]>>4) << 24) | uint(b[base])<<16 | uint(b[base+1])<<8 | uint(b[base+2])
		}
		return (uint(b[base+3]&0x0f) << 24) | uint(b[base+4])<<16 | uint(b[base+5])<<8 | uint(b[base+6])
	default: // 32
		off := base + uint(index)*4
		return uint(b[off])<<24 | uint(b[off+1])<<16 | uint(b[off+2])<<8 | uint(b[off+3])
	}
}

// Lookup resolves an IP to its decoded record (or nil if not present).
func (r *mmReader) Lookup(ip net.IP) (interface{}, int, error) {
	var addr []byte
	if v4 := ip.To4(); v4 != nil {
		// Walk 96 zero bits then the 32 address bits (IPv4-in-IPv6 tree).
		addr = make([]byte, 16)
		copy(addr[12:], v4)
	} else {
		addr = ip.To16()
		if addr == nil {
			return nil, 0, errors.New("invalid IP")
		}
	}
	node := uint(0)
	bitLen := len(addr) * 8
	prefix := 0
	for i := 0; i < bitLen; i++ {
		if node >= r.nodeCount {
			break
		}
		bit := (addr[i>>3] >> (7 - uint(i&7))) & 1
		node = r.readNode(node, int(bit))
		prefix++
	}
	// For IPv4 report the prefix in IPv4 terms (/24, not /120 of the ::/96 tree).
	if ip.To4() != nil && prefix >= 96 {
		prefix -= 96
	}
	if node == r.nodeCount {
		return nil, prefix, nil // no data
	}
	if node < r.nodeCount {
		return nil, prefix, errors.New("search ended inside the tree")
	}
	// node > nodeCount → data pointer.
	offset := r.searchTreeSize + (node - r.nodeCount)
	if offset < r.dataStart || offset >= uint(len(r.buf)) {
		return nil, prefix, errors.New("data pointer out of range")
	}
	d := &decoder{buf: r.buf, ptrBase: r.dataStart}
	v, _, err := d.decode(offset)
	return v, prefix, err
}

// ---- data-section decoder ----

type decoder struct {
	buf     []byte
	ptrBase uint // offset that data pointers are relative to
	depth   int
}

func (d *decoder) decode(off uint) (interface{}, uint, error) {
	if off >= uint(len(d.buf)) {
		return nil, off, errors.New("offset past end of buffer")
	}
	if d.depth > 512 {
		return nil, off, errors.New("decode recursion too deep")
	}
	ctrl := d.buf[off]
	off++
	typ := ctrl >> 5
	if typ == 0 { // extended type
		if off >= uint(len(d.buf)) {
			return nil, off, errors.New("truncated extended type")
		}
		typ = d.buf[off] + 7
		off++
	}
	if typ == 1 { // pointer
		return d.decodePointer(ctrl, off)
	}
	size := uint(ctrl & 0x1f)
	switch {
	case size == 29:
		size = 29 + uint(d.buf[off])
		off++
	case size == 30:
		size = 285 + uint(d.buf[off])<<8 | uint(d.buf[off+1])
		off += 2
	case size == 31:
		size = 65821 + uint(d.buf[off])<<16 | uint(d.buf[off+1])<<8 | uint(d.buf[off+2])
		off += 3
	}
	switch typ {
	case 2: // UTF-8 string
		end := off + size
		if end > uint(len(d.buf)) {
			return nil, off, errors.New("string overruns buffer")
		}
		return string(d.buf[off:end]), end, nil
	case 3: // double
		if off+8 > uint(len(d.buf)) {
			return nil, off, errors.New("double overruns buffer")
		}
		bits := binary.BigEndian.Uint64(d.buf[off : off+8])
		return math.Float64frombits(bits), off + 8, nil
	case 4: // bytes
		end := off + size
		if end > uint(len(d.buf)) {
			return nil, off, errors.New("bytes overrun buffer")
		}
		b := make([]byte, size)
		copy(b, d.buf[off:end])
		return b, end, nil
	case 5, 6, 9, 10: // uint16/32/64/128
		return d.readUint(off, size)
	case 7: // map
		return d.decodeMap(off, size)
	case 8: // int32
		return d.readInt(off, size)
	case 11: // array
		return d.decodeArray(off, size)
	case 14: // boolean
		return size != 0, off, nil
	case 15: // float (float32)
		if off+4 > uint(len(d.buf)) {
			return nil, off, errors.New("float overruns buffer")
		}
		bits := binary.BigEndian.Uint32(d.buf[off : off+4])
		return float64(math.Float32frombits(bits)), off + 4, nil
	default:
		return nil, off, fmt.Errorf("unknown MMDB data type %d", typ)
	}
}

func (d *decoder) decodePointer(ctrl byte, off uint) (interface{}, uint, error) {
	pSize := (ctrl >> 3) & 0x3
	var ptr uint
	switch pSize {
	case 0:
		ptr = (uint(ctrl&0x7) << 8) | uint(d.buf[off])
		off++
	case 1:
		ptr = (uint(ctrl&0x7)<<16 | uint(d.buf[off])<<8 | uint(d.buf[off+1])) + 2048
		off += 2
	case 2:
		ptr = (uint(ctrl&0x7)<<24 | uint(d.buf[off])<<16 | uint(d.buf[off+1])<<8 | uint(d.buf[off+2])) + 526336
		off += 3
	default: // 3
		ptr = uint(d.buf[off])<<24 | uint(d.buf[off+1])<<16 | uint(d.buf[off+2])<<8 | uint(d.buf[off+3])
		off += 4
	}
	target := d.ptrBase + ptr
	sub := &decoder{buf: d.buf, ptrBase: d.ptrBase, depth: d.depth + 1}
	v, _, err := sub.decode(target)
	return v, off, err // main stream advances past the pointer only
}

func (d *decoder) readUint(off, size uint) (interface{}, uint, error) {
	end := off + size
	if end > uint(len(d.buf)) {
		return nil, off, errors.New("uint overruns buffer")
	}
	var v uint64
	for _, b := range d.buf[off:end] {
		v = v<<8 | uint64(b)
	}
	return v, end, nil
}

func (d *decoder) readInt(off, size uint) (interface{}, uint, error) {
	end := off + size
	if end > uint(len(d.buf)) {
		return nil, off, errors.New("int overruns buffer")
	}
	var v int64
	for _, b := range d.buf[off:end] {
		v = v<<8 | int64(b)
	}
	return v, end, nil
}

func (d *decoder) decodeMap(off, size uint) (interface{}, uint, error) {
	m := make(map[string]interface{}, size)
	for i := uint(0); i < size; i++ {
		kv, noff, err := d.decode(off)
		if err != nil {
			return nil, noff, err
		}
		key, ok := kv.(string)
		if !ok {
			return nil, noff, errors.New("map key is not a string")
		}
		val, noff2, err := d.decode(noff)
		if err != nil {
			return nil, noff2, err
		}
		m[key] = val
		off = noff2
	}
	return m, off, nil
}

func (d *decoder) decodeArray(off, size uint) (interface{}, uint, error) {
	arr := make([]interface{}, 0, size)
	for i := uint(0); i < size; i++ {
		v, noff, err := d.decode(off)
		if err != nil {
			return nil, noff, err
		}
		arr = append(arr, v)
		off = noff
	}
	return arr, off, nil
}

func asUint(v interface{}) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		if n < 0 {
			return 0
		}
		return uint64(n)
	}
	return 0
}

// ============================================================
//  Geo record extraction
// ============================================================

type GeoResult struct {
	IP                string   `json:"ip"`
	Found             bool     `json:"found"`
	PrefixLen         int      `json:"network_prefix_bits"`
	ContinentCode     string   `json:"continent_code,omitempty"`
	Continent         string   `json:"continent,omitempty"`
	CountryISO        string   `json:"country_iso,omitempty"`
	Country           string   `json:"country,omitempty"`
	RegisteredISO     string   `json:"registered_country_iso,omitempty"`
	RegisteredCountry string   `json:"registered_country,omitempty"`
	InEU              bool     `json:"country_in_eu,omitempty"`
	Subdivisions      []string `json:"subdivisions,omitempty"`
	City              string   `json:"city,omitempty"`
	Postal            string   `json:"postal,omitempty"`
	Latitude          float64  `json:"latitude,omitempty"`
	Longitude         float64  `json:"longitude,omitempty"`
	AccuracyRadiusKm  uint64   `json:"accuracy_radius_km,omitempty"`
	TimeZone          string   `json:"time_zone,omitempty"`
	MetroCode         uint64   `json:"metro_code,omitempty"`
	IsAnonProxy       bool     `json:"is_anonymous_proxy,omitempty"`
	IsSatellite       bool     `json:"is_satellite_provider,omitempty"`
	HasLatLon         bool     `json:"has_lat_lon"`
}

func mapGet(m interface{}, keys ...string) interface{} {
	cur := m
	for _, k := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func nameOf(node interface{}, langs []string) string {
	names, ok := mapGet(node, "names").(map[string]interface{})
	if !ok {
		return ""
	}
	for _, l := range langs {
		if s, ok := names[l].(string); ok && s != "" {
			return s
		}
	}
	if s, ok := names["en"].(string); ok {
		return s
	}
	for _, v := range names {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func str(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func fl(v interface{}) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
func boolOf(v interface{}) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func extractGeo(rec interface{}, prefix int, langPref []string) GeoResult {
	g := GeoResult{PrefixLen: prefix}
	if rec == nil {
		return g
	}
	g.Found = true
	langs := langPref
	if cont := mapGet(rec, "continent"); cont != nil {
		g.ContinentCode = str(mapGet(cont, "code"))
		g.Continent = nameOf(cont, langs)
	}
	if c := mapGet(rec, "country"); c != nil {
		g.CountryISO = str(mapGet(c, "iso_code"))
		g.Country = nameOf(c, langs)
		g.InEU = boolOf(mapGet(c, "is_in_european_union"))
	}
	if c := mapGet(rec, "registered_country"); c != nil {
		g.RegisteredISO = str(mapGet(c, "iso_code"))
		g.RegisteredCountry = nameOf(c, langs)
	}
	if subs, ok := mapGet(rec, "subdivisions").([]interface{}); ok {
		for _, s := range subs {
			if n := nameOf(s, langs); n != "" {
				g.Subdivisions = append(g.Subdivisions, n)
			}
		}
	}
	if city := mapGet(rec, "city"); city != nil {
		g.City = nameOf(city, langs)
	}
	if p := mapGet(rec, "postal", "code"); p != nil {
		g.Postal = str(p)
	}
	if loc := mapGet(rec, "location"); loc != nil {
		g.Latitude = fl(mapGet(loc, "latitude"))
		g.Longitude = fl(mapGet(loc, "longitude"))
		g.AccuracyRadiusKm = asUint(mapGet(loc, "accuracy_radius"))
		g.TimeZone = str(mapGet(loc, "time_zone"))
		g.MetroCode = asUint(mapGet(loc, "metro_code"))
		if mapGet(loc, "latitude") != nil && mapGet(loc, "longitude") != nil {
			g.HasLatLon = true
		}
	}
	if tr := mapGet(rec, "traits"); tr != nil {
		g.IsAnonProxy = boolOf(mapGet(tr, "is_anonymous_proxy"))
		g.IsSatellite = boolOf(mapGet(tr, "is_satellite_provider"))
	}
	return g
}

// ============================================================
//  Scope / reserved-range classification
// ============================================================

type scopeInfo struct {
	Scope    string // global | reserved | private | ...
	Detail   string
	Routable bool
}

var reservedV4 = []struct {
	cidr   string
	detail string
}{
	{"0.0.0.0/8", "this network (RFC 1122)"},
	{"10.0.0.0/8", "private (RFC 1918)"},
	{"100.64.0.0/10", "CGNAT shared (RFC 6598)"},
	{"127.0.0.0/8", "loopback (RFC 1122)"},
	{"169.254.0.0/16", "link-local (RFC 3927)"},
	{"172.16.0.0/12", "private (RFC 1918)"},
	{"192.0.0.0/24", "IETF protocol assignments (RFC 6890)"},
	{"192.0.2.0/24", "documentation TEST-NET-1 (RFC 5737)"},
	{"192.88.99.0/24", "6to4 anycast relay (RFC 7526)"},
	{"192.168.0.0/16", "private (RFC 1918)"},
	{"198.18.0.0/15", "benchmarking (RFC 2544)"},
	{"198.51.100.0/24", "documentation TEST-NET-2 (RFC 5737)"},
	{"203.0.113.0/24", "documentation TEST-NET-3 (RFC 5737)"},
	{"224.0.0.0/4", "multicast (RFC 5771)"},
	{"240.0.0.0/4", "reserved for future use (RFC 1112)"},
	{"255.255.255.255/32", "limited broadcast (RFC 919)"},
}

var reservedV6 = []struct {
	cidr   string
	detail string
}{
	{"::1/128", "loopback (RFC 4291)"},
	{"::/128", "unspecified (RFC 4291)"},
	{"::ffff:0:0/96", "IPv4-mapped (RFC 4291)"},
	{"64:ff9b::/96", "NAT64 well-known (RFC 6052)"},
	{"100::/64", "discard-only (RFC 6666)"},
	{"2001:db8::/32", "documentation (RFC 3849)"},
	{"2002::/16", "6to4 (RFC 3056)"},
	{"fc00::/7", "unique local (RFC 4193)"},
	{"fe80::/10", "link-local (RFC 4291)"},
	{"ff00::/8", "multicast (RFC 4291)"},
}

func classifyScope(ip net.IP) scopeInfo {
	list := reservedV4
	if ip.To4() == nil {
		list = reservedV6
	}
	for _, r := range list {
		_, n, err := net.ParseCIDR(r.cidr)
		if err == nil && n.Contains(ip) {
			routable := false
			scope := "reserved"
			if strings.Contains(r.detail, "RFC 1918") || strings.Contains(r.detail, "RFC 6598") || strings.Contains(r.detail, "unique local") {
				scope = "private"
			} else if strings.Contains(r.detail, "loopback") {
				scope = "loopback"
			} else if strings.Contains(r.detail, "link-local") {
				scope = "link-local"
			} else if strings.Contains(r.detail, "multicast") {
				scope = "multicast"
			}
			return scopeInfo{Scope: scope, Detail: r.detail, Routable: routable}
		}
	}
	return scopeInfo{Scope: "global", Detail: "global unicast (publicly routable)", Routable: true}
}

// ============================================================
//  ASN / BGP prefix via Team Cymru DNS (origin.asn.cymru.com)
// ============================================================

type asnInfo struct {
	ASN      string
	Prefix   string
	Country  string
	Registry string
	AllocAt  string
	Name     string
}

func reverseV4(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

func reverseV6(ip net.IP) string {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return ""
	}
	var b strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		b.WriteString(fmt.Sprintf("%x.%x.", v6[i]&0x0f, v6[i]>>4))
	}
	return strings.TrimSuffix(b.String(), ".")
}

var asnResolveTimeout = 5 * time.Second

func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func lookupASN(ip net.IP) (*asnInfo, error) {
	var query string
	if ip.To4() != nil {
		rev := reverseV4(ip)
		if rev == "" {
			return nil, errors.New("bad IPv4")
		}
		query = rev + ".origin.asn.cymru.com"
	} else {
		rev := reverseV6(ip)
		if rev == "" {
			return nil, errors.New("bad IPv6")
		}
		query = rev + ".origin6.asn.cymru.com"
	}
	res := net.Resolver{}
	ctx, cancel := contextTimeout(asnResolveTimeout)
	defer cancel()
	txts, err := res.LookupTXT(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(txts) == 0 {
		return nil, errors.New("no ASN record")
	}
	// "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
	// If several ASNs map a prefix, pick the most specific prefix.
	best := txts[0]
	bestLen := -1
	for _, t := range txts {
		parts := strings.Split(t, "|")
		if len(parts) >= 2 {
			if _, cidr, err := net.ParseCIDR(strings.TrimSpace(parts[1])); err == nil {
				ones, _ := cidr.Mask.Size()
				if ones > bestLen {
					bestLen = ones
					best = t
				}
			}
		}
	}
	a := parseCymru(best)
	// AS name: AS<n>.asn.cymru.com
	if a.ASN != "" {
		firstAS := strings.Fields(a.ASN)[0]
		ctx2, cancel2 := contextTimeout(asnResolveTimeout)
		defer cancel2()
		if n, err := res.LookupTXT(ctx2, "AS"+firstAS+".asn.cymru.com"); err == nil && len(n) > 0 {
			np := strings.Split(n[0], "|")
			if len(np) >= 5 {
				a.Name = strings.TrimSpace(np[4])
			}
		}
	}
	return a, nil
}

func parseCymru(t string) *asnInfo {
	p := strings.Split(t, "|")
	for i := range p {
		p[i] = strings.TrimSpace(p[i])
	}
	a := &asnInfo{}
	if len(p) > 0 {
		a.ASN = p[0]
	}
	if len(p) > 1 {
		a.Prefix = p[1]
	}
	if len(p) > 2 {
		a.Country = p[2]
	}
	if len(p) > 3 {
		a.Registry = p[3]
	}
	if len(p) > 4 {
		a.AllocAt = p[4]
	}
	return a
}

// ============================================================
//  DB discovery
// ============================================================

func candidatePaths() []string {
	var c []string
	if p := os.Getenv("OGEOIP_DB"); p != "" {
		c = append(c, p)
	}
	if p := os.Getenv("GEOIP_DB"); p != "" {
		c = append(c, p)
	}
	wd, _ := os.Getwd()
	c = append(c, filepath.Join(wd, "GeoLite2-City.mmdb"))
	if exe, err := os.Executable(); err == nil {
		c = append(c, filepath.Join(filepath.Dir(exe), "GeoLite2-City.mmdb"))
	}
	home := ""
	if u, err := user.Current(); err == nil {
		home = u.HomeDir
	}
	if home != "" {
		c = append(c,
			filepath.Join(home, ".local/share/GeoIP/GeoLite2-City.mmdb"),
			filepath.Join(home, "Desktop/hik/geoip/GeoLite2-City.mmdb"),
		)
	}
	c = append(c,
		"/usr/share/GeoIP/GeoLite2-City.mmdb",
		"/var/lib/GeoIP/GeoLite2-City.mmdb",
		"/usr/local/share/GeoIP/GeoLite2-City.mmdb",
		"/opt/GeoIP/GeoLite2-City.mmdb",
	)
	return c
}

func findDB(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("--db %q: %w", explicit, err)
		}
		return explicit, nil
	}
	for _, p := range candidatePaths() {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("no GeoLite2-City.mmdb found (set --db or $OGEOIP_DB)")
}

var langPreference = []string{"en"}

// ============================================================
//  Rendering
// ============================================================

func printGeo(g GeoResult, a *asnInfo) {
	rows := [][]string{}
	add := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			rows = append(rows, []string{k, v})
		}
	}
	cc := g.CountryISO
	if cc == "" {
		cc = g.RegisteredISO
	}
	countryLine := g.Country
	if countryLine == "" && g.RegisteredCountry != "" {
		countryLine = g.RegisteredCountry + " (registered)"
	}
	if cc != "" {
		countryLine = countryLine + "  [" + cc + "]"
		if g.InEU {
			countryLine += " EU"
		}
	}
	if g.Continent != "" || g.ContinentCode != "" {
		cont := g.Continent
		if g.ContinentCode != "" {
			cont = strings.TrimSpace(cont + " (" + g.ContinentCode + ")")
		}
		add("Continent", cont)
	}
	add("Country", countryLine)
	if len(g.Subdivisions) > 0 {
		add("Region", strings.Join(g.Subdivisions, " / "))
	}
	add("City", g.City)
	add("Postal", g.Postal)
	if g.HasLatLon {
		add("Coordinates", fmt.Sprintf("%.4f, %.4f", g.Latitude, g.Longitude))
		if g.AccuracyRadiusKm > 0 {
			add("Accuracy", fmt.Sprintf("~%d km radius", g.AccuracyRadiusKm))
		}
		add("Map", fmt.Sprintf("https://www.openstreetmap.org/?mlat=%.4f&mlon=%.4f#map=10/%.4f/%.4f",
			g.Latitude, g.Longitude, g.Latitude, g.Longitude))
	}
	add("Time zone", g.TimeZone)
	if g.IsAnonProxy {
		add("Flag", "anonymous proxy")
	}
	if g.IsSatellite {
		add("Flag", "satellite provider")
	}
	if a != nil {
		if a.ASN != "" {
			name := a.Name
			if name != "" {
				add("ASN", "AS"+a.ASN+"  "+name)
			} else {
				add("ASN", "AS"+a.ASN)
			}
		}
		add("BGP prefix", a.Prefix)
		add("Registry", strings.TrimSpace(a.Registry+" "+a.AllocAt))
	}
	if len(rows) == 0 {
		warnMsg("No geolocation data for this address in the database.")
		return
	}
	table([]string{"Field", "Value"}, rows)
}

// ============================================================
//  Actions (shared by TUI + CLI)
// ============================================================

func resolveToIP(input string) (net.IP, string, error) {
	input = strings.TrimSpace(input)
	if ip := net.ParseIP(input); ip != nil {
		return ip, "", nil
	}
	ips, err := net.LookupIP(input)
	if err != nil || len(ips) == 0 {
		return nil, "", fmt.Errorf("cannot resolve %q", input)
	}
	// prefer IPv4
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, input, nil
		}
	}
	return ips[0], input, nil
}

func geolocate(db *mmReader, ip net.IP) (GeoResult, error) {
	rec, prefix, err := db.Lookup(ip)
	if err != nil {
		return GeoResult{}, err
	}
	g := extractGeo(rec, prefix, langPreference)
	g.IP = ip.String()
	return g, nil
}

// ============================================================
//  TUI
// ============================================================

var dbPath string

func mustDB() *mmReader {
	path, err := findDB(dbPath)
	if err != nil {
		errMsg(err.Error())
		info("Place GeoLite2-City.mmdb next to the binary, or run with --db /path.")
		return nil
	}
	db, err := openMMDB(path)
	if err != nil {
		errMsg("open database: " + err.Error())
		return nil
	}
	info(fmt.Sprintf("DB: %s  (%s, built %s)", path, db.databaseType, epoch(db.buildEpoch)))
	return db
}

func epoch(e uint64) string {
	if e == 0 {
		return "unknown"
	}
	return time.Unix(int64(e), 0).UTC().Format("2006-01-02")
}

func uiGeolocate() {
	sectionHeader("Geolocate an IP (offline)")
	db := mustDB()
	if db == nil {
		return
	}
	in := prompt("IP or hostname")
	ip, resolved, err := resolveToIP(in)
	if err != nil {
		errMsg(err.Error())
		return
	}
	fmt.Println()
	if resolved != "" {
		info("Resolved " + resolved + " → " + ip.String())
	}
	sc := classifyScope(ip)
	if !sc.Routable {
		warnMsg("Scope: " + sc.Scope + " — " + sc.Detail + " (no public geolocation)")
		return
	}
	g, err := geolocate(db, ip)
	if err != nil {
		errMsg(err.Error())
		return
	}
	var a *asnInfo
	if ai, err := lookupASN(ip); err == nil {
		a = ai
	} else {
		info("ASN lookup unavailable: " + err.Error())
	}
	okMsg("Geolocation for " + ip.String())
	fmt.Println()
	printGeo(g, a)
}

func uiClassify() {
	sectionHeader("Classify IP (scope / reserved)")
	in := prompt("IP address")
	ip := net.ParseIP(in)
	if ip == nil {
		errMsg("not a valid IP literal")
		return
	}
	fmt.Println()
	fam := "IPv6"
	if ip.To4() != nil {
		fam = "IPv4"
	}
	sc := classifyScope(ip)
	kv("Address", ip.String())
	kv("Family", fam)
	kv("Scope", sc.Scope)
	kv("Detail", sc.Detail)
	if sc.Routable {
		okMsg("Publicly routable — eligible for geolocation.")
	} else {
		warnMsg("Not publicly routable — geolocation does not apply.")
	}
}

func uiReverse() {
	sectionHeader("Reverse DNS (PTR)")
	in := prompt("IP address")
	ip := net.ParseIP(in)
	if ip == nil {
		errMsg("not a valid IP literal")
		return
	}
	names, err := net.LookupAddr(ip.String())
	fmt.Println()
	if err != nil {
		errMsg("rDNS failed: " + err.Error())
		return
	}
	if len(names) == 0 {
		warnMsg("No PTR records.")
		return
	}
	okMsg(fmt.Sprintf("%d PTR record(s):", len(names)))
	for _, n := range names {
		fmt.Println("     " + col(strings.TrimSuffix(n, "."), W))
	}
}

func uiForward() {
	sectionHeader("Forward DNS (A / AAAA)")
	host := prompt("hostname")
	ips, err := net.LookupIP(host)
	fmt.Println()
	if err != nil {
		errMsg(err.Error())
		return
	}
	okMsg(fmt.Sprintf("%d address(es) for %s", len(ips), host))
	fmt.Println()
	rows := [][]string{}
	for _, ip := range ips {
		fam := "IPv6"
		if ip.To4() != nil {
			fam = "IPv4"
		}
		rows = append(rows, []string{fam, ip.String(), classifyScope(ip).Scope})
	}
	table([]string{"Family", "Address", "Scope"}, rows)
}

func uiASN() {
	sectionHeader("ASN / BGP prefix (Team Cymru DNS)")
	in := prompt("IP address")
	ip, _, err := resolveToIP(in)
	if err != nil {
		errMsg(err.Error())
		return
	}
	fmt.Println()
	if !classifyScope(ip).Routable {
		warnMsg("Non-routable address — no ASN.")
		return
	}
	info("Querying asn.cymru.com for " + ip.String() + " …")
	a, err := lookupASN(ip)
	if err != nil {
		errMsg("ASN lookup failed: " + err.Error())
		return
	}
	fmt.Println()
	rows := [][]string{}
	if a.Name != "" {
		rows = append(rows, []string{"AS" + a.ASN, a.Name})
	} else {
		rows = append(rows, []string{"AS" + a.ASN, "(name unavailable)"})
	}
	table([]string{"ASN", "Holder"}, rows)
	kv("BGP prefix", a.Prefix)
	kv("Country", a.Country)
	kv("Registry", strings.TrimSpace(a.Registry+" "+a.AllocAt))
}

func uiBulk() {
	sectionHeader("Bulk geolocate (offline, no rate limit)")
	db := mustDB()
	if db == nil {
		return
	}
	info("Enter IPs separated by comma / space / newline. Blank line ends input.")
	var all []string
	for {
		line := prompt("IPs")
		if strings.TrimSpace(line) == "" {
			break
		}
		all = append(all, line)
	}
	targets := splitList(strings.Join(all, " "))
	if len(targets) == 0 {
		warnMsg("Nothing to do.")
		return
	}
	fmt.Println()
	rows := bulkRows(db, targets)
	table([]string{"IP", "CC", "City", "Region", "Scope"}, rows)
}

func splitList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == ';'
	})
	return f
}

func bulkRows(db *mmReader, targets []string) [][]string {
	rows := [][]string{}
	for _, t := range targets {
		ip := net.ParseIP(t)
		if ip == nil {
			rows = append(rows, []string{t, col("INVALID", R), "", "", ""})
			continue
		}
		sc := classifyScope(ip)
		if !sc.Routable {
			rows = append(rows, []string{t, "—", "", "", sc.Scope})
			continue
		}
		g, err := geolocate(db, ip)
		if err != nil {
			rows = append(rows, []string{t, col("ERR", R), err.Error(), "", ""})
			continue
		}
		cc := g.CountryISO
		if cc == "" {
			cc = g.RegisteredISO
		}
		region := ""
		if len(g.Subdivisions) > 0 {
			region = g.Subdivisions[0]
		}
		if !g.Found {
			rows = append(rows, []string{t, "?", "(not in DB)", "", "global"})
			continue
		}
		rows = append(rows, []string{t, cc, trunc(g.City, 20), trunc(region, 18), "global"})
	}
	return rows
}

func uiDBInfo() {
	sectionHeader("Database information")
	path, err := findDB(dbPath)
	if err != nil {
		errMsg(err.Error())
		return
	}
	db, err := openMMDB(path)
	if err != nil {
		errMsg(err.Error())
		return
	}
	kv("Path", path)
	kv("Type", db.databaseType)
	kv("Description", db.description)
	kv("Built", epoch(db.buildEpoch))
	kv("IP version", "IPv"+strconv.Itoa(db.ipVersion))
	kv("Record size", strconv.Itoa(int(db.recordSize))+"-bit")
	kv("Nodes", strconv.FormatUint(uint64(db.nodeCount), 10))
	kv("Tree size", humanBytes(db.searchTreeSize))
	kv("File size", humanBytes(uint(len(db.buf))))
	kv("Languages", strings.Join(db.languages, ", "))
}

func humanBytes(n uint) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

type action struct {
	name string
	desc string
	fn   func()
}

var tuiActions = []action{
	{"Geolocate IP", "Offline MMDB lookup + ASN", uiGeolocate},
	{"Classify IP", "Scope / reserved-range analysis", uiClassify},
	{"Reverse DNS", "PTR records for an IP", uiReverse},
	{"Forward DNS", "A / AAAA records for a host", uiForward},
	{"ASN lookup", "AS number + BGP prefix (Cymru)", uiASN},
	{"Bulk geolocate", "Many IPs, offline, no limit", uiBulk},
	{"Database info", "Metadata of the loaded MMDB", uiDBInfo},
}

func mainMenu() {
	for {
		clear()
		banner()
		fmt.Println("  " + col("⬡  Main Menu", B+CY))
		fmt.Println()
		for i, a := range tuiActions {
			fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " +
				col(pad(a.name, 18), W) + col("─ "+a.desc, DIM))
		}
		fmt.Println()
		fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 18), W) + col("─ How to use, every option, CLI flags & examples", DIM))
		fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 18), W) + col("─ Quit "+APPNAME, DIM))
		fmt.Println()
		rule()
		c := strings.TrimLeft(prompt("Select option"), "0")
		if c == "" {
			clear()
			okMsg("Goodbye.")
			return
		}
		if strings.EqualFold(c, "h") || strings.EqualFold(c, "help") || c == "?" {
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(c)
		if err != nil || n < 1 || n > len(tuiActions) {
			errMsg("Unknown option")
			pause()
			continue
		}
		clear()
		banner()
		tuiActions[n-1].fn()
		pause()
	}
}

// ============================================================
//  CLI / selftest / demo
// ============================================================

func usage() {
	banner()
	sec := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	sec("USAGE")
	fmt.Println("    " + APPNAME + " [flags]            (no flags → interactive TUI)")
	fmt.Println()
	sec("DESCRIPTION")
	fmt.Println("    Offline IP geolocation from a MaxMind GeoLite2-City .mmdb (own reader, no API,")
	fmt.Println("    no rate limit), IP scope classification, and ASN / BGP prefix via Team Cymru DNS.")
	fmt.Println()
	sec("LOOKUP")
	fmt.Println("    --ip IP|HOST      geolocate one IP or hostname (offline)")
	fmt.Println("    --bulk LIST       comma / space separated IPs, one table row each")
	fmt.Println("    --classify IP     print scope / reserved-range classification and exit")
	fmt.Println("    --asn             also resolve ASN + BGP prefix (needs DNS)")
	fmt.Println("    --lang CODE       preferred language for place names (default en; de, es, fr,")
	fmt.Println("                      ja, pt-BR, ru, zh-CN when present in the database)")
	fmt.Println()
	sec("DATABASE")
	fmt.Println("    --db PATH         path to GeoLite2-City.mmdb")
	fmt.Println("    --dbinfo          print database metadata and exit")
	fmt.Println("    search order: --db, $OGEOIP_DB, ./GeoLite2-City.mmdb, next to the binary,")
	fmt.Println("                  ~/.local/share/GeoIP, /usr/share/GeoIP, …")
	fmt.Println()
	sec("OUTPUT")
	fmt.Println("    --json            machine-readable JSON output")
	fmt.Println("    --no-color        disable ANSI colour")
	fmt.Println()
	sec("GENERAL")
	fmt.Println("    --demo  --selftest  --version  -h/--help")
	fmt.Println()
	sec("EXAMPLES")
	fmt.Println("    " + APPNAME + " --ip 8.8.8.8")
	fmt.Println("    " + APPNAME + " --ip example.com --asn")
	fmt.Println("    " + APPNAME + " --ip 2001:4860:4860::8888 --lang de")
	fmt.Println("    " + APPNAME + " --bulk \"1.1.1.1,8.8.8.8 9.9.9.9\" --json > geo.json")
	fmt.Println("    " + APPNAME + " --bulk \"$(cut -d' ' -f1 access.log | sort -u | tr '\\n' ' ')\"")
	fmt.Println("    " + APPNAME + " --classify 100.64.1.1")
	fmt.Println("    " + APPNAME + " --db ~/geoip/GeoLite2-City.mmdb --dbinfo")
	fmt.Println("    export OGEOIP_DB=~/geoip/GeoLite2-City.mmdb   # set once, then omit --db")
	fmt.Println()
	rule()
}

func main() { os.Exit(run()) }

func run() int {
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.Usage = usage
	var (
		ipFlag    = fs.String("ip", "", "")
		bulkFlag  = fs.String("bulk", "", "")
		classFlag = fs.String("classify", "", "")
		asnFlag   = fs.Bool("asn", false, "")
		db        = fs.String("db", "", "")
		lang      = fs.String("lang", "en", "")
		jsonOut   = fs.Bool("json", false, "")
		dbinfo    = fs.Bool("dbinfo", false, "")
		nocol     = fs.Bool("no-color", false, "")
		self      = fs.Bool("selftest", false, "")
		demo      = fs.Bool("demo", false, "")
		ver       = fs.Bool("version", false, "")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *nocol {
		noColor = true
	}
	if *ver {
		fmt.Printf("%s %s\n", APPNAME, VERSION)
		return 0
	}
	if *lang != "" {
		langPreference = []string{*lang, "en"}
	}
	dbPath = *db
	if *self {
		return selftest()
	}
	if *demo {
		return demoRun()
	}

	fail := func(err error) int { errMsg(err.Error()); return 1 }

	if *classFlag != "" {
		ip := net.ParseIP(*classFlag)
		if ip == nil {
			return fail(fmt.Errorf("not a valid IP: %s", *classFlag))
		}
		sc := classifyScope(ip)
		if *jsonOut {
			emitJSON(map[string]interface{}{"ip": ip.String(), "scope": sc.Scope, "detail": sc.Detail, "routable": sc.Routable})
			return 0
		}
		kv("Address", ip.String())
		kv("Scope", sc.Scope)
		kv("Detail", sc.Detail)
		return 0
	}

	if *dbinfo {
		path, err := findDB(dbPath)
		if err != nil {
			return fail(err)
		}
		d, err := openMMDB(path)
		if err != nil {
			return fail(err)
		}
		if *jsonOut {
			emitJSON(map[string]interface{}{
				"path": path, "type": d.databaseType, "built": epoch(d.buildEpoch),
				"ip_version": d.ipVersion, "record_size": d.recordSize,
				"nodes": d.nodeCount, "languages": d.languages,
			})
			return 0
		}
		uiDBInfo()
		return 0
	}

	if *bulkFlag != "" {
		path, err := findDB(dbPath)
		if err != nil {
			return fail(err)
		}
		d, err := openMMDB(path)
		if err != nil {
			return fail(err)
		}
		targets := splitList(*bulkFlag)
		if *jsonOut {
			var out []GeoResult
			for _, t := range targets {
				ip := net.ParseIP(t)
				if ip == nil {
					continue
				}
				g, _ := geolocate(d, ip)
				g.IP = t
				out = append(out, g)
			}
			emitJSON(out)
			return 0
		}
		table([]string{"IP", "CC", "City", "Region", "Scope"}, bulkRows(d, targets))
		return 0
	}

	if *ipFlag != "" {
		return cliGeolocate(*ipFlag, *asnFlag, *jsonOut)
	}

	// No action flags → interactive menu.
	mainMenu()
	return 0
}

func cliGeolocate(target string, withASN, jsonOut bool) int {
	ip, resolved, err := resolveToIP(target)
	if err != nil {
		errMsg(err.Error())
		return 1
	}
	sc := classifyScope(ip)
	var a *asnInfo
	var g GeoResult
	if sc.Routable {
		path, err := findDB(dbPath)
		if err != nil {
			errMsg(err.Error())
			return 1
		}
		d, err := openMMDB(path)
		if err != nil {
			errMsg(err.Error())
			return 1
		}
		g, err = geolocate(d, ip)
		if err != nil {
			errMsg(err.Error())
			return 1
		}
		if withASN {
			a, _ = lookupASN(ip)
		}
	} else {
		g.IP = ip.String()
	}
	if jsonOut {
		m := map[string]interface{}{"geo": g, "scope": sc.Scope, "scope_detail": sc.Detail}
		if a != nil {
			m["asn"] = a
		}
		emitJSON(m)
		return 0
	}
	if resolved != "" {
		info("Resolved " + resolved + " → " + ip.String())
	}
	if !sc.Routable {
		warnMsg("Scope: " + sc.Scope + " — " + sc.Detail)
		return 0
	}
	okMsg("Geolocation for " + ip.String())
	fmt.Println()
	printGeo(g, a)
	return 0
}

func emitJSON(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

// ============================================================
//  Self-test & demo
// ============================================================

func selftest() int {
	pass, fail := 0, 0
	check := func(name string, cond bool, detail string) {
		if cond {
			pass++
			okMsg(name)
		} else {
			fail++
			errMsg(name + " — " + detail)
		}
	}
	sectionHeader("OGeoIP self-test")

	// Scope classification
	check("10.0.0.1 is private", classifyScope(net.ParseIP("10.0.0.1")).Scope == "private", "")
	check("100.64.0.1 is CGNAT (private)", classifyScope(net.ParseIP("100.64.0.1")).Scope == "private", "")
	check("127.0.0.1 is loopback", classifyScope(net.ParseIP("127.0.0.1")).Scope == "loopback", "")
	check("169.254.1.1 is link-local", classifyScope(net.ParseIP("169.254.1.1")).Scope == "link-local", "")
	check("192.0.2.5 is reserved (TEST-NET)", classifyScope(net.ParseIP("192.0.2.5")).Scope == "reserved", "")
	check("8.8.8.8 is global", classifyScope(net.ParseIP("8.8.8.8")).Routable, "")
	check("2001:db8::1 is reserved (doc)", classifyScope(net.ParseIP("2001:db8::1")).Scope == "reserved", "")
	check("fe80::1 is link-local", classifyScope(net.ParseIP("fe80::1")).Scope == "link-local", "")
	check("2606:4700::1 is global v6", classifyScope(net.ParseIP("2606:4700::1")).Routable, "")

	// Cymru reverse encoding
	check("reverseV4(8.8.4.4)=4.4.8.8", reverseV4(net.ParseIP("8.8.4.4")) == "4.4.8.8", reverseV4(net.ParseIP("8.8.4.4")))

	// MMDB decoder unit tests (synthetic values)
	check("decode uint32", decUint([]byte{0xc2, 0x01, 0x02}) == 0x0102, "")
	check("decode string", decStr([]byte{0x43, 'a', 'b', 'c'}) == "abc", "")
	check("decode true", decBool([]byte{0x01, 0x07}) == true, "")
	check("decode map{k:v}", decMapKV() == "v1", "")
	check("decode double 1.5", decDouble() == 1.5, "")

	// Real DB lookups when available
	if path, err := findDB(dbPath); err == nil {
		if d, err := openMMDB(path); err == nil {
			info("Using DB: " + path)
			g, _ := geolocate(d, net.ParseIP("8.8.8.8"))
			check("8.8.8.8 → US", g.CountryISO == "US", "got "+g.CountryISO)
			// 9.9.9.9/32 has no country, only registered_country=US — exercises
			// exact block resolution and the registered-country fallback.
			g2, _ := geolocate(d, net.ParseIP("9.9.9.9"))
			check("9.9.9.9 → registered US", g2.CountryISO == "" && g2.RegisteredISO == "US", "got iso="+g2.CountryISO+" reg="+g2.RegisteredISO)
			check("8.8.8.8 has coordinates", g.HasLatLon, "")
			check("DB is GeoLite2/GeoIP2 City", strings.Contains(d.databaseType, "City"), d.databaseType)
			check("DB ip_version=6", d.ipVersion == 6, strconv.Itoa(d.ipVersion))
		} else {
			warnMsg("DB present but failed to open: " + err.Error())
		}
	} else {
		info("No MMDB found — skipping live lookup tests (decoder tested synthetically).")
	}

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("All %d checks passed.", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d failed.", pass, fail))
	return 1
}

// Synthetic decode helpers for self-test (data section with ptrBase 0).
func decUint(b []byte) uint64 {
	d := &decoder{buf: b}
	v, _, _ := d.decode(0)
	if u, ok := v.(uint64); ok {
		return u
	}
	return 0xffffffff
}
func decStr(b []byte) string {
	d := &decoder{buf: b}
	v, _, _ := d.decode(0)
	return str(v)
}
func decBool(b []byte) bool {
	d := &decoder{buf: b}
	v, _, _ := d.decode(0)
	return boolOf(v)
}
func decDouble() float64 {
	// control 0x68 = type 3 (double), size 8; then 8 bytes of 1.5
	var buf []byte
	buf = append(buf, 0x68)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], math.Float64bits(1.5))
	buf = append(buf, tmp[:]...)
	d := &decoder{buf: buf}
	v, _, _ := d.decode(0)
	return fl(v)
}
func decMapKV() string {
	// map with 1 pair: key "k1" (string len2), value "v1" (string len2)
	b := []byte{0xe1, 0x42, 'k', '1', 0x42, 'v', '1'}
	d := &decoder{buf: b}
	v, _, _ := d.decode(0)
	if m, ok := v.(map[string]interface{}); ok {
		return str(m["k1"])
	}
	return ""
}

func demoRun() int {
	clear()
	banner()
	sectionHeader("Demo — offline geolocation")
	path, err := findDB(dbPath)
	if err != nil {
		warnMsg("No MMDB database found, showing classification only.")
		for _, ip := range []string{"8.8.8.8", "10.0.0.1", "192.0.2.1", "100.64.0.1"} {
			sc := classifyScope(net.ParseIP(ip))
			kv(ip, sc.Scope+" — "+sc.Detail)
		}
		return 0
	}
	d, err := openMMDB(path)
	if err != nil {
		errMsg(err.Error())
		return 1
	}
	info("Database: " + path)
	fmt.Println()
	targets := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"}
	rows := bulkRows(d, targets)
	table([]string{"IP", "CC", "City", "Region", "Scope"}, rows)
	fmt.Println()
	okMsg("All lookups above were resolved offline from the local MMDB.")
	return 0
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OGeoIP finds where an IP address is located (country, region, city, coordinates, time zone, accuracy radius) using a local MaxMind GeoLite2-City .mmdb database. Lookups are offline, so there are no API keys, no rate limits, and the IP you investigate is never sent to a third party.",
	"It also classifies IPs (private, loopback, CGNAT, documentation, multicast, reserved ...), does reverse / forward DNS, and finds the ASN, owner and BGP prefix through the Team Cymru DNS service. These DNS features need network access.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. The database is found automatically in this order: --db, $OGEOIP_DB, ./GeoLite2-City.mmdb, next to the binary, ~/.local/share/GeoIP, /usr/share/GeoIP. If it is missing, download GeoLite2-City.mmdb (free MaxMind account) and put it in one of those places. [H] opens this help, [0] or a blank line quits.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Geolocate IP: enter an IP (8.8.8.8, 2001:4860::8888) or a hostname, which is resolved first. Shows location, coordinates, time zone and ASN. Private / reserved addresses are explained instead, because they have no public location."},
	{"2", "Classify IP: enter an IP to see its scope and which reserved range (RFC) it belongs to. Works without the database."},
	{"3", "Reverse DNS: enter an IP to get its PTR host names."},
	{"4", "Forward DNS: enter a hostname to get its A / AAAA addresses."},
	{"5", "ASN lookup: enter an IP to get the AS number, owner, BGP prefix and registry."},
	{"6", "Bulk geolocate: paste IPs separated by commas, spaces or new lines, and finish with an empty line. Prints one table row per IP. There is no limit, because everything is offline."},
	{"7", "Database info: version, build date, IP version and record count of the loaded .mmdb."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "IP geolocation is approximate. City-level results can be tens of kilometres off. Check the accuracy radius."},
	{"*", "VPNs, proxies, Tor and cloud providers show the server's location, not the person's."},
	{"*", "MaxMind updates GeoLite2 twice a week. Refresh the .mmdb regularly for accurate results."},
}

func owlHelpCLI() { usage() }
