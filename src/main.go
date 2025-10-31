package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

type Config struct {
	ListenPort  string `yaml:"listen_port"`
	BindAddress string `yaml:"bind_address"`
	HostsFile   string `yaml:"hosts_file"`
	LogLevel    string `yaml:"log_level"`
	PollFreq    int    `yaml:"poll_freq"`
	FallbackDNS string `yaml:"fallback_dns"`
}

type Record struct {
	Type string
	TTL  uint32
	Data string
	Pref uint16
}

var (
	records          map[string]Record
	hostsFileModTime time.Time
	config           = &Config{}
)

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, config)
}

func parseFlags() {
	configPath := flag.String("config", "config.yaml", "Path to config file")
	port := flag.String("port", "", "Listen port")
	bindaddr := flag.String("bindaddr", "", "Binding address")
	zones := flag.String("zones", "", "Zone file path")
	fallback := flag.String("fallback", "", "Fallback DNS (e.g. 8.8.8.8:53)")
	poll := flag.Int("poll", 0, "Zone file reload frequency (seconds)")

	flag.Parse()

	_ = loadConfig(*configPath)

	// Env var PORT overrides everything else
	if envPort := os.Getenv("PORT"); envPort != "" {
		config.ListenPort = envPort
	} else if *port != "" {
		config.ListenPort = *port
	}
 	
	if *bindaddr != "" {
                config.BindAddress = *bindaddr
    }
	
	if *zones != "" {
		config.HostsFile = *zones
	}
	if *fallback != "" {
		config.FallbackDNS = *fallback
	}
	if *poll > 0 {
		config.PollFreq = *poll
	}
}

func loadZoneFile(path string) (map[string]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	recs := make(map[string]Record)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			log.Printf("Invalid line %d: too few fields", lineNum)
			continue
		}
		name := dns.Fqdn(fields[0])
		ttl, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			log.Printf("Invalid TTL on line %d: %v", lineNum, err)
			continue
		}
		class := strings.ToUpper(fields[2])
		rtype := strings.ToUpper(fields[3])
		if class != "IN" {
			log.Printf("Unsupported class on line %d: %s", lineNum, class)
			continue
		}

		switch rtype {
		case "A":
			if net.ParseIP(fields[4]) == nil {
				log.Printf("Invalid IP on line %d: %s", lineNum, fields[4])
				continue
			}
			recs[name] = Record{Type: "A", TTL: uint32(ttl), Data: fields[4]}
		case "CNAME":
			target := dns.Fqdn(fields[4])
			_, ok := dns.IsDomainName(target)
			if !ok {
				log.Printf("Invalid CNAME target on line %d: %s", lineNum, target)
				continue
			}
			recs[name] = Record{Type: "CNAME", TTL: uint32(ttl), Data: target}
		case "TXT":
			txt := strings.Join(fields[4:], " ")
			recs[name] = Record{Type: "TXT", TTL: uint32(ttl), Data: txt}
		case "MX":
			if len(fields) < 6 {
				log.Printf("Invalid MX on line %d: missing preference/host", lineNum)
				continue
			}
			pref, err := strconv.Atoi(fields[4])
			if err != nil {
				log.Printf("Invalid MX preference on line %d: %v", lineNum, err)
				continue
			}
			host := dns.Fqdn(fields[5])
			_, ok := dns.IsDomainName(host)
			if !ok {
				log.Printf("Invalid MX host on line %d: %s", lineNum, host)
				continue
			}
			recs[name] = Record{Type: "MX", TTL: uint32(ttl), Data: host, Pref: uint16(pref)}
		default:
			log.Printf("Unsupported record type on line %d: %s", lineNum, rtype)
		}
	}
	return recs, scanner.Err()
}

func reloadZoneIfChanged() {
	for {
		time.Sleep(time.Duration(config.PollFreq) * time.Second)
		info, err := os.Stat(config.HostsFile)
		if err == nil && info.ModTime().After(hostsFileModTime) {
			newRecords, err := loadZoneFile(config.HostsFile)
			if err == nil {
				records = newRecords
				hostsFileModTime = info.ModTime()
				log.Println("Reloaded zone file")
			}
		}
	}
}

func forwardToFallback(r *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp"}
	resp, _, err := c.Exchange(r, config.FallbackDNS)
	return resp, err
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	answered := false

	for _, q := range r.Question {
		log.Printf("Received query: %s %s", dns.TypeToString[q.Qtype], q.Name)

		name := dns.Fqdn(strings.ToLower(q.Name))
		rec, found := records[name]
		if found {
			switch q.Qtype {
			case dns.TypeA:
				if rec.Type == "A" {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rec.TTL},
						A:   net.ParseIP(rec.Data).To4(),
					})
					answered = true
				} else if rec.Type == "CNAME" {
					m.Answer = append(m.Answer, &dns.CNAME{
						Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rec.TTL},
						Target: rec.Data,
					})
					answered = true
				}
			case dns.TypeCNAME:
				if rec.Type == "CNAME" {
					m.Answer = append(m.Answer, &dns.CNAME{
						Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rec.TTL},
						Target: rec.Data,
					})
					answered = true
				}
			case dns.TypeTXT:
				if rec.Type == "TXT" {
					m.Answer = append(m.Answer, &dns.TXT{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: rec.TTL},
						Txt: []string{rec.Data},
					})
					answered = true
				}
			case dns.TypeMX:
				if rec.Type == "MX" {
					m.Answer = append(m.Answer, &dns.MX{
						Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: rec.TTL},
						Preference: rec.Pref,
						Mx:         rec.Data,
					})
					answered = true
				}
			default:
				m.Rcode = dns.RcodeNotImplemented
			}
		}
	}

	if !answered && config.FallbackDNS != "" {
		resp, err := forwardToFallback(r)
		if err == nil {
			w.WriteMsg(resp)
			for _, rr := range resp.Answer {
				log.Printf("Forwarded response: %s", rr.String())
			}
			return
		}
		m.Rcode = dns.RcodeServerFailure
	}

	w.WriteMsg(m)

	for _, rr := range m.Answer {
		log.Printf("Responded with: %s", rr.String())
	}
}

func main() {
	log.SetOutput(os.Stdout)

	parseFlags()

	var err error
	records, err = loadZoneFile(config.HostsFile)
	if err != nil {
		log.Fatalf("Failed to load zone file: %v", err)
	}

	info, err := os.Stat(config.HostsFile)
	if err == nil {
		hostsFileModTime = info.ModTime()
	}

	go reloadZoneIfChanged()

	dns.HandleFunc(".", handleDNSRequest)
	server := &dns.Server{Addr: config.BindAddress + ":" + config.ListenPort, Net: "udp"}
	fmt.Printf("DNS resolver listening on UDP port %s\n", config.ListenPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

