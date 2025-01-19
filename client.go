package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/cache"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/task"

	"github.com/miekg/dns"
)

const (
	DefaultTTL     = 600
	DefaultTimeout = 10 * time.Second
)

var (
	ErrNoRawSupport           = E.New("no raw query support by current transport")
	ErrNotCached              = E.New("not cached")
	ErrResponseRejected       = E.New("response rejected")
	ErrResponseRejectedCached = E.Extend(ErrResponseRejected, "cached")
)

type Hosts struct {
	CNAMEHosts map[string]string
	IPv4Hosts  map[string]*ipHosts
	IPv6Hosts  map[string]*ipHosts
}

type ipHosts struct {
	index int32
	addrs []netip.Addr
}

func (ih *ipHosts) RoundRobin() []netip.Addr {
	if len(ih.addrs) == 1 {
		return ih.addrs
	}
	i := atomic.AddInt32(&ih.index, 1)
	start := int(i-1) % len(ih.addrs)
	return append(ih.addrs[start:], ih.addrs[:start]...)
}

func NewHosts(hostsMap map[string][]string) (*Hosts, error) {
	if len(hostsMap) == 0 {
		return nil, nil
	}
	hosts := Hosts{
		CNAMEHosts: make(map[string]string),
		IPv4Hosts:  make(map[string]*ipHosts),
		IPv6Hosts:  make(map[string]*ipHosts),
	}
	for domain, addrs := range hostsMap {
		var ipv4Addr, ipv6Addr []netip.Addr
		for _, addr := range addrs {
			SAddr := M.ParseSocksaddr(addr)
			if SAddr.Port != 0 {
				return nil, E.New("hosts cannot containing port")
			}
			if SAddr.IsFqdn() {
				if len(addrs) > 1 {
					return nil, E.New("CNAME hosts can only be used alone")
				}
				hosts.CNAMEHosts[domain] = SAddr.Fqdn
			} else if SAddr.IsIPv4() {
				ipv4Addr = append(ipv4Addr, SAddr.Addr)
			} else if SAddr.IsIPv6() {
				if SAddr.Addr.Is4In6() {
					ipv4Addr = append(ipv4Addr, netip.AddrFrom4(SAddr.Addr.As4()))
				} else {
					ipv6Addr = append(ipv6Addr, SAddr.Addr)
				}
			}
		}
		if len(ipv4Addr) > 0 {
			hosts.IPv4Hosts[domain] = &ipHosts{addrs: ipv4Addr}
		}
		if len(ipv6Addr) > 0 {
			hosts.IPv6Hosts[domain] = &ipHosts{addrs: ipv6Addr}
		}
	}
	return &hosts, nil
}

type Client struct {
	timeout          time.Duration
	disableCache     bool
	disableExpire    bool
	independentCache bool
	roundRobinCache  bool
	useStaleCache    bool
	staleCache       uint32
	minCacheTTL      uint32
	maxCacheTTL      uint32
	hosts            *Hosts
	rdrc             RDRCStore
	initRDRCFunc     func() RDRCStore
	logger           logger.ContextLogger
	cache            *cache.LruCache[dns.Question, *dnsMsg]
	transportCache   *cache.LruCache[transportCacheKey, *dnsMsg]
	cacheUpdating    *cache.LruCache[dns.Question, struct{}]
	transportCacheUpdating *cache.LruCache[transportCacheKey, struct{}]
	updateAccess     sync.Mutex
}

type RDRCStore interface {
	LoadRDRC(transportName string, qName string, qType uint16) (rejected bool)
	SaveRDRC(transportName string, qName string, qType uint16) error
	SaveRDRCAsync(transportName string, qName string, qType uint16, logger logger.Logger)
}

type dnsMsg struct {
	ipv4Index   int32
	ipv6Index   int32
	msg         *dns.Msg
	expiredTime time.Time
}

func removeAnswersOfType(answers []dns.RR, rrType uint16) []dns.RR {
	var filteredAnswers []dns.RR
	for _, ans := range answers {
		if ans.Header().Rrtype != rrType {
			filteredAnswers = append(filteredAnswers, ans)
		}
	}
	return filteredAnswers
}

func (dm *dnsMsg) RoundRobin() *dns.Msg {
	var (
		ipv4Answers []*dns.A
		ipv6Answers []*dns.AAAA
	)
	for _, ans := range dm.msg.Answer {
		switch a := ans.(type) {
		case *dns.A:
			ipv4Answers = append(ipv4Answers, a)
		case *dns.AAAA:
			ipv6Answers = append(ipv6Answers, a)
		}
	}
	rotatedMsg := dm.msg.Copy()
	if len(ipv4Answers) > 1 {
		atomic.AddInt32(&dm.ipv4Index, 1)
		rotatedIPv4 := dm.rotateSlice(ipv4Answers, dm.ipv4Index)
		rotatedMsg.Answer = removeAnswersOfType(rotatedMsg.Answer, dns.TypeA)
		if ipv4List, ok := rotatedIPv4.([]*dns.A); ok {
			for _, ipv4 := range ipv4List {
				rotatedMsg.Answer = append(rotatedMsg.Answer, ipv4)
			}
		}
	}
	if len(ipv6Answers) > 1 {
		atomic.AddInt32(&dm.ipv6Index, 1)
		rotatedIPv6 := dm.rotateSlice(ipv6Answers, dm.ipv6Index)
		rotatedMsg.Answer = removeAnswersOfType(rotatedMsg.Answer, dns.TypeAAAA)
		if ipv6List, ok := rotatedIPv6.([]*dns.AAAA); ok {
			for _, ipv6 := range ipv6List {
				rotatedMsg.Answer = append(rotatedMsg.Answer, ipv6)
			}
		}
	}
	return rotatedMsg
}

func (dm *dnsMsg) rotateSlice(slice interface{}, index int32) interface{} {
	var rotatedSlice interface{}
	switch v := slice.(type) {
	case []*dns.A:
		if len(v) > 1 {
			index = index % int32(len(v))
			rotatedSlice = append([]*dns.A{}, v[index:]...)  // Copy the rotated part
			rotatedSlice = append(rotatedSlice.([]*dns.A), v[:index]...)  // Add the rest
		} else {
			rotatedSlice = append([]*dns.A{}, v...)  // If only one element, return it as is
		}
	case []*dns.AAAA:
		if len(v) > 1 {
			index = index % int32(len(v))
			rotatedSlice = append([]*dns.AAAA{}, v[index:]...)  // Copy the rotated part
			rotatedSlice = append(rotatedSlice.([]*dns.AAAA), v[:index]...)  // Add the rest
		} else {
			rotatedSlice = append([]*dns.AAAA{}, v...)  // If only one element, return it as is
		}
	}
	return rotatedSlice
}

type transportCacheKey struct {
	dns.Question
	transportName string
}

type ClientOptions struct {
	Timeout          time.Duration
	DisableCache     bool
	DisableExpire    bool
	IndependentCache bool
	RoundRobinCache  bool
	StaleCache       uint32
	MinCacheTTL      uint32
	MaxCacheTTL      uint32
	Hosts            *Hosts
	RDRC             func() RDRCStore
	Logger           logger.ContextLogger
}

func NewClient(options ClientOptions) *Client {
	client := &Client{
		timeout:          options.Timeout,
		disableCache:     options.DisableCache,
		disableExpire:    options.DisableExpire,
		independentCache: options.IndependentCache,
		roundRobinCache:  options.RoundRobinCache,
		useStaleCache:    options.StaleCache > 0,
		staleCache:       options.StaleCache,
		minCacheTTL:      options.MinCacheTTL,
		maxCacheTTL:      options.MaxCacheTTL,
		hosts:            options.Hosts,
		initRDRCFunc:     options.RDRC,
		logger:           options.Logger,
	}
	if client.maxCacheTTL == 0 {
		client.maxCacheTTL = 86400
	}
	if client.minCacheTTL > client.maxCacheTTL {
		client.maxCacheTTL = client.minCacheTTL
	}
	if client.timeout == 0 {
		client.timeout = DefaultTimeout
	}
	if !client.disableCache {
		if !client.independentCache {
			client.cache = cache.New[dns.Question, *dnsMsg]()
			client.cacheUpdating = cache.New[dns.Question, struct{}]()
		} else {
			client.transportCache = cache.New[transportCacheKey, *dnsMsg]()
			client.transportCacheUpdating = cache.New[transportCacheKey, struct{}]()
		}
	}
	return client
}

func (c *Client) Start() {
	if c.initRDRCFunc != nil {
		c.rdrc = c.initRDRCFunc()
	}
}

func (c *Client) SearchCNAMEHosts(ctx context.Context, message *dns.Msg) (*dns.Msg, []dns.RR) {
	if c.hosts == nil || len(message.Question) == 0 {
		return nil, nil
	}
	question := message.Question[0]
	domain := fqdnToDomain(question.Name)
	cname, hasHosts := c.hosts.CNAMEHosts[domain]
	if !hasHosts || (question.Qtype != dns.TypeCNAME && question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil, nil
	}
	var records []dns.RR
	for {
		if c.logger != nil {
			c.logger.DebugContext(ctx, "match CNAME hosts: ", domain, " => ", cname)
		}
		domain = cname
		records = append(records, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:     question.Name,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      1,
				Rdlength: uint16(len(dns.Fqdn(cname))),
			},
			Target: dns.Fqdn(cname),
		})
		cname, hasHosts = c.hosts.CNAMEHosts[domain]
		if !hasHosts {
			break
		}
	}
	if question.Qtype != dns.TypeCNAME {
		message.Question[0].Name = dns.Fqdn(domain)
		return nil, records
	}
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       message.Id,
			Response: true,
			Authoritative: true,
			RecursionDesired: true,
			RecursionAvailable: true,
			Rcode:    dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
		Answer:   records,
	}, nil
}

func (c *Client) printIPHostsLog(ctx context.Context, domain string, addrs []netip.Addr, nolog bool) {
	if nolog || c.logger == nil {
		return
	}
	logString := addrs[0].String()
	versionStr := "IPv4"
	if addrs[0].Is6() {
		versionStr = "IPv6"
	}
	if len(addrs) > 1 {
		logString = strings.Join(common.Map(addrs, func(addr netip.Addr) string {
			return addr.String()
		}), ", ")
		logString = "[" + logString + "]"
	}
	c.logger.DebugContext(ctx, "match ", versionStr, " hosts: ", domain, " => ", logString)
}

func (c *Client) SearchIPHosts(ctx context.Context, message *dns.Msg, strategy DomainStrategy) *dns.Msg {
	if c.hosts == nil || len(message.Question) == 0 {
		return nil
	}
	question := message.Question[0]
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return nil
	}
	domain := fqdnToDomain(question.Name)
	ipv4Addrs, hasIPv4 := c.hosts.IPv4Hosts[domain]
	ipv6Addrs, hasIPv6 := c.hosts.IPv6Hosts[domain]
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       message.Id,
			Response: true,
			Authoritative: true,
			RecursionDesired: true,
			RecursionAvailable: true,
			Rcode:    dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
	}
	if !hasIPv4 && !hasIPv6 {
		return nil
	}
	switch question.Qtype {
	case dns.TypeA:
		if !hasIPv4 {
			return nil
		}
		if strategy == DomainStrategyUseIPv6 {
			if c.logger != nil {
				c.logger.DebugContext(ctx, "strategy rejected")
			}
			break
		}
		var ipAddrs []netip.Addr
		if !c.roundRobinCache {
			ipAddrs = ipv4Addrs.addrs
		} else {
			ipAddrs = ipv4Addrs.RoundRobin()
		}
		c.printIPHostsLog(ctx, domain, ipAddrs, false)
		for _, addr := range ipAddrs {
			record := addr.AsSlice()
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:     question.Name,
					Rrtype:   dns.TypeA,
					Class:    dns.ClassINET,
					Ttl:      1,
					Rdlength: uint16(len(record)),
				},
				A: record,
			})
		}
	case dns.TypeAAAA:
		if !hasIPv6 {
			return nil
		}
		if strategy == DomainStrategyUseIPv4 {
			if c.logger != nil {
				c.logger.DebugContext(ctx, "strategy rejected")
			}
			break
		}
		var ipAddrs []netip.Addr
		if !c.roundRobinCache {
			ipAddrs = ipv6Addrs.addrs
		} else {
			ipAddrs = ipv6Addrs.RoundRobin()
		}
		c.printIPHostsLog(ctx, domain, ipAddrs, false)
		for _, addr := range ipAddrs {
			record := addr.AsSlice()
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:     question.Name,
					Rrtype:   dns.TypeAAAA,
					Class:    dns.ClassINET,
					Ttl:      1,
					Rdlength: uint16(len(record)),
				},
				A: addr.AsSlice(),
			})
		}
	default:
		return nil
	}
	return &response
}

func (c *Client) Exchange(ctx context.Context, transport Transport, message *dns.Msg, strategy DomainStrategy) (*dns.Msg, error) {
	return c.ExchangeWithResponseCheck(ctx, transport, message, strategy, nil)
}

type updateDnsCacheContext struct{}

var UpdateDnsCacheContextKey = updateDnsCacheContext{}

func GetUpdateDnsCacheFromContext(ctx context.Context) bool {
	_, ok := ctx.Value(UpdateDnsCacheContextKey).(struct{})
	return ok
}

func AddUpdateDnsCacheToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, UpdateDnsCacheContextKey, struct{}{})
}

func (c *Client) ExchangeWithResponseCheck(ctx context.Context, transport Transport, message *dns.Msg, strategy DomainStrategy, responseChecker func(response *dns.Msg) bool) (*dns.Msg, error) {
	if len(message.Question) == 0 {
		if c.logger != nil {
			c.logger.WarnContext(ctx, "bad question size: ", len(message.Question))
		}
		responseMessage := dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       message.Id,
				Response: true,
				Rcode:    dns.RcodeFormatError,
			},
			Question: message.Question,
		}
		return &responseMessage, nil
	}
	question := message.Question[0]
	isUpdateCache := GetUpdateDnsCacheFromContext(ctx)
	if isUpdateCache {
		var key interface{}
		isUpdating := func() bool {
			c.updateAccess.Lock()
			defer c.updateAccess.Unlock()
			var exist bool
			if !c.independentCache {
				_, exist = c.cacheUpdating.Load(question)
				if !exist {
					c.cacheUpdating.Store(question, struct{}{})
					key = question
				}
			} else {
				transportKey := transportCacheKey{
					Question:      question,
					transportName: transport.Name(),
				}
				_, exist = c.transportCacheUpdating.Load(transportKey)
				if !exist {
					c.transportCacheUpdating.Store(transportKey, struct{}{})
					key = transportKey
				}
			}
			return exist
		}()
		if !isUpdating && key != nil {
			defer func() {
				c.updateAccess.Lock()
				defer c.updateAccess.Unlock()
				if !c.independentCache {
					c.cacheUpdating.Delete(key.(dns.Question))
				} else {
					c.transportCacheUpdating.Delete(key.(transportCacheKey))
				}
			}()
		}
		if isUpdating {
			return nil, nil
		}
	}
	clientSubnet, clientSubnetLoaded := ClientSubnetFromContext(ctx)
	if clientSubnetLoaded {
		message = SetClientSubnet(message, clientSubnet, true)
	}
	isSimpleRequest := len(message.Question) == 1 &&
		len(message.Ns) == 0 &&
		len(message.Extra) == 0 &&
		!clientSubnetLoaded
	disableCache := !isSimpleRequest || c.disableCache || DisableCacheFromContext(ctx)
	if !disableCache && !isUpdateCache {
		response, ttl := c.loadResponse(question, transport)
		if response != nil {
			logCachedResponse(c.logger, ctx, response, ttl)
			response.Id = message.Id
			return response, nil
		}
	}
	if question.Qtype == dns.TypeA && strategy == DomainStrategyUseIPv6 || question.Qtype == dns.TypeAAAA && strategy == DomainStrategyUseIPv4 {
		responseMessage := dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       message.Id,
				Response: true,
				Authoritative: true,
				RecursionDesired: true,
				RecursionAvailable: true,
				Rcode:    dns.RcodeSuccess,
			},
			Question: []dns.Question{question},
		}
		if c.logger != nil {
			c.logger.DebugContext(ctx, "strategy rejected")
		}
		return &responseMessage, nil
	}
	if !transport.Raw() {
		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			return c.exchangeToLookup(ctx, transport, message, question)
		}
		return nil, ErrNoRawSupport
	}
	messageId := message.Id
	contextTransport, clientSubnetLoaded := transportNameFromContext(ctx)
	if clientSubnetLoaded && transport.Name() == contextTransport {
		return nil, E.New("DNS query loopback in transport[", contextTransport, "]")
	}
	ctx = contextWithTransportName(ctx, transport.Name())
	if responseChecker != nil && c.rdrc != nil {
		rejected := c.rdrc.LoadRDRC(transport.Name(), question.Name, question.Qtype)
		if rejected {
			return nil, ErrResponseRejectedCached
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	response, err := transport.Exchange(ctx, message)
	cancel()
	if err != nil {
		return nil, err
	}
	if responseChecker != nil && !responseChecker(response) {
		if c.rdrc != nil {
			c.rdrc.SaveRDRCAsync(transport.Name(), question.Name, question.Qtype, c.logger)
		}
		return response, ErrResponseRejected
	}
	if question.Qtype == dns.TypeHTTPS {
		if strategy == DomainStrategyUseIPv4 || strategy == DomainStrategyUseIPv6 {
			for _, rr := range response.Answer {
				https, isHTTPS := rr.(*dns.HTTPS)
				if !isHTTPS {
					continue
				}
				content := https.SVCB
				content.Value = common.Filter(content.Value, func(it dns.SVCBKeyValue) bool {
					if strategy == DomainStrategyUseIPv4 {
						return it.Key() != dns.SVCB_IPV6HINT
					} else {
						return it.Key() != dns.SVCB_IPV4HINT
					}
				})
				https.SVCB = content
			}
		}
	}
	var timeToLive uint32
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			if timeToLive == 0 || record.Header().Ttl > 0 && record.Header().Ttl < timeToLive {
				timeToLive = record.Header().Ttl
			}
		}
	}
	if timeToLive < c.minCacheTTL {
		timeToLive = c.minCacheTTL
	}
	if timeToLive > c.maxCacheTTL {
		timeToLive = c.maxCacheTTL
	}
	if rewriteTTL, loaded := RewriteTTLFromContext(ctx); loaded {
		timeToLive = rewriteTTL
	}
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			record.Header().Ttl = timeToLive
		}
	}
	response.Id = messageId
	response.MsgHdr.Authoritative = true
	if !disableCache {
		c.storeCache(transport, question, response, int(timeToLive))
	}
	logExchangedResponse(c.logger, ctx, response, int(timeToLive))
	return response, err
}

func (c *Client) GetExactDomainFromHosts(ctx context.Context, domain string, nolog bool) string {
	if c.hosts == nil || domain == "" {
		return domain
	}
	for {
		cname, hasCNAME := c.hosts.CNAMEHosts[domain]
		if !hasCNAME {
			break
		}
		if !nolog && c.logger != nil {
			c.logger.DebugContext(ctx, "match CNAME hosts: ", domain, " => ", cname)
		}
		domain = cname
	}
	return domain
}

func (c *Client) GetAddrsFromHosts(ctx context.Context, domain string, stategy DomainStrategy, nolog bool) []netip.Addr {
	if c.hosts == nil || domain == "" {
		return nil
	}
	var addrs []netip.Addr
	ipv4Addrs, hasIPv4 := c.hosts.IPv4Hosts[domain]
	ipv6Addrs, hasIPv6 := c.hosts.IPv6Hosts[domain]
	if (!hasIPv4 && !hasIPv6) || (!hasIPv4 && stategy == DomainStrategyUseIPv4) || (!hasIPv6 && stategy == DomainStrategyUseIPv6) {
		return nil
	}
	if hasIPv4 && stategy != DomainStrategyUseIPv6 {
		ipAddrs := ipv4Addrs.addrs
		if !c.roundRobinCache {
			ipAddrs = ipv4Addrs.addrs
		} else {
			ipAddrs = ipv4Addrs.RoundRobin()
		}
		c.printIPHostsLog(ctx, domain, ipAddrs, nolog)
		addrs = append(addrs, ipAddrs...)
	}
	if hasIPv6 && stategy != DomainStrategyUseIPv4 {
		var ipAddrs []netip.Addr
		if !c.roundRobinCache {
			ipAddrs = ipv6Addrs.addrs
		} else {
			ipAddrs = ipv6Addrs.RoundRobin()
		}
		c.printIPHostsLog(ctx, domain, ipAddrs, nolog)
		addrs = append(addrs, ipAddrs...)
	}
	return addrs
}

func (c *Client) Lookup(ctx context.Context, transport Transport, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return c.LookupWithResponseCheck(ctx, transport, domain, strategy, nil)
}

func (c *Client) LookupWithResponseCheck(ctx context.Context, transport Transport, domain string, strategy DomainStrategy, responseChecker func(responseAddrs []netip.Addr) bool) ([]netip.Addr, error) {
	if dns.IsFqdn(domain) {
		domain = domain[:len(domain)-1]
	}
	dnsName := dns.Fqdn(domain)
	if transport.Raw() {
		if strategy == DomainStrategyUseIPv4 {
			return c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, strategy, responseChecker)
		} else if strategy == DomainStrategyUseIPv6 {
			return c.lookupToExchange(ctx, transport, dnsName, dns.TypeAAAA, strategy, responseChecker)
		}
		var response4 []netip.Addr
		var response6 []netip.Addr
		var group task.Group
		group.Append("exchange4", func(ctx context.Context) error {
			response, err := c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, strategy, responseChecker)
			if err != nil {
				return err
			}
			response4 = response
			return nil
		})
		group.Append("exchange6", func(ctx context.Context) error {
			response, err := c.lookupToExchange(ctx, transport, dnsName, dns.TypeAAAA, strategy, responseChecker)
			if err != nil {
				return err
			}
			response6 = response
			return nil
		})
		err := group.Run(ctx)
		if len(response4) == 0 && len(response6) == 0 {
			return nil, err
		}
		return sortAddresses(response4, response6, strategy), nil
	}
	isUpdateCache := GetUpdateDnsCacheFromContext(ctx)
	if isUpdateCache {
		return nil, nil
	}
	disableCache := c.disableCache || DisableCacheFromContext(ctx)
	if !disableCache && !isUpdateCache {
		if strategy == DomainStrategyUseIPv4 {
			response, _, err := c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}, transport)
			if err != ErrNotCached {
				return response, err
			}
		} else if strategy == DomainStrategyUseIPv6 {
			response, _, err := c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}, transport)
			if err != ErrNotCached {
				return response, err
			}
		} else {
			response4, _, _ := c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}, transport)
			response6, _, _ := c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}, transport)
			if len(response4) > 0 || len(response6) > 0 {
				return sortAddresses(response4, response6, strategy), nil
			}
		}
	}
	if responseChecker != nil && c.rdrc != nil {
		var rejected bool
		if strategy != DomainStrategyUseIPv6 {
			rejected = c.rdrc.LoadRDRC(transport.Name(), dnsName, dns.TypeA)
		}
		if !rejected && strategy != DomainStrategyUseIPv4 {
			rejected = c.rdrc.LoadRDRC(transport.Name(), dnsName, dns.TypeAAAA)
		}
		if rejected {
			return nil, ErrResponseRejectedCached
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	var rCode int
	response, err := transport.Lookup(ctx, domain, strategy)
	cancel()
	if err != nil {
		return nil, wrapError(err)
	}
	if responseChecker != nil && !responseChecker(response) {
		if c.rdrc != nil {
			if common.Any(response, func(addr netip.Addr) bool {
				return addr.Is4()
			}) {
				c.rdrc.SaveRDRCAsync(transport.Name(), dnsName, dns.TypeA, c.logger)
			}
			if common.Any(response, func(addr netip.Addr) bool {
				return addr.Is6()
			}) {
				c.rdrc.SaveRDRCAsync(transport.Name(), dnsName, dns.TypeAAAA, c.logger)
			}
		}
		return response, ErrResponseRejected
	}
	header := dns.MsgHdr{
		Response: true,
		Rcode:    rCode,
	}
	if !disableCache {
		var timeToLive uint32
		if rewriteTTL, loaded := RewriteTTLFromContext(ctx); loaded {
			timeToLive = rewriteTTL
		} else {
			timeToLive = DefaultTTL
		}
		if strategy != DomainStrategyUseIPv6 {
			question4 := dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			response4 := common.Filter(response, func(addr netip.Addr) bool {
				return addr.Is4() || addr.Is4In6()
			})
			message4 := &dns.Msg{
				MsgHdr:   header,
				Question: []dns.Question{question4},
			}
			if len(response4) > 0 {
				for _, address := range response4 {
					message4.Answer = append(message4.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   question4.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    timeToLive,
						},
						A: address.AsSlice(),
					})
				}
			}
			c.storeCache(transport, question4, message4, int(timeToLive))
		}
		if strategy != DomainStrategyUseIPv4 {
			question6 := dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}
			response6 := common.Filter(response, func(addr netip.Addr) bool {
				return addr.Is6() && !addr.Is4In6()
			})
			message6 := &dns.Msg{
				MsgHdr:   header,
				Question: []dns.Question{question6},
			}
			if len(response6) > 0 {
				for _, address := range response6 {
					message6.Answer = append(message6.Answer, &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   question6.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    DefaultTTL,
						},
						AAAA: address.AsSlice(),
					})
				}
			}
			c.storeCache(transport, question6, message6, int(timeToLive))
		}
	}
	return response, nil
}

func (c *Client) ClearCache() {
	if c.cache != nil {
		c.cache.Clear()
	}
	if c.transportCache != nil {
		c.transportCache.Clear()
	}
}

func (c *Client) LookupCache(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, bool, bool) {
	if c.independentCache {
		return nil, false, false
	}
	disableCache := c.disableCache || DisableCacheFromContext(ctx)
	if disableCache {
		return nil, false, false
	}
	if dns.IsFqdn(domain) {
		domain = domain[:len(domain)-1]
	}
	dnsName := dns.Fqdn(domain)
	if strategy == DomainStrategyUseIPv4 {
		response, ttl, err := c.questionCache(dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}, nil)
		if err != ErrNotCached {
			return response, true, ttl <= 1
		}
	} else if strategy == DomainStrategyUseIPv6 {
		response, ttl, err := c.questionCache(dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeAAAA,
			Qclass: dns.ClassINET,
		}, nil)
		if err != ErrNotCached {
			return response, true, ttl <= 1
		}
	} else {
		response4, ttl4, _ := c.questionCache(dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}, nil)
		response6, ttl6, _ := c.questionCache(dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeAAAA,
			Qclass: dns.ClassINET,
		}, nil)
		if len(response4) > 0 || len(response6) > 0 {
			if ttl6 > ttl4 {
				ttl4 = ttl6
			}
			return sortAddresses(response4, response6, strategy), true, ttl4 <= 1
		}
	}
	return nil, false, false
}

func (c *Client) ExchangeCache(ctx context.Context, message *dns.Msg) (*dns.Msg, bool, bool) {
	if c.independentCache || len(message.Question) != 1 {
		return nil, false, false
	}
	question := message.Question[0]
	_, clientSubnetLoaded := transportNameFromContext(ctx)
	isSimpleRequest := len(message.Question) == 1 &&
		len(message.Ns) == 0 &&
		len(message.Extra) == 0 &&
		!clientSubnetLoaded
	disableCache := !isSimpleRequest || c.disableCache || DisableCacheFromContext(ctx)
	if disableCache {
		return nil, false, false
	}
	response, ttl := c.loadResponse(question, nil)
	if response == nil {
		return nil, false, false
	}
	logCachedResponse(c.logger, ctx, response, ttl)
	response.Id = message.Id
	return response, true, ttl <= 1
}

func sortAddresses(response4 []netip.Addr, response6 []netip.Addr, strategy DomainStrategy) []netip.Addr {
	if strategy == DomainStrategyPreferIPv6 {
		return append(response6, response4...)
	} else {
		return append(response4, response6...)
	}
}

func (c *Client) storeCache(transport Transport, question dns.Question, message *dns.Msg, timeToLive int) {
	if timeToLive == 0 {
		return
	}
	pdnsMsg := &dnsMsg{
		msg: message,
	}
	if c.disableExpire {
		if !c.independentCache {
			c.cache.Store(question, pdnsMsg)
		} else {
			c.transportCache.Store(transportCacheKey{
				Question:      question,
				transportName: transport.Name(),
			}, pdnsMsg)
		}
		return
	}
	expireAt := time.Now().Add(time.Second * time.Duration(timeToLive))
	pdnsMsg.expiredTime = expireAt
	if c.useStaleCache {
		expireAt = expireAt.Add(time.Second * time.Duration(c.staleCache))
	}
	if !c.independentCache {
		c.cache.StoreWithExpire(question, pdnsMsg, expireAt)
	} else {
		c.transportCache.StoreWithExpire(transportCacheKey{
			Question:      question,
			transportName: transport.Name(),
		}, pdnsMsg, expireAt)
	}
}

func (c *Client) exchangeToLookup(ctx context.Context, transport Transport, message *dns.Msg, question dns.Question) (*dns.Msg, error) {
	domain := question.Name
	var strategy DomainStrategy
	if question.Qtype == dns.TypeA {
		strategy = DomainStrategyUseIPv4
	} else {
		strategy = DomainStrategyUseIPv6
	}
	result, err := c.Lookup(ctx, transport, domain, strategy)
	if err != nil {
		return nil, wrapError(err)
	}
	var timeToLive uint32
	if rewriteTTL, loaded := RewriteTTLFromContext(ctx); loaded {
		timeToLive = rewriteTTL
	} else {
		timeToLive = DefaultTTL
	}
	return FixedResponse(message.Id, question, result, timeToLive), nil
}

func (c *Client) lookupToExchange(ctx context.Context, transport Transport, name string, qType uint16, strategy DomainStrategy, responseChecker func(responseAddrs []netip.Addr) bool) ([]netip.Addr, error) {
	question := dns.Question{
		Name:   name,
		Qtype:  qType,
		Qclass: dns.ClassINET,
	}
	isUpdateCache := GetUpdateDnsCacheFromContext(ctx)
	disableCache := c.disableCache || DisableCacheFromContext(ctx)
	if !disableCache && !isUpdateCache {
		cachedAddresses, _, err := c.questionCache(question, transport)
		if err != ErrNotCached {
			return cachedAddresses, err
		}
	}
	message := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: []dns.Question{question},
	}
	var (
		response *dns.Msg
		err      error
	)
	if responseChecker != nil {
		response, err = c.ExchangeWithResponseCheck(ctx, transport, message, strategy, func(response *dns.Msg) bool {
			addresses, addrErr := MessageToAddresses(response)
			if addrErr != nil {
				return false
			}
			return responseChecker(addresses)
		})
	} else {
		response, err = c.Exchange(ctx, transport, message, strategy)
	}
	if response == nil || err != nil {
		return nil, err
	}
	return MessageToAddresses(response)
}

func (c *Client) questionCache(question dns.Question, transport Transport) ([]netip.Addr, int, error) {
	response, ttl := c.loadResponse(question, transport)
	if response == nil {
		return nil, 0, ErrNotCached
	}
	addr, err := MessageToAddresses(response)
	return addr, ttl, err
}

func (c *Client) getRoundRobin(response *dnsMsg) *dns.Msg {
	if c.roundRobinCache {
		return response.RoundRobin()
	} else {
		return response.msg.Copy()
	}
}

func (c *Client) loadResponse(question dns.Question, transport Transport) (*dns.Msg, int) {
	var (
		resp     *dnsMsg
		response *dns.Msg
		loaded   bool
	)
	if c.disableExpire {
		if !c.independentCache {
			resp, loaded = c.cache.Load(question)
		} else {
			resp, loaded = c.transportCache.Load(transportCacheKey{
				Question:      question,
				transportName: transport.Name(),
			})
		}
		if !loaded {
			return nil, 0
		}
		return c.getRoundRobin(resp), 0
	} else {
		var expireAt time.Time
		if !c.independentCache {
			resp, expireAt, loaded = c.cache.LoadWithExpire(question)
		} else {
			resp, expireAt, loaded = c.transportCache.LoadWithExpire(transportCacheKey{
				Question:      question,
				transportName: transport.Name(),
			})
		}
		if !loaded {
			return nil, 0
		}
		timeNow := time.Now()
		if timeNow.After(expireAt) {
			if !c.independentCache {
				c.cache.Delete(question)
			} else {
				c.transportCache.Delete(transportCacheKey{
					Question:      question,
					transportName: transport.Name(),
				})
			}
			return nil, 0
		}
		response = c.getRoundRobin(resp)
		if c.useStaleCache {
			expireAt = resp.expiredTime
			if timeNow.After(expireAt) {
				for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
					for _, record := range recordList {
						record.Header().Ttl = 1
					}
				}
				return response, 1
			}
		}
		var originTTL int
		for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
			for _, record := range recordList {
				if originTTL == 0 || record.Header().Ttl > 0 && int(record.Header().Ttl) < originTTL {
					originTTL = int(record.Header().Ttl)
				}
			}
		}
		nowTTL := int(expireAt.Sub(timeNow).Seconds())
		if nowTTL < 0 {
			nowTTL = 0
		}
		if originTTL > 0 {
			duration := uint32(originTTL - nowTTL)
			for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range recordList {
					record.Header().Ttl = record.Header().Ttl - duration
				}
			}
		} else {
			for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range recordList {
					record.Header().Ttl = uint32(nowTTL)
				}
			}
		}
		return response, nowTTL
	}
}

func MessageToAddresses(response *dns.Msg) ([]netip.Addr, error) {
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return nil, RCodeError(response.Rcode)
	}
	addresses := make([]netip.Addr, 0, len(response.Answer))
	for _, rawAnswer := range response.Answer {
		switch answer := rawAnswer.(type) {
		case *dns.A:
			addresses = append(addresses, M.AddrFromIP(answer.A))
		case *dns.AAAA:
			addresses = append(addresses, M.AddrFromIP(answer.AAAA))
		case *dns.HTTPS:
			for _, value := range answer.SVCB.Value {
				if value.Key() == dns.SVCB_IPV4HINT || value.Key() == dns.SVCB_IPV6HINT {
					addresses = append(addresses, common.Map(strings.Split(value.String(), ","), M.ParseAddr)...)
				}
			}
		}
	}
	return addresses, nil
}

func wrapError(err error) error {
	switch dnsErr := err.(type) {
	case *net.DNSError:
		if dnsErr.IsNotFound {
			return RCodeNameError
		}
	case *net.AddrError:
		return RCodeNameError
	}
	return err
}
