package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/oschwald/geoip2-golang"
	"go4.org/netipx"
)

const (
	ClassReject     = iota
	ClassCleanCN
	ClassOverseas
)

var (
	cleanBuilder    netipx.IPSetBuilder
	overseasBuilder netipx.IPSetBuilder
	rejectCount     int
	approvedASNs    = make(map[uint]bool)
)

func main() {
	fmt.Println("📜 正在加载人工绝对筛选的 ASN 白名单底册...")
	loadApprovedASNs("source_unique_asns.txt")
	fmt.Printf("✅ 成功加载 %d 个绝对信任的 ASN。\n", len(approvedASNs))

	countryDB, err := geoip2.Open("GeoLite2-Country.mmdb")
	if err != nil {
		log.Fatalf("无法打开 GeoLite2-Country.mmdb: %v", err)
	}
	defer countryDB.Close()

	asnDB, err := geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		log.Fatalf("无法打开 GeoLite2-ASN.mmdb: %v", err)
	}
	defer asnDB.Close()

	inFile, err := os.Open("chinamax_cidr.txt")
	if err != nil {
		log.Fatalf("无法打开源文件 chinamax_cidr.txt: %v", err)
	}
	defer inFile.Close()

	scanner := bufio.NewScanner(inFile)
	fmt.Println("🚀 绝对白名单分流引擎已启动，正在执行跨国切割与内存加载...")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ip, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			ip = net.ParseIP(line)
			if ip == nil {
				continue
			}
			maskLen := 32
			if ip.To4() == nil {
				maskLen = 128
			}
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(maskLen, maskLen*8)}
		}

		if ip4 := ipNet.IP.To4(); ip4 != nil {
			ipNet.IP = ip4
		}

		auditCIDR(ipNet, countryDB, asnDB)
	}

	fmt.Println("🔄 正在执行全局路由聚合、去重与合并压缩...")

	cleanOut, _ := os.Create("clean_cn_whitelisted.txt")
	cleanSet, _ := cleanBuilder.IPSet()
	for _, p := range cleanSet.Prefixes() {
		cleanOut.WriteString(p.String() + "\n")
	}
	cleanOut.Close()

	overseasOut, _ := os.Create("overseas_but_whitelisted.txt")
	overseasSet, _ := overseasBuilder.IPSet()
	for _, p := range overseasSet.Prefixes() {
		overseasOut.WriteString(p.String() + "\n")
	}
	overseasOut.Close()

	fmt.Println("\n========================= 聚合过滤最终报告 =========================")
	fmt.Printf("✅ [放行直连] 国内纯净段 (合并去重后) : %d 条\n", len(cleanSet.Prefixes()))
	fmt.Printf("⚠️ [隔离代理] 白名单出海段 (合并去重后) : %d 条\n", len(overseasSet.Prefixes()))
	fmt.Printf("❌ [无情斩杀] 不在白名单内的脏数据拦截次数 : %d 次\n", rejectCount)
	fmt.Println("====================================================================")
}

func loadApprovedASNs(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("无法打开白名单文件 %s: %v", filename, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, " ", 2)
		if len(parts) > 0 && strings.HasPrefix(parts[0], "AS") {
			asnStr := parts[0][2:]
			asnInt, err := strconv.ParseUint(asnStr, 10, 32)
			if err == nil {
				approvedASNs[uint(asnInt)] = true
			}
		}
	}
}

func auditCIDR(ipNet *net.IPNet, countryDB *geoip2.Reader, asnDB *geoip2.Reader) {
	parentClass := evaluateSubnet(ipNet.IP, countryDB, asnDB)

	ones, bits := ipNet.Mask.Size()
	targetOnes := 24
	if bits == 128 {
		if ones >= 48 && ones < 64 {
			targetOnes = 64
		} else if ones >= 64 {
			targetOnes = ones
		} else {
			targetOnes = ones
		}
	}

	if ones >= targetOnes {
		pushToPipeline(parentClass, ipNet.String())
		return
	}

	left, right := splitCIDR(ipNet)
	leftClass := evaluateSubnet(left.IP, countryDB, asnDB)
	rightClass := evaluateSubnet(right.IP, countryDB, asnDB)

	if leftClass == parentClass && rightClass == parentClass {
		pushToPipeline(parentClass, ipNet.String())
		return
	}

	auditCIDR(left, countryDB, asnDB)
	auditCIDR(right, countryDB, asnDB)
}

func evaluateSubnet(ip net.IP, countryDB *geoip2.Reader, asnDB *geoip2.Reader) int {
	asnRecord, err := asnDB.ASN(ip)
	if err != nil || asnRecord.AutonomousSystemNumber == 0 || !approvedASNs[asnRecord.AutonomousSystemNumber] {
		return ClassReject
	}

	countryRecord, err := countryDB.Country(ip)
	if err == nil && countryRecord.Country.IsoCode == "CN" {
		return ClassCleanCN
	}

	return ClassOverseas
}

func pushToPipeline(class int, cidrStr string) {
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return
	}
	switch class {
	case ClassCleanCN:
		cleanBuilder.AddPrefix(prefix)
	case ClassOverseas:
		overseasBuilder.AddPrefix(prefix)
	case ClassReject:
		rejectCount++
	}
}

func splitCIDR(ipNet *net.IPNet) (*net.IPNet, *net.IPNet) {
	ones, bits := ipNet.Mask.Size()
	if ones >= bits {
		return ipNet, nil
	}
	newOnes := ones + 1

	leftIP := make(net.IP, len(ipNet.IP))
	copy(leftIP, ipNet.IP)
	left := &net.IPNet{IP: leftIP, Mask: net.CIDRMask(newOnes, bits)}

	rightIP := make(net.IP, len(ipNet.IP))
	copy(rightIP, ipNet.IP)
	byteIdx := (newOnes - 1) / 8
	bitIdx := 7 - ((newOnes - 1) % 8)
	rightIP[byteIdx] |= (1 << bitIdx)
	right := &net.IPNet{IP: rightIP, Mask: net.CIDRMask(newOnes, bits)}

	return left, right
}
