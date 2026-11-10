export interface Vulnerability {
  id: string;
  cveId: string;
  title: string;
  description: string;
  cvss: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  publishedAt: string;
  affected: string[];
  vendor: string;
  exploitedInWild: boolean;
  patchAvailable: boolean;
  source: 'KISA' | 'NVD' | 'CISA' | 'VENDOR';
  solution: string;
  references: string[];
}

export const INITIAL_VULNS: Vulnerability[] = [
  {
    id: 'v1',
    cveId: 'CVE-2026-24108',
    title: '리눅스 커널 eBPF 서브시스템 권한 상승 취약점',
    description: 'Linux 커널의 eBPF 검증기(verifier) 내 경계 검사 오류로 인해 로컬 권한 없는 사용자가 root 권한을 획득할 수 있는 취약점입니다.',
    cvss: 9.8,
    severity: 'CRITICAL',
    publishedAt: '2026-11-07 10:20',
    affected: ['Linux Kernel 6.1 ~ 6.12', 'Ubuntu 24.04 LTS', 'RHEL 9.x'],
    vendor: 'Linux Foundation',
    exploitedInWild: true,
    patchAvailable: true,
    source: 'KISA',
    solution: '커널 버전 6.12.8 이상으로 즉시 업그레이드하고 unprivileged_bpf_disabled 설정을 1로 적용하십시오.',
    references: ['https://www.boho.or.kr', 'https://nvd.nist.gov/vuln/detail/CVE-2026-24108']
  },
  {
    id: 'v2',
    cveId: 'CVE-2026-31902',
    title: 'Google Chrome V8 엔진 원격 코드 실행(RCE) 0-day',
    description: 'Chrome V8 자바스크립트 엔진의 Type Confusion 버그로 인해 특수 제작된 웹페이지 방문 시 브라우저 샌드박스를 우회하고 악성 코드가 실행될 수 있습니다.',
    cvss: 8.8,
    severity: 'HIGH',
    publishedAt: '2026-11-06 18:45',
    affected: ['Chrome < 131.0.6778.86', 'Edge < 131.0.2903.70', 'Whale < 3.28'],
    vendor: 'Google',
    exploitedInWild: true,
    patchAvailable: true,
    source: 'CISA',
    solution: '모바일 및 데스크톱 브라우저를 최신 업데이트(131.0.6778.86 이상)로 재시작 및 업데이트 적용 권장.',
    references: ['https://chromereleases.googleblog.com', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog']
  },
  {
    id: 'v3',
    cveId: 'CVE-2026-28104',
    title: 'Spring Framework WebClient SSRF 취약점',
    description: 'Spring Framework의 WebClient 구현체에서 URL 검증 미흡으로 인해 내부 사설망 서비스에 불법 접근이 가능한 서버 사이드 요청 위조(SSRF) 취약점입니다.',
    cvss: 7.5,
    severity: 'HIGH',
    publishedAt: '2026-11-05 14:10',
    affected: ['Spring Framework 6.0.0 ~ 6.1.13', 'Spring Boot 3.2.x'],
    vendor: 'VMware Spring',
    exploitedInWild: false,
    patchAvailable: true,
    source: 'NVD',
    solution: 'Spring Boot 3.3.5 또는 Spring Framework 6.1.14 이상으로 의존성을 업데이트하십시오.',
    references: ['https://spring.io/security/cve-2026-28104']
  },
  {
    id: 'v4',
    cveId: 'CVE-2026-19033',
    title: 'OpenSSL 취약한 개인키 복원 부채널 공격 취약점',
    description: 'OpenSSL의 ECDSA 서명 알고리즘 처리 중 타이밍 부채널 정보 누출로 인해 공격자가 비밀키 정보를 복원할 수 있는 위험이 보고되었습니다.',
    cvss: 5.9,
    severity: 'MEDIUM',
    publishedAt: '2026-11-04 09:30',
    affected: ['OpenSSL 3.0.0 ~ 3.0.15', 'OpenSSL 3.3.0 ~ 3.3.2'],
    vendor: 'OpenSSL Project',
    exploitedInWild: false,
    patchAvailable: true,
    source: 'VENDOR',
    solution: 'OpenSSL 3.3.3 버전 이상 보안 패치 적용.',
    references: ['https://www.openssl.org/news/secadv/']
  },
  {
    id: 'v5',
    cveId: 'CVE-2026-30211',
    title: 'Apple iOS / iPadOS WebKit 메모리 손상 취약점',
    description: '모바일 사파리 및 WebKit 기반 앱에서 웹 콘텐츠 처리 중 발생하는 Use-After-Free 취약점으로, 임의 코드 실행 위험이 존재합니다.',
    cvss: 9.1,
    severity: 'CRITICAL',
    publishedAt: '2026-11-03 21:00',
    affected: ['iOS < 18.1.1', 'iPadOS < 18.1.1', 'macOS Sequoia < 15.1.1'],
    vendor: 'Apple',
    exploitedInWild: true,
    patchAvailable: true,
    source: 'KISA',
    solution: 'iOS 18.1.1 또는 iPadOS 18.1.1 소프트웨어 최신 업데이트 수행.',
    references: ['https://support.apple.com/en-us/HT201222']
  },
  {
    id: 'v6',
    cveId: 'CVE-2026-27150',
    title: 'Apache Tomcat HTTP/2 DoS 서비스 거부 취약점',
    description: '과도한 HTTP/2 스트림 요청 제어 결함으로 인해 Tomcat 데몬의 CPU 점유율이 100%에 달하여 서비스 거부 상태를 유발할 수 있습니다.',
    cvss: 6.5,
    severity: 'MEDIUM',
    publishedAt: '2026-11-02 11:20',
    affected: ['Apache Tomcat 9.0.80 ~ 9.0.96', '10.1.0 ~ 10.1.31'],
    vendor: 'Apache Software Foundation',
    exploitedInWild: false,
    patchAvailable: true,
    source: 'NVD',
    solution: 'Tomcat 10.1.32 또는 9.0.97 버전으로 업그레이드 조치.',
    references: ['https://tomcat.apache.org/security-10.html']
  }
];

const CACHE_KEY = 'secvigil_cve_live_cache';
const CACHE_TTL_MS = 5 * 60 * 1000; // 5분 캐시

interface NvdCveItem {
  cve: {
    id: string;
    sourceIdentifier?: string;
    published?: string;
    lastModified?: string;
    vulnStatus?: string;
    descriptions?: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
      cvssMetricV40?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
      cvssMetricV30?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
      cvssMetricV2?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
    };
    weaknesses?: Array<{ description: Array<{ lang: string; value: string }> }>;
    configurations?: Array<{
      nodes?: Array<{
        cpeMatch?: Array<{ criteria: string }>;
      }>;
    }>;
    references?: Array<{ url: string; source?: string }>;
    cisaExploitAdd?: string;
    cisaActionDue?: string;
    cisaRequiredAction?: string;
  };
}

function parseVendor(sourceIdentifier?: string, desc?: string, refs?: string[]): string {
  if (sourceIdentifier) {
    const src = sourceIdentifier.toLowerCase();
    if (src.includes('redhat')) return 'Red Hat';
    if (src.includes('wordfence')) return 'WordPress / Wordfence';
    if (src.includes('zyxel')) return 'Zyxel';
    if (src.includes('google') || src.includes('chrome')) return 'Google';
    if (src.includes('microsoft')) return 'Microsoft';
    if (src.includes('apple')) return 'Apple';
    if (src.includes('oracle')) return 'Oracle';
    if (src.includes('apache')) return 'Apache';
    if (src.includes('cisco')) return 'Cisco';
    if (src.includes('github')) return 'GitHub';
    if (src.includes('kisa') || src.includes('kr')) return 'KISA KrCERT';
  }

  if (refs && refs.length > 0) {
    try {
      const hostname = new URL(refs[0]).hostname.replace('www.', '');
      const parts = hostname.split('.');
      if (parts.length >= 2) {
        return parts[0].charAt(0).toUpperCase() + parts[0].slice(1);
      }
    } catch {
      // ignore
    }
  }

  if (desc) {
    const match = desc.match(/\b(in|of|for)\s+([A-Z][A-Za-z0-9-_]+(?:\s+[A-Z][A-Za-z0-9-_]+)?)/);
    if (match && match[2]) {
      return match[2].trim();
    }
  }

  return 'Global Vendor';
}

function parseAffected(desc: string, config?: NvdCveItem['cve']['configurations']): string[] {
  const affected: string[] = [];

  if (config && config.length > 0) {
    for (const node of config) {
      if (node.nodes) {
        for (const sub of node.nodes) {
          if (sub.cpeMatch) {
            for (const match of sub.cpeMatch.slice(0, 3)) {
              const parts = match.criteria.split(':');
              if (parts.length > 4) {
                const vendor = parts[3];
                const product = parts[4];
                const version = parts[5] && parts[5] !== '*' ? parts[5] : '';
                affected.push(`${vendor} ${product} ${version}`.trim());
              }
            }
          }
        }
      }
    }
  }

  if (affected.length === 0 && desc) {
    const versionMatch = desc.match(/(before\s+[\d.]+|version[s]?\s+[\d.~x]+|through\s+[\d.]+)/i);
    if (versionMatch) {
      affected.push(versionMatch[0]);
    } else {
      affected.push('상세 버전 보안 권고문 참조');
    }
  }

  return affected.length > 0 ? affected.slice(0, 3) : ['영향 버전 확인 중'];
}

function parseNvdItem(item: NvdCveItem): Vulnerability {
  const cve = item.cve;
  const descObj = cve.descriptions?.find((d) => d.lang === 'en') || cve.descriptions?.[0];
  const description = descObj?.value || '상세 취약점 설명이 제공되지 않았습니다.';

  // CVSS
  const cvssObj =
    cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV40?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV2?.[0]?.cvssData;

  const cvss = cvssObj?.baseScore ? Number(cvssObj.baseScore.toFixed(1)) : 6.0;
  let severity: Vulnerability['severity'] = 'MEDIUM';
  if (cvss >= 9.0) severity = 'CRITICAL';
  else if (cvss >= 7.0) severity = 'HIGH';
  else if (cvss >= 4.0) severity = 'MEDIUM';
  else severity = 'LOW';

  // Title extraction
  const cwe = cve.weaknesses?.[0]?.description?.find((w) => w.value.startsWith('CWE-'))?.value;
  const firstSentence = description.split(/\.\s+/)[0]?.trim();
  let title = firstSentence;
  if (!title || title.length > 120) {
    title = (firstSentence ? firstSentence.slice(0, 100) : description.slice(0, 100)) + '...';
  }
  if (cwe && !title.includes(cwe)) {
    title = `[${cwe}] ${title}`;
  }

  // Published At
  const rawDate = cve.published || new Date().toISOString();
  const datePart = rawDate.split('T')[0];
  const timePart = (rawDate.split('T')[1] || '00:00').slice(0, 5);
  const publishedAt = `${datePart} ${timePart}`;

  // Exploited in wild
  const exploitedInWild = Boolean(cve.cisaExploitAdd);

  // Source
  let source: Vulnerability['source'] = 'NVD';
  if (cve.cisaExploitAdd) source = 'CISA';
  else if (cve.sourceIdentifier?.toLowerCase().includes('kisa') || cve.sourceIdentifier?.toLowerCase().includes('kr')) source = 'KISA';
  else if (cve.sourceIdentifier?.includes('@')) source = 'VENDOR';

  // References
  const references = cve.references?.map((r) => r.url).filter(Boolean) || [
    `https://nvd.nist.gov/vuln/detail/${cve.id}`
  ];

  // Vendor & Affected
  const vendor = parseVendor(cve.sourceIdentifier, description, references);
  const affected = parseAffected(description, cve.configurations);

  // Solution
  const solution =
    cve.cisaRequiredAction ||
    '해당 벤더사 공식 보안 권고를 확인하고 최신 패치 버전을 적용하십시오.';

  return {
    id: `nvd-${cve.id}`,
    cveId: cve.id,
    title,
    description,
    cvss,
    severity,
    publishedAt,
    affected,
    vendor,
    exploitedInWild,
    patchAvailable: true,
    source,
    solution,
    references: references.slice(0, 4)
  };
}

export interface FetchResult {
  vulnerabilities: Vulnerability[];
  isLive: boolean;
  lastUpdated: string;
  sourceType: 'API' | 'CACHE' | 'FALLBACK';
  error?: string;
}

export async function fetchLiveVulnerabilities(forceRefresh = false): Promise<FetchResult> {
  const now = new Date();
  const currentTimeStr = now.toLocaleTimeString('ko-KR', { hour12: false });

  // 1. 캐시 확인
  if (!forceRefresh) {
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (cached) {
        const parsed = JSON.parse(cached);
        if (parsed.timestamp && Date.now() - parsed.timestamp < CACHE_TTL_MS && Array.isArray(parsed.data)) {
          return {
            vulnerabilities: parsed.data,
            isLive: true,
            lastUpdated: parsed.lastUpdated || currentTimeStr,
            sourceType: 'CACHE'
          };
        }
      }
    } catch {
      // ignore localStorage errors
    }
  }

  // 2. NVD API 호출 (최근 7일치 취약점 우선 요청)
  try {
    const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const endDate = now.toISOString();

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${encodeURIComponent(
      startDate
    )}&pubEndDate=${encodeURIComponent(endDate)}&resultsPerPage=25&noRejected`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8초 타임아웃

    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        Accept: 'application/json'
      }
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`NVD API 응답 코드: ${response.status}`);
    }

    const json = await response.json();
    const rawItems: NvdCveItem[] = json.vulnerabilities || [];

    const fetchedVulns = rawItems.map(parseNvdItem);

    // 최신 등록 순 내림차순 정렬
    fetchedVulns.sort((a, b) => b.publishedAt.localeCompare(a.publishedAt));

    // 기존 중요/한국형 취약점(INITIAL_VULNS)과 결합하되 중복 제거
    const combinedMap = new Map<string, Vulnerability>();
    for (const v of fetchedVulns) {
      combinedMap.set(v.cveId, v);
    }
    for (const v of INITIAL_VULNS) {
      if (!combinedMap.has(v.cveId)) {
        combinedMap.set(v.cveId, v);
      }
    }

    const finalVulns = Array.from(combinedMap.values());
    // 최신 날짜순 정렬
    finalVulns.sort((a, b) => b.publishedAt.localeCompare(a.publishedAt));

    // 캐시 저장
    try {
      localStorage.setItem(
        CACHE_KEY,
        JSON.stringify({
          data: finalVulns,
          timestamp: Date.now(),
          lastUpdated: currentTimeStr
        })
      );
    } catch {
      // ignore storage quota
    }

    return {
      vulnerabilities: finalVulns,
      isLive: true,
      lastUpdated: currentTimeStr,
      sourceType: 'API'
    };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : '네트워크 오류';
    console.warn('NVD API 실시간 조회 실패, 캐시 또는 기본 데이터 사용:', errorMsg);

    // 실패 시 로컬 캐시 조회
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (cached) {
        const parsed = JSON.parse(cached);
        if (Array.isArray(parsed.data) && parsed.data.length > 0) {
          return {
            vulnerabilities: parsed.data,
            isLive: false,
            lastUpdated: parsed.lastUpdated || currentTimeStr,
            sourceType: 'CACHE',
            error: errorMsg
          };
        }
      }
    } catch {
      // ignore
    }

    // 최종 Fallback: 초기 고정 데이터
    return {
      vulnerabilities: INITIAL_VULNS,
      isLive: false,
      lastUpdated: currentTimeStr,
      sourceType: 'FALLBACK',
      error: errorMsg
    };
  }
}

// 특정 CVE ID 직접 검색 API
export async function searchCveById(cveId: string): Promise<Vulnerability | null> {
  const cleaned = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d+$/i.test(cleaned)) {
    return null;
  }

  try {
    const response = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cleaned)}`
    );
    if (!response.ok) return null;
    const json = await response.json();
    const item = json.vulnerabilities?.[0];
    if (item) {
      return parseNvdItem(item);
    }
  } catch {
    // ignore
  }
  return null;
}
