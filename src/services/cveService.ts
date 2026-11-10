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

export function isWithinLast7Days(publishedAt: string): boolean {
  try {
    const datePart = publishedAt.split(' ')[0];
    if (!datePart) return false;
    const pubTime = new Date(`${datePart}T00:00:00.000Z`).getTime();
    const now = new Date();
    const nowDateOnly = new Date(now.toISOString().split('T')[0] + 'T23:59:59.999Z').getTime();
    const sevenDaysAgo = nowDateOnly - 7 * 24 * 60 * 60 * 1000;
    return pubTime >= sevenDaysAgo;
  } catch {
    return false;
  }
}

const CACHE_KEY = 'secvigil_vulncheck_live_7days_v1';
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
    if (src.includes('kisa') || src.includes('kr') || src.includes('krcert')) return 'KISA KrCERT';
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

  // CVSS 점수 추출
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

  // CWE 및 타이틀 추출
  const cwe = cve.weaknesses?.[0]?.description?.find((w) => w.value.startsWith('CWE-'))?.value;
  const firstSentence = description.split(/\.\s+/)[0]?.trim();
  let title = firstSentence;
  if (!title || title.length > 120) {
    title = (firstSentence ? firstSentence.slice(0, 100) : description.slice(0, 100)) + '...';
  }
  if (cwe && !title.includes(cwe)) {
    title = `[${cwe}] ${title}`;
  }

  // 등록 일자
  const rawDate = cve.published || new Date().toISOString();
  const datePart = rawDate.split('T')[0];
  const timePart = (rawDate.split('T')[1] || '00:00').slice(0, 5);
  const publishedAt = `${datePart} ${timePart}`;

  // 악용 여부
  const exploitedInWild = Boolean(cve.cisaExploitAdd);

  // 참고 링크
  const references = cve.references?.map((r) => r.url).filter(Boolean) || [
    `https://nvd.nist.gov/vuln/detail/${cve.id}`
  ];

  // 출처 분류 (KISA, CISA, VENDOR, NVD)
  let source: Vulnerability['source'] = 'NVD';
  const srcLower = (cve.sourceIdentifier || '').toLowerCase();
  const descLower = description.toLowerCase();
  const hasKrRef = references.some((r) => r.includes('krcert.or.kr') || r.includes('boho.or.kr') || r.includes('.kr/'));

  if (cve.cisaExploitAdd) {
    source = 'CISA';
  } else if (
    srcLower.includes('kisa') ||
    srcLower.includes('krcert') ||
    srcLower.includes('.kr') ||
    descLower.includes('krcert') ||
    descLower.includes('kisa') ||
    hasKrRef
  ) {
    source = 'KISA';
  } else if (cve.sourceIdentifier?.includes('@')) {
    source = 'VENDOR';
  }

  // 벤더 및 영향 시스템
  const vendor = parseVendor(cve.sourceIdentifier, description, references);
  const affected = parseAffected(description, cve.configurations);

  // 조치 방안
  const solution =
    cve.cisaRequiredAction ||
    '해당 벤더사 및 공식 보안 기관(KISA/VulnCheck)의 최신 패치 버전을 확인하여 즉시 업데이트하십시오.';

  return {
    id: `vulncheck-${cve.id}`,
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
  sourceType: 'API' | 'CACHE' | 'EMPTY';
  kisaCount: number;
  error?: string;
}

function getAuthHeaders(): Record<string, string> {
  const apiKey = (typeof window !== 'undefined' ? localStorage.getItem('vulncheck_api_key') : '') || '';
  const headers: Record<string, string> = {
    Accept: 'application/json'
  };
  if (apiKey) {
    headers['apiKey'] = apiKey;
  }
  return headers;
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
          const valid7Days = parsed.data.filter((v: Vulnerability) => isWithinLast7Days(v.publishedAt));
          const kisaCount = valid7Days.filter((v: Vulnerability) => v.source === 'KISA').length;
          return {
            vulnerabilities: valid7Days,
            isLive: true,
            lastUpdated: parsed.lastUpdated || currentTimeStr,
            sourceType: 'CACHE',
            kisaCount
          };
        }
      }
    } catch {
      // ignore localStorage errors
    }
  }

  // 2. VulnCheck Community API 호출 (NVD 2.0 호환 엔드포인트 + CORS 프록시 우회)
  try {
    const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const endDate = now.toISOString();

    const apiUrl = `https://api.vulncheck.com/rest/json/cves/2.0?pubStartDate=${encodeURIComponent(
      startDate
    )}&pubEndDate=${encodeURIComponent(endDate)}&resultsPerPage=50&noRejected`;

    const proxyUrl = `https://corsproxy.io/?${encodeURIComponent(apiUrl)}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 9000); // 9초 타임아웃

    const response = await fetch(proxyUrl, {
      signal: controller.signal,
      headers: getAuthHeaders()
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`VulnCheck API 응답 코드: ${response.status}`);
    }

    const json = await response.json();
    const rawItems: NvdCveItem[] = json.vulnerabilities || [];

    const fetchedVulns = rawItems.map(parseNvdItem);
    const finalVulns = fetchedVulns.filter((v) => isWithinLast7Days(v.publishedAt));
    finalVulns.sort((a, b) => b.publishedAt.localeCompare(a.publishedAt));

    const kisaCount = finalVulns.filter((v) => v.source === 'KISA').length;

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
      sourceType: 'API',
      kisaCount
    };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : '네트워크 오류';
    console.warn('VulnCheck API 실시간 조회 실패:', errorMsg);

    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (cached) {
        const parsed = JSON.parse(cached);
        if (Array.isArray(parsed.data) && parsed.data.length > 0) {
          const valid7Days = parsed.data.filter((v: Vulnerability) => isWithinLast7Days(v.publishedAt));
          return {
            vulnerabilities: valid7Days,
            isLive: false,
            lastUpdated: parsed.lastUpdated || currentTimeStr,
            sourceType: 'CACHE',
            kisaCount: valid7Days.filter((v: Vulnerability) => v.source === 'KISA').length,
            error: errorMsg
          };
        }
      }
    } catch {
      // ignore
    }

    return {
      vulnerabilities: [],
      isLive: false,
      lastUpdated: currentTimeStr,
      sourceType: 'EMPTY',
      kisaCount: 0,
      error: errorMsg
    };
  }
}

// 특정 CVE ID 직접 검색 API (VulnCheck NVD 호환 엔드포인트)
export async function searchCveById(cveId: string): Promise<Vulnerability | null> {
  const cleaned = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d+$/i.test(cleaned)) {
    return null;
  }

  try {
    const apiUrl = `https://api.vulncheck.com/rest/json/cves/2.0?cveId=${encodeURIComponent(cleaned)}`;
    const proxyUrl = `https://corsproxy.io/?${encodeURIComponent(apiUrl)}`;
    const response = await fetch(proxyUrl, {
      headers: getAuthHeaders()
    });
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
