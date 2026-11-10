import { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  Info,
  Clock,
  Layers,
  CheckCircle2,
  Share2,
  X,
  Bell,
  Flame
} from 'lucide-react';

interface Vulnerability {
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

const INITIAL_VULNS: Vulnerability[] = [
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

export default function App() {
  const [selectedFilter, setSelectedFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'EXPLOITED' | 'KISA'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [copied, setCopied] = useState(false);

  const filteredVulns = useMemo(() => {
    return INITIAL_VULNS.filter((v) => {
      if (selectedFilter === 'CRITICAL' && v.severity !== 'CRITICAL') return false;
      if (selectedFilter === 'HIGH' && v.severity !== 'HIGH') return false;
      if (selectedFilter === 'EXPLOITED' && !v.exploitedInWild) return false;
      if (selectedFilter === 'KISA' && v.source !== 'KISA') return false;

      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesCve = v.cveId.toLowerCase().includes(query);
        const matchesTitle = v.title.toLowerCase().includes(query);
        const matchesVendor = v.vendor.toLowerCase().includes(query);
        const matchesAffected = v.affected.some((a) => a.toLowerCase().includes(query));
        return matchesCve || matchesTitle || matchesVendor || matchesAffected;
      }
      return true;
    });
  }, [selectedFilter, searchQuery]);

  const stats = useMemo(() => {
    const total = INITIAL_VULNS.length;
    const critical = INITIAL_VULNS.filter((v) => v.severity === 'CRITICAL').length;
    const high = INITIAL_VULNS.filter((v) => v.severity === 'HIGH').length;
    const exploited = INITIAL_VULNS.filter((v) => v.exploitedInWild).length;
    return { total, critical, high, exploited };
  }, []);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
    }, 600);
  };

  const handleShare = (v: Vulnerability) => {
    const text = `[보안 취약점 긴급공지]\n${v.cveId} (${v.severity} / CVSS ${v.cvss})\n${v.title}\n조치: ${v.solution}`;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getSeverityBadge = (severity: Vulnerability['severity'], cvss: number) => {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <Flame className="w-3 h-3 text-rose-400" />
            CRITICAL {cvss}
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            HIGH {cvss}
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-sky-500/15 text-sky-400 border border-sky-500/30">
            MEDIUM {cvss}
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-slate-500/15 text-slate-400 border border-slate-500/30">
            LOW {cvss}
          </span>
        );
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col max-w-md mx-auto relative shadow-2xl pb-8 font-sans select-none">
      {/* Top Header */}
      <header className="sticky top-0 z-30 bg-slate-900/95 backdrop-blur-md border-b border-slate-800 px-4 pt-4 pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-rose-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-rose-500/20">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <h1 className="text-base font-black tracking-tight text-white">SecVigil</h1>
                <span className="text-[10px] font-bold bg-indigo-500/20 text-indigo-400 px-1.5 py-0.5 rounded border border-indigo-500/30">
                  MOBILE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-none mt-0.5">실시간 보안 취약점 레이더</p>
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={handleRefresh}
              className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition-all active:scale-95"
              aria-label="새로고침"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-indigo-400' : ''}`} />
            </button>
            <div className="relative">
              <button className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition-all active:scale-95">
                <Bell className="w-4 h-4 text-slate-300" />
              </button>
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
            </div>
          </div>
        </div>

        {/* Live Status Banner */}
        <div className="mt-3 flex items-center justify-between bg-slate-800/80 rounded-xl px-3 py-1.5 border border-slate-700/60 text-[11px]">
          <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
            KISA · NVD 실시간 피드 연동
          </span>
          <span className="text-slate-400">최신 갱신됨</span>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 px-4 pt-3 space-y-4">
        {/* Quick Stats Grid */}
        <div className="grid grid-cols-4 gap-2">
          <div
            onClick={() => setSelectedFilter('ALL')}
            className={`p-2.5 rounded-xl border transition-all text-center cursor-pointer ${
              selectedFilter === 'ALL'
                ? 'bg-indigo-950/40 border-indigo-500/60 shadow-md shadow-indigo-500/10'
                : 'bg-slate-900 border-slate-800 hover:bg-slate-800/60'
            }`}
          >
            <div className="text-[10px] text-slate-400 font-medium">전체</div>
            <div className="text-lg font-black text-white">{stats.total}</div>
          </div>
          <div
            onClick={() => setSelectedFilter('CRITICAL')}
            className={`p-2.5 rounded-xl border transition-all text-center cursor-pointer ${
              selectedFilter === 'CRITICAL'
                ? 'bg-rose-950/40 border-rose-500/60 shadow-md shadow-rose-500/10'
                : 'bg-slate-900 border-slate-800 hover:bg-slate-800/60'
            }`}
          >
            <div className="text-[10px] text-rose-400 font-medium">긴급</div>
            <div className="text-lg font-black text-rose-400">{stats.critical}</div>
          </div>
          <div
            onClick={() => setSelectedFilter('HIGH')}
            className={`p-2.5 rounded-xl border transition-all text-center cursor-pointer ${
              selectedFilter === 'HIGH'
                ? 'bg-amber-950/40 border-amber-500/60 shadow-md shadow-amber-500/10'
                : 'bg-slate-900 border-slate-800 hover:bg-slate-800/60'
            }`}
          >
            <div className="text-[10px] text-amber-400 font-medium">고위험</div>
            <div className="text-lg font-black text-amber-400">{stats.high}</div>
          </div>
          <div
            onClick={() => setSelectedFilter('EXPLOITED')}
            className={`p-2.5 rounded-xl border transition-all text-center cursor-pointer ${
              selectedFilter === 'EXPLOITED'
                ? 'bg-red-950/40 border-red-500/60 shadow-md shadow-red-500/10'
                : 'bg-slate-900 border-slate-800 hover:bg-slate-800/60'
            }`}
          >
            <div className="text-[10px] text-red-400 font-medium">악용중</div>
            <div className="text-lg font-black text-red-400">{stats.exploited}</div>
          </div>
        </div>

        {/* Search Bar */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="CVE 번호, 소프트웨어(Chrome, Linux, iOS) 검색"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 text-sm text-slate-100 placeholder-slate-400 pl-9 pr-8 py-2.5 rounded-xl border border-slate-800 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 p-0.5"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Filter Chip Carousel */}
        <div className="flex gap-1.5 overflow-x-auto no-scrollbar py-0.5">
          <button
            onClick={() => setSelectedFilter('ALL')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-all ${
              selectedFilter === 'ALL'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            전체 피드
          </button>
          <button
            onClick={() => setSelectedFilter('CRITICAL')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-all ${
              selectedFilter === 'CRITICAL'
                ? 'bg-rose-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            긴급 (Critical)
          </button>
          <button
            onClick={() => setSelectedFilter('HIGH')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-all ${
              selectedFilter === 'HIGH'
                ? 'bg-amber-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            고위험 (High)
          </button>
          <button
            onClick={() => setSelectedFilter('EXPLOITED')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-all ${
              selectedFilter === 'EXPLOITED'
                ? 'bg-red-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            실제 공격 악용 (In Wild)
          </button>
          <button
            onClick={() => setSelectedFilter('KISA')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-all ${
              selectedFilter === 'KISA'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            KISA 한국인터넷진흥원
          </button>
        </div>

        {/* List Header */}
        <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
          <span>최신 등록 순 ({filteredVulns.length}건)</span>
          <span className="flex items-center gap-1 text-[11px] text-slate-400">
            카드 터치 시 상세 가이드
          </span>
        </div>

        {/* Vulnerability List Cards */}
        <div className="space-y-3">
          {filteredVulns.length === 0 ? (
            <div className="p-8 text-center bg-slate-900/60 rounded-2xl border border-slate-800 space-y-2">
              <ShieldCheck className="w-10 h-10 text-slate-500 mx-auto" />
              <p className="text-sm font-semibold text-slate-300">검색 조건에 맞는 취약점이 없습니다.</p>
              <p className="text-xs text-slate-500">검색어를 바꾸거나 필터를 전체로 변경해 보세요.</p>
            </div>
          ) : (
            filteredVulns.map((vuln) => (
              <div
                key={vuln.id}
                onClick={() => setSelectedVuln(vuln)}
                className="bg-slate-900/90 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 rounded-2xl p-4 transition-all duration-150 active:scale-[0.99] cursor-pointer space-y-2.5 relative overflow-hidden group shadow-lg"
              >
                {/* Top Badges */}
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-slate-200 tracking-wide bg-slate-950 px-2.5 py-0.5 rounded border border-slate-800">
                      {vuln.cveId}
                    </span>
                    <span className="text-[10px] text-indigo-400 font-semibold px-1.5 py-0.5 bg-indigo-500/10 rounded border border-indigo-500/20">
                      {vuln.source}
                    </span>
                  </div>
                  {getSeverityBadge(vuln.severity, vuln.cvss)}
                </div>

                {/* Title */}
                <h3 className="text-sm font-bold text-slate-100 group-hover:text-indigo-300 transition-colors line-clamp-1">
                  {vuln.title}
                </h3>

                {/* Description Preview */}
                <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                  {vuln.description}
                </p>

                {/* Tags & Meta */}
                <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px]">
                  {vuln.exploitedInWild && (
                    <span className="inline-flex items-center gap-1 text-[10px] font-bold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
                      <Flame className="w-3 h-3 text-rose-500" />
                      악용 확인
                    </span>
                  )}
                  <span className="text-[10px] text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800 truncate max-w-[150px]">
                    {vuln.vendor}
                  </span>
                  <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    <CheckCircle2 className="w-3 h-3" />
                    패치 가능
                  </span>
                  <div className="ml-auto text-[10px] text-slate-400 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {vuln.publishedAt.split(' ')[0]}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-1 border-t border-slate-800 text-[11px] text-indigo-400 font-medium">
                  <span>상세 분석 및 조치 가이드 보기</span>
                  <ChevronRight className="w-3.5 h-3.5 text-slate-400 group-hover:translate-x-0.5 transition-transform" />
                </div>
              </div>
            ))
          )}
        </div>
      </main>

      {/* Detail Modal / Bottom Sheet */}
      {selectedVuln && (
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/75 backdrop-blur-sm p-0 sm:p-4">
          <div
            className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-t-3xl sm:rounded-2xl max-h-[88vh] flex flex-col shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Sheet Handle */}
            <div className="w-12 h-1.5 bg-slate-700 rounded-full mx-auto mt-3 mb-1 sm:hidden" />

            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-start justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-bold text-white bg-slate-950 px-2.5 py-0.5 rounded border border-slate-800">
                    {selectedVuln.cveId}
                  </span>
                  {getSeverityBadge(selectedVuln.severity, selectedVuln.cvss)}
                </div>
                <h2 className="text-base font-bold text-slate-100 pt-1 leading-snug">
                  {selectedVuln.title}
                </h2>
              </div>
              <button
                onClick={() => setSelectedVuln(null)}
                className="p-1.5 rounded-full bg-slate-800 text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Scrollable Body */}
            <div className="p-4 space-y-4 overflow-y-auto flex-1 text-xs">
              {/* Exploited Alert Box */}
              {selectedVuln.exploitedInWild && (
                <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-start gap-2.5 text-rose-300">
                  <Flame className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-bold text-rose-200 text-xs">실제 침해 공격에 악용 중 (CISA KEV 등재)</h4>
                    <p className="text-[11px] text-rose-300/80 mt-0.5 leading-relaxed">
                      공격자 및 해킹 조직에 의해 활발히 익스플로잇되고 있는 취약점입니다. 시스템 관리자는 최우선 순위로 조치를 적용해야 합니다.
                    </p>
                  </div>
                </div>
              )}

              {/* Description */}
              <div className="space-y-1.5">
                <h4 className="font-bold text-slate-300 flex items-center gap-1.5">
                  <Info className="w-4 h-4 text-indigo-400" />
                  취약점 개요
                </h4>
                <p className="text-slate-300 leading-relaxed bg-slate-950/80 p-3 rounded-xl border border-slate-800">
                  {selectedVuln.description}
                </p>
              </div>

              {/* Affected Systems */}
              <div className="space-y-1.5">
                <h4 className="font-bold text-slate-300 flex items-center gap-1.5">
                  <Layers className="w-4 h-4 text-indigo-400" />
                  영향 받는 시스템 및 버전
                </h4>
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 space-y-1.5">
                  {selectedVuln.affected.map((aff, i) => (
                    <div key={i} className="flex items-center gap-2 text-slate-300 font-mono text-[11px]">
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0" />
                      <span>{aff}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Solution / Mitigation */}
              <div className="space-y-1.5">
                <h4 className="font-bold text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  대응 및 보안 조치 가이드
                </h4>
                <div className="bg-emerald-950/20 border border-emerald-500/30 p-3 rounded-xl text-emerald-200 leading-relaxed font-medium">
                  {selectedVuln.solution}
                </div>
              </div>

              {/* External References */}
              <div className="space-y-1.5">
                <h4 className="font-bold text-slate-300 flex items-center gap-1.5">
                  <ExternalLink className="w-4 h-4 text-slate-400" />
                  관련 보안 권고 링크
                </h4>
                <div className="space-y-1">
                  {selectedVuln.references.map((url, i) => (
                    <a
                      key={i}
                      href={url}
                      target="_blank"
                      rel="noreferrer"
                      className="block p-2 rounded-lg bg-slate-950/60 hover:bg-slate-950 border border-slate-800 text-indigo-400 hover:text-indigo-300 truncate"
                    >
                      {url}
                    </a>
                  ))}
                </div>
              </div>
            </div>

            {/* Modal Footer Actions */}
            <div className="p-3 border-t border-slate-800 bg-slate-900/95 flex gap-2">
              <button
                onClick={() => handleShare(selectedVuln)}
                className="flex-1 py-2.5 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-lg shadow-indigo-600/30 active:scale-95 transition-all"
              >
                <Share2 className="w-4 h-4" />
                {copied ? '정보 클립보드 복사됨!' : '정보 복사 및 공유'}
              </button>
              <button
                onClick={() => setSelectedVuln(null)}
                className="py-2.5 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold text-xs active:scale-95 transition-all"
              >
                닫기
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
