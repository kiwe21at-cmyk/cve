import { useState, useMemo, useEffect } from 'react';
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
  Filter,
  Flame,
  Radio,
  Loader2,
  Tags,
  Check
} from 'lucide-react';
import {
  type Vulnerability,
  fetchLiveVulnerabilities,
  searchCveById
} from './services/cveService';

const OS_TAGS = ['Linux', 'Windows', 'macOS', 'Android', 'iOS', 'Red Hat', 'Ubuntu', 'Debian'];
const SOFTWARE_TAGS = [
  'WordPress',
  'Apache',
  'Nginx',
  'Chrome',
  'Microsoft',
  'Oracle',
  'Cisco',
  'GitHub',
  'Google',
  'Apple',
  'Docker',
  'MySQL',
  'PHP',
  'Node.js'
];
const LANGUAGE_TAGS = [
  'Java',
  'PHP',
  'JavaScript',
  'TypeScript',
  'Python',
  'Ruby',
  'Go',
  'C++',
  'Vue',
  'React',
  'Spring Boot',
  'Spring Framework'
];
const ALL_DEFAULT_TAGS = [...OS_TAGS, ...SOFTWARE_TAGS, ...LANGUAGE_TAGS];

export default function App() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [isLoadingInitial, setIsLoadingInitial] = useState(true);
  const [selectedFilter, setSelectedFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'EXPLOITED' | 'KISA'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [copied, setCopied] = useState(false);

  // 태그 설정 모달 및 선택된 태그 상태
  const [selectedTags, setSelectedTags] = useState<string[]>(() => {
    try {
      const saved = localStorage.getItem('secvigil_selected_tags');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch {
      // ignore
    }
    return ALL_DEFAULT_TAGS;
  });
  const [isTagModalOpen, setIsTagModalOpen] = useState(false);

  // 실시간 API 연동 상태
  const [isLive, setIsLive] = useState(false);
  const [lastUpdated, setLastUpdated] = useState('초기화 중...');
  const [apiStatusText, setApiStatusText] = useState('VulnCheck API 연결 중...');
  const [isSearchingApi, setIsSearchingApi] = useState(false);
  const [searchNotice, setSearchNotice] = useState<string | null>(null);

  // 동적 벤더 추출
  const dynamicVendors = useMemo(() => {
    const set = new Set<string>();
    vulns.forEach((v) => {
      if (v.vendor && !ALL_DEFAULT_TAGS.includes(v.vendor)) {
        set.add(v.vendor);
      }
    });
    return Array.from(set).slice(0, 15);
  }, [vulns]);

  // 초기 로드 및 5분 주기 백그라운드 자동 갱신
  useEffect(() => {
    let isMounted = true;

    const loadData = async (force = false) => {
      setIsRefreshing(true);
      const res = await fetchLiveVulnerabilities(force);
      if (!isMounted) return;

      setVulns(res.vulnerabilities);
      setIsLive(res.isLive);
      setLastUpdated(res.lastUpdated);
      setIsRefreshing(false);
      setIsLoadingInitial(false);

      if (res.sourceType === 'API') {
        setApiStatusText('VulnCheck · KISA 최근 7일 피드 연동');
      } else if (res.sourceType === 'CACHE') {
        setApiStatusText('최근 7일 피드 (캐시 보호 모드)');
      } else {
        setApiStatusText('API 연결 대기 중 (API Key 확인)');
      }
    };

    loadData(false);

    // 5분마다 실시간 갱신
    const timer = setInterval(() => {
      loadData(false);
    }, 5 * 60 * 1000);

    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, []);

  const handleRefresh = async () => {
    if (isRefreshing) return;
    setIsRefreshing(true);
    setApiStatusText('최근 7일 데이터 실시간 갱신 중...');
    const res = await fetchLiveVulnerabilities(true);
    setVulns(res.vulnerabilities);
    setIsLive(res.isLive);
    setLastUpdated(res.lastUpdated);
    setIsRefreshing(false);

    if (res.sourceType === 'API') {
      setApiStatusText('VulnCheck · KISA 최근 7일 갱신 완료');
    } else if (res.sourceType === 'CACHE') {
      setApiStatusText('최근 7일 피드 유지 (속도제한 보호)');
    } else {
      setApiStatusText('API 일시 지연 또는 Key 확인 필요');
    }
  };

  const handleDirectSearch = async () => {
    const q = searchQuery.trim();
    if (!q) return;

    setIsSearchingApi(true);
    setSearchNotice(`VulnCheck 데이터베이스에서 "${q}" 검색 중...`);
    const found = await searchCveById(q);
    setIsSearchingApi(false);

    if (found) {
      setVulns((prev) => {
        if (prev.some((v) => v.cveId === found.cveId)) return prev;
        return [found, ...prev];
      });
      setSelectedVuln(found);
      setSearchNotice(`${found.cveId} 조회 성공`);
    } else {
      setSearchNotice(`"${q}"에 해당하는 CVE를 VulnCheck에서 찾지 못했습니다.`);
    }

    setTimeout(() => {
      setSearchNotice(null);
    }, 3500);
  };

  const tagFilteredVulns = useMemo(() => {
    return vulns.filter((v) => {
      if (selectedTags.length > 0) {
        const matchesTag = selectedTags.some((tag) => {
          const tLower = tag.toLowerCase();
          const vendorMatch = v.vendor.toLowerCase().includes(tLower);
          const affectedMatch = v.affected.some((a) => a.toLowerCase().includes(tLower));
          const titleMatch = v.title.toLowerCase().includes(tLower);
          const descMatch = v.description.toLowerCase().includes(tLower);
          return vendorMatch || affectedMatch || titleMatch || descMatch;
        });
        if (!matchesTag) return false;
      }
      return true;
    });
  }, [vulns, selectedTags]);

  const filteredVulns = useMemo(() => {
    return tagFilteredVulns.filter((v) => {
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
  }, [tagFilteredVulns, selectedFilter, searchQuery]);

  const stats = useMemo(() => {
    const total = tagFilteredVulns.length;
    const critical = tagFilteredVulns.filter((v) => v.severity === 'CRITICAL').length;
    const high = tagFilteredVulns.filter((v) => v.severity === 'HIGH').length;
    const exploited = tagFilteredVulns.filter((v) => v.exploitedInWild).length;
    const kisa = tagFilteredVulns.filter((v) => v.source === 'KISA').length;
    return { total, critical, high, exploited, kisa };
  }, [tagFilteredVulns]);

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
              <p className="text-[11px] text-slate-400 leading-none mt-0.5">최근 7일 실시간 보안 취약점 레이더</p>
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition-all active:scale-95 disabled:opacity-60"
              aria-label="새로고침"
              title="실시간 API 새로고침"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-indigo-400' : ''}`} />
            </button>
            <button
              onClick={() => setIsTagModalOpen(true)}
              className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition-all active:scale-95 relative group"
              aria-label="필터 설정"
              title="OS 및 소프트웨어 태그 필터 설정"
            >
              <Filter className="w-4 h-4 text-slate-300 group-hover:text-indigo-400 transition-colors" />
              {selectedTags.length > 0 && (
                <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-indigo-500 animate-pulse" />
              )}
            </button>
          </div>
        </div>

        {/* Live Status Banner */}
        <div className="mt-3 flex items-center justify-between bg-slate-800/80 rounded-xl px-3 py-1.5 border border-slate-700/60 text-[11px]">
          <span className="flex items-center gap-1.5 font-medium">
            <Radio className={`w-3.5 h-3.5 ${isLive ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
            <span className={isLive ? 'text-emerald-400' : 'text-amber-300'}>{apiStatusText}</span>
          </span>
          <span className="text-slate-400 text-[10px] flex items-center gap-1">
            <Clock className="w-2.5 h-2.5" />
            {lastUpdated}
          </span>
        </div>

        {/* Search Notice Bar */}
        {searchNotice && (
          <div className="mt-2 text-center text-xs px-2.5 py-1 bg-indigo-950/80 border border-indigo-500/40 text-indigo-300 rounded-lg animate-fade-in">
            {searchNotice}
          </div>
        )}
      </header>

      {/* Main Content Area */}
      <main className="flex-1 px-4 pt-3 space-y-4">
        {/* Tag Filter Settings Button */}
        <button
          onClick={() => setIsTagModalOpen(true)}
          className="w-full py-2.5 px-3.5 rounded-xl bg-slate-900 hover:bg-slate-850 border border-slate-800 text-slate-300 text-xs font-medium flex items-center justify-between transition-all shadow-md group"
        >
          <span className="flex items-center gap-2">
            <Tags className="w-4 h-4 text-indigo-400 group-hover:scale-110 transition-transform" />
            <span>OS 및 소프트웨어 태그 설정</span>
          </span>
          <span className="px-2.5 py-0.5 rounded-lg bg-indigo-500/10 text-indigo-400 text-[11px] font-bold border border-indigo-500/25">
            {selectedTags.length}개 태그 활성
          </span>
        </button>

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
        <div className="space-y-1.5">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="CVE 번호, 제품(WordPress, Linux, Chrome) 검색"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && searchQuery.toUpperCase().startsWith('CVE-')) {
                  handleDirectSearch();
                }
              }}
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

          {/* CVE 직접 검색 지원 버튼 */}
          {searchQuery.toUpperCase().startsWith('CVE-') && (
            <button
              onClick={handleDirectSearch}
              disabled={isSearchingApi}
              className="w-full py-1.5 px-3 rounded-xl bg-indigo-950/60 hover:bg-indigo-900/60 border border-indigo-500/40 text-indigo-300 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all"
            >
              {isSearchingApi ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-400" />
                  <span>VulnCheck 데이터베이스 검색 중...</span>
                </>
              ) : (
                <>
                  <Search className="w-3.5 h-3.5 text-indigo-400" />
                  <span>VulnCheck에서 <strong>{searchQuery.trim().toUpperCase()}</strong> 직접 검색</span>
                </>
              )}
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
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-all flex items-center gap-1.5 ${
              selectedFilter === 'KISA'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            <span>KISA 보안권고</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-blue-950 text-blue-300 font-bold border border-blue-500/30">
              {stats.kisa}
            </span>
          </button>
        </div>

        {/* List Header */}
        <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
          <span>선택된 태그 필터 결과 ({filteredVulns.length}건)</span>
          <span className="flex items-center gap-1 text-[11px] text-slate-400">
            카드 터치 시 상세 가이드
          </span>
        </div>

        {/* Vulnerability List Cards */}
        <div className="space-y-3">
          {isLoadingInitial && vulns.length === 0 ? (
            <div className="p-12 text-center bg-slate-900/60 rounded-2xl border border-slate-800 space-y-3">
              <Loader2 className="w-8 h-8 text-indigo-400 animate-spin mx-auto" />
              <p className="text-sm font-semibold text-slate-200">실시간 보안 취약점 피드를 불러오는 중입니다...</p>
              <p className="text-xs text-slate-400 leading-relaxed">
                VulnCheck Community API에서 최근 7일간의 최신 CVE 데이터를 실시간 동기화하고 있습니다.
              </p>
            </div>
          ) : filteredVulns.length === 0 ? (
            <div className="p-8 text-center bg-slate-900/60 rounded-2xl border border-slate-800 space-y-3">
              <ShieldCheck className="w-10 h-10 text-slate-500 mx-auto" />
              <p className="text-sm font-semibold text-slate-300">선택된 태그에 해당하는 취약점이 없습니다.</p>
              <p className="text-xs text-slate-500 leading-relaxed">
                상단의 <strong>'OS 및 소프트웨어 태그 설정'</strong> 버튼을 눌러 더 많은 태그를 선택하거나 검색어를 변경해 보세요.
              </p>
              <button
                onClick={() => setSelectedTags(ALL_DEFAULT_TAGS)}
                className="mt-2 py-1.5 px-3 rounded-xl bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-300 text-xs font-semibold border border-indigo-500/40 transition-all"
              >
                모든 기본 태그 활성화
              </button>
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

      {/* Tag Settings Modal */}
      {isTagModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div
            className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-indigo-500/15 flex items-center justify-center text-indigo-400 border border-indigo-500/30">
                  <Tags className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">태그 설정 (OS / 소프트웨어)</h3>
                  <p className="text-[11px] text-slate-400">관심 있는 태그만 선택하여 모니터링하세요.</p>
                </div>
              </div>
              <button
                onClick={() => setIsTagModalOpen(false)}
                className="p-1.5 rounded-full bg-slate-800 text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-4 space-y-4 overflow-y-auto flex-1 text-xs">
              {/* Quick Actions */}
              <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-[11px]">
                <span className="text-slate-400">
                  선택된 태그: <strong className="text-indigo-400">{selectedTags.length}개</strong>
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setSelectedTags([...OS_TAGS, ...SOFTWARE_TAGS, ...LANGUAGE_TAGS, ...dynamicVendors])}
                    className="text-indigo-400 hover:underline font-semibold"
                  >
                    전체 선택
                  </button>
                  <span className="text-slate-700">|</span>
                  <button
                    onClick={() => setSelectedTags([])}
                    className="text-slate-400 hover:underline font-semibold"
                  >
                    전체 해제
                  </button>
                </div>
              </div>

              {/* OS Tags Section */}
              <div className="space-y-2">
                <h4 className="font-bold text-slate-300 text-xs flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-indigo-500" />
                  운영체제 (OS) 태그
                </h4>
                <div className="grid grid-cols-2 gap-2">
                  {OS_TAGS.map((tag) => {
                    const isSelected = selectedTags.includes(tag);
                    return (
                      <button
                        key={tag}
                        onClick={() => {
                          if (isSelected) {
                            setSelectedTags(selectedTags.filter((t) => t !== tag));
                          } else {
                            setSelectedTags([...selectedTags, tag]);
                          }
                        }}
                        className={`p-2.5 rounded-xl border text-left flex items-center justify-between transition-all ${
                          isSelected
                            ? 'bg-indigo-950/50 border-indigo-500/60 text-white shadow-sm'
                            : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                        }`}
                      >
                        <span className="font-medium truncate">{tag}</span>
                        <div
                          className={`w-4 h-4 rounded flex items-center justify-center border ${
                            isSelected
                              ? 'bg-indigo-600 border-indigo-500 text-white'
                              : 'bg-slate-900 border-slate-700 text-transparent'
                          }`}
                        >
                          <Check className="w-3 h-3" />
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Software Tags Section */}
              <div className="space-y-2 pt-2">
                <h4 className="font-bold text-slate-300 text-xs flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  소프트웨어 / 벤더 태그
                </h4>
                <div className="grid grid-cols-2 gap-2">
                  {SOFTWARE_TAGS.map((tag) => {
                    const isSelected = selectedTags.includes(tag);
                    return (
                      <button
                        key={tag}
                        onClick={() => {
                          if (isSelected) {
                            setSelectedTags(selectedTags.filter((t) => t !== tag));
                          } else {
                            setSelectedTags([...selectedTags, tag]);
                          }
                        }}
                        className={`p-2.5 rounded-xl border text-left flex items-center justify-between transition-all ${
                          isSelected
                            ? 'bg-emerald-950/50 border-emerald-500/60 text-white shadow-sm'
                            : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                        }`}
                      >
                        <span className="font-medium truncate">{tag}</span>
                        <div
                          className={`w-4 h-4 rounded flex items-center justify-center border ${
                            isSelected
                              ? 'bg-emerald-600 border-emerald-500 text-white'
                              : 'bg-slate-900 border-slate-700 text-transparent'
                          }`}
                        >
                          <Check className="w-3 h-3" />
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Development Language / Framework Tags Section */}
              <div className="space-y-2 pt-2">
                <h4 className="font-bold text-slate-300 text-xs flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-purple-500" />
                  개발 언어 / 프레임워크 태그
                </h4>
                <div className="grid grid-cols-2 gap-2">
                  {LANGUAGE_TAGS.map((tag) => {
                    const isSelected = selectedTags.includes(tag);
                    return (
                      <button
                        key={tag}
                        onClick={() => {
                          if (isSelected) {
                            setSelectedTags(selectedTags.filter((t) => t !== tag));
                          } else {
                            setSelectedTags([...selectedTags, tag]);
                          }
                        }}
                        className={`p-2.5 rounded-xl border text-left flex items-center justify-between transition-all ${
                          isSelected
                            ? 'bg-purple-950/50 border-purple-500/60 text-white shadow-sm'
                            : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                        }`}
                      >
                        <span className="font-medium truncate">{tag}</span>
                        <div
                          className={`w-4 h-4 rounded flex items-center justify-center border ${
                            isSelected
                              ? 'bg-purple-600 border-purple-500 text-white'
                              : 'bg-slate-900 border-slate-700 text-transparent'
                          }`}
                        >
                          <Check className="w-3 h-3" />
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Dynamic Vendors from current vulns */}
              {dynamicVendors.length > 0 && (
                <div className="space-y-2 pt-2">
                  <h4 className="font-bold text-slate-300 text-xs flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-amber-500" />
                    기타 감지된 벤더/제품 태그
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {dynamicVendors.map((tag) => {
                      const isSelected = selectedTags.includes(tag);
                      return (
                        <button
                          key={tag}
                          onClick={() => {
                            if (isSelected) {
                              setSelectedTags(selectedTags.filter((t) => t !== tag));
                            } else {
                              setSelectedTags([...selectedTags, tag]);
                            }
                          }}
                          className={`px-3 py-1.5 rounded-xl border text-xs font-medium transition-all flex items-center gap-1.5 ${
                            isSelected
                              ? 'bg-amber-950/50 border-amber-500/60 text-amber-200'
                              : 'bg-slate-950/60 border-slate-800 text-slate-400'
                          }`}
                        >
                          <span>{tag}</span>
                          {isSelected && <Check className="w-3 h-3 text-amber-400" />}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-900/95 flex gap-2">
              <button
                onClick={() => {
                  try {
                    localStorage.setItem('secvigil_selected_tags', JSON.stringify(selectedTags));
                  } catch {
                    // ignore
                  }
                  setIsTagModalOpen(false);
                }}
                className="flex-1 py-2.5 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg shadow-indigo-600/30 active:scale-95 transition-all"
              >
                적용하기 ({selectedTags.length}개 태그 필터 적용)
              </button>
              <button
                onClick={() => setIsTagModalOpen(false)}
                className="py-2.5 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold text-xs active:scale-95 transition-all"
              >
                닫기
              </button>
            </div>
          </div>
        </div>
      )}

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
