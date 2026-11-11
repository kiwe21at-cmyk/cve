import fs from 'fs';
import path from 'path';

const CACHE_FILE = path.join(process.cwd(), 'public', 'cves.json');
const API_KEY = process.env.VULNCHECK_API_KEY;

async function buildFeed() {
  if (!API_KEY) {
    if (process.env.CI) {
      console.error('Error: VULNCHECK_API_KEY environment variable is missing in CI!');
      process.exit(1);
    }
    console.warn('Warning: VULNCHECK_API_KEY environment variable is missing. Generating fallback cves.json for local environment.');
    const fallbackPayload = {
      timestamp: Date.now(),
      lastUpdated: new Intl.DateTimeFormat('ko-KR', {
        timeZone: 'Asia/Seoul',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      }).format(new Date()),
      vulnerabilities: []
    };
    fs.mkdirSync(path.dirname(CACHE_FILE), { recursive: true });
    fs.writeFileSync(CACHE_FILE, JSON.stringify(fallbackPayload, null, 2));
    return;
  }

  const now = new Date();
  const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const endDate = now.toISOString();

  const url = `https://api.vulncheck.com/rest/json/cves/2.0?pubStartDate=${encodeURIComponent(
    startDate
  )}&pubEndDate=${encodeURIComponent(endDate)}&resultsPerPage=50&noRejected`;

  console.log('Fetching CVEs from VulnCheck API...');
  const response = await fetch(url, {
    headers: {
      Accept: 'application/json',
      apiKey: API_KEY
    }
  });

  if (!response.ok) {
    throw new Error(`VulnCheck API failed with status ${response.status}`);
  }

  const json = await response.json();
  const rawItems = json.vulnerabilities || [];

  const payload = {
    timestamp: Date.now(),
    lastUpdated: new Intl.DateTimeFormat('ko-KR', {
      timeZone: 'Asia/Seoul',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    }).format(now),
    vulnerabilities: rawItems
  };

  fs.mkdirSync(path.dirname(CACHE_FILE), { recursive: true });
  fs.writeFileSync(CACHE_FILE, JSON.stringify(payload, null, 2));
  console.log(`Successfully generated cves.json with ${rawItems.length} items.`);
}

buildFeed().catch((err) => {
  console.error(err);
  process.exit(1);
});
