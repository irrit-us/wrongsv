// k6-real-browse.js — realistic multi-user browsing simulation through SOCKS5 proxy
// Usage: k6 run --out json=results.json bench/scripts/k6-real-browse.js

import http from 'k6/http';
import { sleep, check } from 'k6';

const PROXY = __ENV.SOCKS5_PROXY || 'socks5://127.0.0.1:10809';
const DURATION = __ENV.DURATION || '60s';
const VUS = parseInt(__ENV.VUS) || 20;

export const options = {
  duration: DURATION,
  vus: VUS,
  thresholds: {
    http_req_duration: ['p(95)<10000'],  // 95% of requests under 10s
    http_req_failed: ['rate<0.05'],       // <5% error rate
  },
};

// Realistic URLs — mix of small, medium, and large responses
const URLS = [
  // Small JSON APIs
  'https://httpbin.org/get',
  'https://httpbin.org/ip',
  'https://api.github.com/repos/rust-lang/rust',
  // Text-heavy pages
  'https://en.wikipedia.org/wiki/Proxy_server',
  'https://en.wikipedia.org/wiki/Transport_Layer_Security',
  // Search engines
  'https://www.google.com/search?q=network+proxy',
  // Mixed content
  'https://httpbin.org/html',
  'https://httpbin.org/bytes/1024',       // 1KB
  'https://httpbin.org/bytes/10240',      // 10KB
  'https://httpbin.org/bytes/102400',     // 100KB
];

export default function () {
  // Each VU picks a random URL with weighted distribution
  const weights = [0.2, 0.1, 0.05, 0.15, 0.1, 0.1, 0.05, 0.1, 0.05, 0.1];
  const url = weightedRandom(URLS, weights);

  const params = {
    timeout: '30s',
    headers: {
      'User-Agent': randomUA(),
      'Accept': 'text/html,application/json,*/*',
      'Accept-Language': randomAcceptLang(),
    },
  };

  const res = http.get(url, params);

  check(res, {
    'status 2xx': (r) => r.status >= 200 && r.status < 300,
    'response time < 10s': (r) => r.timings.duration < 10000,
  });

  // Realistic think time: 1-5 seconds between page loads
  sleep(1 + Math.random() * 4);
}

function weightedRandom(items, weights) {
  let sum = weights.reduce((a, b) => a + b, 0);
  let r = Math.random() * sum;
  for (let i = 0; i < items.length; i++) {
    r -= weights[i];
    if (r <= 0) return items[i];
  }
  return items[items.length - 1];
}

function randomUA() {
  const uas = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1',
  ];
  return uas[Math.floor(Math.random() * uas.length)];
}

function randomAcceptLang() {
  const langs = ['en-US,en;q=0.9', 'zh-CN,zh;q=0.9', 'ja-JP,ja;q=0.9', 'de-DE,de;q=0.9'];
  return langs[Math.floor(Math.random() * langs.length)];
}
