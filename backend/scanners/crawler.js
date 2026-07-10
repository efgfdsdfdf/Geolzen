/**
 * Web Crawler (Spider) Module
 * 
 * Performs a Breadth-First Search (BFS) crawl of a target domain
 * to discover internal pages and endpoints for deep scanning.
 */

const MAX_TIMEOUT_MS = 5000;

/**
 * Extracts links and form actions from HTML content.
 * 
 * @param {string} html - HTML string to parse
 * @param {string} baseUrl - Base URL to resolve relative paths
 * @returns {string[]} Array of resolved absolute URLs
 */
function extractLinks(html, baseUrl) {
  const links = new Set();
  
  // Extract <a href="...">
  const hrefRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']*)["']/gi;
  let match;
  while ((match = hrefRegex.exec(html)) !== null) {
    links.add(match[1]);
  }

  // Extract <form action="...">
  const formRegex = /<form\s+(?:[^>]*?\s+)?action=["']([^"']*)["']/gi;
  while ((match = formRegex.exec(html)) !== null) {
    links.add(match[1]);
  }

  // Resolve and filter URLs
  const resolvedUrls = [];
  const base = new URL(baseUrl);

  for (let link of links) {
    try {
      // Ignore mailto, javascript, tel links
      if (link.startsWith('javascript:') || link.startsWith('mailto:') || link.startsWith('tel:')) {
        continue;
      }
      
      // Ignore anchors on the same page
      if (link.startsWith('#')) {
        continue;
      }

      // Resolve relative to base URL
      const resolved = new URL(link, baseUrl);
      
      // Ensure it's the same origin
      if (resolved.origin === base.origin) {
        // Remove hash fragments to avoid duplicating pages
        resolved.hash = '';
        resolvedUrls.push(resolved.toString());
      }
    } catch (e) {
      // Invalid URL, ignore
    }
  }

  return resolvedUrls;
}

/**
 * Crawls a target URL to find internal pages.
 * 
 * @param {string} targetUrl - Starting URL
 * @param {number} maxDepth - Maximum depth to crawl (default: 2)
 * @param {number} maxPages - Maximum number of unique pages to return (default: 10)
 * @returns {Promise<{pages: string[], metadata: Object}>}
 */
async function crawlSite(targetUrl, maxDepth = 2, maxPages = 10) {
  const startTime = Date.now();
  const queue = [{ url: targetUrl, depth: 0 }];
  const visited = new Set([targetUrl]);
  const discoveredPages = [targetUrl];
  let pagesCrawled = 0;

  while (queue.length > 0 && discoveredPages.length < maxPages) {
    const { url, depth } = queue.shift();
    
    if (depth > maxDepth) continue;
    
    pagesCrawled++;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), MAX_TIMEOUT_MS);

    try {
      const res = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Geolzen-Security-Scanner/1.0',
          'Accept': 'text/html,application/xhtml+xml,*/*'
        }
      });

      // Only parse HTML pages
      const contentType = res.headers.get('content-type') || '';
      if (!contentType.includes('text/html')) {
        clearTimeout(timer);
        continue;
      }

      const html = await res.text();
      clearTimeout(timer);

      const newLinks = extractLinks(html, url);

      for (const link of newLinks) {
        if (!visited.has(link)) {
          visited.add(link);
          
          if (discoveredPages.length < maxPages) {
            discoveredPages.push(link);
            queue.push({ url: link, depth: depth + 1 });
          }
        }
      }

    } catch (error) {
      clearTimeout(timer);
      // Ignore fetch errors (timeout, 404, etc.) and continue crawling
    }
  }

  const elapsedMs = Date.now() - startTime;

  return {
    pages: discoveredPages,
    metadata: {
      scanner: 'crawler',
      startUrl: targetUrl,
      pagesCrawled,
      pagesDiscovered: discoveredPages.length,
      maxDepthReached: maxDepth,
      elapsedMs
    }
  };
}

module.exports = { crawlSite };
