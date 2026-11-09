// Section I — imagery.
const IMAGE_FILES = ['.html', '.jsx', '.tsx', '.vue', '.svelte', '.md', '.css', '.scss', '.js', '.ts'];

const EMPTY_SRC_RE = /\b(?:src|srcSet|poster)\s*=\s*(?:""|''|"#"|'#'|\{\s*(?:""|''|null|undefined)\s*\})/;
const PLACEHOLDER_ASSET_RE =
  /\b(?:src|srcSet|poster|href|url)\s*[=(]\s*['"{]?[^'")\s]*\b(placeholder|placehold|dummy|sample-image|image-placeholder|todo-image|test-image)\b[^'")\s]*/i;
const STOCK_CDN_RE =
  /(images\.unsplash\.com|source\.unsplash\.com|unsplash\.com\/photos|picsum\.photos|placehold\.co|via\.placeholder\.com|placeholder\.com\/|placekitten\.com|loremflickr\.com|dummyimage\.com|pravatar\.cc|ui-avatars\.com|placeimg\.com|lorempixel\.com)/i;

export default [
  {
    id: 'I-1a',
    severity: 'red',
    title: 'Broken or placeholder image',
    why: 'An empty or placeholder src ships a hole in the page.',
    fileTypes: IMAGE_FILES,
    test(line, ctx) {
      if (ctx.svgLines.has(ctx.lineNo)) return null;
      if (EMPTY_SRC_RE.test(line)) return { excerpt: line, note: 'empty src' };
      if (PLACEHOLDER_ASSET_RE.test(line) && !STOCK_CDN_RE.test(line)) {
        return { excerpt: line, note: 'placeholder asset path' };
      }
      return null;
    },
  },
  {
    id: 'I-2',
    severity: 'red',
    title: 'External stock / placeholder image URL',
    why: 'A hotlinked unsplash/picsum image is someone else’s asset on someone else’s uptime.',
    fileTypes: IMAGE_FILES,
    test(line) {
      return STOCK_CDN_RE.test(line) ? { excerpt: line } : null;
    },
  },
];
