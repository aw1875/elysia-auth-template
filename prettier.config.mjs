/** @type {import('prettier').Config} */
export default {
  endOfLine: 'lf',
  semi: true,
  tabWidth: 2,
  printWidth: 100,
  singleQuote: true,
  trailingComma: 'none',
  importOrder: [
    '^bun$',
    '^elysia$',
    '^@elysiajs/(.*)$',
    '^@/middleware',
    '^@/routes',
    '^@/handlers',
    '^@/types',
    '^@/lib',
    '^@/(.*)$',
    '(.*)',
    '^[./]'
  ],
  importOrderSeparation: true,
  importOrderSortSpecifiers: true,
  importOrderCaseInsensitive: false,
  importOrderParserPlugins: ['typescript', 'jsx', 'decorators-legacy'],
  plugins: ['@trivago/prettier-plugin-sort-imports']
};
