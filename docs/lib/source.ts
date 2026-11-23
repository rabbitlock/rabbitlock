import { llms, loader } from 'fumadocs-core/source';
import { defineDocs } from 'fumadocs-mdx/macro';
import { metaSchema, pageSchema } from 'fumadocs-core/source/schema';
import { basePath, docsRoute } from './shared';

const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    schema: pageSchema,
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
  meta: {
    schema: metaSchema,
  },
});

export const source = loader({
  baseUrl: docsRoute,
  source: docs.toFumadocsSource(),
  plugins: [],
});

/** llms.txt for AI agents and assistants reading the docs. */
export const docsLlms = llms(source, {
  renderPage: async (page) => `# ${page.data.title} (${basePath}${page.url})

${await page.data.getText('processed')}`,
  renderUrl: (item) =>
    /^\/.*\.(md|txt)$/.test(item.url) ? `${basePath}/llms.mdx${item.url}` : `${basePath}${item.url}`,
});
