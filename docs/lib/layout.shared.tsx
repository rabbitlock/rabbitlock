import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { gitConfig, siteUrl } from './shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <span className="flex items-center gap-2 font-semibold">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/docs/rabbitlock-mark.svg" alt="" width={22} height={22} />
          RabbitLock <span className="font-normal text-fd-muted-foreground">Docs</span>
        </span>
      ),
      url: '/',
    },
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
    links: [
      { text: 'rabbitlock.com', url: siteUrl, external: true },
      { text: 'Security', url: '/security' },
    ],
  };
}
