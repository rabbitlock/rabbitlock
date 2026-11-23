import type { Metadata } from 'next';
import { Provider } from '@/components/provider';
import './global.css';

export const metadata: Metadata = {
  metadataBase: new URL('https://rabbitlock.com'),
  title: { default: 'RabbitLock Docs', template: '%s | RabbitLock Docs' },
  description: 'Documentation for RabbitLock, the credential broker for coding agents.',
  icons: { icon: '/docs/rabbitlock-mark.svg' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark" style={{ colorScheme: 'dark' }} suppressHydrationWarning>
      <body className="flex flex-col min-h-screen">
        <Provider>{children}</Provider>
      </body>
    </html>
  );
}
