import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';

/**
 * Shared layout configuration
 */
export const baseOptions: BaseLayoutProps = {
  nav: {
    title: 'Lux Warp',
  },
  links: [
    {
      text: 'Documentation',
      url: '/docs',
      active: 'nested-url',
    },
    {
      text: 'GitHub',
      url: 'https://github.com/luxfi/warp',
    },
  ],
};
