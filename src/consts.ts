import type { IconMap, SocialLink, Site } from '@/types'

export const SITE: Site = {
  title: '✧ Alter ✧',
  description:
    'The best thing in the world is finding yourself.',
  href: 'https://5o1z.github.io',
  author: 'K.',
  locale: 'en-US',
  featuredPostCount: 5,
  postsPerPage: 5,
}

export const NAV_LINKS: SocialLink[] = [
  {
    href: '/blog',
    label: 'blog',
  },
  {
    href: '/authors',
    label: 'authors',
  },
  {
    href: '/about',
    label: 'about',
  },
    {
    href: '/archive',
    label: 'archive',
  },
]

export const SOCIAL_LINKS: SocialLink[] = [
  {
    href: 'https://github.com/5o1z',
    label: 'GitHub',
  },
  {
    href: 'https://x.com/5o1z_',
    label: 'Twitter',
  },
  {
    href: 'mailto:vohoanganhkiet2006@gmail.com',
    label: 'Email',
  },
  {
    href: '/rss.xml',
    label: 'RSS',
  },
]

export const ICON_MAP: IconMap = {
  Website: 'lucide:globe',
  GitHub: 'lucide:github',
  LinkedIn: 'lucide:linkedin',
  Twitter: 'lucide:twitter',
  Email: 'lucide:mail',
  RSS: 'lucide:rss',
}
