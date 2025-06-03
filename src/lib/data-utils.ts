import { getCollection, type CollectionEntry } from 'astro:content'

export async function getAllPosts(): Promise<CollectionEntry<'blog'>[]> {
  const posts = await getCollection('blog')
  return posts
    .filter((post) => !post.data.draft)
    .sort((a, b) => {
      // First, sort by pinned status (pinned posts first)
      if (a.data.pinned && !b.data.pinned) return -1
      if (!a.data.pinned && b.data.pinned) return 1
      // Then sort by date (newest first)
      return b.data.date.valueOf() - a.data.date.valueOf()
    })
}

export async function getRecentPosts(
  count: number,
): Promise<CollectionEntry<'blog'>[]> {
  const posts = await getAllPosts()
  return posts.slice(0, count)
}

export async function getAdjacentPosts(currentId: string): Promise<{
  prev: CollectionEntry<'blog'> | null
  next: CollectionEntry<'blog'> | null
}> {
  const posts = await getAllPosts()
  const currentIndex = posts.findIndex((post) => post.id === currentId)

  if (currentIndex === -1) {
    return { prev: null, next: null }
  }

  return {
    next: currentIndex > 0 ? posts[currentIndex - 1] : null,
    prev: currentIndex < posts.length - 1 ? posts[currentIndex + 1] : null,
  }
}

export async function getAllAuthors(): Promise<CollectionEntry<'authors'>[]> {
  return await getCollection('authors')
}

export async function getAllTags(): Promise<Map<string, number>> {
  const posts = await getAllPosts()

  return posts.reduce((acc, post) => {
    post.data.tags?.forEach((tag) => {
      acc.set(tag, (acc.get(tag) || 0) + 1)
    })
    return acc
  }, new Map<string, number>())
}

export async function getSortedTags(): Promise<
  { tag: string; count: number }[]
> {
  const tagCounts = await getAllTags()

  return [...tagCounts.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => {
      const countDiff = b.count - a.count
      return countDiff !== 0 ? countDiff : a.tag.localeCompare(b.tag)
    })
}

export function groupPostsByYear(
  posts: CollectionEntry<'blog'>[],
): Record<string, CollectionEntry<'blog'>[]> {
  return posts.reduce(
    (acc: Record<string, CollectionEntry<'blog'>[]>, post) => {
      const year = post.data.date.getFullYear().toString()
      ;(acc[year] ??= []).push(post)
      return acc
    },
    {},
  )
}

export async function parseAuthors(authorIds: string[] = []) {
  if (!authorIds.length) return []

  const allAuthors = await getAllAuthors()
  const authorMap = new Map(allAuthors.map((author) => [author.id, author]))

  return authorIds.map((id) => {
    const author = authorMap.get(id)

    return {
      id,
      name: author?.data?.name || id,
      avatar: author?.data?.avatar || '/static/logo.png',
      isRegistered: !!author,
    }
  })
}

export async function getPostsByAuthor(
  authorId: string,
): Promise<CollectionEntry<'blog'>[]> {
  const posts = await getAllPosts()
  return posts.filter((post) => post.data.authors?.includes(authorId))
}

export async function getPostsByTag(
  tag: string,
): Promise<CollectionEntry<'blog'>[]> {
  const posts = await getAllPosts()
  return posts.filter((post) => post.data.tags?.includes(tag))
}

export async function getPinnedPosts(): Promise<CollectionEntry<'blog'>[]> {
  const posts = await getAllPosts()
  return posts.filter((post) => post.data.pinned === true)
}

export async function getRecentPostsExcludingPinned(
  count: number,
): Promise<CollectionEntry<'blog'>[]> {
  const posts = await getAllPosts()
  const nonPinnedPosts = posts.filter((post) => !post.data.pinned)
  return nonPinnedPosts.slice(0, count)
}

export async function getPinnedPostsCount(): Promise<number> {
  const pinnedPosts = await getPinnedPosts()
  return pinnedPosts.length
}

export async function getAllPostsWithPinnedFirst(): Promise<CollectionEntry<'blog'>[]> {
  const posts = await getCollection('blog')
  return posts
    .filter((post) => !post.data.draft)
    .sort((a, b) => {
      // First, sort by pinned status (pinned posts first)
      if (a.data.pinned && !b.data.pinned) return -1
      if (!a.data.pinned && b.data.pinned) return 1
      // Then sort by date (newest first)
      return b.data.date.valueOf() - a.data.date.valueOf()
    })
}

export async function getPostsByYear(
  year: string,
): Promise<CollectionEntry<'blog'>[]> {
  const posts = await getAllPosts()
  return posts.filter((post) => {
    const postYear = post.data.date.getFullYear().toString()
    return postYear === year
  })
}

export async function getYearStats(): Promise<
  { year: string; count: number }[]
> {
  const posts = await getAllPosts()
  const yearStats = posts.reduce((acc, post) => {
    const year = post.data.date.getFullYear().toString()
    acc.set(year, (acc.get(year) || 0) + 1)
    return acc
  }, new Map<string, number>())

  return [...yearStats.entries()]
    .map(([year, count]) => ({ year, count }))
    .sort((a, b) => parseInt(b.year) - parseInt(a.year))
}

export function groupPostsByMonth(
  posts: CollectionEntry<'blog'>[],
): Record<string, Record<string, CollectionEntry<'blog'>[]>> {
  return posts.reduce(
    (acc: Record<string, Record<string, CollectionEntry<'blog'>[]>>, post) => {
      const year = post.data.date.getFullYear().toString()
      const month = post.data.date.toLocaleString('default', { month: 'long' })

      if (!acc[year]) {
        acc[year] = {}
      }
      if (!acc[year][month]) {
        acc[year][month] = []
      }

      acc[year][month].push(post)
      return acc
    },
    {},
  )
}
