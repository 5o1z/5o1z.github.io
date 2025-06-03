'use client'

import { useState, useEffect } from 'react'

interface Post {
  title: string
  description: string
  slug: string
  tags?: string[]
  year: string
  image?: string
}

interface TagSearchProps {
  posts: Post[]
  tag: string
}

export function TagSearch({ posts, tag }: TagSearchProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [filteredPosts, setFilteredPosts] = useState<Post[]>(posts)
  const [selectedYear, setSelectedYear] = useState<string>('all')

  // Get unique years from posts
  const years = Array.from(new Set(posts.map((post) => post.year))).sort(
    (a, b) => parseInt(b) - parseInt(a),
  )

  useEffect(() => {
    let filtered = posts

    // Filter by year first
    if (selectedYear !== 'all') {
      filtered = filtered.filter((post) => post.year === selectedYear)
    }

    // Then filter by search query
    if (searchQuery.trim()) {
      filtered = filtered.filter((post) => {
        const searchContent = `${post.title} ${post.description}`.toLowerCase()
        return searchContent.includes(searchQuery.toLowerCase())
      })
    }

    setFilteredPosts(filtered)
  }, [searchQuery, selectedYear, posts])

  // Group filtered posts by year
  const postsByYear = filteredPosts.reduce(
    (acc: Record<string, Post[]>, post) => {
      ;(acc[post.year] ??= []).push(post)
      return acc
    },
    {},
  )

  const displayYears = Object.keys(postsByYear).sort(
    (a, b) => parseInt(b) - parseInt(a),
  )

  return (
    <div className="flex flex-col gap-6">
      {/* Search and Filter Controls */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
        {/* Search Input */}
        <div className="flex-1">
          <div className="bg-background/50 border-border/50 focus-within:border-border focus-within:bg-background/80 flex w-full items-center gap-3 rounded-xl border px-4 py-3 transition-all duration-200">
            <div className="text-muted-foreground">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="lucide lucide-search"
              >
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.3-4.3" />
              </svg>
            </div>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={`Search posts tagged with "${tag}"...`}
              className="placeholder:text-muted-foreground/70 flex-1 bg-transparent text-base outline-none"
              autoComplete="off"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                >
                  <path d="M18 6 6 18" />
                  <path d="m6 6 12 12" />
                </svg>
              </button>
            )}
          </div>
        </div>

        {/* Year Filter */}
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground text-sm">Year:</span>
          <select
            value={selectedYear}
            onChange={(e) => setSelectedYear(e.target.value)}
            className="bg-background border-border focus:ring-ring rounded-lg border px-3 py-2 text-sm outline-none focus:ring-2"
          >
            <option value="all">All years</option>
            {years.map((year) => (
              <option key={year} value={year}>
                {year}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Search Results Info */}
      {(searchQuery || selectedYear !== 'all') && (
        <div className="text-muted-foreground text-sm">
          {filteredPosts.length > 0 ? (
            <>
              Found <span className="font-medium">{filteredPosts.length}</span>{' '}
              posts
              {searchQuery && ` matching "${searchQuery}"`}
              {selectedYear !== 'all' && ` in ${selectedYear}`}
              {` tagged with "${tag}"`}
            </>
          ) : (
            <>
              No posts found
              {searchQuery && ` matching "${searchQuery}"`}
              {selectedYear !== 'all' && ` in ${selectedYear}`}
              {` tagged with "${tag}"`}
            </>
          )}
        </div>
      )}

      {/* Posts grouped by year */}
      {displayYears.length > 0 ? (
        <div className="flex flex-col gap-8">
          {displayYears.map((year) => (
            <div key={year} className="flex flex-col gap-4">
              <div className="flex items-center gap-3">
                <h2 className="text-xl font-semibold">{year}</h2>
                <span className="text-muted-foreground text-sm">
                  ({postsByYear[year].length} posts)
                </span>
              </div>
              <div className="border-muted grid grid-cols-1 gap-4 border-l-2 pl-4">
                {postsByYear[year].map((post) => (
                  <a
                    key={post.slug}
                    href={`/blog/${post.slug}`}
                    className="hover:bg-accent/50 block rounded-lg border p-4 transition-all duration-200 hover:shadow-sm"
                  >
                    <div className="flex flex-col gap-4 sm:flex-row">
                      {post.image && (
                        <div className="w-full sm:w-32 sm:shrink-0">
                          <img
                            src={post.image}
                            alt={post.title}
                            className="h-24 w-full rounded-lg object-cover"
                          />
                        </div>
                      )}
                      <div className="flex-1 space-y-2">
                        <h3 className="leading-snug font-semibold">
                          {post.title}
                        </h3>
                        <p className="text-muted-foreground text-sm leading-relaxed">
                          {post.description}
                        </p>
                        {post.tags && post.tags.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {post.tags.slice(0, 3).map((tag) => (
                              <span
                                key={tag}
                                className="bg-secondary text-secondary-foreground rounded-full px-2 py-1 text-xs"
                              >
                                #{tag}
                              </span>
                            ))}
                            {post.tags.length > 3 && (
                              <span className="text-muted-foreground text-xs">
                                +{post.tags.length - 3} more
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        /* No Results */
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <div className="bg-muted/30 mb-4 flex h-16 w-16 items-center justify-center rounded-2xl">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="text-muted-foreground"
            >
              <circle cx="11" cy="11" r="8" />
              <line x1="21" x2="16.65" y1="21" y2="16.65" />
            </svg>
          </div>
          <h3 className="text-foreground mb-2 font-semibold">
            No results found
          </h3>
          <p className="text-muted-foreground max-w-sm text-sm">
            Try searching with different keywords or selecting a different year
          </p>
        </div>
      )}
    </div>
  )
}
