'use client'

import * as React from 'react'
import { useEffect, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import type { SearchItem } from '@/lib/search'

export function Search() {
  const [open, setOpen] = React.useState(false)
  const [searchQuery, setSearchQuery] = React.useState('')
  const [posts, setPosts] = useState<SearchItem[]>([])
  const [filteredPosts, setFilteredPosts] = useState<SearchItem[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [searchHistory, setSearchHistory] = useState<string[]>([])
  // Load search history from localStorage on mount
  useEffect(() => {
    const savedHistory = localStorage.getItem('search-history')
    if (savedHistory) {
      setSearchHistory(JSON.parse(savedHistory))
    }

    // Load last search query
    const savedQuery = localStorage.getItem('last-search-query')
    if (savedQuery) {
      setSearchQuery(savedQuery)
    }
  }, [])

  // Save search to history
  const saveToHistory = (query: string) => {
    if (query.trim() && !searchHistory.includes(query.trim())) {
      const newHistory = [query.trim(), ...searchHistory.slice(0, 9)] // Keep only 10 recent searches
      setSearchHistory(newHistory)
      localStorage.setItem('search-history', JSON.stringify(newHistory))
    }
  }
  // Clear search history
  const clearHistory = () => {
    setSearchHistory([])
    localStorage.removeItem('search-history')
  }
  // Reset search interface to initial state
  const resetSearchState = () => {
    setSearchQuery('')
  }

  useEffect(() => {
    const fetchPosts = async () => {
      setIsLoading(true)
      try {
        const response = await fetch('/api/search.json')
        const data = await response.json()
        setPosts(data)
      } catch (error) {
        console.error('Error fetching posts:', error)
      } finally {
        setIsLoading(false)
      }
    }
    fetchPosts()
  }, [])

  useEffect(() => {
    const timeoutId = setTimeout(() => {
      const filtered = posts.filter((post) => {
        const searchContent =
          `${post.title} ${post.description} ${post.tags?.join(' ')}`.toLowerCase()
        return searchContent.includes(searchQuery.toLowerCase())
      })
      setFilteredPosts(filtered)

      // Save current search query
      if (searchQuery.trim()) {
        localStorage.setItem('last-search-query', searchQuery)
      }
    }, 150) // Debounce search

    return () => clearTimeout(timeoutId)
  }, [searchQuery, posts]) // Prevent body scroll when dialog is open and ensure proper positioning
  useEffect(() => {
    if (open) {
      // Store current scroll position
      const scrollY = window.scrollY

      // Add a class to the body instead of inline styles
      document.body.classList.add('overflow-hidden')

      // Reset all potential positioning issues
      // Use timeout to ensure this runs after dialog is mounted
      setTimeout(() => {
        // Ensure dialog is centered in viewport
        const dialogContent = document.querySelector('[role="dialog"]')
        if (dialogContent) {
          const dialogOverlay = document.querySelector('[data-radix-portal]')
          if (dialogOverlay) {
            // Force highest z-index
            ;(dialogOverlay as HTMLElement).style.zIndex = '999999'
          }

          // Force center positioning
          ;(dialogContent as HTMLElement).style.position = 'fixed'
          ;(dialogContent as HTMLElement).style.top = '50vh'
          ;(dialogContent as HTMLElement).style.left = '50vw'
          ;(dialogContent as HTMLElement).style.transform =
            'translate(-50%, -50%)'
          ;(dialogContent as HTMLElement).style.zIndex = '1000000'
          ;(dialogContent as HTMLElement).style.margin = '0'
        }
      }, 0)

      return () => {
        // Restore body styles
        document.body.classList.remove('overflow-hidden')

        // Restore scroll position
        window.scrollTo(0, scrollY)
      }
    }
  }, [open])

  return (
    <>
      {' '}
      <button
        onClick={() => setOpen(true)}
        className="text-muted-foreground hover:bg-accent flex h-9 w-9 items-center justify-center rounded-md border transition-all duration-200 ease-out hover:scale-105 active:scale-95"
        aria-label="Search posts"
      >
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
      </button>{' '}
      <Dialog.Root
        open={open}
        onOpenChange={(isOpen) => {
          setOpen(isOpen)
          // Reset search state when dialog closes
          if (!isOpen) {
            resetSearchState()
          }
        }}
      >
        <Dialog.Portal>
          {' '}
          <Dialog.Overlay
            className="data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 fixed inset-0 bg-black/70 backdrop-blur-sm duration-300"
            style={{
              zIndex: 999999,
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              width: '100vw',
              height: '100vh',
            }}
          />
          <Dialog.Content
            className="bg-background data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 max-h-[80vh] w-full max-w-[90%] overflow-hidden rounded-2xl border shadow-2xl duration-300 ease-out sm:max-w-[680px] md:max-w-[720px]"
            style={{
              position: 'fixed',
              top: '50vh',
              left: '50vw',
              transform: 'translate(-50%, -50%)',
              zIndex: 100000,
              maxHeight: '80vh',
              width: '90%',
              maxWidth: '720px',
              margin: 0,
            }}
          >
            <div className="border-border/30 from-background to-muted/10 flex items-center gap-4 border-b bg-gradient-to-r px-6 py-4">
              <div className="bg-muted/30 focus-within:bg-muted/50 flex w-full items-center gap-3 rounded-xl px-4 py-3 transition-all duration-200">
                <div className="text-muted-foreground">
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="20"
                    height="20"
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
                </div>{' '}
                <input
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value)
                    // Save to localStorage when typing
                    localStorage.setItem('last-search-query', e.target.value)
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && searchQuery.trim()) {
                      saveToHistory(searchQuery)
                    }
                  }}
                  onFocus={() => {}}
                  placeholder="Search posts..."
                  className="placeholder:text-muted-foreground/70 flex-1 bg-transparent text-base outline-none"
                  autoFocus
                />
              </div>
              <Dialog.Close className="text-muted-foreground hover:text-foreground hover:bg-muted/50 flex h-10 w-10 items-center justify-center rounded-xl opacity-70 transition-all duration-200 hover:scale-105 hover:opacity-100 focus:outline-none disabled:pointer-events-none">
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
                  className="lucide lucide-x"
                >
                  <path d="M18 6 6 18" />
                  <path d="m6 6 12 12" />
                </svg>
                <span className="sr-only">Close</span>
              </Dialog.Close>
            </div>{' '}
            {!searchQuery ? (
              <div className="px-6 py-4">
                {searchHistory.length > 0 ? (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-foreground text-sm font-semibold">
                        Recent Searches
                      </h3>
                      <button
                        onClick={clearHistory}
                        className="text-muted-foreground hover:text-foreground text-xs transition-colors duration-200"
                      >
                        Clear All
                      </button>
                    </div>
                    <div className="space-y-1">
                      {searchHistory.map((query, index) => (
                        <button
                          key={index}
                          onClick={() => {
                            setSearchQuery(query)
                          }}
                          className="text-muted-foreground hover:text-foreground hover:bg-muted/50 group flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-all duration-200"
                        >
                          <svg
                            xmlns="http://www.w3.org/2000/svg"
                            width="14"
                            height="14"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="2"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            className="text-muted-foreground/60"
                          >
                            <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
                            <path d="M3 3v5h5" />
                          </svg>
                          <span className="flex-1 truncate">{query}</span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              const newHistory = searchHistory.filter(
                                (_, i) => i !== index,
                              )
                              setSearchHistory(newHistory)
                              localStorage.setItem(
                                'search-history',
                                JSON.stringify(newHistory),
                              )
                            }}
                            className="text-muted-foreground/40 hover:text-muted-foreground opacity-0 transition-all duration-200 group-hover:opacity-100"
                          >
                            <svg
                              xmlns="http://www.w3.org/2000/svg"
                              width="12"
                              height="12"
                              viewBox="0 0 24 24"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth="2"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                            >
                              <path d="M18 6 6 18" />
                              <path d="m6 6 12 12" />
                            </svg>
                          </button>
                        </button>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-16 text-center">
                    <div className="from-primary/20 to-primary/5 mb-6 flex h-20 w-20 items-center justify-center rounded-2xl bg-gradient-to-br">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="32"
                        height="32"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        className="text-primary"
                      >
                        <circle cx="11" cy="11" r="8" />
                        <path d="m21 21-4.3-4.3" />
                      </svg>
                    </div>{' '}
                    <h3 className="text-foreground mb-3 text-xl font-semibold">
                      Search Posts
                    </h3>
                    <div className="text-muted-foreground mt-3 flex items-center gap-2 text-xs">
                      <kbd className="bg-muted pointer-events-none flex h-5 items-center rounded border px-1.5 font-mono text-[10px] font-medium">
                        Ctrl
                      </kbd>
                      <span>+</span>
                      <kbd className="bg-muted pointer-events-none flex h-5 items-center rounded border px-1.5 font-mono text-[10px] font-medium">
                        K
                      </kbd>
                      <span>to open quickly</span>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="max-h-[50vh] overflow-y-auto scroll-smooth px-3 py-2">
                {isLoading ? (
                  <div className="flex items-center justify-center py-16">
                    <div className="flex items-center gap-3">
                      <div className="border-primary h-5 w-5 animate-spin rounded-full border-2 border-t-transparent"></div>{' '}
                      <div className="text-muted-foreground font-medium">
                        Searching...
                      </div>
                    </div>
                  </div>
                ) : filteredPosts.length > 0 ? (
                  <div className="space-y-1">
                    {filteredPosts.map((post) => (
                      <a
                        key={post.slug}
                        href={`/blog/${post.slug}`}
                        className="hover:bg-muted/50 block rounded-xl border p-4 transition-all duration-200 hover:shadow-md"
                        onClick={() => {
                          if (searchQuery.trim()) {
                            saveToHistory(searchQuery)
                          }
                          setOpen(false)
                          resetSearchState()
                        }}
                      >
                        {' '}
                        <div className="space-y-2">
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
                                  className="bg-muted text-muted-foreground rounded-full px-2 py-1 text-xs"
                                >
                                  {tag}
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
                      </a>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-16 text-center">
                    <div className="bg-muted/30 mb-6 flex h-16 w-16 items-center justify-center rounded-2xl">
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
                    </div>{' '}
                    <h3 className="text-foreground mb-2 font-semibold">
                      No results found
                    </h3>
                    <p className="text-muted-foreground max-w-sm text-sm">
                      Try searching with different keywords or check your
                      spelling
                    </p>
                  </div>
                )}
              </div>
            )}
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </>
  )
}
