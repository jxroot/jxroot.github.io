// Configure marked for security and syntax highlighting
marked.setOptions({
    breaks: true,
    gfm: true,
    headerIds: false,
    mangle: false,
    sanitize: false,
    smartLists: true,
    smartypants: false,
    xhtml: false,
    highlight: function(code, lang) {
        if (lang && hljs.getLanguage(lang)) {
            try {
                return hljs.highlight(code, { language: lang }).value;
            } catch (e) {
                console.error(e);
                return code;
            }
        }
        return hljs.highlightAuto(code).value;
    },
    langPrefix: 'hljs language-'
});

// Custom renderer for Notion-like features
const renderer = {
    blockquote(quote) {
        // بررسی callout syntax
        if (typeof quote === 'string') {
            const calloutMatch = quote.match(/^\[!(\w+)\]\s*(.*)$/m);
            if (calloutMatch) {
                const type = calloutMatch[1].toLowerCase();
                const content = calloutMatch[2];
                let icon = '';
                
                switch(type) {
                    case 'note':
                        icon = '📝';
                        break;
                    case 'warning':
                        icon = '⚠️';
                        break;
                    case 'danger':
                        icon = '🚨';
                        break;
                    case 'tip':
                        icon = '💡';
                        break;
                }
                
                return `<div class="callout callout-${type}">
                    <div class="callout-header">
                        <span class="callout-icon">${icon}</span>
                        <span class="callout-title">${type.charAt(0).toUpperCase() + type.slice(1)}</span>
                    </div>
                    <div class="callout-content">${marked.parseInline(content)}</div>
                </div>`;
            }
        }
        return `<blockquote>${marked.parseInline(quote)}</blockquote>`;
    },
    code(code, language) {
        if (!code) return '';
        
        // Extract the actual code content if it's an object
        const codeContent = typeof code === 'object' ? code.text || code.raw || code : code;
        
        // Detect language from code content if not specified
        let detectedLanguage = language;
        if (!detectedLanguage) {
            // Check for language hints in the code
            const firstLine = codeContent.split('\n')[0];
            const langMatch = firstLine.match(/^```(\w+)/);
            if (langMatch) {
                detectedLanguage = langMatch[1];
            } else {
                // Auto-detect language based on code content
                const autoDetected = hljs.highlightAuto(codeContent);
                detectedLanguage = autoDetected.language || 'plaintext';
            }
        }
        
        // Validate language
        const validLanguage = detectedLanguage && hljs.getLanguage(detectedLanguage) ? detectedLanguage : 'plaintext';
        let highlightedCode;
        
        try {
            // Highlight the code
            highlightedCode = hljs.highlight(codeContent, { 
                language: validLanguage,
                ignoreIllegals: true
            }).value;
        } catch (e) {
            console.error('Error highlighting code:', e);
            highlightedCode = codeContent;
        }
        
        return `
            <div class="code-block">
                <div class="code-header">
                    <span class="code-language">${validLanguage}</span>
                </div>
                <pre><code class="hljs language-${validLanguage}">${highlightedCode}</code></pre>
            </div>
        `;
    }
};

marked.use({ renderer });

// Pagination settings
const POSTS_PER_PAGE = 5;
let currentPage = 1;
let totalPosts = [];
let filteredPosts = [];
let activeTag = null;

// Initialize search and tag functionality
function initializeSearch() {
    const searchInput = document.getElementById('search-input');
    const searchBtn = document.querySelector('.search-btn');

    function performSearch() {
        const searchTerm = searchInput.value.toLowerCase();
        filterPosts(searchTerm, activeTag);
    }

    searchInput.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') {
            performSearch();
        }
    });

    searchBtn.addEventListener('click', performSearch);

    // Initialize tag cloud clicks
    const tagLinks = document.querySelectorAll('.tag-cloud a');
    tagLinks.forEach(tag => {
        tag.addEventListener('click', (e) => {
            e.preventDefault();
            const tagText = e.target.textContent;
            
            // Toggle active tag
            if (activeTag === tagText) {
                activeTag = null;
                tagLinks.forEach(t => t.classList.remove('active'));
            } else {
                activeTag = tagText;
                tagLinks.forEach(t => {
                    if (t.textContent === tagText) {
                        t.classList.add('active');
                    } else {
                        t.classList.remove('active');
                    }
                });
            }
            
            filterPosts(searchInput.value.toLowerCase(), activeTag);
        });
    });
}

// Filter posts based on search term and/or tag
function filterPosts(searchTerm, tag) {
    filteredPosts = totalPosts.filter(post => {
        const matchesSearch = !searchTerm || 
            post.title.toLowerCase().includes(searchTerm) ||
            post.preview.toLowerCase().includes(searchTerm) ||
            post.tags.some(t => t.toLowerCase().includes(searchTerm)) ||
            post.author.toLowerCase().includes(searchTerm);
            
        const matchesTag = !tag || post.tags.includes(tag);
        
        return matchesSearch && matchesTag;
    });
    
    currentPage = 1;
    displayPosts(currentPage);
    updateActiveFilters(searchTerm, tag);
}

// Update UI to show active filters
function updateActiveFilters(searchTerm, tag) {
    const filtersContainer = document.getElementById('active-filters');
    if (!filtersContainer) {
        const postsContainer = document.getElementById('posts-list');
        const newFiltersContainer = document.createElement('div');
        newFiltersContainer.id = 'active-filters';
        postsContainer.parentNode.insertBefore(newFiltersContainer, postsContainer);
    }

    const filters = [];
    if (searchTerm) {
        filters.push(`Search: "${searchTerm}"`);
    }
    if (tag) {
        filters.push(`Tag: ${tag}`);
    }

    document.getElementById('active-filters').innerHTML = filters.length ? `
        <div class="active-filters">
            <span>Active Filters:</span>
            ${filters.map(filter => `
                <span class="filter-tag">
                    ${filter}
                    <i class="fas fa-times" onclick="clearFilters()"></i>
                </span>
            `).join('')}
        </div>
    ` : '';
}

// Clear all filters
function clearFilters() {
    const searchInput = document.getElementById('search-input');
    searchInput.value = '';
    activeTag = null;
    
    // Remove active class from all tags
    document.querySelectorAll('.tag-cloud a').forEach(tag => {
        tag.classList.remove('active');
    });
    
    filterPosts('', null);
}

// Load posts from posts.json
function loadPosts() {
    console.log('Loading posts...');
    fetch('./posts.json')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            totalPosts = data;
            filteredPosts = [...totalPosts];
            console.log('Posts loaded:', totalPosts);
            displayPosts(currentPage);
        })
        .catch(error => {
            console.error('Error loading posts:', error);
            showError();
        });
}

function showError() {
    document.getElementById('posts-list').innerHTML = `
        <div class="post-item">
            <div class="post-title">Error loading posts</div>
            <div class="post-date">Please refresh the page</div>
        </div>
    `;
}

// Display posts for the current page
function displayPosts(page) {
    const postsList = document.getElementById('posts-list');
    if (!postsList) {
        console.error('Posts list element not found!');
        return;
    }

    if (!filteredPosts || filteredPosts.length === 0) {
        postsList.innerHTML = `
            <div class="post-item">
                <div class="post-title">No posts found</div>
                <div class="post-date">Try different search terms or tags</div>
            </div>
        `;
        return;
    }

    const startIndex = (page - 1) * POSTS_PER_PAGE;
    const endIndex = startIndex + POSTS_PER_PAGE;
    const postsToShow = filteredPosts.slice(startIndex, endIndex);

    postsList.innerHTML = postsToShow.map(post => `
        <div class="post-item" onclick="loadPost('${post.id}')">
            <div class="post-image">
                <img src="${post.image}" alt="${post.title}" onerror="this.src='images/default.png'">
            </div>
            <div class="post-content-preview">
                <div class="post-meta">
                    <span class="post-author"><i class="fas fa-user"></i> ${post.author}</span>
                    <span class="post-date"><i class="fas fa-calendar"></i> ${post.date}</span>
                    <span class="post-read-time"><i class="fas fa-clock"></i> ${post.read_time}</span>
                </div>
                <div class="post-title">${post.title}</div>
                <div class="post-preview">${post.preview}</div>
                <div class="post-tags">
                    ${post.tags ? post.tags.map(tag => `
                        <span class="tag ${tag === activeTag ? 'active' : ''}" 
                              onclick="event.stopPropagation(); filterByTag('${tag}')">
                            ${tag}
                        </span>
                    `).join('') : ''}
                </div>
                <div class="post-read-more">
                    <span class="read-more-btn">Read More <i class="fas fa-arrow-right"></i></span>
                </div>
            </div>
        </div>
    `).join('');
    
    displayPagination();
}

// Display pagination controls
function displayPagination() {
    const totalPages = Math.ceil(filteredPosts.length / POSTS_PER_PAGE);
    
    // Remove existing pagination if any
    const existingPagination = document.querySelector('.pagination');
    if (existingPagination) {
        existingPagination.remove();
    }

    const paginationContainer = document.createElement('div');
    paginationContainer.className = 'pagination';

    let paginationHTML = '';

    // Previous button
    paginationHTML += `
        <button class="pagination-btn" 
                onclick="changePage(${currentPage - 1})" 
                ${currentPage === 1 ? 'disabled' : ''}>
            <i class="fas fa-chevron-left"></i>
        </button>
    `;

    // Page numbers
    for (let i = 1; i <= totalPages; i++) {
        paginationHTML += `
            <button class="pagination-btn ${i === currentPage ? 'active' : ''}" 
                    onclick="changePage(${i})">
                ${i}
            </button>
        `;
    }

    // Next button
    paginationHTML += `
        <button class="pagination-btn" 
                onclick="changePage(${currentPage + 1})" 
                ${currentPage === totalPages ? 'disabled' : ''}>
            <i class="fas fa-chevron-right"></i>
        </button>
    `;

    paginationContainer.innerHTML = paginationHTML;
    document.getElementById('posts-list').appendChild(paginationContainer);
}

// Change page
function changePage(page) {
    if (page < 1 || page > Math.ceil(filteredPosts.length / POSTS_PER_PAGE)) {
        return;
    }
    currentPage = page;
    displayPosts(currentPage);
}

// Load and display a single post
function loadPost(postId) {
    console.log('Loading post:', postId);
    fetch(`./posts/${postId}.md`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.text();
        })
        .then(markdown => {
            console.log('Markdown content loaded');
            const html = marked.parse(markdown);
            console.log('Markdown parsed to HTML');
            
            // Create post page
            const container = document.querySelector('.container');
            container.innerHTML = `
                <header>
                    <nav>
                        <div class="logo">
                            <i class="fas fa-terminal"></i>
                            <span>Cyber Blog</span>
                        </div>
                        <div class="nav-links">
                            <a href="index.html" class="active">Blog</a>
                            <a href="about.html">About</a>
                            <a href="contact.html">Contact</a>
                        </div>
                        <div class="nav-right">
                            <div class="search-container">
                                <input type="text" id="search-input" placeholder="Search posts...">
                                <button class="search-btn">
                                    <i class="fas fa-search"></i>
                                </button>
                            </div>
                        </div>
                    </nav>
                    <div class="header-content">
                        <h1>root@cyber:~#</h1>
                        <p class="subtitle">Security Blog</p>
                    </div>
                </header>
                <main>
                    <div class="post-content">
                        ${html}
                    </div>
                    <a href="#" class="back-button" onclick="window.location.reload()">
                        <i class="fas fa-arrow-left"></i> Back
                    </a>
                </main>
                <footer>
                    <div class="footer-content">
                        <div class="tags">
                            <h3>Tags</h3>
                            <div class="tag-cloud">
                                <a href="#">Android</a>
                                <a href="#">Malware</a>
                                <a href="#">ReverseEngineering</a>
                                <a href="#">Exploitation</a>
                                <a href="#">CTF</a>
                                <a href="#">WebHacking</a>
                            </div>
                        </div>
                        <div class="copyright">
                            <p>© 2025 Cyber Security Blog. All rights reserved.</p>
                        </div>
                    </div>
                </footer>
            `;
            
            // Initialize highlight.js on the new content
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightBlock(block);
            });
            
            // Reinitialize search after loading post
            initializeSearch();
        })
        .catch(error => {
            console.error('Error processing post:', error);
            showPostError(error.message);
        });
}

// Handle browser back/forward buttons
window.addEventListener('popstate', function(event) {
    if (window.location.pathname === '/') {
        window.location.reload();
    }
});

function showPostError(errorMessage) {
    const container = document.querySelector('.container');
    container.innerHTML = `
        <header>
            <nav>
                <div class="logo">
                    <i class="fas fa-terminal"></i>
                    <span>Cyber Blog</span>
                </div>
                <div class="nav-links">
                    <a href="index.html" class="active">Blog</a>
                    <a href="about.html">About</a>
                    <a href="contact.html">Contact</a>
                </div>
                <div class="nav-right">
                    <div class="search-container">
                        <input type="text" id="search-input" placeholder="Search posts...">
                        <button class="search-btn">
                            <i class="fas fa-search"></i>
                        </button>
                    </div>
                </div>
            </nav>
            <div class="header-content">
                <h1>root@cyber:~#</h1>
                <p class="subtitle">Security Blog</p>
            </div>
        </header>
        <main>
            <div class="post-content">
                <h2>Error Loading Post</h2>
                <p>Sorry, there was an error loading this post.</p>
                <p>Error: ${errorMessage}</p>
                <a href="#" class="back-button" onclick="window.location.reload()">
                    <i class="fas fa-arrow-left"></i> Back
                </a>
            </div>
        </main>
        <footer>
            <div class="footer-content">
                <div class="tags">
                    <h3>Tags</h3>
                    <div class="tag-cloud">
                        <a href="#">Android</a>
                        <a href="#">Malware</a>
                        <a href="#">ReverseEngineering</a>
                        <a href="#">Exploitation</a>
                        <a href="#">CTF</a>
                        <a href="#">WebHacking</a>
                    </div>
                </div>
                <div class="copyright">
                    <p>© 2025 Cyber Security Blog. All rights reserved.</p>
                </div>
            </div>
        </footer>
    `;
    
    // Reinitialize search after error
    initializeSearch();
}

// Filter by tag helper function
function filterByTag(tag) {
    activeTag = activeTag === tag ? null : tag;
    
    // Update tag cloud active states
    document.querySelectorAll('.tag-cloud a').forEach(tagLink => {
        if (tagLink.textContent === tag) {
            tagLink.classList.toggle('active');
        } else {
            tagLink.classList.remove('active');
        }
    });
    
    filterPosts(document.getElementById('search-input').value.toLowerCase(), activeTag);
}

// Initialize the blog
document.addEventListener('DOMContentLoaded', () => {
    loadPosts();
    initializeSearch();
}); 
