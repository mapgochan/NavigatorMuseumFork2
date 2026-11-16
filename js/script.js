document.addEventListener('DOMContentLoaded', () => {
    const el = {
        sidebar: document.getElementById('sidebarLeft'),   
        overlay: document.querySelector('.overlay'),       
        openBtn: document.getElementById('openCatalog'),   
        closeBtn: document.getElementById('closeSidebar'), 
        backBtn: document.getElementById('backBtn'),       
        title: document.getElementById('catalogTitle'),    
        grid: document.getElementById('catalogGrid'),      
        searchInput: document.getElementById('searchInput'),   
        searchClearBtn: document.getElementById('searchClearBtn') 
    };

    let state = {
        history: [],      
        catalog: null,    
        searchQuery: ''   
    };

    function logEvent(type, id, objType, desc, data = {}) {
        fetch('/navigator/api/audit/logs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ event_type: type, object_id: id, object_type: objType, description: desc, status: data.status || null, additional_data: data })
        }).catch(err => console.warn('Аудит не отправлен:', err)); 
    }

    function saveState() {
        sessionStorage.setItem('catalogState', JSON.stringify({
            historyStack: state.history,           
            sidebarActive: el.sidebar.classList.contains('active') 
        }));
    }

    function restoreState() {
        const saved = sessionStorage.getItem('catalogState');
        if (!saved) return; 
        try {
            const data = JSON.parse(saved);
            if (data.historyStack?.length > 0) {
                state.history = data.historyStack; 
                render();                          
                if (data.sidebarActive) showSidebar(); 
            }
        } catch (e) {
            console.warn('Не удалось восстановить состояние', e);
        }
    }

    function getIconPath(iconName) {
        const placeholders = [
            'https://vm-fb.anosov.ru/share/--KIpVUO ',
            'https://vm-fb.anosov.ru/files/Иконки fb/',
            'vm-ftp.anosov.ru/icons/folder.gif'
        ];
        if (!iconName?.trim()) return 'page/logo.png';           
        if (placeholders.some(p => iconName.includes(p))) return 'page/logo.png'; 
        if (iconName.startsWith('http://') || iconName.startsWith('https://')) return iconName; 
        return `page/${iconName}`;                               
    }

    function searchCatalog(query, items = state.catalog?.children || []) {
        if (!query?.trim()) return [];
        const searchQuery = query.toLowerCase().trim();
        function findMatchesInTree(nodeList, currentPath = []) {
            const results = []; 
            for (const node of nodeList) {
                const newPath = [...currentPath, node.name];
                if (node.name.toLowerCase().includes(searchQuery)) {
                    results.push({ ...node, searchPath: newPath.join(' / ') });
                }
                if (node.children?.length > 0) {
                    results.push(...findMatchesInTree(node.children, newPath));
                }
            }
            return results; 
        }
        return findMatchesInTree(items);
    }

    function isVideoFile(url) {
        if (!url) return false;
        try {
            return /\.(mp4|webm|ogg|mov|avi|mkv|flv|wmv|m4v)\s*$/i.test(decodeURIComponent(url.trim().replace(/(https?)\s*:/i, '$1:')));
        } catch { return false; }
    }

    function render() {
        if (state.history.length === 0) return;
        const current = state.history[state.history.length - 1];
        const isSearchMode = !!state.searchQuery;
        const itemsToShow = isSearchMode ? searchCatalog(state.searchQuery) : current.items;
        
        if (el.title) el.title.textContent = isSearchMode ? `Поиск: "${state.searchQuery}"` : current.title;
        renderItems(itemsToShow, isSearchMode);
        if (el.backBtn) el.backBtn.hidden = state.history.length <= 1;
        saveState();
    }

    function renderItems(items, isSearch) {
        if (!el.grid) return;
        el.grid.innerHTML = '';
        if (items.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'item';
            empty.style.cssText = 'justify-content:center;align-items:center;color:#999;font-size:16px';
            empty.textContent = isSearch ? 'Ничего не найдено' : 'Пусто';
            el.grid.appendChild(empty);
            return;
        }
        items.forEach(item => el.grid.appendChild(createItemElement(item, isSearch)));
    }

    function createItemElement(item, isSearch) {
        const div = document.createElement('div');
        div.className = 'item';
        div.setAttribute('role', 'button');  
        div.setAttribute('tabindex', '0');   
        div.dataset.name = item.name;

        const img = document.createElement('img');
        img.className = 'item-icon';
        img.src = getIconPath(item.icon);
        img.alt = item.name;
        img.loading = 'lazy';                
        img.onerror = () => { img.src = 'page/logo.png'; }; 

        const nameSpan = document.createElement('span');
        nameSpan.className = 'item-name';
        nameSpan.textContent = item.name;

        const hasChildren = item.children?.length > 0;
        const isEmpty = !hasChildren && !item.url;
        
        if (isEmpty) {
            const msg = document.createElement('span');
            msg.className = 'item-empty-message';
            msg.textContent = '(пустой)';
            msg.style.cssText = 'color:#999;font-size:12px;margin-top:4px';
            nameSpan.append(document.createElement('br'), msg);
            div.style.opacity = '0.7'; 
        }

        if (isSearch && item.searchPath) {
            const pathSpan = document.createElement('span');
            pathSpan.className = 'item-search-path';
            pathSpan.textContent = item.searchPath;
            nameSpan.append(document.createElement('br'), pathSpan);
        }

        div.append(img, nameSpan);
        div._itemData = item; 
        return div;
    }

    function resetToRoot() {
        if (!state.catalog) {
            setTimeout(resetToRoot, 100);
            return;
        }
        state.history = [{ title: state.catalog.name, items: state.catalog.children }];
        render();
    }

    function handleItemClick(e) {
        const itemDiv = e.target.closest('.item');
        if (!itemDiv?._itemData) return; 
        const item = itemDiv._itemData;
        const hasChildren = item.children?.length > 0;
        const isEmpty = !hasChildren && !item.url;

        if (isEmpty) { alert(`Элемент "${item.name}" пустой.`); return; }

        if (hasChildren) {
            if (state.searchQuery) clearSearch(); 
            state.history.push({ title: item.name, items: item.children }); 
            render();
        } else if (item.url?.trim()) {
            saveState();
            const url = item.url.trim().replace(/(https?|ftp)\s*:/gi, '$1:'); 
            logEvent('link_click', item.name, 'catalog_item_link', `Переход по ссылке: ${item.name}`, { url, status: 'initiated' });

            if (isVideoFile(url)) {
                const playerUrl = `/navigator/video-player?url=${encodeURIComponent(url)}&name=${encodeURIComponent(item.name)}`;
                logEvent('video_player_open', item.name, 'video_file', `Открытие видео: ${item.name}`, { url, player_url: playerUrl });
                window.location.href = playerUrl;
            } else {
                try {
                    const a = document.createElement('a');
                    a.href = url; a.target = '_blank'; a.rel = 'noopener noreferrer'; 
                    document.body.append(a); a.click(); a.remove();
                    logEvent('external_link_open', item.name, 'external_link', `Внешняя ссылка: ${item.name}`, { url, status: 'success' });
                } catch (err) {
                    logEvent('external_link_error', item.name, 'external_link', `Ошибка ссылки: ${item.name}`, { url, error: err.message });
                }
            }
            if (state.searchQuery) clearSearch(); 
        }
    }

    function goBack() {
        if (state.history.length > 1) { state.history.pop(); render(); } 
        else if (state.searchQuery) { clearSearch(); }
    }

    function clearSearch() {
        state.searchQuery = '';
        if (el.searchInput) el.searchInput.value = '';
        if (el.searchClearBtn) el.searchClearBtn.hidden = true;
        resetToRoot();
    }

    function showSidebar() {
        if (!state.catalog) { loadCatalog().then(showSidebar); return; }
        if (el.sidebar.classList.contains('active')) return; 
        resetToRoot();                
        el.sidebar.removeAttribute('hidden');
        if (el.overlay) el.overlay.removeAttribute('hidden');
        void el.sidebar.offsetHeight; 
        el.sidebar.classList.add('active');
        if (el.overlay) el.overlay.classList.add('active');
        if (el.openBtn) el.openBtn.setAttribute('aria-expanded', 'true');
        saveState();
    }

    function hideSidebar() {
        if (!el.sidebar.classList.contains('active')) return; 
        el.sidebar.classList.remove('active');
        if (el.overlay) el.overlay.classList.remove('active');
        if (el.openBtn) el.openBtn.setAttribute('aria-expanded', 'false');

        let done = false;
        const onEnd = () => {
            if (done) return; done = true;
            el.sidebar.setAttribute('hidden', '');
            if (el.overlay) el.overlay.setAttribute('hidden', '');
            clearTimeout(timer);
            saveState();
        };
        const timer = setTimeout(onEnd, 1500);
        el.sidebar.addEventListener('transitionend', onEnd);
        if (el.overlay) el.overlay.addEventListener('transitionend', onEnd);
    }

    async function loadCatalog() {
        try {
            // ВАЖНО: Если вы используете локальный JSON, замените путь ниже на '/data/catalog.json'
            const res = await fetch('/navigator/api/catalog');
            if (!res.ok) throw new Error('Ошибка загрузки');
            state.catalog = await res.json();
            if (el.sidebar.classList.contains('active')) resetToRoot();
            return state.catalog;
        } catch (e) {
            console.error('Не удалось загрузить каталог:', e);
            state.catalog = { name: 'Ошибка загрузки', children: [] };
        }
    }

    if (el.openBtn) {
        el.openBtn.addEventListener('click', () => {
            logEvent('web_resource_view', 'main_page_catalog', 'ui_element', 'Открытие каталога');
            showSidebar();
        });
    }

    if (el.closeBtn) el.closeBtn.addEventListener('click', hideSidebar);
    if (el.overlay) el.overlay.addEventListener('click', hideSidebar);
    if (el.backBtn) el.backBtn.addEventListener('click', goBack);

    if (el.grid) {
        el.grid.addEventListener('click', e => {
            const itemDiv = e.target.closest('.item');
            if (itemDiv?._itemData) logEvent('web_resource_view', itemDiv._itemData.name, 'catalog_item', `Просмотр: ${itemDiv._itemData.name}`, {});
            handleItemClick(e);
        });
        el.grid.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === ' ') {
                const item = e.target.closest('.item');
                if (item) { e.preventDefault(); handleItemClick({ target: item }); }
            }
        });
    }

    if (el.searchInput) {
        el.searchInput.addEventListener('input', e => {
            state.searchQuery = e.target.value.trim();
            if (el.searchClearBtn) el.searchClearBtn.hidden = state.searchQuery === '';
            render();
        });
    }

    if (el.searchClearBtn) el.searchClearBtn.addEventListener('click', clearSearch);

    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && el.sidebar.classList.contains('active')) {
            state.searchQuery ? clearSearch() : hideSidebar();
        }
    });

    (async () => {
        await loadCatalog();   
        restoreState();        
        window.addEventListener('storage', e => {
            if (e.key === 'catalogUpdated') loadCatalog().then(() => { if (state.history.length > 0) render(); });
        });
    })();
});