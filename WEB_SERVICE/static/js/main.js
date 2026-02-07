// E-MAT Web Interface - Main JavaScript

document.addEventListener('DOMContentLoaded', () => {

    // ============================================================
    // HISTORY MANAGEMENT
    // ============================================================
    const historyList = document.getElementById('historyList');
    let analysisHistory = JSON.parse(localStorage.getItem('emat_history') || '[]');

    function saveHistory() {
        localStorage.setItem('emat_history', JSON.stringify(analysisHistory.slice(-30)));
    }

    function addToHistory(result) {
        const fi = result.file_info || {};
        const yaraCount = (result.static_analysis && result.static_analysis.yara_matches)
            ? result.static_analysis.yara_matches.length : 0;
        const entropy = fi.entropy || 0;
        let level = 'safe';
        if (yaraCount > 0 || entropy > 7.5) level = 'malicious';
        else if (entropy > 6.5) level = 'suspicious';

        const entry = {
            id: Date.now(),
            name: fi.filename || 'unknown',
            size: fi.size || 0,
            type: fi.description || fi.mime_type || 'unknown',
            sha256: (fi.hashes && fi.hashes.sha256) || '',
            entropy: entropy,
            yaraCount: yaraCount,
            level: level,
            time: new Date().toLocaleTimeString(),
            result: result
        };
        analysisHistory.unshift(entry);
        saveHistory();
        renderHistory();
    }

    function renderHistory() {
        if (analysisHistory.length === 0) {
            historyList.innerHTML = '<div class="history-empty">No analyses yet. Upload a file to get started.</div>';
            return;
        }
        historyList.innerHTML = '';
        analysisHistory.forEach(entry => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.innerHTML =
                '<div class="hi-name">' + escapeHtml(entry.name) + '</div>' +
                '<div class="hi-meta">' + entry.time + ' &middot; ' + formatSize(entry.size) + '</div>' +
                '<span class="hi-badge ' + entry.level + '">' + entry.level.toUpperCase() + '</span>';
            div.addEventListener('click', () => {
                // Switch to File/URL tab and show result
                document.querySelectorAll('.tab-button')[0].click();
                displayResultsNeat(entry.result, document.getElementById('resultsSection'));
            });
            historyList.appendChild(div);
        });
    }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    renderHistory();

    // ============================================================
    // NEAT RESULT DISPLAY (card-based, not raw pre)
    // ============================================================
    function displayResultsNeat(result, container) {
        const fi = result.file_info || {};
        const sa = result.static_analysis || {};
        const es = result.educational_summary || {};
        const yaraMatches = sa.yara_matches || [];

        let html = '';
        html += '<div class="result-header"><h2 class="result-title">Analysis Results</h2></div>';

        // File Info
        html += '<div class="result-section-title">File Information</div>';
        html += row('Filename', fi.filename);
        html += row('Size', fi.size ? fi.size.toLocaleString() + ' bytes' : 'N/A');
        html += row('Type', fi.description);
        html += row('MIME', fi.mime_type);
        html += row('Entropy', fi.entropy + ' - ' + fi.entropy_analysis);

        // Hashes
        html += '<div class="result-section-title">File Hashes</div>';
        if (fi.hashes) {
            for (const [k, v] of Object.entries(fi.hashes)) {
                html += row(k.toUpperCase(), v);
            }
        }

        // PE
        if (sa.pe_analysis && sa.pe_analysis.is_pe) {
            const pe = sa.pe_analysis;
            html += '<div class="result-section-title">PE Analysis</div>';
            html += row('Architecture', pe.architecture);
            html += row('Subsystem', pe.subsystem);
            html += row('Compile Time', pe.compile_timestamp);
            html += row('Entry Point', pe.entry_point);
        }

        // Strings
        if (sa.strings && !sa.strings.error) {
            const s = sa.strings;
            html += '<div class="result-section-title">String Analysis</div>';
            html += row('Total Strings', s.total_count || 0);
            const stats = s.statistics || {};
            if (stats.urls_found) html += row('URLs Found', stats.urls_found);
            if (stats.ips_found) html += row('IPs Found', stats.ips_found);
            if (stats.suspicious_keywords_found) html += row('Suspicious Keywords', stats.suspicious_keywords_found);
        }

        // YARA
        if (yaraMatches.length > 0) {
            html += '<div class="result-section-title">YARA Matches (' + yaraMatches.length + ')</div>';
            yaraMatches.forEach(m => {
                const sev = (m.meta && m.meta.severity) || 'unknown';
                html += row('Rule', m.rule + ' <span class="hi-badge ' +
                    (sev === 'high' ? 'malicious' : sev === 'medium' ? 'suspicious' : 'safe') +
                    '">' + sev.toUpperCase() + '</span>');
            });
        }

        // Educational Summary
        html += '<div class="result-section-title">Educational Summary</div>';
        html += '<div class="result-row" style="flex-direction:column;padding:0.6rem 1rem;">';
        html += '<div style="color:var(--text-primary);font-size:0.8rem;margin-bottom:0.5rem;">' + escapeHtml(es.overall_assessment || '') + '</div>';
        if (es.suggested_learning_topics && es.suggested_learning_topics.length > 0) {
            html += '<div style="color:var(--text-secondary);font-size:0.78rem;">';
            es.suggested_learning_topics.forEach(t => {
                html += '&bull; ' + escapeHtml(t) + '<br>';
            });
            html += '</div>';
        }
        html += '</div>';

        container.innerHTML = html;
        container.classList.add('active');
    }

    function row(label, value) {
        return '<div class="result-row"><div class="result-label">' + escapeHtml(label) +
            '</div><div class="result-value">' + (value != null ? value : 'N/A') + '</div></div>';
    }

    // ============================================================
    // TAB SWITCHING
    // ============================================================
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            button.classList.add('active');
            const t = document.getElementById('tab-' + button.getAttribute('data-tab'));
            if (t) t.classList.add('active');
        });
    });

    // ============================================================
    // TAB 1: FILE/URL ANALYSIS
    // ============================================================
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const progressContainer = document.getElementById('progressContainer');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const resultsSection = document.getElementById('resultsSection');

    let selectedFile = null;

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault(); dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) handleFileSelect(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', e => {
        if (e.target.files.length > 0) handleFileSelect(e.target.files[0]);
    });

    function handleFileSelect(file) {
        selectedFile = file;
        dropZone.querySelector('.drop-text').textContent = 'Selected: ' + file.name;
        dropZone.style.borderColor = 'var(--success)';
        analyzeBtn.disabled = false;
    }

    analyzeBtn.addEventListener('click', async () => {
        if (!selectedFile) return;
        progressContainer.classList.add('active');
        resultsSection.classList.remove('active');
        analyzeBtn.disabled = true;
        progressFill.style.width = '0%';

        const formData = new FormData();
        formData.append('file', selectedFile);

        // Smooth progress animation
        let progress = 0;
        const progressInterval = setInterval(() => {
            progress = Math.min(progress + 2, 85);
            progressFill.style.width = progress + '%';
            progressText.textContent = 'Analyzing... ' + Math.round(progress) + '%';
        }, 300);

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 120000); // 2 min timeout

            const response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData,
                signal: controller.signal
            });
            clearTimeout(timeout);
            clearInterval(progressInterval);

            if (!response.ok) {
                let errMsg = 'Analysis failed (HTTP ' + response.status + ')';
                try { const e = await response.json(); errMsg = e.error || errMsg; } catch(_) {}
                throw new Error(errMsg);
            }

            const result = await response.json();
            progressFill.style.width = '100%';
            progressText.textContent = 'Analysis complete!';

            setTimeout(() => {
                displayResultsNeat(result, resultsSection);
                addToHistory(result);
                progressContainer.classList.remove('active');
                analyzeBtn.disabled = false;
                selectedFile = null;
                fileInput.value = '';
                dropZone.querySelector('.drop-text').textContent = 'Drag & Drop For Instant Analysis';
                dropZone.style.borderColor = '';
            }, 400);

        } catch (error) {
            clearInterval(progressInterval);
            progressContainer.classList.remove('active');
            analyzeBtn.disabled = false;

            if (error.name === 'AbortError') {
                alert('Analysis timed out. The file may be too large or the server is busy.');
            } else {
                alert('Error: ' + error.message);
            }
        }
    });

    // ============================================================
    // TAB 2: FILE COLLECTION
    // ============================================================
    const collDropZone = document.getElementById('collectionDropZone');
    const collFileInput = document.getElementById('collectionFileInput');
    const collAnalyzeBtn = document.getElementById('collectionAnalyzeBtn');
    const collFileList = document.getElementById('collectionFileList');
    const collProgress = document.getElementById('collectionProgress');
    const collProgressFill = document.getElementById('collectionProgressFill');
    const collProgressText = document.getElementById('collectionProgressText');
    const collResults = document.getElementById('collectionResults');
    let collFiles = [];

    collDropZone.addEventListener('click', () => collFileInput.click());
    collDropZone.addEventListener('dragover', e => { e.preventDefault(); collDropZone.classList.add('dragover'); });
    collDropZone.addEventListener('dragleave', () => collDropZone.classList.remove('dragover'));
    collDropZone.addEventListener('drop', e => { e.preventDefault(); collDropZone.classList.remove('dragover'); addCollFiles(e.dataTransfer.files); });
    collFileInput.addEventListener('change', e => addCollFiles(e.target.files));

    function addCollFiles(fl) {
        for (let i = 0; i < fl.length; i++) collFiles.push(fl[i]);
        renderCollFiles();
        collAnalyzeBtn.disabled = collFiles.length === 0;
    }
    function renderCollFiles() {
        collFileList.innerHTML = '';
        collFiles.forEach((f, i) => {
            const d = document.createElement('div');
            d.className = 'file-list-item';
            d.innerHTML = '<span>' + escapeHtml(f.name) + ' (' + formatSize(f.size) + ')</span>' +
                '<button onclick="window._removeCollFile(' + i + ')" class="btn-small">Remove</button>';
            collFileList.appendChild(d);
        });
    }
    window._removeCollFile = function(i) { collFiles.splice(i, 1); renderCollFiles(); collAnalyzeBtn.disabled = collFiles.length === 0; };

    collAnalyzeBtn.addEventListener('click', async () => {
        if (collFiles.length === 0) return;
        collProgress.classList.add('active'); collResults.classList.remove('active');
        collAnalyzeBtn.disabled = true;
        collProgressFill.style.width = '20%'; collProgressText.textContent = 'Uploading...';

        const fd = new FormData();
        collFiles.forEach(f => fd.append('files', f));

        try {
            const r = await fetch('/api/collection', { method: 'POST', body: fd });
            collProgressFill.style.width = '100%'; collProgressText.textContent = 'Complete!';
            if (!r.ok) throw new Error('Collection analysis failed');
            const data = await r.json();

            let html = '<div class="result-header"><h2 class="result-title">Collection Results (' + data.total_files + ' files)</h2></div>';
            (data.results || []).forEach(res => {
                if (res.error) {
                    html += '<div class="result-section-title" style="color:var(--danger);">' + escapeHtml(res.filename || 'unknown') + ' - ERROR</div>';
                    html += row('Error', res.error);
                } else {
                    const fi = res.file_info;
                    html += '<div class="result-section-title">' + escapeHtml(fi.filename) + '</div>';
                    html += row('Size', fi.size.toLocaleString() + ' bytes');
                    html += row('Type', fi.description);
                    html += row('SHA256', fi.hashes.sha256 || 'N/A');
                    html += row('Entropy', fi.entropy + ' - ' + fi.entropy_analysis);
                    const yc = (res.static_analysis && res.static_analysis.yara_matches) ? res.static_analysis.yara_matches.length : 0;
                    html += row('YARA', yc + ' match(es)');
                    addToHistory(res);
                }
            });
            collResults.innerHTML = html;
            collResults.classList.add('active');
        } catch (e) { alert('Error: ' + e.message); }
        finally {
            setTimeout(() => collProgress.classList.remove('active'), 800);
            collAnalyzeBtn.disabled = false; collFiles = []; renderCollFiles();
        }
    });

    // ============================================================
    // TAB 3: REPORT SEARCH
    // ============================================================
    const repInput = document.getElementById('reportSearchInput');
    const repBtn = document.getElementById('reportSearchBtn');
    const repResults = document.getElementById('reportResults');

    repBtn.addEventListener('click', doRepSearch);
    repInput.addEventListener('keypress', e => { if (e.key === 'Enter') doRepSearch(); });

    async function doRepSearch() {
        const q = repInput.value.trim();
        if (!q) return alert('Enter a search term.');
        repBtn.disabled = true; repBtn.textContent = 'Searching...';
        try {
            const r = await fetch('/api/search/report?q=' + encodeURIComponent(q));
            const data = await r.json();
            let html = '<div class="result-header"><h2 class="result-title">Search: "' + escapeHtml(data.query || q) + '" (' + (data.total_results || 0) + ' results)</h2></div>';
            if (!data.results || data.results.length === 0) {
                html += '<div class="result-row"><div class="result-value" style="padding:1rem;color:var(--text-secondary);">No matching reports. Analyze files first to build history.</div></div>';
            } else {
                data.results.forEach(r => {
                    html += '<div class="result-section-title">' + escapeHtml(r.filename || 'unknown') + '</div>';
                    html += row('Time', r.timestamp);
                    html += row('Type', r.mime_type);
                    html += row('Size', (r.size || 0).toLocaleString() + ' bytes');
                    html += row('SHA256', (r.hashes && r.hashes.sha256) || 'N/A');
                    html += row('YARA', (r.yara_matches || 0) + ' match(es)');
                });
            }
            repResults.innerHTML = html;
            repResults.classList.add('active');
        } catch (e) { alert('Search failed: ' + e.message); }
        finally { repBtn.disabled = false; repBtn.textContent = 'Search'; }
    }

    // ============================================================
    // TAB 4: YARA SEARCH
    // ============================================================
    const yaraDropZone = document.getElementById('yaraDropZone');
    const yaraRuleInput = document.getElementById('yaraRuleInput');
    const yaraTargetInput = document.getElementById('yaraTargetInput');
    const yaraTargetBtn = document.getElementById('yaraTargetBtn');
    const yaraFileInfo = document.getElementById('yaraFileInfo');
    const yaraProgress = document.getElementById('yaraProgress');
    const yaraProgressFill = document.getElementById('yaraProgressFill');
    const yaraProgressText = document.getElementById('yaraProgressText');
    const yaraResults = document.getElementById('yaraResults');
    let yaraRuleFile = null, yaraTargetFile = null;

    yaraDropZone.addEventListener('click', () => yaraRuleInput.click());
    yaraDropZone.addEventListener('dragover', e => { e.preventDefault(); yaraDropZone.classList.add('dragover'); });
    yaraDropZone.addEventListener('dragleave', () => yaraDropZone.classList.remove('dragover'));
    yaraDropZone.addEventListener('drop', e => {
        e.preventDefault(); yaraDropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) { yaraRuleFile = e.dataTransfer.files[0]; updateYaraInfo(); tryYaraScan(); }
    });
    yaraRuleInput.addEventListener('change', e => { if (e.target.files.length > 0) { yaraRuleFile = e.target.files[0]; updateYaraInfo(); tryYaraScan(); } });
    yaraTargetBtn.addEventListener('click', () => yaraTargetInput.click());
    yaraTargetInput.addEventListener('change', e => { if (e.target.files.length > 0) { yaraTargetFile = e.target.files[0]; updateYaraInfo(); tryYaraScan(); } });

    function updateYaraInfo() {
        let h = '';
        if (yaraRuleFile) h += '<div class="file-list-item"><span>Rule: ' + escapeHtml(yaraRuleFile.name) + '</span></div>';
        if (yaraTargetFile) h += '<div class="file-list-item"><span>Target: ' + escapeHtml(yaraTargetFile.name) + '</span></div>';
        yaraFileInfo.innerHTML = h;
    }

    async function tryYaraScan() {
        if (!yaraRuleFile) return;
        yaraProgress.classList.add('active'); yaraResults.classList.remove('active');
        yaraProgressFill.style.width = '40%'; yaraProgressText.textContent = 'Scanning...';
        const fd = new FormData();
        fd.append('file', yaraRuleFile);
        if (yaraTargetFile) fd.append('target', yaraTargetFile);
        try {
            const r = await fetch('/api/yara/search', { method: 'POST', body: fd });
            yaraProgressFill.style.width = '100%'; yaraProgressText.textContent = 'Complete!';
            const data = await r.json();
            let html = '<div class="result-header"><h2 class="result-title">YARA Results</h2></div>';
            if (data.error) { html += row('Error', data.error); }
            else if (data.message) { html += row('Info', data.message); }
            else {
                html += row('Scanned', data.scanned ? 'Yes' : 'No');
                html += row('Matches', data.matches_count || 0);
                (data.matches || []).forEach(m => {
                    html += '<div class="result-section-title">Rule: ' + escapeHtml(m.rule) + '</div>';
                    html += row('Severity', ((m.meta && m.meta.severity) || 'unknown').toUpperCase());
                    html += row('Description', (m.meta && m.meta.description) || 'N/A');
                });
            }
            yaraResults.innerHTML = html; yaraResults.classList.add('active');
        } catch (e) { alert('YARA scan failed: ' + e.message); }
        finally { setTimeout(() => yaraProgress.classList.remove('active'), 800); }
    }

    // ============================================================
    // TAB 5: STRING SEARCH
    // ============================================================
    const strInput = document.getElementById('stringSearchInput');
    const strBtn = document.getElementById('stringSearchBtn');
    const strFileBtn = document.getElementById('stringFileBtn');
    const strFileInput = document.getElementById('stringFileInput');
    const strFileInfo = document.getElementById('stringFileInfo');
    const strProgress = document.getElementById('stringProgress');
    const strProgressFill = document.getElementById('stringProgressFill');
    const strProgressText = document.getElementById('stringProgressText');
    const strResults = document.getElementById('stringResults');
    let strTargetFile = null;

    strFileBtn.addEventListener('click', () => strFileInput.click());
    strFileInput.addEventListener('change', e => {
        if (e.target.files.length > 0) {
            strTargetFile = e.target.files[0];
            strFileInfo.innerHTML = '<div class="file-list-item"><span>File: ' + escapeHtml(strTargetFile.name) + '</span></div>';
        }
    });
    strBtn.addEventListener('click', doStrSearch);
    strInput.addEventListener('keypress', e => { if (e.key === 'Enter') doStrSearch(); });

    async function doStrSearch() {
        const p = strInput.value.trim();
        if (!p) return alert('Enter a search pattern.');
        strProgress.classList.add('active'); strResults.classList.remove('active');
        strBtn.disabled = true; strProgressFill.style.width = '40%'; strProgressText.textContent = 'Searching...';
        const fd = new FormData();
        fd.append('pattern', p);
        if (strTargetFile) fd.append('file', strTargetFile);
        try {
            const r = await fetch('/api/string/search', { method: 'POST', body: fd });
            strProgressFill.style.width = '100%'; strProgressText.textContent = 'Complete!';
            const data = await r.json();
            let html = '<div class="result-header"><h2 class="result-title">String Search Results</h2></div>';
            if (data.error) { html += row('Error', data.error); }
            else if (data.filename) {
                html += row('File', data.filename);
                html += row('Pattern', data.pattern);
                html += row('ASCII Matches', data.ascii_matches || 0);
                html += row('HEX Matches', data.hex_matches || 0);
                if (data.matches && data.matches.length > 0) {
                    html += '<div class="result-section-title">Matches</div>';
                    html += '<div class="result-content">';
                    data.matches.forEach(m => { html += '[' + m.type + '] Offset: ' + m.offset + '  Context: ' + escapeHtml(m.context) + '\n'; });
                    html += '</div>';
                }
            } else {
                html += row('Pattern', data.pattern);
                html += row('History Matches', data.history_matches || 0);
                if (data.results && data.results.length > 0) {
                    data.results.forEach(r => { html += row('File', (r.filename || 'unknown') + ' | ' + ((r.hashes && r.hashes.sha256) || 'N/A')); });
                } else {
                    html += '<div class="result-row"><div class="result-value" style="padding:1rem;color:var(--text-secondary);">No matches. Upload a file to search within it.</div></div>';
                }
            }
            strResults.innerHTML = html; strResults.classList.add('active');
        } catch (e) { alert('String search failed: ' + e.message); }
        finally { setTimeout(() => strProgress.classList.remove('active'), 800); strBtn.disabled = false; }
    }

});
