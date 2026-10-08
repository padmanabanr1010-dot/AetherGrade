document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const authModal = document.getElementById('authModal');
    const loginForm = document.getElementById('login-form');
    const loginUsernameInput = document.getElementById('login-username');
    const loginPasswordInput = document.getElementById('login-password');
    const authErrorMsg = document.getElementById('auth-error-msg');
    const sessionUserBadge = document.getElementById('session-user-badge');
    const btnLogout = document.getElementById('btn-logout');
    const lowAttendanceBanner = document.getElementById('low-attendance-banner');

    const enrollFormCard = document.getElementById('enroll-form-card');
    const updateFormCard = document.getElementById('update-form-card');

    const studentForm = document.getElementById('student-form');
    const studentTableBody = document.getElementById('student-table-body');
    const noDataDiv = document.getElementById('no-data');
    const searchInput = document.getElementById('search-input');
    const sortSelect = document.getElementById('sort-select');
    const alertBanner = document.getElementById('alert-banner');
    
    // KPI elements
    const statTotalStudents = document.getElementById('stat-total-students');
    const statClassAverage = document.getElementById('stat-class-average');
    const statPassRate = document.getElementById('stat-pass-rate');
    const statLowAttendance = document.getElementById('stat-low-attendance');

    // Tab buttons and content
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const rosterFilters = document.getElementById('roster-filters');
    const departmentGridContainer = document.getElementById('department-grid-container');

    // Report Exporter elements
    const btnGenerateReport = document.getElementById('btn-generate-report');
    const reportProgressArea = document.getElementById('report-progress-area');
    const reportProgressBar = document.getElementById('report-progress-bar');
    const reportStatusText = document.getElementById('report-status-text');
    const reportPercentageText = document.getElementById('report-percentage-text');
    const downloadArea = document.getElementById('download-area');

    // Form buttons and inputs
    const btnClear = document.getElementById('btn-clear');
    const btnSubmit = document.getElementById('btn-submit');
    const btnRandomMarks = document.getElementById('btn-random-marks');
    const formTitle = document.getElementById('form-title');

    // Update Marks section elements
    const updateMarksForm = document.getElementById('update-marks-form');
    const updateStudentIdInput = document.getElementById('update-student-id-input');
    const enrolledStudentsList = document.getElementById('enrolled-students-list');
    const btnFetchStudent = document.getElementById('btn-fetch-student');
    const updateStudentPreview = document.getElementById('update-student-preview');
    const updatePreviewName = document.getElementById('update-preview-name');
    const updatePreviewMeta = document.getElementById('update-preview-meta');
    const btnUpdateRandom = document.getElementById('btn-update-random');
    const btnUpdateClear = document.getElementById('btn-update-clear');
    
    const upJavaMarks = document.getElementById('up-javaMarks');
    const upOsMarks = document.getElementById('up-osMarks');
    const upMathsMarks = document.getElementById('up-mathsMarks');
    const upDaaMarks = document.getElementById('up-daaMarks');
    const upCaMarks = document.getElementById('up-caMarks');
    const upMlMarks = document.getElementById('up-mlMarks');
    
    const upTotalPreview = document.getElementById('up-total-preview');
    const upPercentPreview = document.getElementById('up-percent-preview');
    const upGradePreview = document.getElementById('up-grade-preview');

    // Local state
    let jwtToken = sessionStorage.getItem('jwtToken') || null;
    let currentUser = null;
    let userRole = null;
    let userStudentId = null;
    let studentsData = [];
    let pollingInterval = null;
    let editingStudentId = null;

    // XSS Mitigation Helper
    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Authenticated API Wrapper
    async function fetchWithAuth(url, options = {}) {
        options.headers = options.headers || {};
        if (jwtToken) {
            options.headers['Authorization'] = `Bearer ${jwtToken}`;
        }
        
        const res = await fetch(url, options);

        if (res.status === 401) {
            openLoginModal();
            throw new Error('Unauthorized: Please log in.');
        }
        if (res.status === 403) {
            showNotification('Forbidden: You do not have permission for this action.', 'error');
            throw new Error('Forbidden action.');
        }

        return res;
    }

    // Quick demo login fill function exposed globally
    window.fillDemoCredentials = function(username, password) {
        if (loginUsernameInput) loginUsernameInput.value = username;
        if (loginPasswordInput) loginPasswordInput.value = password;
    };

    function openLoginModal() {
        if (authModal) authModal.classList.remove('hidden');
        if (authErrorMsg) authErrorMsg.classList.add('hidden');
    }

    function closeLoginModal() {
        if (authModal) authModal.classList.add('hidden');
    }

    // Check user session state
    async function checkSession() {
        if (!jwtToken) {
            openLoginModal();
            return;
        }

        try {
            const res = await fetchWithAuth('/api/auth/me');
            if (res.ok) {
                const data = await res.json();
                if (data.authenticated) {
                    currentUser = data.username;
                    userRole = data.role;
                    userStudentId = data.studentId;
                    updateSessionUI();
                    closeLoginModal();
                    fetchData();
                    return;
                }
            }
        } catch (e) {}

        sessionStorage.removeItem('jwtToken');
        jwtToken = null;
        openLoginModal();
    }

    function updateSessionUI() {
        if (!sessionUserBadge) return;

        sessionUserBadge.textContent = `${currentUser} (${userRole})`;
        sessionUserBadge.className = `badge role-badge ${userRole}`;
        
        if (btnLogout) btnLogout.classList.remove('hidden');

        // Apply RBAC UI Rules
        if (enrollFormCard) enrollFormCard.style.display = 'block';
        if (updateFormCard) updateFormCard.style.display = 'block';
    }

    if (btnLogout) {
        btnLogout.addEventListener('click', () => {
            sessionStorage.removeItem('jwtToken');
            jwtToken = null;
            currentUser = null;
            userRole = null;
            userStudentId = null;
            if (sessionUserBadge) {
                sessionUserBadge.textContent = 'Guest';
                sessionUserBadge.className = 'badge role-badge Guest';
            }
            btnLogout.classList.add('hidden');
            openLoginModal();
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = loginUsernameInput.value.trim();
            const password = loginPasswordInput.value.trim();

            if (!username || !password) {
                authErrorMsg.textContent = 'Username and password are required.';
                authErrorMsg.classList.remove('hidden');
                return;
            }

            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await res.json();

                if (res.ok && data.success) {
                    jwtToken = data.token;
                    sessionStorage.setItem('jwtToken', jwtToken);
                    currentUser = data.username;
                    userRole = data.role;
                    userStudentId = data.studentId;
                    
                    updateSessionUI();
                    closeLoginModal();
                    fetchData();
                    showNotification(`Welcome back, ${currentUser}! Authenticated as ${userRole}.`, 'success');
                } else {
                    authErrorMsg.textContent = data.message || 'Invalid credentials.';
                    authErrorMsg.classList.remove('hidden');
                }
            } catch (err) {
                authErrorMsg.textContent = err.message || 'Login failed.';
                authErrorMsg.classList.remove('hidden');
            }
        });
    }

    // Initialize application state
    checkSession();

    // Fetch roster data & stats
    async function fetchData() {
        try {
            const sortBy = sortSelect.value;
            const resRoster = await fetchWithAuth(`/api/students?sort=${sortBy}`);
            if (!resRoster.ok) throw new Error('Failed to load roster data.');
            studentsData = await resRoster.json();

            renderRosterTable(studentsData);
            populateEnrolledStudentsDatalist(studentsData);
            fetchStats();
        } catch (err) {
            showNotification(err.message, 'error');
        }
    }

    // Fetch KPI and Dept statistics
    async function fetchStats() {
        try {
            const resStats = await fetchWithAuth('/api/stats');
            if (!resStats.ok) throw new Error('Failed to load statistics.');
            const stats = await resStats.json();

            // Populate KPIs
            statTotalStudents.textContent = stats.totalStudents;
            statClassAverage.textContent = stats.totalStudents > 0 ? `${stats.averagePercentage.toFixed(1)}%` : '0.0%';
            statPassRate.textContent = stats.totalStudents > 0 ? `${stats.passRate.toFixed(1)}%` : '0.0%';
            statLowAttendance.textContent = stats.lowAttendanceCount;

            // Low attendance alert banner
            if (stats.lowAttendanceCount > 0 && lowAttendanceBanner) {
                lowAttendanceBanner.innerHTML = `⚠️ <strong>Observer Alert</strong>: ${stats.lowAttendanceCount} student(s) currently have attendance below the 75% exam eligibility threshold.`;
                lowAttendanceBanner.classList.remove('hidden');
            } else if (lowAttendanceBanner) {
                lowAttendanceBanner.classList.add('hidden');
            }

            renderDepartmentInsights(stats.departmentStats);
        } catch (err) {
            console.error('Stats fetch error:', err);
        }
    }

    // Render roster table with XSS protection & RBAC controls
    function renderRosterTable(students) {
        const query = searchInput.value.toLowerCase().trim();
        const filtered = students.filter(s => {
            const name = s.name ? s.name.toLowerCase() : '';
            const id = s.studentId ? s.studentId.toString() : '';
            const dept = s.department ? s.department.toLowerCase() : '';
            return name.includes(query) || id.includes(query) || dept.includes(query);
        });

        studentTableBody.innerHTML = '';

        // Hide/Show action header based on role
        const actionHeaders = document.querySelectorAll('.actions-col');
        actionHeaders.forEach(th => {
            th.style.display = 'table-cell';
        });

        if (filtered.length === 0) {
            noDataDiv.classList.remove('hidden');
            return;
        }

        noDataDiv.classList.add('hidden');

        filtered.forEach(s => {
            const tr = document.createElement('tr');
            
            let gradeClass = 'O';
            if (s.grade === 'A+') gradeClass = 'A-plus';
            else if (s.grade === 'A') gradeClass = 'A';
            else if (s.grade === 'B') gradeClass = 'B';
            else if (s.grade === 'C') gradeClass = 'C';
            else if (s.grade === 'FAIL') gradeClass = 'FAIL';

            const isEligible = s.attendance >= 75.0;
            const eligibilityText = isEligible ? 'Eligible' : 'Ineligible';
            const eligibilityClass = isEligible ? 'eligible' : 'ineligible';

            const actionCellHtml = `
                <td class="actions-col">
                    <div class="row-actions">
                        <button type="button" class="action-icon zk-badge-btn" onclick="openAetherLockZkCredentialModal(${s.studentId})" title="AetherLock: Generate Time-Locked ZK Credential & QR Badge">
                            <span style="font-size: 12px;">🔒</span> <span>ZK</span>
                        </button>
                        <button type="button" class="action-icon report-btn" onclick="openReportCardForStudent(${s.studentId})" title="View Official Report Card / Transcript">
                            🪪
                        </button>
                        <button type="button" class="action-icon edit" data-id="${s.studentId}" title="Edit Student Record">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                        </button>
                        <button type="button" class="action-icon delete" data-id="${s.studentId}" title="Delete Record">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                        </button>
                    </div>
                </td>
            `;

            tr.innerHTML = `
                <td><strong>#${s.studentId}</strong></td>
                <td>
                    <div class="student-info-cell">
                        <span class="student-name">${escapeHtml(s.name)}</span>
                        <span class="student-meta">${escapeHtml(s.department)} &bull; Y${s.year}</span>
                    </div>
                </td>
                <td class="mark-col">${s.javaMarks}</td>
                <td class="mark-col">${s.osMarks}</td>
                <td class="mark-col">${s.mathsMarks}</td>
                <td class="mark-col">${s.daaMarks != null ? s.daaMarks : 0}</td>
                <td class="mark-col">${s.caMarks != null ? s.caMarks : 0}</td>
                <td class="mark-col">${s.mlMarks != null ? s.mlMarks : 0}</td>
                <td><strong>${s.total}</strong></td>
                <td>${s.percentage.toFixed(1)}%</td>
                <td><span class="grade-badge ${gradeClass}">${escapeHtml(s.grade)}</span></td>
                <td>
                    <span class="attendance-text ${s.attendance < 75 ? 'danger' : 'safe'}">
                        ${s.attendance.toFixed(1)}%
                    </span>
                </td>
                <td>
                    <span class="eligibility-badge ${eligibilityClass}">
                        <span class="status-indicator ${isEligible ? 'online' : ''}" style="${!isEligible ? 'background-color:#f43f5e; box-shadow:0 0 10px #f43f5e;' : ''}"></span>
                        ${eligibilityText}
                    </span>
                </td>
                ${actionCellHtml}
            `;

            studentTableBody.appendChild(tr);
        });

        // Event listeners
        document.querySelectorAll('.action-icon.delete').forEach(btn => {
            btn.addEventListener('click', handleDeleteStudent);
        });
        document.querySelectorAll('.action-icon.edit').forEach(btn => {
            btn.addEventListener('click', handleEditStudent);
        });
    }

    // Render Department Insights Tab
    function renderDepartmentInsights(deptStats) {
        departmentGridContainer.innerHTML = '';
        
        const depts = Object.keys(deptStats);
        if (depts.length === 0) {
            departmentGridContainer.innerHTML = `<div class="no-data"><p>No department statistics available.</p></div>`;
            return;
        }

        depts.forEach(deptName => {
            const stats = deptStats[deptName];
            const div = document.createElement('div');
            
            let styleClass = '';
            if (deptName.includes('CSE')) styleClass = 'cse';
            else if (deptName.includes('AIML')) styleClass = 'aiml';

            div.className = `dept-card ${styleClass}`;
            div.innerHTML = `
                <div class="dept-header">
                    <span>${escapeHtml(deptName)}</span>
                    <span class="dept-student-badge">${stats.studentCount} Students</span>
                </div>
                <div class="dept-metrics">
                    <div class="metric-bar-group">
                        <div class="metric-label-row">
                            <span>Average Grade %</span>
                            <span class="metric-value-span">${stats.averagePercentage.toFixed(1)}%</span>
                        </div>
                        <div class="metric-bar-track">
                            <div class="metric-bar-fill purple" style="width: ${stats.averagePercentage}%"></div>
                        </div>
                    </div>
                    <div class="metric-bar-group">
                        <div class="metric-label-row">
                            <span>Pass Rate</span>
                            <span class="metric-value-span">${stats.passRate.toFixed(1)}%</span>
                        </div>
                        <div class="metric-bar-track">
                            <div class="metric-bar-fill cyan" style="width: ${stats.passRate}%"></div>
                        </div>
                    </div>
                </div>
            `;
            departmentGridContainer.appendChild(div);
        });
    }

    if (btnRandomMarks) {
        btnRandomMarks.addEventListener('click', () => {
            const subjects = ['javaMarks', 'osMarks', 'mathsMarks', 'daaMarks', 'caMarks', 'mlMarks'];
            subjects.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = Math.floor(Math.random() * 54) + 45;
            });
            showNotification('Generated random marks for all 6 subjects!', 'success');
        });
    }

    function populateEnrolledStudentsDatalist(students) {
        if (!enrolledStudentsList) return;
        enrolledStudentsList.innerHTML = '';
        students.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.studentId;
            opt.label = `#${s.studentId} - ${s.name} (${s.department})`;
            enrolledStudentsList.appendChild(opt);
        });
    }

    function loadStudentForUpdate(studentId) {
        const student = studentsData.find(s => s.studentId === studentId);
        if (!student) {
            if (updateStudentPreview) updateStudentPreview.classList.add('hidden');
            return false;
        }

        if (updatePreviewName) updatePreviewName.textContent = student.name;
        if (updatePreviewMeta) updatePreviewMeta.textContent = `ID #${student.studentId} • ${student.department} • Year ${student.year}`;
        if (updateStudentPreview) updateStudentPreview.classList.remove('hidden');

        if (upJavaMarks) upJavaMarks.value = student.javaMarks != null ? student.javaMarks : 0;
        if (upOsMarks) upOsMarks.value = student.osMarks != null ? student.osMarks : 0;
        if (upMathsMarks) upMathsMarks.value = student.mathsMarks != null ? student.mathsMarks : 0;
        if (upDaaMarks) upDaaMarks.value = student.daaMarks != null ? student.daaMarks : 0;
        if (upCaMarks) upCaMarks.value = student.caMarks != null ? student.caMarks : 0;
        if (upMlMarks) upMlMarks.value = student.mlMarks != null ? student.mlMarks : 0;

        calculateUpdateMarksSummary();
        return true;
    }

    if (updateStudentIdInput) {
        updateStudentIdInput.addEventListener('input', () => {
            const val = parseInt(updateStudentIdInput.value);
            if (!isNaN(val)) {
                loadStudentForUpdate(val);
            } else if (updateStudentPreview) {
                updateStudentPreview.classList.add('hidden');
            }
        });
    }

    if (btnFetchStudent) {
        btnFetchStudent.addEventListener('click', () => {
            const val = parseInt(updateStudentIdInput.value);
            if (isNaN(val) || val <= 0) {
                showNotification('Please enter a valid numeric Student ID.', 'error');
                return;
            }
            if (!loadStudentForUpdate(val)) {
                showNotification(`Student ID #${val} not found in database.`, 'error');
            } else {
                showNotification(`Loaded marks for Student #${val}.`, 'success');
            }
        });
    }

    function calculateUpdateMarksSummary() {
        const j = parseInt(upJavaMarks.value) || 0;
        const o = parseInt(upOsMarks.value) || 0;
        const m = parseInt(upMathsMarks.value) || 0;
        const d = parseInt(upDaaMarks.value) || 0;
        const c = parseInt(upCaMarks.value) || 0;
        const ml = parseInt(upMlMarks.value) || 0;

        const total = j + o + m + d + c + ml;
        const pct = total / 6.0;

        let grade = 'FAIL';
        let gradeClass = 'FAIL';
        if (pct >= 90) { grade = 'O'; gradeClass = 'O'; }
        else if (pct >= 80) { grade = 'A+'; gradeClass = 'A-plus'; }
        else if (pct >= 70) { grade = 'A'; gradeClass = 'A'; }
        else if (pct >= 60) { grade = 'B'; gradeClass = 'B'; }
        else if (pct >= 50) { grade = 'C'; gradeClass = 'C'; }

        if (upTotalPreview) upTotalPreview.textContent = `${total} / 600`;
        if (upPercentPreview) upPercentPreview.textContent = `${pct.toFixed(1)}%`;
        if (upGradePreview) {
            upGradePreview.textContent = grade;
            upGradePreview.className = `summary-val grade-tag ${gradeClass}`;
        }
    }

    [upJavaMarks, upOsMarks, upMathsMarks, upDaaMarks, upCaMarks, upMlMarks].forEach(inp => {
        if (inp) inp.addEventListener('input', calculateUpdateMarksSummary);
    });

    if (btnUpdateRandom) {
        btnUpdateRandom.addEventListener('click', () => {
            [upJavaMarks, upOsMarks, upMathsMarks, upDaaMarks, upCaMarks, upMlMarks].forEach(inp => {
                if (inp) inp.value = Math.floor(Math.random() * 54) + 45;
            });
            calculateUpdateMarksSummary();
            showNotification('Randomized subject marks!', 'success');
        });
    }

    if (btnUpdateClear) {
        btnUpdateClear.addEventListener('click', () => {
            if (updateMarksForm) updateMarksForm.reset();
            if (updateStudentPreview) updateStudentPreview.classList.add('hidden');
            calculateUpdateMarksSummary();
        });
    }

    if (updateMarksForm) {
        updateMarksForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const studentId = parseInt(updateStudentIdInput.value);
            if (!studentId || studentId <= 0) {
                showNotification('Please specify a valid Student ID.', 'error');
                return;
            }

            const javaMarks = parseInt(upJavaMarks.value) || 0;
            const osMarks = parseInt(upOsMarks.value) || 0;
            const mathsMarks = parseInt(upMathsMarks.value) || 0;
            const daaMarks = parseInt(upDaaMarks.value) || 0;
            const caMarks = parseInt(upCaMarks.value) || 0;
            const mlMarks = parseInt(upMlMarks.value) || 0;

            const payload = { studentId, javaMarks, osMarks, mathsMarks, daaMarks, caMarks, mlMarks };

            try {
                const res = await fetchWithAuth('/api/students/marks', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const resData = await res.json();
                if (!res.ok) throw new Error(resData.error || 'Failed to update marks.');

                showNotification(resData.message || 'Marks updated in database!', 'success');
                fetchData();
            } catch (err) {
                showNotification(err.message, 'error');
            }
        });
    }

    if (studentForm) {
        studentForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = new FormData(studentForm);
            const studentId = parseInt(formData.get('studentId'));
            const name = formData.get('name').trim();
            const department = formData.get('department');
            const attendance = parseFloat(formData.get('attendance'));
            const javaMarks = parseInt(formData.get('javaMarks'));
            const osMarks = parseInt(formData.get('osMarks'));
            const mathsMarks = parseInt(formData.get('mathsMarks'));
            const daaMarks = parseInt(formData.get('daaMarks'));
            const caMarks = parseInt(formData.get('caMarks'));
            const mlMarks = parseInt(formData.get('mlMarks'));

            const studentPayload = {
                studentId, name, department, year: 2,
                attendance, javaMarks, osMarks, mathsMarks, daaMarks, caMarks, mlMarks
            };

            try {
                const method = editingStudentId ? 'PUT' : 'POST';
                const res = await fetchWithAuth('/api/students', {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(studentPayload)
                });

                const resData = await res.json();
                if (!res.ok) throw new Error(resData.error || 'Failed to save student.');

                showNotification(resData.message || 'Student record updated!', 'success');
                resetForm();
                fetchData();
            } catch (err) {
                showNotification(err.message, 'error');
            }
        });
    }

    if (btnClear) btnClear.addEventListener('click', resetForm);

    function resetForm() {
        if (studentForm) studentForm.reset();
        editingStudentId = null;
        document.getElementById('studentId').disabled = false;
        formTitle.textContent = 'Enroll New Student';
        btnSubmit.textContent = 'Enroll Student';
    }

    function handleEditStudent(e) {
        const id = parseInt(e.currentTarget.getAttribute('data-id'));
        const student = studentsData.find(s => s.studentId === id);
        if (!student) return;

        editingStudentId = id;
        document.getElementById('studentId').value = student.studentId;
        document.getElementById('studentId').disabled = true;
        document.getElementById('name').value = student.name;
        document.getElementById('department').value = student.department;
        document.getElementById('attendance').value = student.attendance;
        document.getElementById('javaMarks').value = student.javaMarks;
        document.getElementById('osMarks').value = student.osMarks;
        document.getElementById('mathsMarks').value = student.mathsMarks;
        document.getElementById('daaMarks').value = student.daaMarks != null ? student.daaMarks : 0;
        document.getElementById('caMarks').value = student.caMarks != null ? student.caMarks : 0;
        document.getElementById('mlMarks').value = student.mlMarks != null ? student.mlMarks : 0;

        formTitle.textContent = `Edit Student #${id}`;
        btnSubmit.textContent = 'Update Student Details';

        window.scrollTo({ top: enrollFormCard.offsetTop - 20, behavior: 'smooth' });
    }

    async function handleDeleteStudent(e) {
        const id = parseInt(e.currentTarget.getAttribute('data-id'));
        if (!confirm(`Are you sure you want to delete Student #${id}?`)) return;

        try {
            const res = await fetchWithAuth(`/api/students?id=${id}`, { method: 'DELETE' });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Failed to delete student.');

            showNotification(data.message || 'Student deleted successfully!', 'success');
            fetchData();
        } catch (err) {
            showNotification(err.message, 'error');
        }
    }

    if (btnGenerateReport) {
        btnGenerateReport.addEventListener('click', async () => {
            try {
                const res = await fetchWithAuth('/api/report/generate', { method: 'POST' });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Failed to start report generation.');

                reportProgressArea.classList.remove('hidden');
                downloadArea.classList.add('hidden');
                btnGenerateReport.disabled = true;

                startReportPolling();
            } catch (err) {
                showNotification(err.message, 'error');
            }
        });
    }

    function startReportPolling() {
        if (pollingInterval) clearInterval(pollingInterval);
        pollingInterval = setInterval(async () => {
            try {
                const res = await fetchWithAuth('/api/report/status');
                if (!res.ok) return;
                const statusData = await res.json();

                reportProgressBar.style.width = `${statusData.progress}%`;
                reportPercentageText.textContent = `${statusData.progress}%`;

                if (statusData.status === 'RUNNING') {
                    reportStatusText.textContent = `Processing records in Virtual Threads (${statusData.progress}%)...`;
                } else if (statusData.status === 'COMPLETED') {
                    clearInterval(pollingInterval);
                    reportStatusText.textContent = 'Report compiled successfully!';
                    btnGenerateReport.disabled = false;
                    downloadArea.classList.remove('hidden');
                    showNotification('Spreadsheet report ready for download!', 'success');
                } else if (statusData.status === 'FAILED') {
                    clearInterval(pollingInterval);
                    reportStatusText.textContent = 'Report generation failed.';
                    btnGenerateReport.disabled = false;
                    showNotification('Background thread report generation failed.', 'error');
                }
            } catch (err) {
                clearInterval(pollingInterval);
                btnGenerateReport.disabled = false;
            }
        }, 300);
    }

    if (searchInput) searchInput.addEventListener('input', () => renderRosterTable(studentsData));
    if (sortSelect) sortSelect.addEventListener('change', fetchData);

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.add('hidden'));

            btn.classList.add('active');
            const target = btn.getAttribute('data-tab');
            document.getElementById(target).classList.remove('hidden');

            if (target === 'tab-roster') rosterFilters.classList.remove('hidden');
            else rosterFilters.classList.add('hidden');

            if (target === 'tab-audit-ledger') {
                window.loadAuditLedger();
                if (window.loadAetherLockStatus) window.loadAetherLockStatus();
            }
        });
    });

    // --- IMMUTABLE AUDIT LEDGER & ZKP FUNCTIONS ---

    let currentInspectedPayload = '';

    window.copyTextToClipboard = function(text, event) {
        if (event) event.stopPropagation();
        if (!text || text === '0' || text === '-') return;
        navigator.clipboard.writeText(text).then(() => {
            showNotification('SHA-256 Hash copied to clipboard!', 'success');
        }).catch(() => {
            showNotification('Failed to copy hash', 'error');
        });
    };

    window.formatDataPayloadHTML = function(entry) {
        const payloadStr = entry.dataPayload || '';
        if (!payloadStr) return '<span style="color:#64748b; font-style:italic;">(empty)</span>';

        let summaryText = '';
        try {
            if (payloadStr.startsWith('{') && payloadStr.endsWith('}')) {
                const data = JSON.parse(payloadStr);
                if (data.name !== undefined) {
                    summaryText = `${data.name} (${data.department || ''}) • Tot: ${data.total ?? '-'} • Grade: ${data.grade || '-'}`;
                }
            }
        } catch (e) {}

        if (!summaryText) {
            summaryText = payloadStr;
        }

        return `
            <div class="payload-cell-wrapper">
                <div class="payload-summary-box" title="${escapeHtml(payloadStr)}">
                    ${escapeHtml(summaryText)}
                </div>
                <button type="button" class="inspect-payload-btn" onclick="openPayloadInspectModal(${entry.id})">
                    🔍 Inspect Details
                </button>
            </div>
        `;
    };

    window.loadAuditLedger = async function() {
        const ledgerBody = document.getElementById('ledger-table-body');
        const ledgerNoData = document.getElementById('ledger-no-data');
        if (!ledgerBody) return;

        try {
            const res = await fetchWithAuth('/api/v1/audit/ledger');
            if (!res.ok) throw new Error('Failed to load audit ledger records.');
            const entries = await res.json();
            window.currentLedgerEntries = entries;

            ledgerBody.innerHTML = '';
            if (entries.length === 0) {
                if (ledgerNoData) ledgerNoData.classList.remove('hidden');
                return;
            }
            if (ledgerNoData) ledgerNoData.classList.add('hidden');

            entries.forEach((entry, idx) => {
                const tr = document.createElement('tr');
                tr.setAttribute('data-row-id', entry.id);

                const prevHashRaw = entry.previousHash || '0';
                const currHashRaw = entry.currentHash || '-';

                const prevShort = (prevHashRaw === '0' || prevHashRaw.startsWith('000000')) ? 'GENESIS (0x0)' : (prevHashRaw.substring(0, 8) + '...' + prevHashRaw.substring(prevHashRaw.length - 4));
                const currShort = currHashRaw.length > 12 ? (currHashRaw.substring(0, 8) + '...' + currHashRaw.substring(currHashRaw.length - 4)) : currHashRaw;

                let actionIcon = '📝';
                if (entry.actionType.includes('ATTENDANCE')) actionIcon = '⏱️';
                else if (entry.actionType.includes('ADD')) actionIcon = '➕';
                else if (entry.actionType.includes('DELETE')) actionIcon = '🗑️';
                else if (entry.actionType.includes('UPDATE')) actionIcon = '✏️';

                let chainLinkHtml = '<span class="chain-status-badge chained">🔗 Linked</span>';
                if (idx === 0 && (prevHashRaw === '0' || prevHashRaw.startsWith('000000'))) {
                    chainLinkHtml = '<span class="chain-status-badge genesis">🌱 Genesis</span>';
                }

                tr.innerHTML = `
                    <td><strong style="color:#c084fc;">Block #${entry.id}</strong></td>
                    <td style="font-size:0.8rem; color:#94a3b8; white-space:nowrap;">${escapeHtml(entry.timestamp)}</td>
                    <td><span class="badge" style="background:rgba(168,85,247,0.15); color:#c084fc; border:1px solid rgba(168,85,247,0.3);">${escapeHtml(entry.actorId)}</span></td>
                    <td><span class="action-badge-icon ${escapeHtml(entry.actionType)}">${actionIcon} ${escapeHtml(entry.actionType)}</span></td>
                    <td><strong style="color:#38bdf8;">#${entry.recordId}</strong></td>
                    <td>${formatDataPayloadHTML(entry)}</td>
                    <td>
                        <div class="hash-badge-wrapper prev" title="Previous SHA-256 Hash: ${escapeHtml(prevHashRaw)}">
                            <span class="hash-code">${escapeHtml(prevShort)}</span>
                            <button type="button" class="hash-copy-btn" onclick="copyTextToClipboard('${escapeHtml(prevHashRaw)}', event)" title="Copy Previous Hash">📋</button>
                        </div>
                    </td>
                    <td>
                        <div class="hash-badge-wrapper curr" title="Current SHA-256 Hash: ${escapeHtml(currHashRaw)}">
                            <span class="hash-code">${escapeHtml(currShort)}</span>
                            <button type="button" class="hash-copy-btn" onclick="copyTextToClipboard('${escapeHtml(currHashRaw)}', event)" title="Copy Current Hash">📋</button>
                        </div>
                    </td>
                    <td>${chainLinkHtml}</td>
                `;
                ledgerBody.appendChild(tr);
            });
        } catch (err) {
            showNotification(err.message, 'error');
        }
    };

    window.openPayloadInspectModal = function(entryId) {
        const modal = document.getElementById('payloadInspectModal');
        const subtitle = document.getElementById('inspect-modal-subtitle');
        const body = document.getElementById('inspect-modal-body');
        if (!modal || !body) return;

        const entries = window.currentLedgerEntries || [];
        const entry = entries.find(e => e.id === entryId);
        if (!entry) return;

        currentInspectedPayload = entry.dataPayload || '';

        if (subtitle) subtitle.textContent = `Block #${entry.id} • ${entry.actionType} by ${entry.actorId} • ${entry.timestamp}`;

        let parsedJson = null;
        try {
            if (entry.dataPayload && entry.dataPayload.startsWith('{')) {
                parsedJson = JSON.parse(entry.dataPayload);
            }
        } catch (e) {}

        let inspectHtml = '';

        if (parsedJson && parsedJson.name !== undefined) {
            inspectHtml = `
                <div style="background:rgba(168,85,247,0.1); border:1px solid rgba(168,85,247,0.3); border-radius:10px; padding:12px; display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <h4 style="margin:0; color:#f8fafc; font-size:1.1rem;">${escapeHtml(parsedJson.name)}</h4>
                        <span style="font-size:0.85rem; color:#94a3b8;">Student ID #${parsedJson.studentId} • ${escapeHtml(parsedJson.department)} (Year ${parsedJson.year})</span>
                    </div>
                    <div style="text-align:right;">
                        <div class="grade-badge ${parsedJson.grade}" style="font-size:1rem; padding:4px 12px;">Grade: ${escapeHtml(parsedJson.grade)}</div>
                        <div style="font-size:0.8rem; color:#34d399; margin-top:4px;">Attendance: ${parsedJson.attendance}%</div>
                    </div>
                </div>

                <div style="font-size:0.85rem; font-weight:700; color:#cbd5e1; margin-top:6px;">Subject Marks Breakdown (600 Max):</div>
                <div class="inspect-subject-grid">
                    <div class="inspect-subject-card"><div class="sub-label">Java</div><div class="sub-val">${parsedJson.javaMarks ?? '-'}</div></div>
                    <div class="inspect-subject-card"><div class="sub-label">OS</div><div class="sub-val">${parsedJson.osMarks ?? '-'}</div></div>
                    <div class="inspect-subject-card"><div class="sub-label">Maths</div><div class="sub-val">${parsedJson.mathsMarks ?? '-'}</div></div>
                    <div class="inspect-subject-card"><div class="sub-label">DAA</div><div class="sub-val">${parsedJson.daaMarks ?? '-'}</div></div>
                    <div class="inspect-subject-card"><div class="sub-label">CA</div><div class="sub-val">${parsedJson.caMarks ?? '-'}</div></div>
                    <div class="inspect-subject-card"><div class="sub-label">ML</div><div class="sub-val">${parsedJson.mlMarks ?? '-'}</div></div>
                </div>
            `;
        }

        inspectHtml += `
            <div style="font-size:0.85rem; font-weight:700; color:#cbd5e1; margin-top:10px;">Raw JSON / Data Payload Payload:</div>
            <textarea readonly rows="6" style="width:100%; font-family:monospace; font-size:0.8rem; padding:10px; border-radius:8px; background:rgba(15,23,42,0.9); border:1px solid rgba(255,255,255,0.1); color:#38bdf8; resize:vertical;">${escapeHtml(parsedJson ? JSON.stringify(parsedJson, null, 2) : entry.dataPayload)}</textarea>
        `;

        body.innerHTML = inspectHtml;
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
        modal.style.zIndex = '20000';
    };

    window.closePayloadInspectModal = function() {
        const modal = document.getElementById('payloadInspectModal');
        if (modal) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }
    };

    window.copyRawPayload = function() {
        if (currentInspectedPayload) {
            navigator.clipboard.writeText(currentInspectedPayload);
            showNotification('Raw data payload copied to clipboard!', 'success');
        }
    };

    window.verifyLedgerIntegrity = async function() {
        const banner = document.getElementById('integrity-status-banner');
        if (!banner) return;

        try {
            const res = await fetchWithAuth('/api/v1/audit/verify');
            if (!res.ok) throw new Error('Failed to execute ledger verification engine.');
            const data = await res.json();

            banner.classList.remove('hidden');

            if (data.valid && data.status === 'SECURE') {
                banner.className = 'alert-banner success';
                banner.style.border = '1px solid rgba(34, 197, 94, 0.4)';
                banner.style.background = 'rgba(34, 197, 94, 0.1)';
                banner.style.color = '#86efac';
                banner.innerHTML = `🛡️ <strong>INTEGRITY VERIFIED - ALL HASHES INTACT</strong><br>Checked ${data.totalRecords} blocks in cryptographic sequence. Zero tampering or sequence alteration detected.`;
                showNotification(`Verified ${data.totalRecords} ledger blocks intact.`, 'success');
            } else {
                banner.className = 'alert-banner danger-banner';
                banner.style.border = '1px solid rgba(244, 63, 94, 0.5)';
                banner.style.background = 'rgba(244, 63, 94, 0.15)';
                banner.style.color = '#fecdd3';
                banner.innerHTML = `🚨 <strong>TAMPER DETECTED AT ROW #${data.brokenRowId}</strong><br>${escapeHtml(data.details)}`;
                showNotification(`SECURITY WARNING: Ledger tampering detected at Row #${data.brokenRowId}!`, 'error');

                // Reload ledger and highlight tampered row
                await window.loadAuditLedger();
                const badRow = document.querySelector(`tr[data-row-id="${data.brokenRowId}"]`);
                if (badRow) {
                    badRow.style.background = 'rgba(244, 63, 94, 0.3)';
                    badRow.style.border = '2px solid #f43f5e';
                }
            }
        } catch (err) {
            showNotification(err.message, 'error');
        }
    };

    window.generateZkpToken = async function(studentId) {
        try {
            const res = await fetchWithAuth('/api/v1/student/zkp-token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ studentId })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Failed to generate ZKP assertion token.');

            const tokenArea = document.getElementById('zkp-token-text');
            const qrContainer = document.getElementById('zkp-qr-code-container');
            const modal = document.getElementById('zkpTokenModal');

            if (tokenArea) tokenArea.value = data.token;
            if (qrContainer) qrContainer.innerHTML = generateQrSvg(data.token);
            if (modal) {
                modal.classList.remove('hidden');
                modal.style.display = 'flex';
                modal.style.zIndex = '20000';
            }

            showNotification(`ZKP assertion token generated for Student #${studentId}`, 'success');
        } catch (err) {
            showNotification(err.message, 'error');
        }
    };

    window.closeZkpTokenModal = function() {
        const modal = document.getElementById('zkpTokenModal');
        if (modal) modal.classList.add('hidden');
    };

    window.copyZkpToken = function() {
        const tokenArea = document.getElementById('zkp-token-text');
        if (tokenArea && tokenArea.value) {
            navigator.clipboard.writeText(tokenArea.value);
            showNotification('Token copied to clipboard!', 'success');
        }
    };

    window.downloadZkpToken = function() {
        const tokenArea = document.getElementById('zkp-token-text');
        if (tokenArea && tokenArea.value) {
            const blob = new Blob([tokenArea.value], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ZKP_Verification_Token_${Date.now()}.txt`;
            a.click();
            URL.revokeObjectURL(url);
        }
    };

    window.closeZkpTokenModal = function() {
        const modal = document.getElementById('zkpTokenModal');
        if (modal) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }
    };

    window.openPublicReportCardModal = function() {
        const authModal = document.getElementById('authModal');
        if (authModal) authModal.classList.add('hidden');

        const modal = document.getElementById('publicReportCardModal');
        if (modal) {
            modal.classList.remove('hidden');
            modal.style.display = 'flex';
            modal.style.zIndex = '30000';
        }
    };

    window.openReportCardForStudent = function(studentId) {
        window.openPublicReportCardModal();
        const input = document.getElementById('report-card-student-id');
        if (input) {
            input.value = studentId;
            window.generatePublicStudentReportCard();
        }
    };

    window.closePublicReportCardModal = function() {
        const modal = document.getElementById('publicReportCardModal');
        if (modal) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }

        if (!currentUser) {
            const authModal = document.getElementById('authModal');
            if (authModal) authModal.classList.remove('hidden');
        }
    };

    window.generatePublicStudentReportCard = async function() {
        const input = document.getElementById('report-card-student-id');
        const area = document.getElementById('report-card-preview-area');
        if (!input || !area) return;

        const studentId = input.value.trim();
        if (!studentId || parseInt(studentId) <= 0) {
            showNotification('Please enter a valid Student ID.', 'error');
            return;
        }

        area.classList.remove('hidden');
        area.innerHTML = '<div style="color:#c084fc; font-weight:600; font-size:0.95rem; text-align:center; padding:20px;">⏳ Fetching student record & generating creative PDF report card...</div>';

        try {
            const res = await fetch(`/api/public/reportcard?id=${encodeURIComponent(studentId)}`);
            const data = await res.json();

            if (!res.ok) {
                area.innerHTML = `
                    <div style="background:rgba(244,63,94,0.15); border:1px solid rgba(244,63,94,0.4); border-radius:12px; padding:16px; color:#fb7185; text-align:center;">
                        ❌ <strong>Report Card Generation Failed</strong><br>
                        ${escapeHtml(data.error || 'Student record not found in system.')}
                    </div>
                `;
                return;
            }

            const eligible = data.attendance >= 75.0;
            const eligibleBadge = eligible 
                ? '<span class="rc-status-tag eligible">✅ EXAM ELIGIBLE (Att >= 75%)</span>' 
                : '<span class="rc-status-tag ineligible">❌ NOT ELIGIBLE (Att < 75%)</span>';

            const pct = data.percentage !== undefined ? Number(data.percentage).toFixed(2) : '0.00';

            area.innerHTML = `
                <div class="creative-report-card" id="print-report-card-doc">
                    <div class="rc-header">
                        <div class="rc-brand">
                            <div class="rc-logo-symbol">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7L12 12L22 7L12 2Z"/><path d="M2 17L12 22L22 17"/><path d="M2 12L12 17L22 12"/></svg>
                            </div>
                            <div>
                                <h3 class="rc-inst-name">AETHER ACADEMIC PERFORMANCE ENGINE</h3>
                                <p class="rc-inst-sub">OFFICIAL STUDENT PERFORMANCE TRANSCRIPT & REPORT CARD</p>
                            </div>
                        </div>
                        <div class="rc-official-stamp">OFFICIAL RECORD</div>
                    </div>

                    <div class="rc-profile-grid">
                        <div class="rc-profile-item">
                            <span class="rc-lbl">STUDENT ID</span>
                            <span class="rc-val purple">#${data.studentId}</span>
                        </div>
                        <div class="rc-profile-item">
                            <span class="rc-lbl">FULL NAME</span>
                            <span class="rc-val">${escapeHtml(data.name)}</span>
                        </div>
                        <div class="rc-profile-item">
                            <span class="rc-lbl">DEPARTMENT</span>
                            <span class="rc-val cyan">${escapeHtml(data.department)}</span>
                        </div>
                        <div class="rc-profile-item">
                            <span class="rc-lbl">ACADEMIC YEAR</span>
                            <span class="rc-val">Year ${data.year}</span>
                        </div>
                    </div>

                    <div class="rc-table-title">SUBJECT-WISE ACADEMIC MARKS BREAKDOWN</div>
                    <table class="rc-marks-table">
                        <thead>
                            <tr>
                                <th>Subject Code</th>
                                <th>Subject Title</th>
                                <th>Max Marks</th>
                                <th>Marks Obtained</th>
                                <th>Subject Grade</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr><td>CS-301</td><td>Java Programming</td><td>100</td><td><strong>${data.javaMarks}</strong></td><td><span class="grade-badge ${getGradeForMark(data.javaMarks)}">${getGradeForMark(data.javaMarks)}</span></td><td>${data.javaMarks >= 50 ? '<span class="pass-tag">PASS</span>' : '<span class="fail-tag">FAIL</span>'}</td></tr>
                            <tr><td>CS-302</td><td>Operating Systems</td><td>100</td><td><strong>${data.osMarks}</strong></td><td><span class="grade-badge ${getGradeForMark(data.osMarks)}">${getGradeForMark(data.osMarks)}</span></td><td>${data.osMarks >= 50 ? '<span class="pass-tag">PASS</span>' : '<span class="fail-tag">FAIL</span>'}</td></tr>
                            <tr><td>MA-303</td><td>Mathematics & Statistics</td><td>100</td><td><strong>${data.mathsMarks}</strong></td><td><span class="grade-badge ${getGradeForMark(data.mathsMarks)}">${getGradeForMark(data.mathsMarks)}</span></td><td>${data.mathsMarks >= 50 ? '<span class="pass-tag">PASS</span>' : '<span class="fail-tag">FAIL</span>'}</td></tr>
                            <tr><td>CS-304</td><td>Design & Analysis of Algorithms</td><td>100</td><td><strong>${data.daaMarks}</strong></td><td><span class="grade-badge ${getGradeForMark(data.daaMarks)}">${getGradeForMark(data.daaMarks)}</span></td><td>${data.daaMarks >= 50 ? '<span class="pass-tag">PASS</span>' : '<span class="fail-tag">FAIL</span>'}</td></tr>
                            <tr><td>CS-305</td><td>Computer Architecture</td><td>100</td><td><strong>${data.caMarks}</strong></td><td><span class="grade-badge ${getGradeForMark(data.caMarks)}">${getGradeForMark(data.caMarks)}</span></td><td>${data.caMarks >= 50 ? '<span class="pass-tag">PASS</span>' : '<span class="fail-tag">FAIL</span>'}</td></tr>
                            <tr><td>AI-306</td><td>Machine Learning Principles</td><td>100</td><td><strong>${data.mlMarks}</strong></td><td><span class="grade-badge ${getGradeForMark(data.mlMarks)}">${getGradeForMark(data.mlMarks)}</span></td><td>${data.mlMarks >= 50 ? '<span class="pass-tag">PASS</span>' : '<span class="fail-tag">FAIL</span>'}</td></tr>
                        </tbody>
                    </table>

                    <div class="rc-kpi-summary">
                        <div class="rc-kpi-box">
                            <span class="kpi-title">TOTAL MARKS</span>
                            <span class="kpi-number">${data.total} / 600</span>
                        </div>
                        <div class="rc-kpi-box">
                            <span class="kpi-title">PERCENTAGE</span>
                            <span class="kpi-number cyan">${pct}%</span>
                        </div>
                        <div class="rc-kpi-box">
                            <span class="kpi-title">OVERALL GRADE</span>
                            <span class="kpi-number purple">${escapeHtml(data.grade)}</span>
                        </div>
                        <div class="rc-kpi-box">
                            <span class="kpi-title">ATTENDANCE</span>
                            <span class="kpi-number green">${data.attendance}%</span>
                        </div>
                    </div>

                    <div class="rc-eligibility-row">
                        <span>Exam Eligibility Status:</span>
                        ${eligibleBadge}
                    </div>

                    <div class="rc-auth-footer">
                        <div class="rc-sec-seal">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            <span>Cryptographically Authenticated on MySQL SHA-256 Audit Ledger</span>
                        </div>
                        <button type="button" class="btn primary print-action-btn" onclick="printStudentReportCardDoc()">
                            🖨️ Print / Save PDF
                        </button>
                    </div>
                </div>
            `;
        } catch (err) {
            area.innerHTML = `<div style="color:#f43f5e; text-align:center; padding:16px;">Error generating report card: ${escapeHtml(err.message)}</div>`;
        }
    };

    function getGradeForMark(m) {
        if (m >= 90) return 'O';
        if (m >= 80) return 'A-plus';
        if (m >= 70) return 'A';
        if (m >= 60) return 'B';
        if (m >= 50) return 'C';
        return 'FAIL';
    }

    window.printStudentReportCardDoc = function() {
        const elem = document.getElementById('print-report-card-doc');
        if (!elem) return;

        const printWindow = window.open('', '_blank', 'width=900,height=1000');
        printWindow.document.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Student Academic Report Card</title>
                <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
                <style>
                    body { font-family: 'Outfit', sans-serif; background: #08080f; color: #f8fafc; padding: 24px; }
                    .creative-report-card { background: #0e0e1a; border: 1px solid rgba(168,85,247,0.3); border-radius: 16px; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
                    .rc-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 16px; margin-bottom: 20px; }
                    .rc-brand { display: flex; align-items: center; gap: 14px; }
                    .rc-inst-name { font-size: 1.1rem; font-weight: 800; color: #c084fc; margin: 0; }
                    .rc-inst-sub { font-size: 0.75rem; color: #94a3b8; margin: 4px 0 0 0; }
                    .rc-official-stamp { background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.3); padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.75rem; }
                    .rc-profile-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; background: rgba(255,255,255,0.03); padding: 14px; border-radius: 10px; margin-bottom: 20px; }
                    .rc-profile-item { display: flex; flex-direction: column; gap: 4px; }
                    .rc-lbl { font-size: 0.7rem; color: #94a3b8; font-weight: 600; }
                    .rc-val { font-size: 1rem; font-weight: 700; color: #f8fafc; }
                    .rc-val.purple { color: #c084fc; }
                    .rc-val.cyan { color: #38bdf8; }
                    .rc-table-title { font-size: 0.85rem; font-weight: 700; color: #cbd5e1; margin-bottom: 10px; }
                    .rc-marks-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; text-align: left; }
                    .rc-marks-table th, .rc-marks-table td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 0.85rem; }
                    .rc-marks-table th { background: rgba(15,23,42,0.8); color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; }
                    .grade-badge { padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; display: inline-block; }
                    .grade-badge.O { background: rgba(168,85,247,0.2); color: #c084fc; border: 1px solid rgba(168,85,247,0.3); }
                    .grade-badge.A-plus { background: rgba(6,182,212,0.2); color: #22d3ee; border: 1px solid rgba(6,182,212,0.3); }
                    .grade-badge.A { background: rgba(59,130,246,0.2); color: #60a5fa; border: 1px solid rgba(59,130,246,0.3); }
                    .grade-badge.B { background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3); }
                    .grade-badge.C { background: rgba(249,115,22,0.2); color: #fb923c; border: 1px solid rgba(249,115,22,0.3); }
                    .grade-badge.FAIL { background: rgba(244,63,94,0.2); color: #fb7185; border: 1px solid rgba(244,63,94,0.3); }
                    .pass-tag { color: #34d399; font-weight: 700; font-size: 0.75rem; }
                    .fail-tag { color: #fb7185; font-weight: 700; font-size: 0.75rem; }
                    .rc-kpi-summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
                    .rc-kpi-box { background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06); padding: 12px; border-radius: 10px; text-align: center; }
                    .kpi-title { font-size: 0.7rem; color: #94a3b8; font-weight: 600; display: block; margin-bottom: 4px; }
                    .kpi-number { font-size: 1.2rem; font-weight: 800; color: #f8fafc; }
                    .kpi-number.cyan { color: #38bdf8; }
                    .kpi-number.purple { color: #c084fc; }
                    .kpi-number.green { color: #34d399; }
                    .rc-eligibility-row { background: rgba(255,255,255,0.03); padding: 12px; border-radius: 8px; font-weight: 600; display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; font-size: 0.9rem; }
                    .rc-status-tag.eligible { color: #34d399; font-weight: 700; }
                    .rc-status-tag.ineligible { color: #fb7185; font-weight: 700; }
                    .rc-auth-footer { display: flex; justify-content: space-between; align-items: center; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 16px; font-size: 0.75rem; color: #94a3b8; }
                    .print-action-btn { display: none; }
                    @media print {
                        body { background: #fff !important; color: #000 !important; }
                        .creative-report-card { border: 2px solid #000 !important; background: #fff !important; color: #000 !important; }
                        .rc-inst-name, .rc-val, .kpi-number { color: #000 !important; }
                        .print-action-btn { display: none !important; }
                    }
                </style>
            </head>
            <body>
                ${elem.outerHTML}
                <script>
                    window.onload = function() { window.print(); }
                </script>
            </body>
            </html>
        `);
        printWindow.document.close();
    };

    window.openPublicVerifierModal = function() {
        const modal = document.getElementById('publicVerifyModal');
        if (modal) {
            modal.classList.remove('hidden');
            modal.style.display = 'flex';
            modal.style.zIndex = '20000';
        }
    };

    window.closePublicVerifierModal = function() {
        const modal = document.getElementById('publicVerifyModal');
        if (modal) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }
    };

    window.submitPublicClaimVerification = async function() {
        const input = document.getElementById('public-token-input');
        const box = document.getElementById('verify-claim-result-box');
        if (!input || !box) return;

        const token = input.value.trim();
        if (!token) {
            showNotification('Please paste a verification token.', 'error');
            return;
        }

        box.classList.remove('hidden');
        box.innerHTML = '<div style="color:#38bdf8; font-weight:500; font-size:0.9rem;">⏳ Cryptographically verifying HMAC signature and payload...</div>';

        try {
            const res = await fetch('/api/v1/verify-claim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token })
            });

            const data = await res.json();
            box.classList.remove('hidden');

            if (res.ok && data.valid) {
                const claims = data.claims || {};
                const eligBadge = claims.is_eligible_for_exam 
                    ? `<span style="color:#4ade80; font-weight:700;">✅ ELIGIBLE (Attendance >= 75%)</span>`
                    : `<span style="color:#f43f5e; font-weight:700;">❌ NOT ELIGIBLE</span>`;
                const passBadge = claims.has_passed_all
                    ? `<span style="color:#4ade80; font-weight:700;">✅ PASSED ALL SUBJECTS</span>`
                    : `<span style="color:#f43f5e; font-weight:700;">❌ FAILED ONE OR MORE SUBJECTS</span>`;

                box.innerHTML = `
                    <div style="color:#38bdf8; font-weight:700; font-size:1.05rem; margin-bottom:12px; display:flex; align-items:center; gap:8px;">
                        <span>🔒 Cryptographic HMAC Signature Verified</span>
                    </div>
                    <div style="display:flex; flex-direction:column; gap:8px; font-size:0.9rem; color:#e2e8f0;">
                        <div>Exam Eligibility: ${eligBadge}</div>
                        <div>Academic Pass Status: ${passBadge}</div>
                        <div>GPA Bracket Claim: <strong style="color:#a7f3d0;">${escapeHtml(claims.gpa_bracket)}</strong></div>
                        <div style="font-size:0.75rem; color:#94a3b8; margin-top:8px; border-top:1px solid rgba(255,255,255,0.1); padding-top:8px;">
                            Issued: ${new Date(data.issuedAt).toLocaleString()}<br>
                            Expires: ${new Date(data.expiresAt).toLocaleString()}<br>
                            <em>Zero personal identity or raw subject marks exposed.</em>
                        </div>
                    </div>
                `;
            } else {
                box.innerHTML = `
                    <div style="color:#f43f5e; font-weight:700; font-size:1.05rem; margin-bottom:8px;">
                        ❌ Verification Failed
                    </div>
                    <div style="color:#fecdd3; font-size:0.85rem;">
                        ${escapeHtml(data.error || 'Invalid or forged verification token.')}
                    </div>
                `;
            }
        } catch (err) {
            box.classList.remove('hidden');
            box.innerHTML = `<div style="color:#f43f5e;">Error verifying claim: ${escapeHtml(err.message)}</div>`;
        }
    };

    function generateQrSvg(text) {
        let hash = 0;
        for (let i = 0; i < text.length; i++) {
            hash = ((hash << 5) - hash) + text.charCodeAt(i);
            hash |= 0;
        }
        const size = 15;
        let rects = '';
        const isFinder = (r, c) => {
            if (r < 4 && c < 4) return true;
            if (r < 4 && c >= size - 4) return true;
            if (r >= size - 4 && c < 4) return true;
            return false;
        };
        for (let r = 0; r < size; r++) {
            for (let c = 0; c < size; c++) {
                let fill = false;
                if (isFinder(r, c)) {
                    fill = (r === 0 || r === 3 || c === 0 || c === 3 || (r >= 1 && r <= 2 && c >= 1 && c <= 2)) ||
                           (r === 0 || r === 3 || c === size - 4 || c === size - 1 || (r >= 1 && r <= 2 && c >= size - 3 && c <= size - 2)) ||
                           (r === size - 4 || r === size - 1 || c === 0 || c === 3 || (r >= size - 3 && r <= size - 2 && c >= 1 && c <= 2));
                } else {
                    fill = ((hash ^ (r * 17 + c * 31)) % 3) === 0;
                }
                if (fill) {
                    rects += `<rect x="${c*10}" y="${r*10}" width="9" height="9" fill="#38bdf8" rx="1.5" />`;
                }
            }
        }
        return `<svg width="150" height="150" viewBox="0 0 150 150" style="background:#0f172a; padding:10px; border-radius:12px; border:1px solid rgba(56,189,248,0.3);">${rects}</svg>`;
    }

    function showNotification(msg, type = 'info') {
        if (!alertBanner) return;
        alertBanner.textContent = msg;
        alertBanner.className = `alert-banner ${type}`;
        alertBanner.classList.remove('hidden');

        setTimeout(() => {
            alertBanner.classList.add('hidden');
        }, 4000);
    }

    // =========================================================================
    // AETHERLOCK CRYPTOGRAPHIC ENGINE & ZERO-TRUST PORTAL LOGIC
    // =========================================================================

    window.currentAetherLockToken = '';

    window.loadAetherLockStatus = async function() {
        const statusCard = document.getElementById('aetherlock-status-container');
        if (!statusCard) return;

        try {
            const res = await fetchWithAuth('/api/v1/aetherlock/status');
            if (!res.ok) return;
            const data = await res.json();

            const isSealed = data.isSystemSealed;
            const latestSeal = data.seals && data.seals.length > 0 ? data.seals[0] : null;

            const termBadge = document.getElementById('aetherlock-active-term-badge');
            const summaryText = document.getElementById('aetherlock-status-summary');
            const rightActions = document.getElementById('aetherlock-card-right-actions');

            if (termBadge && latestSeal) {
                termBadge.textContent = latestSeal.termId;
            }

            if (isSealed && latestSeal) {
                if (summaryText) {
                    summaryText.innerHTML = `Term <strong style="color:#a7f3d0;">${escapeHtml(latestSeal.termId)}</strong> is <strong style="color:#4ade80;">Cryptographically Sealed & Immutable</strong>. Merkle Tree Root generated across ${latestSeal.studentCount} student records. Database writes are frozen.`;
                }
                if (rightActions) {
                    rightActions.innerHTML = `
                        <div class="merkle-root-pill" title="Click to copy SHA-256 Merkle Root">
                            <span>Root: 0x${latestSeal.merkleRoot.substring(0, 16)}...</span>
                            <button type="button" class="btn-xs secondary-glow" onclick="window.copyTextToClipboard('${latestSeal.merkleRoot}', event)" title="Copy Merkle Root">📋</button>
                        </div>
                        <span class="seal-pill locked">🔒 IMMUTABLE</span>
                    `;
                }
            } else {
                if (summaryText) {
                    summaryText.innerHTML = `Academic term is currently <strong style="color:#facc15;">UNSEALED & MUTABLE</strong>. Records can be modified. Seal term to generate Merkle root and freeze database records.`;
                }
                if (rightActions) {
                    rightActions.innerHTML = `
                        <span class="seal-pill unlocked">🔓 UNSEALED</span>
                        <button type="button" class="btn-xs warning-glow" onclick="window.openAetherLockSealModal()">⚡ Seal Term Now</button>
                    `;
                }
            }
        } catch (err) {
            console.error('Failed to load AetherLock status:', err);
        }
    };

    window.openAetherLockSealModal = function() {
        const modal = document.getElementById('aetherlockSealModal');
        if (modal) {
            modal.classList.remove('hidden');
            modal.style.display = 'flex';
            modal.style.zIndex = '35000';

            // Reset modal internal state
            const cascadeArea = document.getElementById('merkle-cascade-area');
            const successBadge = document.getElementById('seal-success-badge');
            const btnExecute = document.getElementById('btn-execute-term-seal');
            if (cascadeArea) cascadeArea.classList.add('hidden');
            if (successBadge) successBadge.classList.add('hidden');
            if (btnExecute) btnExecute.disabled = false;
        }
    };

    window.closeAetherLockSealModal = function() {
        const modal = document.getElementById('aetherlockSealModal');
        if (modal) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }
    };

    window.executeAetherLockSeal = async function() {
        const termInput = document.getElementById('seal-term-input');
        const cascadeArea = document.getElementById('merkle-cascade-area');
        const cascadeDisplay = document.getElementById('cascade-nodes-display');
        const stageTitle = document.getElementById('cascade-stage-title');
        const successBadge = document.getElementById('seal-success-badge');
        const btnExecute = document.getElementById('btn-execute-term-seal');

        const termId = termInput ? termInput.value.trim() : 'SPRING-2026';
        if (!termId) {
            showNotification('Please enter a term identifier (e.g. SPRING-2026).', 'error');
            return;
        }

        if (btnExecute) btnExecute.disabled = true;
        if (cascadeArea) cascadeArea.classList.remove('hidden');
        if (successBadge) successBadge.classList.add('hidden');
        if (cascadeDisplay) cascadeDisplay.innerHTML = '';

        try {
            if (stageTitle) stageTitle.textContent = 'Stage 1: Hashing Student Roster into Salted Leaves...';

            const res = await fetchWithAuth('/api/v1/aetherlock/seal-term', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ termId })
            });

            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Failed to seal academic term.');

            const seal = data.seal;
            const treeLevels = data.treeLevels || [];
            const studentLeaves = data.studentLeaves || [];

            // Stage 1 Animation: Displaying student leaves sequentially
            let leafHtml = '<div class="tree-level-container"><span class="tree-level-label">Leaf Level (Salted Student Digests)</span><div class="tree-nodes-row">';
            studentLeaves.forEach(leaf => {
                leafHtml += `
                    <div class="tree-node-chip leaf" title="Student #${leaf.studentId} • ${escapeHtml(leaf.department)} (Grade ${leaf.grade})">
                        <span>#${leaf.studentId}</span>
                        <span>0x${leaf.leafHash.substring(0, 8)}...</span>
                    </div>
                `;
            });
            leafHtml += '</div></div>';
            if (cascadeDisplay) cascadeDisplay.innerHTML = leafHtml;

            // Stage 2 Animation: Cascade to Parent Hashes after short pause
            await new Promise(r => setTimeout(r, 700));
            if (stageTitle) stageTitle.textContent = 'Stage 2: Pairwise Binary SHA-256 Cascade Compression...';

            for (let l = 1; l < treeLevels.length - 1; l++) {
                const levelHashes = treeLevels[l];
                let levelHtml = `<div class="tree-level-container"><span class="tree-level-label">Internal Node Level ${l}</span><div class="tree-nodes-row">`;
                levelHashes.forEach(h => {
                    levelHtml += `
                        <div class="tree-node-chip parent">
                            <span>0x${h.substring(0, 10)}...</span>
                        </div>
                    `;
                });
                levelHtml += '</div></div>';
                if (cascadeDisplay) cascadeDisplay.innerHTML = levelHtml + cascadeDisplay.innerHTML;
                await new Promise(r => setTimeout(r, 500));
            }

            // Stage 3 Animation: Final Merkle Root Generation
            await new Promise(r => setTimeout(r, 600));
            if (stageTitle) stageTitle.textContent = 'Stage 3: Cryptographic Root Digest & Institutional HMAC Signature Issued!';

            const rootHtml = `
                <div class="tree-level-container">
                    <span class="tree-level-label" style="color:#4ade80; font-weight:800;">🔒 Merkle Tree Root Anchor (Top)</span>
                    <div class="tree-node-chip root">
                        <span>MERKLE ROOT: 0x${seal.merkleRoot}</span>
                    </div>
                </div>
            `;
            if (cascadeDisplay) cascadeDisplay.innerHTML = rootHtml + cascadeDisplay.innerHTML;

            // Render Final Success Badge
            if (successBadge) {
                successBadge.classList.remove('hidden');
                successBadge.innerHTML = `
                    <div class="verifier-badge-verified">
                        <div class="seal-stamp-circle">🔒</div>
                        <h3 style="color:#4ade80; margin:0 0 6px 0; font-size:1.25rem;">TERM CRYPTOGRAPHICALLY LOCKED</h3>
                        <p style="color:#cbd5e1; font-size:0.85rem; margin:0 0 12px 0;">
                            AetherLock Seal generated for <strong>${escapeHtml(seal.termId)}</strong> with <strong>${seal.studentCount} student records</strong>.
                        </p>
                        <div style="background:rgba(15,23,42,0.8); border:1px solid rgba(255,255,255,0.1); border-radius:10px; padding:12px; font-family:monospace; font-size:0.8rem; color:#38bdf8; word-break:break-all; text-align:left; margin-bottom:12px;">
                            <div><strong>Seal UUID:</strong> ${seal.sealId}</div>
                            <div><strong>Merkle Root:</strong> 0x${seal.merkleRoot}</div>
                            <div><strong>Institutional Sig:</strong> ${seal.signature.substring(0, 32)}...</div>
                            <div><strong>Locked At:</strong> ${seal.lockedAt}</div>
                        </div>
                        <div style="background:rgba(244,63,94,0.1); border:1px solid rgba(244,63,94,0.3); border-radius:8px; padding:10px; color:#fecdd3; font-size:0.8rem;">
                            🛡️ <strong>Database Immutability Active:</strong> Records in this term cannot be modified or deleted. Any direct UPDATE will be rejected.
                        </div>
                    </div>
                `;
            }

            showNotification(`Term '${termId}' successfully sealed with AetherLock Merkle root!`, 'success');
            window.loadAetherLockStatus();
            window.loadAuditLedger();
            fetchData();

        } catch (err) {
            showNotification(err.message, 'error');
            if (stageTitle) stageTitle.textContent = 'Seal Execution Failed';
        } finally {
            if (btnExecute) btnExecute.disabled = false;
        }
    };

    window.openAetherLockZkCredentialModal = async function(studentId) {
        try {
            const res = await fetchWithAuth(`/api/v1/aetherlock/generate-credential?studentId=${studentId}`);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Failed to generate ZK credential.');

            window.currentAetherLockToken = data.token;
            let payload = {};
            try {
                const decodedStr = atob(data.token.replace(/-/g, '+').replace(/_/g, '/'));
                const parsed = JSON.parse(decodedStr);
                payload = parsed.payload || parsed;
            } catch (e) {
                console.error('Error decoding local token payload:', e);
            }

            const claims = payload.claims || {};
            const cardContainer = document.getElementById('zk-credential-card-container');
            const modal = document.getElementById('aetherlockZkModal');

            if (cardContainer) {
                const isHonors = claims.status && claims.status.includes('Honors');
                cardContainer.innerHTML = `
                    <div class="zk-credential-card">
                        <div class="zk-card-watermark">AETHERLOCK</div>
                        <div class="zk-badge-header">
                            <div>
                                <div class="zk-badge-title">${escapeHtml(data.studentName || 'Student #' + studentId)}</div>
                                <span style="font-size:0.8rem; color:#94a3b8;">ID: #${studentId} • ${escapeHtml(data.department || claims.department || 'Academic Department')}</span>
                            </div>
                            <span class="zk-privacy-tag">ZK-SNARK Proof</span>
                        </div>

                        <div style="display:flex; justify-content:center; margin: 16px 0;">
                            ${generateQrSvg(data.token)}
                        </div>

                        <div class="zk-claims-list">
                            <div class="zk-claim-item">
                                <span class="zk-claim-label">Academic Status</span>
                                <span class="zk-claim-value" style="color: ${isHonors ? '#a7f3d0' : '#f8fafc'};">${escapeHtml(claims.status || 'Enrolled Student')}</span>
                            </div>
                            <div class="zk-claim-item">
                                <span class="zk-claim-label">Exam Eligibility (Attendance >= 75%)</span>
                                <span class="zk-claim-value" style="color: ${claims.isEligibleForExam ? '#4ade80' : '#f43f5e'};">
                                    ${claims.isEligibleForExam ? '✅ VERIFIED ELIGIBLE' : '❌ NOT ELIGIBLE'}
                                </span>
                            </div>
                            <div class="zk-claim-item">
                                <span class="zk-claim-label">Course Clearance (All Subjects Passed)</span>
                                <span class="zk-claim-value" style="color: ${claims.hasPassedAll ? '#4ade80' : '#f43f5e'};">
                                    ${claims.hasPassedAll ? '✅ ALL PASSED' : '❌ NOT PASSED'}
                                </span>
                            </div>
                            <div class="zk-claim-item">
                                <span class="zk-claim-label">GPA Bracket Standing</span>
                                <span class="zk-claim-value" style="color: #38bdf8;">${escapeHtml(claims.gpaBracket || 'STANDARDIZED')}</span>
                            </div>
                            <div class="zk-claim-item">
                                <span class="zk-claim-label">Merkle Tree Root Anchor</span>
                                <span class="zk-claim-value" style="font-family:monospace; font-size:0.75rem; color:#c084fc;">
                                    0x${(payload.merkleRoot || '').substring(0, 16)}...
                                </span>
                            </div>
                        </div>

                        <div class="zk-redacted-box">
                            🔒 <strong>Raw Marks Redacted:</strong> Subject scores (Java, OS, Maths, DAA, CA, ML) are mathematically hidden behind HMAC-SHA256 zero-knowledge commitments.
                        </div>
                    </div>
                `;
            }

            if (modal) {
                modal.classList.remove('hidden');
                modal.style.display = 'flex';
                modal.style.zIndex = '35000';
            }

            showNotification(`Generated AetherLock ZK Credential Badge for Student #${studentId}!`, 'success');

        } catch (err) {
            showNotification(err.message, 'error');
        }
    };

    window.closeAetherLockZkCredentialModal = function() {
        const modal = document.getElementById('aetherlockZkModal');
        if (modal) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }
    };

    window.copyAetherLockToken = function() {
        if (!window.currentAetherLockToken) return;
        navigator.clipboard.writeText(window.currentAetherLockToken).then(() => {
            showNotification('AetherLock ZK Token copied to clipboard!', 'success');
        });
    };

    window.downloadAetherLockToken = function() {
        if (!window.currentAetherLockToken) return;
        const blob = new Blob([window.currentAetherLockToken], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `AetherLock_ZK_Credential_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    window.openAetherLockVerifierPortalModal = function(initialToken) {
        const authModal = document.getElementById('authModal');
        if (authModal) authModal.classList.add('hidden');

        const modal = document.getElementById('aetherlockVerifierPortalModal');
        const input = document.getElementById('aether-verifier-input');
        const resultBox = document.getElementById('aether-verify-result-box');

        if (input && initialToken) {
            input.value = initialToken;
        }

        if (resultBox) {
            resultBox.classList.add('hidden');
            resultBox.innerHTML = '';
        }

        if (modal) {
            modal.classList.remove('hidden');
            modal.style.display = 'flex';
            modal.style.zIndex = '40000';
        }

        if (initialToken) {
            window.submitAetherLockVerification();
        }
    };

    window.closeAetherLockVerifierPortalModal = function() {
        const modal = document.getElementById('aetherlockVerifierPortalModal');
        if (modal) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }
    };

    window.loadDemoAetherProof = async function(studentId) {
        try {
            const res = await fetch(`/api/v1/aetherlock/generate-credential?studentId=${studentId}`);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Failed to generate demo proof.');

            const input = document.getElementById('aether-verifier-input');
            if (input) input.value = data.token;
            showNotification(`Loaded authentic Zero-Knowledge proof for Student #${studentId}`, 'success');
            window.submitAetherLockVerification();
        } catch (err) {
            showNotification(err.message, 'error');
        }
    };

    window.loadDemoTamperedAetherProof = async function() {
        try {
            const res = await fetch(`/api/v1/aetherlock/generate-credential?studentId=101`);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Failed to fetch base proof.');

            // Tamper with the token
            let rawStr = atob(data.token.replace(/-/g, '+').replace(/_/g, '/'));
            let tamperedStr = rawStr.replace('"gpaBracket":"FIRST_CLASS_DISTINCTION"', '"gpaBracket":"FORGED_HONORS_SUMMA"');
            if (tamperedStr === rawStr) {
                tamperedStr = rawStr.replace('"studentId":101', '"studentId":999');
            }
            const tamperedToken = btoa(tamperedStr);

            const input = document.getElementById('aether-verifier-input');
            if (input) input.value = tamperedToken;
            showNotification('Loaded deliberately tampered proof token to demonstrate rejection.', 'info');
            window.submitAetherLockVerification();
        } catch (err) {
            showNotification(err.message, 'error');
        }
    };

    window.submitAetherLockVerification = async function() {
        const input = document.getElementById('aether-verifier-input');
        const box = document.getElementById('aether-verify-result-box');
        if (!input || !box) return;

        const token = input.value.trim();
        if (!token) {
            showNotification('Please paste an AetherLock ZK token to verify.', 'error');
            return;
        }

        box.classList.remove('hidden');
        box.innerHTML = `
            <div style="color:#38bdf8; font-weight:600; font-size:0.95rem; display:flex; align-items:center; gap:8px;">
                <span class="status-indicator online"></span>
                <span>Executing Zero-Trust cryptographic verification & Merkle membership proof...</span>
            </div>
        `;

        try {
            const res = await fetch('/api/v1/aetherlock/verify-proof', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token })
            });

            const data = await res.json();
            if (res.ok && data.valid) {
                const claims = data.claims || {};
                box.innerHTML = `
                    <div class="verifier-badge-verified">
                        <div class="seal-stamp-circle">🛡️</div>
                        <h3 style="color:#4ade80; margin:0 0 4px 0; font-size:1.3rem;">100% CRYPTOGRAPHICALLY VERIFIED</h3>
                        <p style="color:#cbd5e1; font-size:0.85rem; margin:0;">
                            Verified authentic institutional membership in Merkle Root <strong>0x${(data.merkleRoot || '').substring(0, 16)}...</strong>
                        </p>
                    </div>

                    <div style="background:rgba(15,23,42,0.85); border:1px solid rgba(56,189,248,0.3); border-radius:12px; padding:18px;">
                        <h4 style="margin:0 0 12px 0; color:#f8fafc; font-size:1rem; display:flex; align-items:center; gap:8px;">
                            <span>Authenticated Zero-Knowledge Claims:</span>
                        </h4>
                        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px; font-size:0.88rem;">
                            <div>Student ID: <strong style="color:#38bdf8;">#${data.studentId}</strong></div>
                            <div>Department: <strong style="color:#e2e8f0;">${escapeHtml(claims.department || 'Enrolled')}</strong></div>
                            <div>Academic Standing: <strong style="color:#a7f3d0;">${escapeHtml(claims.status || 'Verified')}</strong></div>
                            <div>GPA Classification: <strong style="color:#38bdf8;">${escapeHtml(claims.gpaBracket || 'HONORS')}</strong></div>
                            <div>Exam Eligibility: <strong style="color:#4ade80;">${claims.isEligibleForExam ? '✅ ELIGIBLE' : '❌ INELIGIBLE'}</strong></div>
                            <div>Pass Status: <strong style="color:#4ade80;">${claims.hasPassedAll ? '✅ PASSED ALL' : '❌ FAILED'}</strong></div>
                        </div>
                        <div style="font-size:0.75rem; color:#94a3b8; margin-top:14px; border-top:1px solid rgba(255,255,255,0.08); padding-top:10px;">
                            Zero internal database queries performed. Statistically tamper-evident via SHA-256 Merkle root.
                        </div>
                    </div>
                `;
            } else {
                box.innerHTML = `
                    <div style="background:rgba(244,63,94,0.15); border:2px solid #f43f5e; border-radius:12px; padding:18px; text-align:center; box-shadow:0 0 20px rgba(244,63,94,0.3);">
                        <div style="font-size:2rem; margin-bottom:6px;">🚨</div>
                        <h3 style="color:#fecdd3; margin:0 0 6px 0; font-size:1.2rem;">CRYPTOGRAPHIC PROOF REJECTED</h3>
                        <p style="color:#fda4af; font-size:0.85rem; margin:0;">
                            ${escapeHtml(data.error || 'The cryptographic signature or Merkle path failed mathematical verification.')}
                        </p>
                    </div>
                `;
            }
        } catch (err) {
            box.classList.remove('hidden');
            box.innerHTML = `<div style="color:#f43f5e; padding:12px;">Error executing zero-trust verification: ${escapeHtml(err.message)}</div>`;
        }
    };

    // Auto-fetch AetherLock status on initial load
    window.loadAetherLockStatus();
});

