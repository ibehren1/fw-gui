// Toolbar for operational command output on the push page.
//
// The table view lives in #op-table and the device's raw output in
// #results-content (see templates/_op_output.html). Table/Raw switches
// between them; the filter hides rows whose text does not match, and a table
// with no matching rows; clicking a header sorts that table's rows. Cells
// carry their unformatted value in data-v so sorting ignores the display
// formatting. A row marked "op-pinned" (a chain's default action) stays last.
// The show firewall view adds: hide zero-hit rules, collapse a ruleset by
// its header or all at once, and jump links that expand and scroll to the
// target chain.
(function () {
    const tableView = document.getElementById('op-table');
    const raw = document.getElementById('results-content');
    if (!tableView || !raw) {
        return;
    }

    function setView(view) {
        document.querySelectorAll('[data-op-view]').forEach(function (b) {
            b.setAttribute('aria-pressed', b.getAttribute('data-op-view') === view ? 'true' : 'false');
        });
        tableView.hidden = view !== 'table';
        raw.hidden = view !== 'raw';
    }

    function applyFilter() {
        const input = document.getElementById('op-filter');
        const q = input ? input.value.trim().toLowerCase() : '';
        tableView.querySelectorAll('.op-block').forEach(function (block) {
            const head = block.querySelector('.block-head');
            const headHit = q !== '' && head !== null && head.textContent.toLowerCase().indexOf(q) !== -1;
            let any = false;
            block.querySelectorAll('tbody tr').forEach(function (tr) {
                const hit = q === '' || headHit || tr.textContent.toLowerCase().indexOf(q) !== -1;
                tr.classList.toggle('op-filtered', !hit);
                any = any || hit;
            });
            block.hidden = !any;
        });
    }

    function sortBy(th) {
        const table = th.closest('table');
        const tbody = table.tBodies[0];
        const index = Array.prototype.indexOf.call(th.parentNode.children, th);
        const numeric = th.hasAttribute('data-numeric');
        // First click: numbers largest first, text A-Z. Later clicks flip.
        const asc = th.classList.contains('sorted') ? !th.classList.contains('asc') : !numeric;
        th.parentNode.querySelectorAll('th').forEach(function (x) {
            x.classList.remove('sorted', 'asc');
        });
        th.classList.add('sorted');
        if (asc) {
            th.classList.add('asc');
        }
        function value(tr) {
            const td = tr.children[index];
            const v = td ? (td.getAttribute('data-v') || td.textContent.trim()) : '';
            return numeric ? Number(v) || 0 : v.toLowerCase();
        }
        const rows = Array.prototype.slice.call(tbody.rows);
        rows.sort(function (a, b) {
            const pa = a.classList.contains('op-pinned');
            const pb = b.classList.contains('op-pinned');
            if (pa !== pb) {
                return pa ? 1 : -1;
            }
            const x = value(a);
            const y = value(b);
            const c = x > y ? 1 : x < y ? -1 : 0;
            return asc ? c : -c;
        });
        rows.forEach(function (r) {
            tbody.appendChild(r);
        });
    }

    document.addEventListener('click', function (e) {
        const viewButton = e.target.closest('[data-op-view]');
        if (viewButton) {
            setView(viewButton.getAttribute('data-op-view'));
            return;
        }
        const th = e.target.closest('#op-table th[data-sort]');
        if (th) {
            sortBy(th);
            return;
        }
        const jump = e.target.closest('.op-jump');
        if (jump) {
            const target = document.getElementById(jump.getAttribute('href').slice(1));
            if (target) {
                e.preventDefault();
                target.classList.remove('collapsed');
                target.scrollIntoView({ behavior: 'smooth' });
            }
            return;
        }
        if (e.target.closest('#op-collapse')) {
            const button = e.target.closest('#op-collapse');
            const chains = tableView.querySelectorAll('.op-chain');
            const collapse = Array.prototype.some.call(chains, function (c) {
                return !c.classList.contains('collapsed');
            });
            chains.forEach(function (c) {
                c.classList.toggle('collapsed', collapse);
            });
            button.textContent = collapse ? 'Expand all' : 'Collapse all';
            return;
        }
        const head = e.target.closest('.op-toggle');
        if (head && !e.target.closest('a, button')) {
            head.parentNode.classList.toggle('collapsed');
            return;
        }
        const copy = e.target.closest('#op-copy');
        if (copy) {
            navigator.clipboard.writeText(raw.textContent).then(function () {
                const label = copy.textContent;
                copy.textContent = 'Copied!';
                setTimeout(function () {
                    copy.textContent = label;
                }, 1500);
            });
        }
    });

    const zero = document.getElementById('op-zero');
    if (zero) {
        zero.addEventListener('change', function () {
            tableView.classList.toggle('op-hide-zero', zero.checked);
        });
    }

    const filter = document.getElementById('op-filter');
    if (filter) {
        filter.addEventListener('input', applyFilter);
    }
})();
