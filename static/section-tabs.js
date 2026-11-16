// Show one section of a view at a time, selected by the URL hash.
//
// Nav links carry class "section-tab" and href "#<section id>" (or "#all").
// Sections carry class "tab-section". Optional ".tab-section-group" wrappers
// (the IPv4 / IPv6 containers) stay visible only while they hold the selected
// section. A hash naming a group itself (e.g. "#ipv4") shows every section in
// that group. An empty, "all" or unknown hash shows everything.
(function () {
    function selectedId() {
        try {
            return decodeURIComponent(window.location.hash.slice(1));
        } catch (e) {
            return '';
        }
    }

    function apply() {
        const id = selectedId();
        const sections = document.querySelectorAll('.tab-section');
        const groups = document.querySelectorAll('.tab-section-group');
        let target = null;
        sections.forEach(function (s) {
            if (s.id === id) {
                target = s;
            }
        });
        let group = null;
        if (target === null) {
            groups.forEach(function (g) {
                if (g.id && g.id === id) {
                    group = g;
                }
            });
        }

        sections.forEach(function (s) {
            if (target !== null) {
                s.hidden = s !== target;
            } else {
                s.hidden = group !== null && !group.contains(s);
            }
        });
        groups.forEach(function (g) {
            if (target !== null) {
                g.hidden = !g.contains(target);
            } else {
                g.hidden = group !== null && g !== group;
            }
        });

        const activeHref = target || group ? '#' + id : '#all';
        document.querySelectorAll('.section-tab').forEach(function (link) {
            let href = link.getAttribute('href');
            try {
                href = decodeURIComponent(href);
            } catch (e) {
                // Leave an undecodable href as-is; it just won't match.
            }
            link.classList.toggle('active', href === activeHref);
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('.section-tab').forEach(function (link) {
            link.addEventListener('click', function (event) {
                event.preventDefault();
                history.pushState(null, '', link.getAttribute('href'));
                apply();
            });
        });
        apply();
    });

    window.addEventListener('popstate', apply);
    window.addEventListener('hashchange', apply);
})();
