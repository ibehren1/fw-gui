// Show one section of a view at a time, selected by the URL hash.
//
// Nav links carry class "section-tab" and href "#<section id>" (or "#all").
// Sections carry class "tab-section". Optional ".tab-section-group" wrappers
// (the IPv4 / IPv6 containers) stay visible only while they hold the selected
// section. An empty, "all" or unknown hash shows everything.
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
        let target = null;
        sections.forEach(function (s) {
            if (s.id === id) {
                target = s;
            }
        });

        sections.forEach(function (s) {
            s.hidden = target !== null && s !== target;
        });
        document.querySelectorAll('.tab-section-group').forEach(function (g) {
            g.hidden = target !== null && !g.contains(target);
        });

        const activeHref = target ? '#' + id : '#all';
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
