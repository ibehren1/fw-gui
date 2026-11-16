// Group detail cards for group references in rule tables.
//
// A reference is an element with class "ref" and a data-ref key. The page
// carries one hidden ".ref-card" per group with a matching data-ref-card key
// (see group_cards in templates/_macros.html). Hovering or focusing a
// reference shows a copy of its card in a floating popover. The popover is
// attached to <body> because the table cells clip their overflow.
(function () {
    let popover = null;
    let anchor = null;

    function cardFor(key) {
        const cards = document.querySelectorAll('.ref-card[data-ref-card]');
        for (let i = 0; i < cards.length; i++) {
            if (cards[i].getAttribute('data-ref-card') === key) {
                return cards[i];
            }
        }
        return null;
    }

    function missingCard(key) {
        const card = document.createElement('div');
        card.className = 'ref-card';
        const head = document.createElement('div');
        head.className = 'ref-card-head';
        const name = document.createElement('span');
        name.className = 'mono strong';
        name.textContent = key.split('|').slice(2).join('|');
        head.appendChild(name);
        const meta = document.createElement('div');
        meta.className = 'ref-card-meta';
        meta.textContent = 'Group not found in this configuration.';
        card.appendChild(head);
        card.appendChild(meta);
        return card;
    }

    function place() {
        const r = anchor.getBoundingClientRect();
        const w = popover.offsetWidth;
        const h = popover.offsetHeight;
        let left = Math.min(r.left, window.innerWidth - w - 8);
        let top = r.bottom + 8;
        if (top + h > window.innerHeight - 8) {
            top = Math.max(8, r.top - h - 6);
        }
        popover.style.left = Math.max(8, left) + 'px';
        popover.style.top = top + 'px';
    }

    function show(el) {
        hide();
        const key = el.getAttribute('data-ref');
        const source = cardFor(key);
        anchor = el;
        popover = document.createElement('div');
        popover.className = 'ref-popover';
        popover.setAttribute('role', 'tooltip');
        popover.appendChild(source ? source.cloneNode(true) : missingCard(key));
        document.body.appendChild(popover);
        place();
    }

    function hide() {
        if (popover) {
            popover.remove();
        }
        popover = null;
        anchor = null;
    }

    document.addEventListener('mouseover', function (event) {
        const el = event.target.closest('.ref[data-ref]');
        if (el && el !== anchor) {
            show(el);
        } else if (!el && anchor) {
            hide();
        }
    });
    document.addEventListener('focusin', function (event) {
        const el = event.target.closest('.ref[data-ref]');
        if (el) {
            show(el);
        }
    });
    document.addEventListener('focusout', function (event) {
        if (event.target === anchor) {
            hide();
        }
    });
    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') {
            hide();
        }
    });
    window.addEventListener('scroll', hide, true);
})();
