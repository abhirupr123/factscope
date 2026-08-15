(() => {
  const menuButton = document.querySelector('.nav-toggle');
  const menu = document.getElementById('primary-nav');
  if (menuButton && menu) {
    menuButton.addEventListener('click', () => {
      const open = menuButton.getAttribute('aria-expanded') === 'true';
      menuButton.setAttribute('aria-expanded', String(!open));
      menu.classList.toggle('open', !open);
    });
    menu.addEventListener('click', (event) => {
      if (event.target.closest('a')) {
        menuButton.setAttribute('aria-expanded', 'false');
        menu.classList.remove('open');
      }
    });
  }

  const tabs = [...document.querySelectorAll('[data-demo-target]')];
  for (const tab of tabs) {
    tab.addEventListener('click', () => {
      for (const candidate of tabs) {
        const selected = candidate === tab;
        candidate.setAttribute('aria-selected', String(selected));
        const panel = document.getElementById(candidate.dataset.demoTarget);
        if (panel) {
          panel.hidden = !selected;
          panel.classList.toggle('active', selected);
        }
      }
    });
    tab.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
      event.preventDefault();
      const direction = event.key === 'ArrowRight' ? 1 : -1;
      const next = tabs[(tabs.indexOf(tab) + direction + tabs.length) % tabs.length];
      next.focus();
      next.click();
    });
  }

  const statusButton = document.querySelector('[data-status-check]');
  const status = document.querySelector('[data-api-status]');
  const updateStatus = (state, title, detail) => {
    if (!status) return;
    status.className = `status-indicator ${state}`;
    status.querySelector('strong').textContent = title;
    status.querySelector('span').textContent = detail;
  };
  if (statusButton && status) {
    statusButton.addEventListener('click', async () => {
      statusButton.disabled = true;
      updateStatus('checking', 'Checking availability…', 'This may take a moment after the service has been idle.');
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12000);
      try {
        const response = await fetch('https://factscope-api.onrender.com/health', {
          method: 'GET', cache: 'no-store', signal: controller.signal,
        });
        if (!response.ok) throw new Error('Health check returned an error');
        updateStatus('available', 'FactScope API is responding', `Checked ${new Date().toLocaleTimeString()}. External providers may still vary.`);
      } catch {
        updateStatus('unavailable', 'Availability could not be confirmed', 'The service may be waking, unavailable, or blocked by this browser. Try again shortly.');
      } finally {
        clearTimeout(timer);
        statusButton.disabled = false;
      }
    });
  }
})();