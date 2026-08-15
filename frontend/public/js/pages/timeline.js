'use strict';

import { el, clear, loadingState, emptyState, formatDate } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { openModal, confirmDialog } from '../components/modal.js';
import { toast } from '../components/toast.js';

export async function renderTimeline(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('Life Timeline', 'The milestones that shaped your story.', [
    el('button', { class: 'btn', text: '+ Add Event', onclick: () => openEditor(outlet) }),
  ]));
  outlet.appendChild(loadingState());

  let data;
  try {
    data = await apiRequest('/timeline');
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  outlet.querySelector('.loading-state')?.remove();

  if (data.events.length === 0) {
    outlet.appendChild(el('div', { class: 'card' }, [emptyState('🕰️', 'No life events yet', 'Add the milestones you want your family to remember.')]));
    return;
  }

  const timeline = el('div', { class: 'card' }, [
    el('div', { class: 'timeline' }, data.events.map((ev) =>
      el('div', { class: 'timeline-item' }, [
        el('div', { class: 'date', text: formatDate(ev.eventDate) }),
        el('div', { class: 'list-item', style: 'padding-top:0.2rem;' }, [
          el('div', { style: 'flex:1;min-width:0;' }, [
            el('div', { class: 'title', text: ev.title }),
            ev.category ? el('div', { class: 'meta', text: ev.category }) : null,
            ev.description ? el('div', { class: 'body-text', text: ev.description }) : null,
          ]),
          el('div', { class: 'actions' }, [
            el('button', { class: 'btn small secondary', text: 'Edit', onclick: () => openEditor(outlet, ev) }),
            el('button', { class: 'btn small danger', text: 'Delete', onclick: () => {
              confirmDialog({
                title: `Delete "${ev.title}"?`,
                message: 'This cannot be undone.',
                onConfirm: async () => {
                  await apiRequest(`/timeline/${ev.id}`, { method: 'DELETE' });
                  toast('Deleted', 'success');
                  renderTimeline(outlet);
                },
              });
            } }),
          ]),
        ]),
      ])
    )),
  ]);
  outlet.appendChild(timeline);
}

function openEditor(outlet, existing) {
  openModal({
    title: existing ? 'Edit Life Event' : 'New Life Event',
    submitLabel: existing ? 'Save Changes' : 'Add Event',
    initialValues: existing ? { title: existing.title, eventDate: existing.eventDate.slice(0, 10), category: existing.category || '', description: existing.description || '' } : {},
    fields: [
      { name: 'title', label: 'Title' },
      { name: 'eventDate', label: 'Date', type: 'date' },
      { name: 'category', label: 'Category (e.g. Career, Family, Milestone)' },
      { name: 'description', label: 'Description', type: 'textarea' },
    ],
    onSubmit: async (values) => {
      const body = { title: values.title, eventDate: values.eventDate, category: values.category || null, description: values.description || null };
      if (existing) {
        await apiRequest(`/timeline/${existing.id}`, { method: 'PUT', body });
      } else {
        await apiRequest('/timeline', { method: 'POST', body });
      }
      toast(existing ? 'Updated' : 'Added', 'success');
      renderTimeline(outlet);
    },
  });
}
