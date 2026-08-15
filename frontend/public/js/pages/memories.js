'use strict';

import { el, clear, loadingState, emptyState, formatDate } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { openModal, confirmDialog } from '../components/modal.js';
import { toast } from '../components/toast.js';

const TYPE_LABELS = { memory: 'Memory', story: 'Story', instruction: 'Instruction' };
const TYPE_ICONS = { memory: '📖', story: '📜', instruction: '🗒️' };

let activeTab = 'memory';

export async function renderMemories(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('Memories & Stories', 'Preserve the moments and words you want remembered.', [
    el('button', { class: 'btn', text: '+ New', onclick: () => openEditor(outlet) }),
  ]));

  const tabs = el('div', { class: 'tabs' }, ['memory', 'story', 'instruction'].map((t) =>
    el('div', { class: `tab${activeTab === t ? ' active' : ''}`, text: `${TYPE_ICONS[t]} ${TYPE_LABELS[t]}s`, onclick: () => { activeTab = t; renderMemories(outlet); } })
  ));
  outlet.appendChild(tabs);
  outlet.appendChild(loadingState());

  let data;
  try {
    data = await apiRequest(`/memories?type=${activeTab}`);
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  outlet.querySelector('.loading-state')?.remove();

  const card = el('div', { class: 'card' });
  if (data.memories.length === 0) {
    card.appendChild(emptyState(TYPE_ICONS[activeTab], `No ${activeTab}s yet`, `Click "+ New" to add your first ${activeTab}.`));
  } else {
    data.memories.forEach((m) => {
      card.appendChild(el('div', { class: 'list-item' }, [
        el('div', { style: 'flex:1;min-width:0;' }, [
          el('div', { class: 'title', text: m.title }),
          el('div', { class: 'meta', text: `${formatDate(m.createdAt)}${m.tags.length ? ' · ' + m.tags.join(', ') : ''}` }),
          el('div', { class: 'body-text', text: m.content.length > 240 ? m.content.slice(0, 240) + '…' : m.content }),
        ]),
        el('div', { class: 'actions' }, [
          el('button', { class: 'btn small secondary', text: 'Edit', onclick: () => openEditor(outlet, m) }),
          el('button', { class: 'btn small danger', text: 'Delete', onclick: () => {
            confirmDialog({
              title: `Delete "${m.title}"?`,
              message: 'This cannot be undone.',
              onConfirm: async () => {
                await apiRequest(`/memories/${m.id}`, { method: 'DELETE' });
                toast('Deleted', 'success');
                renderMemories(outlet);
              },
            });
          } }),
        ]),
      ]));
    });
  }
  outlet.appendChild(card);
}

function openEditor(outlet, existing) {
  openModal({
    title: existing ? `Edit ${TYPE_LABELS[existing.type]}` : `New ${TYPE_LABELS[activeTab]}`,
    submitLabel: existing ? 'Save Changes' : 'Create',
    initialValues: existing ? { title: existing.title, content: existing.content, tags: existing.tags.join(', ') } : {},
    fields: [
      { name: 'title', label: 'Title' },
      { name: 'content', label: 'Content', type: 'textarea', rows: 8 },
      { name: 'tags', label: 'Tags (comma separated)', hint: 'Used for search, e.g. family, wedding, advice' },
    ],
    onSubmit: async (values) => {
      const body = {
        title: values.title,
        content: values.content,
        tags: values.tags ? values.tags.split(',').map((t) => t.trim()).filter(Boolean) : [],
      };
      if (existing) {
        await apiRequest(`/memories/${existing.id}`, { method: 'PUT', body });
      } else {
        body.type = activeTab;
        await apiRequest('/memories', { method: 'POST', body });
      }
      toast(existing ? 'Updated' : 'Created', 'success');
      renderMemories(outlet);
    },
  });
}
