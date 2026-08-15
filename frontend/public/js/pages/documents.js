'use strict';

import { el, clear, loadingState, emptyState, formatDate, formatBytes } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { confirmDialog } from '../components/modal.js';
import { toast } from '../components/toast.js';

export async function renderDocuments(outlet) {
  clear(outlet);
  const fileInput = el('input', { type: 'file', id: 'doc-file-input', style: 'display:none' });
  fileInput.addEventListener('change', () => handleUpload(outlet, fileInput));

  outlet.appendChild(pageHeader('Documents', 'Wills, IDs, deeds, and other important paperwork — encrypted at rest.', [
    el('button', { class: 'btn', text: '+ Upload Document', onclick: () => fileInput.click() }),
  ]));
  outlet.appendChild(fileInput);
  outlet.appendChild(loadingState());
  await loadList(outlet);
}

async function loadList(outlet) {
  let data;
  try {
    data = await apiRequest('/documents');
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  outlet.querySelector('.loading-state')?.remove();
  outlet.querySelector('#doc-list-card')?.remove();

  const card = el('div', { class: 'card', id: 'doc-list-card' });
  if (data.documents.length === 0) {
    card.appendChild(emptyState('📄', 'No documents yet', 'Upload PDFs, Word documents, or images of important paperwork. Files are encrypted before being stored.'));
  } else {
    card.appendChild(el('div', { class: 'grid cols-3' }, data.documents.map((d) =>
      el('div', { class: 'file-tile' }, [
        el('div', { class: 'name', text: d.filename }),
        el('div', { class: 'size', text: `${formatBytes(d.sizeBytes)} · ${formatDate(d.createdAt)}` }),
        d.description ? el('div', { class: 'text-muted', style: 'font-size:0.85rem;', text: d.description }) : null,
        el('div', { class: 'actions', style: 'display:flex;gap:0.4rem;' }, [
          el('button', { class: 'btn small secondary', text: 'Download', onclick: () => downloadFile(`/documents/${d.id}/download`, d.filename) }),
          el('button', { class: 'btn small danger', text: 'Delete', onclick: () => {
            confirmDialog({
              title: `Delete "${d.filename}"?`,
              message: 'This cannot be undone.',
              onConfirm: async () => {
                await apiRequest(`/documents/${d.id}`, { method: 'DELETE' });
                toast('Deleted', 'success');
                await loadList(outlet);
              },
            });
          } }),
        ]),
      ])
    )));
  }
  outlet.appendChild(card);
}

async function handleUpload(outlet, fileInput) {
  const file = fileInput.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append('file', file);
  toast(`Uploading ${file.name}...`, 'info');
  try {
    await apiRequest('/documents', { method: 'POST', formData });
    toast('Document uploaded and encrypted', 'success');
    await loadList(outlet);
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    fileInput.value = '';
  }
}

export async function downloadFile(path, filename) {
  try {
    const res = await apiRequest(path, { raw: true });
    if (!res.ok) throw new Error('Download failed');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'download';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    toast(err.message || 'Download failed', 'error');
  }
}
