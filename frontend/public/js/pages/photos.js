'use strict';

import { el, clear, loadingState, emptyState, formatDate } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { confirmDialog } from '../components/modal.js';
import { toast } from '../components/toast.js';

export async function renderPhotos(outlet) {
  clear(outlet);
  const fileInput = el('input', { type: 'file', accept: 'image/*', id: 'photo-file-input', style: 'display:none' });
  fileInput.addEventListener('change', () => handleUpload(outlet, fileInput));

  outlet.appendChild(pageHeader('Photos', 'Pictures worth preserving for the people you love.', [
    el('button', { class: 'btn', text: '+ Upload Photo', onclick: () => fileInput.click() }),
  ]));
  outlet.appendChild(fileInput);
  outlet.appendChild(loadingState());
  await loadGallery(outlet);
}

async function loadGallery(outlet) {
  let data;
  try {
    data = await apiRequest('/photos');
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  outlet.querySelector('.loading-state')?.remove();
  outlet.querySelector('#photo-gallery-card')?.remove();

  const card = el('div', { class: 'card', id: 'photo-gallery-card' });
  if (data.photos.length === 0) {
    card.appendChild(emptyState('🖼️', 'No photos yet', 'Upload photos to accompany your memories and life events.'));
  } else {
    card.appendChild(el('div', { class: 'grid cols-4' }, data.photos.map((p) => renderPhotoTile(outlet, p))));
  }
  outlet.appendChild(card);
}

function renderPhotoTile(outlet, p) {
  const img = el('img', { alt: p.caption || 'photo', style: 'width:100%;height:120px;object-fit:cover;border-radius:6px;background:#eee;' });
  // Fetch as an authenticated blob rather than pointing <img src> at the API
  // directly, since the endpoint requires a Bearer token the browser won't
  // attach to a plain <img> request.
  apiRequest(`/photos/${p.id}/download`, { raw: true }).then(async (res) => {
    if (res.ok) img.src = URL.createObjectURL(await res.blob());
  }).catch(() => {});

  return el('div', { class: 'file-tile' }, [
    img,
    p.caption ? el('div', { class: 'text-muted', style: 'font-size:0.82rem;', text: p.caption }) : null,
    el('div', { class: 'size', text: formatDate(p.createdAt) }),
    el('button', { class: 'btn small danger', text: 'Delete', onclick: () => {
      confirmDialog({
        title: 'Delete this photo?',
        message: 'This cannot be undone.',
        onConfirm: async () => {
          await apiRequest(`/photos/${p.id}`, { method: 'DELETE' });
          toast('Deleted', 'success');
          await loadGallery(outlet);
        },
      });
    } }),
  ]);
}

async function handleUpload(outlet, fileInput) {
  const file = fileInput.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append('file', file);
  toast(`Uploading ${file.name}...`, 'info');
  try {
    await apiRequest('/photos', { method: 'POST', formData });
    toast('Photo uploaded and encrypted', 'success');
    await loadGallery(outlet);
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    fileInput.value = '';
  }
}
