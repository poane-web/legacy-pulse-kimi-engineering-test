'use strict';

const state = {
  user: null, // { id, email, fullName, role }
};

const listeners = new Set();

export function getUser() {
  return state.user;
}
export function setUser(user) {
  state.user = user;
  listeners.forEach((fn) => fn(state.user));
}
export function onUserChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}
