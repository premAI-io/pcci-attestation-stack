// This helper modules is for binding to the right fetch in case the global
// fetch gets overwritten
const baseFetch = globalThis.fetch.bind(globalThis);

export function realFetch(input, init) {
    return baseFetch(input, init);
}
