// Serves only this release's encrypted files. The fragment key never goes in a network request.
const base = self.registration.scope
const view = new URL('view/', base).pathname
const utf8 = new TextEncoder()
let active
let audioCache

self.addEventListener('install', event => event.waitUntil(self.skipWaiting()))
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()))

// A non-extractable key lets an unlocked browser reload after the OS stops its worker.
function savedKey(key) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('invitation:' + base, 1)
    request.onupgradeneeded = () => request.result.createObjectStore('invite')
    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      const db = request.result
      const tx = db.transaction('invite', key ? 'readwrite' : 'readonly')
      const store = tx.objectStore('invite')
      const op = key ? store.put(key, 'key') : store.get('key')
      tx.oncomplete = () => { db.close(); resolve(op.result) }
      tx.onabort = () => { db.close(); reject(tx.error) }
    }
  })
}
async function decrypt(key, name, file) {
  const response = await fetch(new URL(file, base))
  if (!response.ok) throw Error('Unavailable')
  const body = new Uint8Array(await response.arrayBuffer())
  return crypto.subtle.decrypt({name:'AES-GCM', iv:body.subarray(0,12), additionalData:utf8.encode(name)}, key, body.subarray(12))
}
async function unlock(key) {
  const names = await decrypt(key, 'manifest', 'index.bin')
  return {key, files:JSON.parse(new TextDecoder().decode(names))}
}
self.addEventListener('message', event => {
  const port = event.ports[0]
  // Only accept an invitation from this release's own landing page.
  if (!port || !event.source?.url || new URL(event.source.url).origin !== self.location.origin ||
      new URL(event.source.url).pathname.replace(/index\.html$/, '') !== new URL('../', base).pathname ||
      event.data?.kind !== 'open' || !/^[0-9a-f]{64}$/.test(event.data.key)) return
  event.waitUntil((async () => {
    try {
      const bytes = Uint8Array.from(event.data.key.match(/../g), pair => parseInt(pair, 16))
      const key = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['decrypt'])
      const session = await unlock(key)
      await savedKey(key)
      active = session
      port.postMessage('ok')
    } catch (error) { port.postMessage(error.name === 'OperationError' ? 'invalid' : 'unavailable') }
  })())
})
function ranged(buffer, type, range) {
  const size = buffer.byteLength
  const headers = {'Content-Type':type, 'Cache-Control':'no-store', 'Accept-Ranges':'bytes', 'Referrer-Policy':'no-referrer', 'X-Content-Type-Options':'nosniff'}
  if (!range) return new Response(buffer,{headers:{...headers,'Content-Length':String(size)}})
  const match = /^bytes=(\d*)-(\d*)$/.exec(range)
  const start = match?.[1] ? Number(match[1]) : Math.max(0,size-Number(match?.[2]))
  const end = match?.[1] && match[2] ? Math.min(size-1,Number(match[2])) : size-1
  if (!match || !(match[1] || match[2]) || start>end || start>=size) return new Response(null,{status:416,headers:{'Content-Range':'bytes */'+size}})
  return new Response(buffer.slice(start,end+1),{status:206,headers:{...headers,'Content-Length':String(end-start+1),'Content-Range':'bytes '+start+'-'+end+'/'+size}})
}
async function serve(request, name) {
  try {
    if (!active) {
      const key = await savedKey()
      if (!key) return Response.redirect(new URL('../',base).href)
      active = await unlock(key)
    }
    const entry = Object.hasOwn(active.files,name) && active.files[name]
    if (!entry) return new Response(null,{status:404})
    const [file,type] = entry
    // Safari may request the same music in several byte ranges.
    let bytes
    if (type.startsWith('audio/')) {
      if (!audioCache) audioCache = decrypt(active.key,name,file).catch(error => { audioCache=undefined; throw error })
      bytes = await audioCache
    } else bytes = await decrypt(active.key,name,file)
    return ranged(bytes,type,request.headers.get('range'))
  } catch {return new Response('请检查网络后刷新。',{status:503,headers:{'Content-Type':'text/plain;charset=utf-8','Cache-Control':'no-store'}})}
}
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url)
  if (event.request.method==='GET' && url.origin===self.location.origin && url.pathname.startsWith(view)) {
    event.respondWith(serve(event.request,url.pathname.slice(view.length)||'index.html'))
  }
})
