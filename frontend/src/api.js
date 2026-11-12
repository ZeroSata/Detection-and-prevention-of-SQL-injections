import axios from 'axios'

export const api = axios.create({ baseURL: '', timeout: 35000 })

/**
 * Выполнить "пробу" из песочницы с явным переключателем WAF.
 * Возвращает нормализованный результат {ok, status, data, ms} —
 * ошибки axios приводятся к обычному объекту, чтобы UI показывал 403/500.
 */
export async function probe({ path, method = 'get', data = null, waf = true }) {
  const started = performance.now()
  try {
    const resp = await api.request({
      url: path,
      method,
      data,
      headers: { 'X-WAF-Enabled': waf ? 'true' : 'false' },
    })
    return { ok: true, status: resp.status, data: resp.data, ms: Math.round(performance.now() - started) }
  } catch (err) {
    if (err.response) {
      return {
        ok: false,
        status: err.response.status,
        data: err.response.data,
        ms: Math.round(performance.now() - started),
      }
    }
    return { ok: false, status: 0, data: { detail: String(err.message) }, ms: Math.round(performance.now() - started) }
  }
}

export const get = (path) => api.get(path).then((r) => r.data)
export const post = (path, data) => api.post(path, data).then((r) => r.data)
export const patch = (path, data) => api.patch(path, data).then((r) => r.data)
