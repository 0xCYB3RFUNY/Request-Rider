"""Ротація проксі-ендпоінтів для browser-driven обходу.

Навіщо. `chm0dx/creepyCrawler` має дві здатності, які ми позначили
`не перенесено` як «комерційний API Detectify»:

    manage_fp()             створює ендпоінти проксі через API і видаляє їх
    prepare_fireprox_url()  прив'язує URL до окремого ендпоинта

Обидві — про **різні вихідні адреси на обхід**, а не про конкретного вендора:
одне й те саме дає будь-який пул, і саме цю частину ми справді не мали. У нас
був один рядок `proxy_server` на весь обхід, тобто весь краул виходив з однієї
адреси — для обходу, який має виглядати як різні відвідувачі, це єдина
конфігурація, яка не працює.

Тому портовано здатність, а не постачальника:

* `ProxyPool.endpoint_for(url)` — прив'язка ос��рки до ендпоинта: той самий
  хост обслуговується тим самим ендпоинтом, різні хости розходяться по колу
  (`prepare_fireprox_url`);
* `ProxyPool.slots(n)` — виділення ендпоинтів паралельним слотам обходу, щоб
  вони не сходилися на одній адресі (`manage_fp` на рівні життєвого циклу);
* кожен результат обходу несе `proxy_used`, тож доказ називає адресу виходу.

Постачальник не вбудовується: пул приходить явним списком у конфігурації, і
робота з віддаленими API (create/delete endpoint) лишається викликом, який
задає оператор. Приховати комерційний залежний сервіс у коді краулера — це
різниця між можливістю та вимаганням.
"""

class ProxyPool:
    """A fixed set of proxy endpoints with round-robin origin affinity.

    Three properties the crawler actually needs, and each is testable without
    a network:

    * a request that stays on one host keeps the same egress, so cookies,
        session state and the site's own view of "one visitor" stay coherent;
    * a request that moves to a new host is very likely to move to a different
        egress, so the crawl does not present one address for the whole site;
    * an empty pool means a direct crawl, which is the default and must stay
        exactly as it was before this existed.
    """

    def __init__(self, servers=(), mode="split"):
        cleaned = []
        for server in servers or ():
            text = str(server or "").strip()
            if not text:
                continue
            if text not in cleaned:
                cleaned.append(text)
        self._servers = cleaned
        self.mode = "replicate" if str(mode or "").strip().lower() in {"replicate", "full", "mirror"} else "split"

        self._host_map = {}
        self.used = []

    @property
    def enabled(self):
        return bool(self._servers)

    def __len__(self):
        return len(self._servers)

    def endpoint_for(self, url):
        """Return the proxy endpoint pinned to this URL's host (origin affinity).

        Requests to the same host keep the same egress endpoint so cookies and
        session state stay coherent. Different hosts cycle round-robin through
        the pool. An empty pool returns an empty string (direct crawl).
        """
        if not self._servers:
            return ""
        from urllib.parse import urlparse
        host = urlparse(str(url or "")).netloc.lower() or str(url or "").lower()
        if not host:
            return self._servers[0]
        if host not in self._host_map:
            assigned = self._servers[len(self._host_map) % len(self._servers)]
            self._host_map[host] = assigned
            if assigned not in self.used:
                self.used.append(assigned)
        return self._host_map[host]


    @property
    def servers(self):
        """The endpoints, in the order the operator gave them."""
        return list(self._servers)

    def slots(self, count):
        """Hand out `count` endpoints, one per parallel crawl slot.

        Distinct slots get distinct endpoints while the pool lasts. With fewer
        endpoints than slots the extras share one, and that is visible in the
        returned list rather than silently hidden.
        """
        wanted = max(1, int(count or 1))
        if not self._servers:
            return ["" for _ in range(wanted)]
        return [self._servers[index % len(self._servers)] for index in range(wanted)]

    def report(self):
        """What the crawl actually used, for the job result and the export."""
        return {
            "enabled": self.enabled,
            "configured": len(self._servers),
            "used": list(self.used),
            "mode": self.mode,
        }


def pool_from_payload(payload):
    """Read the pool out of a job payload.

    `proxy_server` stays supported: a single endpoint is a pool of one, so an
    existing configuration keeps its exact meaning and nothing about a direct
    crawl changes. An explicitly empty list is treated the same way — the pool
    is opt-in, and "no endpoints given" means the default, not a broken list.
    """
    if not isinstance(payload, dict):
        return ProxyPool()
    servers = payload.get("proxy_servers")
    if isinstance(servers, str):
        servers = [part for part in servers.replace("\n", ",").split(",")]
    if not isinstance(servers, (list, tuple)) or not servers:
        single = str(payload.get("proxy_server") or "").strip()
        servers = [single] if single else []
    mode = str(payload.get("proxy_distribution") or payload.get("distribution_mode") or "split").strip().lower()
    return ProxyPool(servers, mode=mode)