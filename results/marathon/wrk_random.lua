
local user_agents = {
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
  "python-requests/2.31.0",
  "Go-http-client/1.1",
}
local paths = {"/", "/health", "/api/status", "/metrics", "/favicon.ico"}
math.randomseed(os.time())
request = function()
  local ua = user_agents[math.random(#user_agents)]
  local path = paths[math.random(#paths)]
  wrk.headers["User-Agent"] = ua
  return wrk.format("GET", path)
end
