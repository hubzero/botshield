-- wrk-cookie.lua — attach a pre-minted `_bs_session` cookie to
-- every wrk request. Reads BENCH_COOKIE from the environment
-- (set by tests/bench/run-bench.sh after running scripts/mint_cookie.py).

local cookie = os.getenv("BENCH_COOKIE")
if cookie == nil or cookie == "" then
    error("wrk-cookie.lua: BENCH_COOKIE env var not set; "
       .. "run-bench.sh should mint one before invoking wrk -s on "
       .. "the cookied scenario.")
end

wrk.headers["Cookie"] = "_bs_session=" .. cookie
