#!/usr/bin/env elixir
# E2E evolution test with GLM-5 via OpenRouter

key = System.get_env("OPENROUTER_API_KEY")

# Resume kill switch
Krait.KillSwitch.resume!()

# Force ALL through cloud
Application.put_env(:krait, Krait.LLM.Router,
  cloud_module: Krait.LLM.OpenRouter,
  force_cloud: [:planning, :reflection, :retry_guide, :code_gen, :test_gen, :chat, :retry],
  force_local: [],
  escalation_threshold: 1
)

# GLM-5 via Novita FP8
Application.put_env(:krait, Krait.LLM.OpenRouter,
  base_url: "https://openrouter.ai/api/v1",
  model: "z-ai/glm-5",
  site_name: "Krait",
  request_timeout: 120_000,
  default_provider: %{
    data_collection: "deny",
    order: ["Novita"],
    quantizations: ["fp8"],
    allow_fallbacks: true
  }
)

# Only 1 retry to conserve credits
Application.put_env(:krait, :max_evolution_retries, 1)


IO.puts("=== KRAIT E2E: GLM-5 via Novita FP8 ===")
IO.puts("Kill switch halted? #{Krait.KillSwitch.halted?()}")
start = System.monotonic_time(:millisecond)

result = Krait.Evolution.evolve(%{
  skill_name: "fizz_buzz",
  description: "A skill that plays FizzBuzz: given a number n, returns Fizz if divisible by 3, Buzz if divisible by 5, FizzBuzz if divisible by both, or the number itself as a string. The execute function takes a map with an integer key n and returns {:ok, result_string}.",
  trigger: "Create a FizzBuzz skill",
  target_path: "lib/krait/skills/community/fizz_buzz.ex",
  test_path: "test/krait/skills/community/fizz_buzz_test.exs"
})

elapsed = System.monotonic_time(:millisecond) - start

IO.puts("")
IO.puts("=== Result (#{div(elapsed, 1000)}s) ===")

case result do
  {:ok, details} ->
    IO.puts("STATUS: #{if details.draft, do: "DRAFT", else: "CLEAN"} PR")
    IO.puts("PR: #{details.pr_url}")
    IO.puts("Attempts: #{details.attempts}")
    if details[:ast_hash], do: IO.puts("AST Hash: #{details.ast_hash}")
    if details[:complexity], do: IO.puts("Complexity: #{details.complexity}")

    if details[:errors] do
      IO.puts("Retry errors:")

      Enum.each(details.errors, fn {a, t, d} ->
        IO.puts("  Attempt #{a}: #{t} — #{inspect(d, limit: 100)}")
      end)
    end

  {:error, :max_retries_exhausted, details} ->
    IO.puts("FAILED after #{details.attempts} attempts")

    Enum.each(details.errors, fn {a, t, d} ->
      IO.puts("  Attempt #{a}: #{t} — #{inspect(d, limit: 200)}")
    end)

  {:error, reason} ->
    IO.puts("ERROR: #{inspect(reason)}")
end

IO.puts("")
IO.puts("--- Credits ---")

case Krait.LLM.OpenRouter.check_credits(api_key: key) do
  {:ok, c} -> IO.puts("Used: $#{c.usage} | Remaining: $#{c.limit_remaining}")
  {:error, e} -> IO.inspect(e)
end
