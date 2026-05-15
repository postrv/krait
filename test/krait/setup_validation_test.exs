defmodule Krait.SetupValidationTest do
  use ExUnit.Case, async: false

  alias Krait.SetupValidation

  setup do
    original_env = Application.get_all_env(:krait)

    on_exit(fn ->
      for {key, _value} <- Application.get_all_env(:krait) do
        Application.delete_env(:krait, key)
      end

      for {key, value} <- original_env do
        Application.put_env(:krait, key, value)
      end
    end)

    :ok
  end

  describe "run/1" do
    test "returns a structured aggregate result" do
      Application.put_env(:krait, :env, :test)
      Application.put_env(:krait, :github_client, Krait.GitHub.DryRunClient)
      Application.put_env(:krait, :attestation_key_path, nil)
      Application.put_env(:krait, :filesystem_sandbox_root, nil)
      Application.put_env(:krait, :admin_auth_token, nil)
      Application.put_env(:krait, Krait.Analyzer.Deep, narsil_binary: "narsil-mcp")

      result =
        SetupValidation.run(
          database_query: fn -> {:ok, %{rows: [[1]]}} end,
          nif_validator: fn _code, _language -> {:ok, %{complexity: 1, hash: "probe"}} end,
          kill_switch_status: fn -> :running end,
          command_runner: fn
            "docker", ["image", "inspect", "krait-sandbox:latest"], _opts -> {"[]", 0}
          end,
          executable_finder: fn
            "narsil-mcp" -> "/usr/local/bin/narsil-mcp"
            "docker" -> "/usr/bin/docker"
          end
        )

      assert result.status in [:ok, :warning]
      assert %DateTime{} = result.checked_at
      assert Enum.any?(result.checks, &(&1.name == :database))
      assert Enum.any?(result.checks, &(&1.name == :nif))
      assert Enum.any?(result.checks, &(&1.name == :narsil))
      assert Enum.any?(result.checks, &(&1.name == :sandbox_image))
      assert Enum.any?(result.checks, &(&1.name == :github_auth))
      assert Enum.any?(result.checks, &(&1.name == :attestation_key))
      assert Enum.any?(result.checks, &(&1.name == :llm))
      assert Enum.any?(result.checks, &(&1.name == :admin_auth))
    end

    test "fails closed for production when Narsil is missing" do
      Application.put_env(:krait, :env, :prod)
      Application.put_env(:krait, Krait.Analyzer.Deep, narsil_binary: "/opt/krait/bin/narsil-mcp")

      result =
        SetupValidation.run(
          checks: [:narsil],
          executable_finder: fn _ -> nil end,
          file_exists?: fn _ -> false end
        )

      assert result.status == :error
      assert [%{name: :narsil, status: :error, message: message}] = result.checks
      assert message =~ "not available"
    end

    test "fails closed for production when Narsil path is relative" do
      Application.put_env(:krait, :env, :prod)
      Application.put_env(:krait, Krait.Analyzer.Deep, narsil_binary: "narsil-mcp")

      result = SetupValidation.run(checks: [:narsil])

      assert result.status == :error
      assert [%{name: :narsil, status: :error, message: message}] = result.checks
      assert message =~ "absolute"
    end

    test "reports docker image inspection failures" do
      Application.put_env(:krait, :env, :prod)
      Application.put_env(:krait, :sandbox_image, "krait-sandbox:release")

      result =
        SetupValidation.run(
          checks: [:sandbox_image],
          executable_finder: fn "docker" -> "/usr/bin/docker" end,
          command_runner: fn "docker", ["image", "inspect", "krait-sandbox:release"], _opts ->
            {"No such image", 1}
          end
        )

      assert result.status == :error
      assert [%{name: :sandbox_image, status: :error, message: message}] = result.checks
      assert message =~ "not inspectable"
    end

    test "accepts dry-run GitHub mode without credentials" do
      Application.put_env(:krait, :env, :prod)
      Application.put_env(:krait, :github_client, Krait.GitHub.DryRunClient)

      result = SetupValidation.run(checks: [:github_auth])

      assert result.status == :ok
      assert [%{name: :github_auth, status: :ok, message: message}] = result.checks
      assert message =~ "dry-run"
    end

    test "accepts Anthropic API key as cloud LLM configuration" do
      Application.put_env(:krait, :env, :prod)
      Application.delete_env(:krait, :openrouter_api_key)
      Application.put_env(:krait, :anthropic_api_key, "sk-ant-test")

      result = SetupValidation.run(checks: [:llm])

      assert result.status == :ok
      assert [%{name: :llm, status: :ok, message: message}] = result.checks
      assert message =~ "Cloud LLM API key"
    end

    test "reports missing cloud API key when router forces cloud tasks" do
      Application.put_env(:krait, :env, :prod)
      Application.delete_env(:krait, :openrouter_api_key)
      Application.delete_env(:krait, :anthropic_api_key)
      Application.put_env(:krait, Krait.LLM.Ollama, base_url: "http://localhost:11434")

      Application.put_env(:krait, Krait.LLM.Router,
        local_module: Krait.LLM.Ollama,
        cloud_module: Krait.LLM.OpenRouter,
        force_cloud: [:code_gen],
        force_local: [],
        escalation_threshold: 1
      )

      result = SetupValidation.run(checks: [:llm])

      assert result.status == :error

      assert [
               %{
                 name: :llm,
                 status: :error,
                 message: message,
                 details: %{force_cloud: [:code_gen]}
               }
             ] = result.checks

      assert message =~ "Cloud LLM API key"
    end

    test "accepts Ollama when router does not force cloud tasks" do
      Application.put_env(:krait, :env, :test)
      Application.delete_env(:krait, :openrouter_api_key)
      Application.delete_env(:krait, :anthropic_api_key)
      Application.put_env(:krait, Krait.LLM.Ollama, base_url: "http://localhost:11434")
      Application.put_env(:krait, Krait.LLM.Router, force_cloud: [], force_local: [:code_gen])

      result = SetupValidation.run(checks: [:llm])

      assert result.status == :ok
      assert [%{name: :llm, status: :ok, message: message}] = result.checks
      assert message =~ "Ollama"
    end

    test "reports kill switch probe errors as setup errors" do
      result =
        SetupValidation.run(
          checks: [:kill_switch],
          kill_switch_status: fn -> {:error, :missing_ets_table} end
        )

      assert result.status == :error

      assert [%{name: :kill_switch, status: :error, message: message, details: details}] =
               result.checks

      assert message =~ "failed"
      assert details.reason =~ "missing_ets_table"
    end

    test "requires long admin token in production" do
      Application.put_env(:krait, :env, :prod)
      Application.put_env(:krait, :admin_auth_token, "short")

      result = SetupValidation.run(checks: [:admin_auth])

      assert result.status == :error
      assert [%{name: :admin_auth, status: :error, message: message}] = result.checks
      assert message =~ "at least 32"
    end
  end
end
