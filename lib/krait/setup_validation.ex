defmodule Krait.SetupValidation do
  @moduledoc """
  Operator-facing setup validation for release readiness.

  This module avoids mutating application state. It gathers the checks an
  operator needs before enabling evolution in production.
  """

  @type check_status :: :ok | :warning | :error
  @type check :: %{
          name: atom(),
          status: check_status(),
          message: String.t(),
          details: map()
        }

  @type result :: %{
          status: check_status(),
          checked_at: DateTime.t(),
          checks: [check()]
        }

  @default_checks [
    :database,
    :nif,
    :narsil,
    :sandbox_image,
    :github_auth,
    :attestation_key,
    :llm,
    :filesystem_sandbox,
    :admin_auth,
    :kill_switch
  ]

  @doc "Runs setup validation checks and returns a structured result."
  @spec run(keyword()) :: result()
  def run(opts \\ []) do
    checks = Keyword.get(opts, :checks, @default_checks)

    results =
      Enum.map(checks, fn check ->
        run_check(check, opts)
      end)

    %{
      status: aggregate_status(results),
      checked_at: DateTime.utc_now(),
      checks: results
    }
  end

  @doc "Converts a validation result to a JSON-safe map."
  @spec to_json_map(result()) :: map()
  def to_json_map(result) do
    %{
      status: Atom.to_string(result.status),
      checked_at: DateTime.to_iso8601(result.checked_at),
      checks:
        Enum.map(result.checks, fn check ->
          %{
            name: Atom.to_string(check.name),
            status: Atom.to_string(check.status),
            message: check.message,
            details: stringify_detail_values(check.details)
          }
        end)
    }
  end

  defp run_check(:database, opts), do: database_check(opts)
  defp run_check(:nif, opts), do: nif_check(opts)
  defp run_check(:narsil, opts), do: narsil_check(opts)
  defp run_check(:sandbox_image, opts), do: sandbox_image_check(opts)
  defp run_check(:github_auth, _opts), do: github_auth_check()
  defp run_check(:attestation_key, opts), do: attestation_key_check(opts)
  defp run_check(:llm, _opts), do: llm_check()
  defp run_check(:filesystem_sandbox, opts), do: filesystem_sandbox_check(opts)
  defp run_check(:admin_auth, _opts), do: admin_auth_check()
  defp run_check(:kill_switch, opts), do: kill_switch_check(opts)

  defp run_check(check, _opts) do
    check(:unknown, :error, "unknown setup validation check: #{inspect(check)}")
  end

  defp database_check(opts) do
    database_query =
      Keyword.get(opts, :database_query, fn ->
        Ecto.Adapters.SQL.query(Krait.Repo, "SELECT 1")
      end)

    case database_query.() do
      {:ok, _result} ->
        check(:database, :ok, "database query succeeded")

      {:error, reason} ->
        check(:database, :error, "database query failed", %{reason: inspect(reason)})
    end
  rescue
    error ->
      check(:database, :error, "database check raised", %{reason: Exception.message(error)})
  catch
    :exit, reason ->
      check(:database, :error, "database check exited", %{reason: inspect(reason)})
  end

  defp nif_check(opts) do
    nif_validator = Keyword.get(opts, :nif_validator, &Krait.Analyzer.Nif.quick_validate/2)

    code = """
    defmodule Krait.SetupValidationProbe do
      def run(values), do: Enum.map(values, & &1)
    end
    """

    case nif_validator.(code, "elixir") do
      {:ok, result} ->
        check(:nif, :ok, "Rust analyzer NIF accepted probe code", %{
          hash: Map.get(result, :hash),
          complexity: Map.get(result, :complexity)
        })

      {:syntax_error, errors} ->
        check(:nif, :error, "Rust analyzer NIF reported syntax errors", %{errors: errors})

      {:policy_violation, details} ->
        check(:nif, :error, "Rust analyzer NIF reported policy violation", %{details: details})

      other ->
        check(:nif, :error, "Rust analyzer NIF returned unexpected result", %{
          result: inspect(other)
        })
    end
  rescue
    error ->
      check(:nif, :error, "Rust analyzer NIF is unavailable", %{reason: Exception.message(error)})
  catch
    :exit, reason ->
      check(:nif, :error, "Rust analyzer NIF exited", %{reason: inspect(reason)})
  end

  defp narsil_check(opts) do
    configured =
      (Application.get_env(:krait, Krait.Analyzer.Deep) || [])
      |> Keyword.get(:narsil_binary, "narsil-mcp")

    cond do
      prod?() and Path.type(configured) != :absolute ->
        check(:narsil, :error, "production NARSIL_BINARY must be an absolute path", %{
          configured: configured
        })

      binary_available?(configured, opts) ->
        check(:narsil, :ok, "narsil-mcp is available", %{configured: configured})

      true ->
        status = if prod?(), do: :error, else: :warning
        check(:narsil, status, "narsil-mcp is not available", %{configured: configured})
    end
  end

  defp sandbox_image_check(opts) do
    image = Application.get_env(:krait, :sandbox_image, "krait-sandbox:latest")
    executable_finder = Keyword.get(opts, :executable_finder, &System.find_executable/1)
    command_runner = Keyword.get(opts, :command_runner, &System.cmd/3)

    cond do
      executable_finder.("docker") == nil ->
        status = if prod?(), do: :error, else: :warning
        check(:sandbox_image, status, "docker executable is not available", %{image: image})

      true ->
        case command_runner.("docker", ["image", "inspect", image], stderr_to_stdout: true) do
          {_output, 0} ->
            check(:sandbox_image, :ok, "sandbox image is inspectable", %{image: image})

          {output, exit_code} ->
            status = if prod?(), do: :error, else: :warning

            check(:sandbox_image, status, "sandbox image is not inspectable", %{
              image: image,
              exit_code: exit_code,
              output: String.trim(to_string(output))
            })
        end
    end
  end

  defp github_auth_check do
    if Application.get_env(:krait, :github_client) == Krait.GitHub.DryRunClient do
      check(:github_auth, :ok, "GitHub dry-run client is enabled")
    else
      required = [
        {:github_app_id, Application.get_env(:krait, :github_app_id)},
        {:github_private_key_path, Application.get_env(:krait, :github_private_key_path)},
        {:github_installation_id, Application.get_env(:krait, :github_installation_id)}
      ]

      missing =
        required
        |> Enum.filter(fn {_key, value} -> blank?(value) end)
        |> Enum.map(fn {key, _value} -> key end)

      if missing == [] do
        check(:github_auth, :ok, "GitHub App configuration is present")
      else
        status = if prod?(), do: :error, else: :warning
        check(:github_auth, status, "GitHub App configuration is incomplete", %{missing: missing})
      end
    end
  end

  defp attestation_key_check(opts) do
    key_path = Application.get_env(:krait, :attestation_key_path)
    file_exists? = Keyword.get(opts, :file_exists?, &File.exists?/1)

    cond do
      blank?(key_path) ->
        status = if prod?(), do: :error, else: :warning
        check(:attestation_key, status, "attestation key path is not configured")

      String.contains?(key_path, "..") ->
        check(:attestation_key, :error, "attestation key path must not contain '..'", %{
          path: key_path
        })

      file_exists?.(key_path) ->
        check(:attestation_key, :ok, "attestation key exists", %{path: key_path})

      true ->
        status = if prod?(), do: :error, else: :warning
        check(:attestation_key, status, "attestation key does not exist", %{path: key_path})
    end
  end

  defp llm_check do
    openrouter_key = Application.get_env(:krait, :openrouter_api_key)
    anthropic_key = Application.get_env(:krait, :anthropic_api_key)
    ollama_config = Application.get_env(:krait, Krait.LLM.Ollama, [])
    ollama_url = Keyword.get(ollama_config, :base_url)
    forced_cloud_tasks = router_force_cloud_tasks()

    cond do
      present?(openrouter_key) ->
        check(:llm, :ok, "Cloud LLM API key is configured", %{provider: :openrouter})

      present?(anthropic_key) ->
        check(:llm, :ok, "Cloud LLM API key is configured", %{provider: :anthropic})

      forced_cloud_tasks != [] ->
        status = if prod?(), do: :error, else: :warning

        check(:llm, status, "Cloud LLM API key is required by router policy", %{
          force_cloud: forced_cloud_tasks
        })

      present?(ollama_url) ->
        status = if prod?(), do: :warning, else: :ok
        check(:llm, status, "Ollama local LLM is configured", %{base_url: ollama_url})

      true ->
        status = if prod?(), do: :error, else: :warning
        check(:llm, status, "no LLM backend is configured")
    end
  end

  defp router_force_cloud_tasks do
    :krait
    |> Application.get_env(Krait.LLM.Router, [])
    |> Keyword.get(:force_cloud, [:planning, :reflection, :retry_guide])
    |> List.wrap()
  end

  defp filesystem_sandbox_check(opts) do
    root = Application.get_env(:krait, :filesystem_sandbox_root)
    file_exists? = Keyword.get(opts, :file_exists?, &File.exists?/1)

    cond do
      blank?(root) ->
        status = if prod?(), do: :error, else: :warning
        check(:filesystem_sandbox, status, "filesystem sandbox root is not configured")

      file_exists?.(root) ->
        check(:filesystem_sandbox, :ok, "filesystem sandbox root exists", %{path: root})

      true ->
        status = if prod?(), do: :error, else: :warning

        check(:filesystem_sandbox, status, "filesystem sandbox root does not exist", %{path: root})
    end
  end

  defp admin_auth_check do
    token = Application.get_env(:krait, :admin_auth_token)

    cond do
      blank?(token) ->
        status = if prod?(), do: :error, else: :warning
        check(:admin_auth, status, "admin token is not configured")

      String.length(token) < 32 ->
        status = if prod?(), do: :error, else: :warning
        check(:admin_auth, status, "admin token must be at least 32 characters")

      true ->
        check(:admin_auth, :ok, "admin token is configured")
    end
  end

  defp kill_switch_check(opts) do
    kill_switch_status = Keyword.get(opts, :kill_switch_status, &kill_switch_status/0)

    case kill_switch_status.() do
      :running ->
        check(:kill_switch, :ok, "kill switch is running and not halted")

      :halted ->
        check(:kill_switch, :warning, "kill switch is currently halted")

      :not_running ->
        check(:kill_switch, :error, "kill switch process is not running")

      {:error, reason} ->
        check(:kill_switch, :error, "kill switch check failed", %{reason: inspect(reason)})

      other ->
        check(:kill_switch, :error, "kill switch returned unexpected status", %{
          status: inspect(other)
        })
    end
  rescue
    error ->
      check(:kill_switch, :error, "kill switch check failed", %{reason: Exception.message(error)})
  end

  defp binary_available?(configured, opts) do
    executable_finder = Keyword.get(opts, :executable_finder, &System.find_executable/1)
    file_exists? = Keyword.get(opts, :file_exists?, &File.exists?/1)

    if Path.type(configured) == :absolute do
      file_exists?.(configured)
    else
      executable_finder.(configured) != nil
    end
  end

  defp kill_switch_status do
    case Process.whereis(Krait.KillSwitch) do
      pid when is_pid(pid) ->
        case :ets.info(:krait_kill_switch) do
          :undefined ->
            {:error, :missing_ets_table}

          _info ->
            if Krait.KillSwitch.halted?(), do: :halted, else: :running
        end

      _ ->
        :not_running
    end
  end

  defp aggregate_status(checks) do
    cond do
      Enum.any?(checks, &(&1.status == :error)) -> :error
      Enum.any?(checks, &(&1.status == :warning)) -> :warning
      true -> :ok
    end
  end

  defp check(name, status, message, details \\ %{}) do
    %{name: name, status: status, message: message, details: details}
  end

  defp prod?, do: Application.get_env(:krait, :env, :dev) == :prod

  defp present?(value) when is_binary(value), do: String.trim(value) != ""
  defp present?(value), do: not is_nil(value)

  defp blank?(value), do: not present?(value)

  defp stringify_detail_values(details) do
    Map.new(details, fn {key, value} -> {Atom.to_string(key), stringify_detail_value(value)} end)
  end

  defp stringify_detail_value(value) when is_atom(value), do: Atom.to_string(value)

  defp stringify_detail_value(value) when is_list(value),
    do: Enum.map(value, &stringify_detail_value/1)

  defp stringify_detail_value(value), do: value
end
