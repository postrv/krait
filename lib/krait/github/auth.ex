defmodule Krait.GitHub.Auth do
  @moduledoc "GitHub App authentication: JWT generation and installation token management"

  @jwt_expiry_seconds 600

  @doc "Generate a JWT for GitHub App authentication using RS256"
  @spec generate_jwt() :: {:ok, String.t()} | {:error, term()}
  def generate_jwt do
    app_id = Application.get_env(:krait, :github_app_id)
    key_path = Application.get_env(:krait, :github_private_key_path)

    with {:ok, pem} <- read_private_key(key_path),
         {:ok, signer} <- build_signer(pem) do
      now = System.system_time(:second)

      claims = %{
        "iss" => to_string(app_id),
        "iat" => now - 60,
        "exp" => now + @jwt_expiry_seconds
      }

      case Joken.generate_and_sign(%{}, claims, signer) do
        {:ok, token, _claims} -> {:ok, token}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc "Generate an installation access token by exchanging a JWT"
  @spec generate_installation_token(String.t() | integer() | nil) ::
          {:ok, String.t()} | {:error, term()}
  def generate_installation_token(installation_id \\ nil) do
    installation_id =
      installation_id || Application.get_env(:krait, :github_installation_id)

    with {:ok, jwt} <- generate_jwt() do
      url =
        "https://api.github.com/app/installations/#{installation_id}/access_tokens"

      case Req.post(url,
             headers: [
               {"authorization", "Bearer #{jwt}"},
               {"accept", "application/vnd.github+json"},
               {"x-github-api-version", "2022-11-28"}
             ],
             redirect: false
           ) do
        {:ok, %{status: 201, body: %{"token" => token}}} ->
          {:ok, token}

        {:ok, %{status: status, body: body}} ->
          {:error, {:github_api, status, body}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp read_private_key(nil), do: {:error, :no_private_key_path}

  defp read_private_key(path) do
    if String.contains?(path, "..") do
      {:error, {:key_path_rejected, "path contains '..'"}}
    else
      expanded = Path.expand(path)

      case Application.get_env(:krait, :github_key_dir) do
        nil ->
          # In production, require explicit key_dir to prevent unrestricted path access
          if Application.get_env(:krait, :env, :dev) == :prod do
            {:error, :key_dir_required}
          else
            do_read_key(expanded)
          end

        allowed_dir ->
          # Resolve symlinks to prevent escape via symlink
          alias Krait.Security.PathResolver

          with {:ok, real_path} <- PathResolver.safe_realpath(expanded),
               {:ok, real_dir} <- PathResolver.safe_realpath(Path.expand(allowed_dir)) do
            if String.starts_with?(real_path, real_dir <> "/") or real_path == real_dir do
              do_read_key(real_path)
            else
              {:error, {:key_path_rejected, "resolved path outside allowed directory"}}
            end
          else
            {:error, reason} -> {:error, {:key_path_rejected, reason}}
          end
      end
    end
  end

  defp do_read_key(path) do
    case File.read(path) do
      {:ok, pem} -> {:ok, pem}
      {:error, reason} -> {:error, {:key_read_failed, reason}}
    end
  end

  defp build_signer(pem) do
    {:ok, Joken.Signer.create("RS256", %{"pem" => pem})}
  rescue
    e in [ArgumentError, RuntimeError] ->
      {:error, {:signer_failed, Exception.message(e)}}
  end
end
