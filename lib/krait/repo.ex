defmodule Krait.Repo do
  use Ecto.Repo,
    otp_app: :krait,
    adapter: Ecto.Adapters.Postgres
end
