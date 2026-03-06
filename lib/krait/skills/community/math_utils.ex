defmodule Krait.Skills.Community.MathUtils do
  @moduledoc "Mathematical utilities — statistics, number theory, sequences"
  @behaviour Krait.Skills.CapableSkill

  @max_input 1000

  @impl true
  def name, do: "math_utils"

  @impl true
  def description,
    do: "Math utilities: mean, median, mode, stddev, percentile, factorial, gcd, fibonacci"

  @impl true
  def required_capabilities, do: []

  @impl true
  def execute(%{"action" => "percentile", "numbers" => numbers, "p" => p}, _caps)
      when is_list(numbers) and is_number(p) do
    cond do
      numbers == [] -> {:error, "numbers list cannot be empty"}
      not Enum.all?(numbers, &is_number/1) -> {:error, "numbers must contain only numeric values"}
      p < 0 or p > 100 -> {:error, "percentile must be between 0 and 100"}
      true -> {:ok, %{result: percentile(numbers, p)}}
    end
  end

  def execute(%{"action" => action, "numbers" => numbers}, _caps)
      when action in ["mean", "median", "mode", "stddev", "percentile"] and is_list(numbers) do
    cond do
      numbers == [] -> {:error, "numbers list cannot be empty"}
      not Enum.all?(numbers, &is_number/1) -> {:error, "numbers must contain only numeric values"}
      true -> dispatch_stats(action, numbers)
    end
  end

  def execute(%{"action" => "factorial", "n" => n}, _caps) when is_integer(n) do
    cond do
      n < 0 -> {:error, "factorial requires a non-negative integer"}
      n > @max_input -> {:error, "input too large (max #{@max_input})"}
      true -> {:ok, %{result: factorial(n)}}
    end
  end

  def execute(%{"action" => "gcd", "a" => a, "b" => b}, _caps)
      when is_integer(a) and is_integer(b) do
    {:ok, %{result: gcd(abs(a), abs(b))}}
  end

  def execute(%{"action" => "fibonacci", "n" => n}, _caps) when is_integer(n) do
    cond do
      n < 0 -> {:error, "fibonacci requires a non-negative integer"}
      n > @max_input -> {:error, "input too large (max #{@max_input})"}
      true -> {:ok, %{result: fibonacci(n)}}
    end
  end

  def execute(%{"action" => action}, _caps)
      when action in ["mean", "median", "mode", "stddev", "percentile"] do
    {:error, "Missing required parameter: numbers"}
  end

  def execute(%{"action" => _}, _caps), do: {:error, "Unknown action or missing parameters"}
  def execute(_params, _caps), do: {:error, "Missing required parameter: action"}

  defp dispatch_stats("mean", numbers), do: {:ok, %{result: mean(numbers)}}
  defp dispatch_stats("median", numbers), do: {:ok, %{result: median(numbers)}}
  defp dispatch_stats("mode", numbers), do: {:ok, %{result: mode(numbers)}}
  defp dispatch_stats("stddev", numbers), do: {:ok, %{result: stddev(numbers)}}

  defp dispatch_stats("percentile", numbers) do
    {:ok, %{result: percentile(numbers, 50)}}
  end

  defp mean(numbers) do
    Enum.sum(numbers) / length(numbers)
  end

  defp median(numbers) do
    sorted = Enum.sort(numbers)
    len = length(sorted)
    mid = div(len, 2)

    if rem(len, 2) == 0 do
      (Enum.at(sorted, mid - 1) + Enum.at(sorted, mid)) / 2
    else
      Enum.at(sorted, mid)
    end
  end

  defp mode(numbers) do
    freqs = Enum.frequencies(numbers)
    max_freq = freqs |> Map.values() |> Enum.max()
    freqs |> Enum.filter(fn {_, f} -> f == max_freq end) |> Enum.map(&elem(&1, 0))
  end

  defp stddev(numbers) do
    avg = mean(numbers)
    n = length(numbers)

    variance =
      numbers
      |> Enum.map(fn x -> (x - avg) * (x - avg) end)
      |> Enum.sum()
      |> Kernel./(n)

    :math.sqrt(variance)
  end

  defp percentile(numbers, p) do
    sorted = Enum.sort(numbers)
    k = p / 100 * (length(sorted) - 1)
    f = floor(k)
    c = ceil(k)

    if f == c do
      Enum.at(sorted, f)
    else
      lower = Enum.at(sorted, f)
      upper = Enum.at(sorted, c)
      lower + (upper - lower) * (k - f)
    end
  end

  defp factorial(0), do: 1
  defp factorial(n), do: n * factorial(n - 1)

  defp gcd(a, 0), do: a
  defp gcd(a, b), do: gcd(b, rem(a, b))

  defp fibonacci(0), do: 0
  defp fibonacci(1), do: 1

  defp fibonacci(n) do
    {result, _} =
      Enum.reduce(2..n, {1, 0}, fn _, {a, b} ->
        {a + b, a}
      end)

    result
  end
end
