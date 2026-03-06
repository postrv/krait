defmodule Krait.Security.PromptSanitizer do
  @moduledoc """
  Shared prompt injection sanitization for all LLM-facing text.

  Provides:
  - `sanitize/1` — strip control chars, zero-width chars, normalize Unicode,
    escape XML delimiters, truncate, strip injection patterns
  - `wrap_untrusted/2` — sanitize then wrap in labeled XML tags
  """

  @max_length 2000

  # Patterns that indicate prompt injection attempts
  @injection_patterns [
    ~r/ignore\s+(previous|above|all)/i,
    ~r/disregard\s+(previous|above|all)/i,
    ~r/\bsystem\s*:/i,
    ~r/\bnew\s+instructions?\b/i,
    ~r/\byou\s+are\s+now\b/i,
    ~r/\bforget\s+(everything|all)\b/i,
    ~r/\boverride\b/i,
    ~r/\bpretend\b/i,
    ~r/\bact\s+as\b/i,
    ~r/\bjailbreak\b/i,
    ~r/\bDAN\s+mode\b/i,
    ~r/\bbehave\s+as\b/i,
    ~r/\broleplay\b/i,
    ~r/\bfrom\s+now\s+on\b/i,
    ~r/\bin\s+your\s+next\s+response\b/i,
    ~r/\bchange\s+your\s+(role|personality|instructions?)\b/i,
    ~r/\breplace\s+(your|the)\s+instructions?\b/i,
    ~r/\bdo\s+not\s+follow\b/i,
    ~r/\brespond\s+as\b/i
  ]

  # ChatML control tokens (e.g., <|im_start|>, <|endoftext|>, <|end_of_turn|>)
  @chatml_pattern ~r/<\|[a-z0-9_-]+\|>/i

  @label_pattern ~r/^[a-z_]+$/

  # Zero-width characters to strip
  @zero_width_chars [
    # Zero-width space
    "\u200B",
    # Zero-width non-joiner
    "\u200C",
    # Zero-width joiner
    "\u200D",
    # BOM / zero-width no-break space
    "\uFEFF"
  ]

  # v26 M-4: Bidirectional override/embedding characters
  # These can reorder displayed text to hide injection payloads
  @bidi_chars [
    "\u202A",
    "\u202B",
    "\u202C",
    "\u202D",
    "\u202E",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069"
  ]

  @doc """
  Sanitize untrusted text for safe inclusion in LLM prompts.

  Strips control characters (keeping newline and tab), zero-width characters,
  escapes XML angle brackets, truncates to max length, and strips known
  injection patterns.
  """
  @spec sanitize(term()) :: String.t()
  def sanitize(text) when is_binary(text) do
    text
    |> strip_control_chars()
    |> strip_zero_width_chars()
    |> strip_bidi_chars()
    |> normalize_confusables()
    |> strip_chatml_tokens()
    |> normalize_fullwidth()
    |> strip_injection_patterns()
    |> escape_xml_delimiters()
    |> truncate(@max_length)
  end

  def sanitize(nil), do: ""
  def sanitize(text), do: sanitize(to_string(text))

  @doc """
  Sanitize text and wrap in labeled XML tags for LLM context.

  Returns: `<label>sanitized_text</label>`
  """
  @spec wrap_untrusted(term(), String.t()) :: String.t()
  def wrap_untrusted(text, label) when is_binary(label) do
    unless Regex.match?(@label_pattern, label) do
      raise ArgumentError,
            "wrap_untrusted label must match [a-z_]+, got: #{inspect(label)}"
    end

    sanitized = sanitize(text)
    "<#{label}>#{sanitized}</#{label}>"
  end

  @doc """
  Strict sanitization: sanitize + strip injection patterns a second time.

  v23 M-2: Double-pass catches patterns that emerge after the first pass's
  normalization/replacements (e.g., fullwidth→ASCII revealing an injection phrase).
  """
  @spec sanitize_strict(term()) :: String.t()
  def sanitize_strict(text) when is_binary(text) do
    text |> sanitize() |> strip_injection_patterns()
  end

  def sanitize_strict(nil), do: ""
  def sanitize_strict(text), do: sanitize_strict(to_string(text))

  # -- Private helpers --------------------------------------------------------

  defp strip_control_chars(text) do
    # Strip control chars except newline (\n = 0x0A) and tab (\t = 0x09)
    String.replace(text, ~r/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/, "")
  end

  defp strip_zero_width_chars(text) do
    Enum.reduce(@zero_width_chars, text, fn char, acc ->
      String.replace(acc, char, "")
    end)
  end

  # v26 M-4: Strip bidirectional override/embedding characters
  defp strip_bidi_chars(text) do
    Enum.reduce(@bidi_chars, text, fn char, acc ->
      String.replace(acc, char, "")
    end)
  end

  # Cyrillic→Latin confusable map for chars NFKC doesn't normalize
  @confusables %{
    # Cyrillic lowercase → Latin
    "\u043E" => "o",
    "\u0435" => "e",
    "\u0430" => "a",
    "\u0441" => "c",
    "\u0440" => "p",
    "\u0455" => "s",
    "\u0456" => "i",
    "\u0445" => "x",
    "\u0443" => "y",
    # Cyrillic uppercase → Latin
    "\u041E" => "O",
    "\u0415" => "E",
    "\u0410" => "A",
    "\u0421" => "C",
    "\u0420" => "P",
    "\u0412" => "B",
    "\u041D" => "H",
    "\u041A" => "K",
    "\u041C" => "M",
    "\u0422" => "T",
    # Greek confusables → Latin
    "\u03BF" => "o",
    "\u03B1" => "a",
    # v25 M-5: Armenian confusables → Latin
    "\u0585" => "o",
    "\u0561" => "a",
    "\u0570" => "h",
    "\u0578" => "n",
    "\u057D" => "s",
    # Cherokee confusables → Latin
    "\u13A0" => "D",
    "\u13A1" => "R",
    "\u13A2" => "T",
    "\u13A9" => "Y",
    "\u13AA" => "A"
  }

  defp normalize_confusables(text) do
    # First apply NFKC normalization
    text = :unicode.characters_to_nfkc_binary(text)

    # Then replace known Cyrillic homoglyphs that NFKC doesn't catch
    Enum.reduce(@confusables, text, fn {from, to}, acc ->
      String.replace(acc, from, to)
    end)
  end

  defp strip_chatml_tokens(text) do
    cleaned = Regex.replace(@chatml_pattern, text, "")
    if cleaned == text, do: text, else: strip_chatml_tokens(cleaned)
  end

  defp normalize_fullwidth(text) do
    # Convert fullwidth ASCII characters (U+FF01-U+FF5E) to normal ASCII
    text
    |> String.to_charlist()
    |> Enum.map(fn
      c when c >= 0xFF01 and c <= 0xFF5E -> c - 0xFEE0
      c -> c
    end)
    |> List.to_string()
  end

  @doc """
  Escape XML delimiters in text to prevent XML injection.

  Escapes `&`, `<`, and `>` characters. The `&` is escaped first to prevent
  double-encoding (e.g., `&lt;` becoming `&amp;lt;`).
  """
  @spec escape_xml_delimiters(String.t()) :: String.t()
  def escape_xml_delimiters(text) do
    text
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
  end

  @doc """
  Truncate text to at most `max` bytes, preserving valid UTF-8.

  Uses `binary_slice/3` (byte-based) instead of `String.slice/3` (grapheme-based)
  to ensure the output never exceeds the byte limit, even with multi-byte characters.
  """
  @spec truncate(String.t(), non_neg_integer()) :: String.t()
  def truncate(text, max) when byte_size(text) <= max, do: text

  def truncate(text, max) do
    binary_slice(text, 0, max) |> ensure_valid_utf8()
  end

  # Trim trailing bytes until the binary is valid UTF-8
  defp ensure_valid_utf8(bin) when is_binary(bin) do
    if String.valid?(bin) do
      bin
    else
      # A UTF-8 char is at most 4 bytes, so trim up to 3 bytes from the end
      trim_until_valid(bin, 1)
    end
  end

  defp trim_until_valid(bin, n) when n > 3, do: binary_slice(bin, 0, byte_size(bin) - 3)

  defp trim_until_valid(bin, n) do
    trimmed = binary_slice(bin, 0, byte_size(bin) - n)

    if String.valid?(trimmed) do
      trimmed
    else
      trim_until_valid(bin, n + 1)
    end
  end

  defp strip_injection_patterns(text) do
    Enum.reduce(@injection_patterns, text, fn pattern, acc ->
      Regex.replace(pattern, acc, "[REDACTED]")
    end)
  end
end
