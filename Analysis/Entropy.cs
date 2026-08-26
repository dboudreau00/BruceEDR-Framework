using System.Text;

namespace BruceEDR.Analysis;

/// <summary>
/// Byte-distribution statistics used by the PE analyzer and the secret scanner.
///
/// These are cheap, allocation-free measures that answer "does this buffer look like
/// structured data, or like ciphertext/compressed output?". They are HINTS. Entropy
/// alone cannot distinguish encryption from compression from a lookup table of random
/// GUIDs, and every one of these functions can be defeated by an attacker who pads
/// their payload with low-entropy filler. Treat a high reading as a reason to look
/// closer, never as a verdict on its own.
/// </summary>
public static class Entropy
{
    /// <summary>
    /// Shannon entropy at or above which a whole PE section is usually compressed,
    /// encrypted or packed rather than ordinary code or data.
    ///
    /// 7.2 bits/byte is the value the packer-detection literature converged on for
    /// SECTION-sized windows: normal x86 code sits around 5.8-6.4, resource and data
    /// sections lower, while UPX/Themida/AES output sits at 7.7-8.0. It is deliberately
    /// below 7.9 so that a partially packed section still trips it, which costs false
    /// positives on legitimately compressed payloads (installers, embedded PNG/ZIP
    /// resources, .NET single-file bundles) -- those are the expected FP class here.
    /// </summary>
    public const double PackedThresholdBitsPerByte = 7.2;

    /// <summary>Maximum Shannon entropy for byte-valued data, in bits per byte.</summary>
    public const double MaxBitsPerByte = 8.0;

    /// <summary>
    /// Shannon entropy of <paramref name="data"/> in bits per byte, in [0, 8].
    /// An empty buffer returns 0 (no information, rather than undefined) so callers
    /// never have to special-case it.
    /// </summary>
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0.0;

        Span<int> counts = stackalloc int[256];
        counts.Clear();
        foreach (byte b in data) counts[b]++;

        double n = data.Length;
        double h = 0.0;
        for (int i = 0; i < 256; i++)
        {
            int c = counts[i];
            if (c == 0) continue;
            double p = c / n;
            h -= p * Math.Log2(p);
        }

        // A single repeated byte yields -0.0 from the sum above; normalise it so
        // callers comparing against 0 and formatting for logs see a plain zero.
        if (h <= 0.0) return 0.0;
        return h > MaxBitsPerByte ? MaxBitsPerByte : h;
    }

    /// <summary>
    /// Shannon entropy of the UTF-8 encoding of <paramref name="text"/>. Measuring the
    /// encoded bytes (not chars) keeps the scale identical to the span overload, so one
    /// threshold works for both a memory buffer and a candidate credential string.
    /// </summary>
    public static double Shannon(string? text)
    {
        if (string.IsNullOrEmpty(text)) return 0.0;
        return Shannon(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>
    /// True when <paramref name="entropy"/> is at or above
    /// <see cref="PackedThresholdBitsPerByte"/>.
    ///
    /// HONEST LIMITATION: "high entropy" means "incompressible", which covers packed,
    /// encrypted AND merely compressed content equally. A signed installer, an embedded
    /// media resource and a ransomware stub all read the same here. This is a triage
    /// hint that should raise a score, not a detection that should quarantine.
    /// </summary>
    public static bool IsLikelyEncryptedOrPacked(double entropy) =>
        entropy >= PackedThresholdBitsPerByte;

    /// <summary>
    /// Pearson chi-square statistic of the byte distribution against a uniform
    /// expectation. Uniform random data converges on ~255 (the degrees of freedom);
    /// text, code and structured data run into the thousands or higher.
    ///
    /// This complements <see cref="Shannon(ReadOnlySpan{byte})"/> because entropy is
    /// insensitive to ORDER and to small biases: a buffer that cycles 0..255 forever
    /// scores a perfect 8.0 bits/byte but a chi-square of 0, which is itself anomalous.
    /// Returns 0 for an empty buffer.
    /// </summary>
    public static double ChiSquare(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0.0;

        Span<int> counts = stackalloc int[256];
        counts.Clear();
        foreach (byte b in data) counts[b]++;

        double expected = data.Length / 256.0;
        double chi = 0.0;
        for (int i = 0; i < 256; i++)
        {
            double d = counts[i] - expected;
            chi += d * d / expected;
        }
        return chi;
    }

    /// <summary>
    /// Fraction of bytes in [0, 1] that are printable ASCII (0x20-0x7E) or common
    /// whitespace (tab, LF, CR).
    ///
    /// Used to separate "this region is text/script the analyst can read" from "this
    /// region is binary". It deliberately counts BYTES, so UTF-16 text scores about
    /// 0.5 because of the interleaved NUL bytes -- callers scanning process memory
    /// should account for that rather than assuming a low ratio means binary.
    /// Returns 0 for an empty buffer.
    /// </summary>
    public static double PrintableRatio(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0.0;

        int printable = 0;
        foreach (byte b in data)
        {
            if (b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x20 && b <= 0x7E)) printable++;
        }
        return (double)printable / data.Length;
    }
}
