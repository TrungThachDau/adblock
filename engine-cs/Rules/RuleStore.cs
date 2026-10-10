using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace AdblockEngine.Rules;

public enum ParsedRuleType
{
    Block,
    Allow
}

public readonly record struct ParsedRule(ParsedRuleType Type, string Domain);

public class RuleStore
{
    private readonly HashSet<string> _blockRules = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _allowlistRules = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _orderedRules = new();
    private readonly ReaderWriterLockSlim _lock = new();

    public static string? NormalizeDomain(string raw)
    {
        var clean = raw.Trim().Trim('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(clean))
            return null;

        foreach (char c in clean)
        {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
                return null;
        }

        var labels = clean.Split('.');
        foreach (var l in labels)
        {
            if (string.IsNullOrEmpty(l))
                return null;
        }

        return clean;
    }

    private static bool IsReservedHost(string host)
    {
        var lower = host.Trim().Trim('.').ToLowerInvariant();
        return lower is "localhost" or "local" or "broadcasthost";
    }

    public static List<ParsedRule> ParseLine(string line)
    {
        var result = new List<ParsedRule>();
        var trimmed = line.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("!") || trimmed.StartsWith("#"))
            return result;

        // Skip rules containing path (/), options ($), cosmetic selectors (##, #?#, #@#, #$#)
        if (trimmed.Contains('/') || trimmed.Contains('$'))
            return result;
        if (trimmed.Contains("##") || trimmed.Contains("#?#") || trimmed.Contains("#@#") || trimmed.Contains("#$#"))
            return result;

        // Skip wildcards unless it is a leading wildcard prefix *.domain
        if (trimmed.Contains('*'))
        {
            if (trimmed.StartsWith("*."))
            {
                var suffix = trimmed.Substring(2);
                if (!suffix.Contains('*'))
                {
                    var valid = NormalizeDomain(suffix);
                    if (valid != null)
                        result.Add(new ParsedRule(ParsedRuleType.Block, valid));
                }
            }
            return result;
        }

        // 1. ABP Allowlist @@||host^
        if (trimmed.StartsWith("@@||"))
        {
            var domain = trimmed.Substring(4).TrimEnd('^');
            var valid = NormalizeDomain(domain);
            if (valid != null)
                result.Add(new ParsedRule(ParsedRuleType.Allow, valid));
            return result;
        }

        // 2. ABP Block ||host^
        if (trimmed.StartsWith("||"))
        {
            var domain = trimmed.Substring(2).TrimEnd('^');
            var valid = NormalizeDomain(domain);
            if (valid != null)
                result.Add(new ParsedRule(ParsedRuleType.Block, valid));
            return result;
        }

        // 3. Hosts format (strip inline comments first)
        int commentIdx = trimmed.IndexOf('#');
        var noComment = commentIdx >= 0 ? trimmed.Substring(0, commentIdx).Trim() : trimmed;
        var parts = noComment.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2)
        {
            var ip = parts[0];
            if (ip is "0.0.0.0" or "127.0.0.1" or "::1" or "::" or "0")
            {
                for (int i = 1; i < parts.Length; i++)
                {
                    if (IsReservedHost(parts[i]))
                        continue;
                    var valid = NormalizeDomain(parts[i]);
                    if (valid != null)
                        result.Add(new ParsedRule(ParsedRuleType.Block, valid));
                }
                return result;
            }
        }

        // 4. Plain domain
        if (!trimmed.Any(char.IsWhiteSpace))
        {
            if (IsReservedHost(trimmed))
                return result;
            var valid = NormalizeDomain(trimmed);
            if (valid != null)
                result.Add(new ParsedRule(ParsedRuleType.Block, valid));
        }

        return result;
    }

    public int Add(IEnumerable<string> rules)
    {
        _lock.EnterWriteLock();
        try
        {
            int addedCount = 0;
            foreach (var raw in rules)
            {
                var parsed = ParseLine(raw);
                foreach (var rule in parsed)
                {
                    if (rule.Type == ParsedRuleType.Block)
                    {
                        if (_blockRules.Add(rule.Domain))
                        {
                            _orderedRules.Add(raw);
                            addedCount++;
                        }
                    }
                    else if (rule.Type == ParsedRuleType.Allow)
                    {
                        if (_allowlistRules.Add(rule.Domain))
                        {
                            addedCount++;
                        }
                    }
                }
            }
            return addedCount;
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    public int AddAllowlist(IEnumerable<string> rules)
    {
        _lock.EnterWriteLock();
        try
        {
            int count = 0;
            foreach (var raw in rules)
            {
                var parsed = ParseLine(raw);
                if (parsed.Count == 0)
                {
                    var valid = NormalizeDomain(raw);
                    if (valid != null && _allowlistRules.Add(valid))
                        count++;
                }
                else
                {
                    foreach (var p in parsed)
                    {
                        if (_allowlistRules.Add(p.Domain))
                            count++;
                    }
                }
            }
            return count;
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    public int Remove(IEnumerable<string> rules)
    {
        _lock.EnterWriteLock();
        try
        {
            int removedCount = 0;
            foreach (var raw in rules)
            {
                var parsed = ParseLine(raw);
                foreach (var p in parsed)
                {
                    bool removedBlock = _blockRules.Remove(p.Domain);
                    bool removedAllow = _allowlistRules.Remove(p.Domain);
                    if (removedBlock || removedAllow)
                    {
                        _orderedRules.RemoveAll(r => r.Contains(p.Domain));
                        removedCount++;
                    }
                }
            }
            return removedCount;
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    public void Clear()
    {
        _lock.EnterWriteLock();
        try
        {
            _blockRules.Clear();
            _allowlistRules.Clear();
            _orderedRules.Clear();
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    public int Count
    {
        get
        {
            _lock.EnterReadLock();
            try { return _blockRules.Count; }
            finally { _lock.ExitReadLock(); }
        }
    }

    public int AllowlistCount
    {
        get
        {
            _lock.EnterReadLock();
            try { return _allowlistRules.Count; }
            finally { _lock.ExitReadLock(); }
        }
    }

    public string? Check(string domain)
    {
        var clean = NormalizeDomain(domain);
        if (clean == null)
            return null;

        _lock.EnterReadLock();
        try
        {
            // 1. Allowlist check FIRST (exact or dot-boundary suffix)
            if (_allowlistRules.Contains(clean))
                return null;

            int dotIndex = clean.IndexOf('.');
            while (dotIndex >= 0)
            {
                var suffix = clean.Substring(dotIndex + 1);
                if (_allowlistRules.Contains(suffix))
                    return null;

                dotIndex = clean.IndexOf('.', dotIndex + 1);
            }

            // 2. Blocklist check (exact or dot-boundary suffix)
            if (_blockRules.Contains(clean))
                return clean;

            dotIndex = clean.IndexOf('.');
            while (dotIndex >= 0)
            {
                var suffix = clean.Substring(dotIndex + 1);
                if (_blockRules.Contains(suffix))
                    return suffix;

                dotIndex = clean.IndexOf('.', dotIndex + 1);
            }

            return null;
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    public (int total, List<string> rules) List(int offset, int limit)
    {
        _lock.EnterReadLock();
        try
        {
            int total = _orderedRules.Count;
            if (offset >= total)
                return (total, new List<string>());

            int count = Math.Min(limit, total - offset);
            return (total, _orderedRules.GetRange(offset, count));
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    public int LoadFile(string path)
    {
        if (!File.Exists(path))
            return 0;

        var lines = File.ReadAllLines(path);
        return Add(lines);
    }
}
