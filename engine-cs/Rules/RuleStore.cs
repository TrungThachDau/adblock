using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace AdblockEngine.Rules;

public class RuleStore
{
    private readonly HashSet<string> _exactRules = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _suffixRules = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _orderedRules = new();
    private readonly ReaderWriterLockSlim _lock = new();

    public static (string normalized, bool isSuffix) NormalizeRule(string rule)
    {
        var trimmed = rule.Trim().ToLowerInvariant();
        if (trimmed.StartsWith("*."))
        {
            return (trimmed.Substring(2).Trim('.'), true);
        }
        return (trimmed.Trim('.'), true);
    }

    public int Add(IEnumerable<string> rules)
    {
        _lock.EnterWriteLock();
        try
        {
            int addedCount = 0;
            foreach (var raw in rules)
            {
                var trimmed = raw.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
                    continue;

                var (normalized, isSuffix) = NormalizeRule(trimmed);
                if (string.IsNullOrEmpty(normalized))
                    continue;

                if (!_exactRules.Contains(normalized) && !_suffixRules.Contains(normalized))
                {
                    if (isSuffix)
                        _suffixRules.Add(normalized);
                    else
                        _exactRules.Add(normalized);

                    _orderedRules.Add(trimmed);
                    addedCount++;
                }
            }
            return addedCount;
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
                var (normalized, _) = NormalizeRule(raw);
                bool removedExact = _exactRules.Remove(normalized);
                bool removedSuffix = _suffixRules.Remove(normalized);
                if (removedExact || removedSuffix)
                {
                    _orderedRules.RemoveAll(r => NormalizeRule(r).normalized == normalized);
                    removedCount++;
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
            _exactRules.Clear();
            _suffixRules.Clear();
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
            try { return _orderedRules.Count; }
            finally { _lock.ExitReadLock(); }
        }
    }

    public string? Check(string domain)
    {
        var clean = domain.Trim().Trim('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(clean))
            return null;

        _lock.EnterReadLock();
        try
        {
            if (_exactRules.Contains(clean) || _suffixRules.Contains(clean))
                return clean;

            int dotIndex = clean.IndexOf('.');
            while (dotIndex >= 0)
            {
                var suffix = clean.Substring(dotIndex + 1);
                if (_suffixRules.Contains(suffix))
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
