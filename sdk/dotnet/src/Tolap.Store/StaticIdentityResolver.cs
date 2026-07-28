namespace Tolap.Store;

/// <summary>
/// Simple identity resolver with manually registered group and role mappings.
/// Useful for testing and development.
/// </summary>
public sealed class StaticIdentityResolver : IIdentityResolver
{
    private readonly Dictionary<string, List<string>> _userGroups = new();
    private readonly Dictionary<string, List<string>> _userRoles = new();

    /// <summary>
    /// Registers group memberships for a user.
    /// </summary>
    public StaticIdentityResolver AddUserToGroups(string userId, params string[] groups)
    {
        if (!_userGroups.ContainsKey(userId))
            _userGroups[userId] = new List<string>();

        _userGroups[userId].AddRange(groups);
        return this;
    }

    /// <summary>
    /// Registers role assignments for a user.
    /// </summary>
    public StaticIdentityResolver AddUserToRoles(string userId, params string[] roles)
    {
        if (!_userRoles.ContainsKey(userId))
            _userRoles[userId] = new List<string>();

        _userRoles[userId].AddRange(roles);
        return this;
    }

    public Task<string[]> GetGroupsForUserAsync(string userId)
    {
        var groups = _userGroups.TryGetValue(userId, out var g) ? g.ToArray() : Array.Empty<string>();
        return Task.FromResult(groups);
    }

    public Task<string[]> GetRolesForUserAsync(string userId)
    {
        var roles = _userRoles.TryGetValue(userId, out var r) ? r.ToArray() : Array.Empty<string>();
        return Task.FromResult(roles);
    }
}
